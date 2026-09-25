"""
routes/biometric.py — GDMR Connect
======================================
Biometric (fingerprint/face) attendance devices.

Device-facing routes implement ADMS ("Automatic Data Master Server"), the
push protocol ZKTeco and most other cloud-capable biometric device vendors
speak natively — the industry-standard mechanism for a device on an office
LAN to report to a cloud backend without a local bridge PC. The /iclock/...
paths below are fixed by that protocol (a device's firmware isn't
configurable beyond the server host/port), not a GDMR Connect convention.

"Connect" in the Admin UI = registering a device's serial number here and
typing our server address into the device's own Cloud Server menu. "The
machine activates" = the moment that device's first heartbeat hits
device_handshake() below and flips it from pending to connected. "Add
finger/face" happens on the device's own sensor (no way to transmit a live
biometric scan over the internet); the device reports each new local
enrollment back here, and an Admin does one thing — map it to an employee.

Punches (device_push, table=ATTLOG) resolve to the mapped employee and flow
through the exact same helpers.record_attendance_punch() a photo check-in
uses — same shift-timing rules, same attendance_col, same dedup index —
just with method="fingerprint"/"face" instead of "photo".
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import biometric_devices_col, biometric_enrollments_col, users_col
from decorators import token_required
from helpers import _is_admin, _has_module_grant, record_attendance_punch, infer_punch_type
from config import IST, BACKEND_PUBLIC_URL

bp = Blueprint("biometric", __name__)


def _authorized(write=False):
    if _is_admin(request.user):
        return True
    return _has_module_grant(request.user, "attendance", write=write)


def _verify_to_method(verify_field):
    """Best-effort ADMS "Verify" -> our `method`. Not fully standardized
    across vendors/firmware (1=fingerprint, 15/9/2=face are the most common
    groupings); anything unrecognized defaults to fingerprint since that's
    this feature's primary use case."""
    try:
        v = int(verify_field)
    except (TypeError, ValueError):
        return "fingerprint"
    return "face" if v in (2, 9, 15) else "fingerprint"


# =============================================================================
# Device-facing: ADMS protocol
# No @token_required — a physical device can't hold a login token. Trust is
# scoped to an already admin-registered serial number: the same "opaque
# shared credential" model as CRON_SECRET-protected /api/attendance/auto-absent
# in routes/stats.py. An unmapped device_pin is inert (no attendance is ever
# created for it) — the safety net for this open trust model.
# =============================================================================

@bp.route("/iclock/cdata", methods=["GET"])
def device_handshake():
    """Handshake + periodic heartbeat. A device calls this on boot and every
    few minutes after — the first successful call is what flips a device
    from "pending" to "connected" in the Admin dashboard."""
    serial = request.args.get("SN")
    if not serial:
        return "ERROR", 400

    device = biometric_devices_col.find_one({"serial_number": serial})
    if not device:
        return "ERROR", 403

    updates = {"last_seen_at": datetime.now(timezone.utc)}
    if device.get("status") == "pending":
        updates["status"] = "connected"
    biometric_devices_col.update_one({"_id": device["_id"]}, {"$set": updates})
    return "OK", 200


@bp.route("/iclock/cdata", methods=["POST"])
def device_push():
    """Punch logs (table=ATTLOG) and locally-enrolled users (table=OPERLOG).
    Exact line layouts are ADMS's — see the field comments below; may need
    small adjustments once verified against the real purchased device."""
    serial = request.args.get("SN")
    table  = (request.args.get("table") or "").upper()
    device = biometric_devices_col.find_one({"serial_number": serial}) if serial else None
    if not device:
        return "ERROR", 403

    biometric_devices_col.update_one({"_id": device["_id"]}, {"$set": {"last_seen_at": datetime.now(timezone.utc)}})
    device_id = str(device["_id"])
    body      = request.get_data(as_text=True) or ""

    if table == "ATTLOG":
        # Each line: PIN <tab> "YYYY-MM-DD HH:MM:SS" <tab> Status <tab> Verify <tab> ...
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            pin, time_str = parts[0].strip(), parts[1].strip()
            verify = parts[3].strip() if len(parts) > 3 else None
            method = _verify_to_method(verify)

            try:
                punch_local = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            punch_time_utc = IST.localize(punch_local).astimezone(timezone.utc)

            enrollment = biometric_enrollments_col.find_one({"device_id": device_id, "device_pin": pin})
            if not enrollment or not enrollment.get("employee_id"):
                # Unmapped PIN — surfaces in the dashboard's mapping queue;
                # no attendance is created until an Admin links it.
                biometric_enrollments_col.update_one(
                    {"device_id": device_id, "device_pin": pin},
                    {"$setOnInsert": {
                        "device_id": device_id, "device_pin": pin, "employee_id": None,
                        "biometric_type": method, "device_reported_name": None,
                    }},
                    upsert=True,
                )
                continue

            try:
                emp = users_col.find_one({"_id": ObjectId(enrollment["employee_id"])})
            except Exception:
                emp = None
            if not emp:
                continue

            uid       = str(emp["_id"])
            today_str = punch_time_utc.astimezone(IST).strftime("%Y-%m-%d")
            punch_type = infer_punch_type(uid, today_str)
            if not punch_type:
                continue  # both checkin and checkout already recorded today — extra punch, ignore

            ok, message, status = record_attendance_punch(
                emp, punch_time_utc, punch_type, method, location=device.get("branch"),
            )
            if not ok:
                print(f"[biometric] punch rejected for {emp.get('email')}: {message} ({status})")

    elif table == "OPERLOG":
        # A user enrolled locally on the device — reported as key=value pairs
        # tab-separated within the line, including PIN and (usually) Name.
        for line in body.splitlines():
            line = line.strip()
            if not line or "PIN=" not in line:
                continue
            fields = {}
            for chunk in line.split("\t"):
                if "=" in chunk:
                    k, _, v = chunk.partition("=")
                    fields[k.strip().upper()] = v.strip()
            pin = fields.get("PIN")
            if not pin:
                continue
            name = fields.get("NAME")
            update = {"$setOnInsert": {
                "device_id": device_id, "device_pin": pin, "employee_id": None, "biometric_type": "fingerprint",
            }}
            if name:
                update["$set"] = {"device_reported_name": name}
            biometric_enrollments_col.update_one({"device_id": device_id, "device_pin": pin}, update, upsert=True)

    return "OK", 200


@bp.route("/iclock/getrequest", methods=["GET"])
def device_getrequest():
    """Device polling for remote commands. Always "no commands" for now —
    a clean extension point for a possible future remote-triggered
    enrollment, not implemented since it's firmware-dependent and
    unverifiable before real hardware is in hand."""
    return "OK", 200


# =============================================================================
# Admin-facing: device + enrollment management
# =============================================================================

def _serialize_device(d):
    device_id = str(d["_id"])
    total  = biometric_enrollments_col.count_documents({"device_id": device_id})
    mapped = biometric_enrollments_col.count_documents({"device_id": device_id, "employee_id": {"$ne": None}})
    return {
        "_id":            device_id,
        "name":           d.get("name", ""),
        "branch":         d.get("branch", ""),
        "model":          d.get("model", ""),
        "serial_number":  d.get("serial_number", ""),
        "status":         d.get("status", "pending"),
        "last_seen_at":   d.get("last_seen_at"),
        "mapped_count":   mapped,
        "unmapped_count": total - mapped,
    }


@bp.route("/api/admin/biometric-devices", methods=["GET"])
@token_required
def list_biometric_devices():
    if not _authorized():
        return jsonify({"message": "Unauthorized"}), 403
    devices = list(biometric_devices_col.find().sort("created_at", -1))
    return jsonify([_serialize_device(d) for d in devices]), 200


@bp.route("/api/admin/biometric-devices", methods=["POST"])
@token_required
def add_biometric_device():
    if not _authorized(write=True):
        return jsonify({"message": "Unauthorized"}), 403
    data   = request.json or {}
    name   = (data.get("name") or "").strip()
    branch = (data.get("branch") or "").strip()
    model  = (data.get("model") or "").strip()
    serial = (data.get("serial_number") or "").strip()
    if not name or not serial:
        return jsonify({"message": "Name and serial number are required."}), 400
    if biometric_devices_col.find_one({"serial_number": serial}):
        return jsonify({"message": "A device with this serial number is already registered."}), 409

    doc = {
        "name": name, "branch": branch, "model": model, "serial_number": serial,
        "status": "pending", "last_seen_at": None,
        "created_by": str(request.user["_id"]), "created_at": datetime.now(timezone.utc),
    }
    ins = biometric_devices_col.insert_one(doc)
    https = BACKEND_PUBLIC_URL.startswith("https")
    return jsonify({
        "message": "Device registered. Enter the setup details below on the device itself (Comm → Cloud Server Settings).",
        "_id": str(ins.inserted_id),
        "setup": {
            "server_address": BACKEND_PUBLIC_URL.split("://", 1)[-1],
            "server_port":    443 if https else 80,
            "use_https":      https,
        },
    }), 200


@bp.route("/api/admin/biometric-devices/<device_id>", methods=["DELETE"])
@token_required
def delete_biometric_device(device_id):
    if not _authorized(write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        oid = ObjectId(device_id)
    except Exception:
        return jsonify({"message": "Invalid device id."}), 400
    res = biometric_devices_col.delete_one({"_id": oid})
    if res.deleted_count == 0:
        return jsonify({"message": "Device not found."}), 404
    biometric_enrollments_col.delete_many({"device_id": device_id})
    return jsonify({"message": "Device removed. Existing attendance history is unaffected."}), 200


# A device pushes to us — it can't be pinged/reached on demand from here (no
# inbound connection to an office-LAN device from the cloud). "Testing" a
# connection honestly means: how recently did we actually hear from it.
# Anything within a normal heartbeat cycle counts as online.
ONLINE_THRESHOLD_MINUTES = 15


@bp.route("/api/admin/biometric-devices/<device_id>/test", methods=["POST"])
@token_required
def test_biometric_device(device_id):
    if not _authorized():
        return jsonify({"message": "Unauthorized"}), 403
    try:
        oid = ObjectId(device_id)
    except Exception:
        return jsonify({"message": "Invalid device id."}), 400
    device = biometric_devices_col.find_one({"_id": oid})
    if not device:
        return jsonify({"message": "Device not found."}), 404

    last_seen = device.get("last_seen_at")
    if not last_seen:
        return jsonify({
            "online": False, "last_seen_at": None,
            "message": "This device has never contacted GDMR Connect yet. Double-check the Cloud Server Address/Port saved on the device, and that it has network access.",
        }), 200

    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    minutes_ago = (datetime.now(timezone.utc) - last_seen).total_seconds() / 60
    online = minutes_ago <= ONLINE_THRESHOLD_MINUTES

    if online:
        message = f"Online — last heard from this device {int(minutes_ago)} minute(s) ago."
    else:
        hours_ago = minutes_ago / 60
        when = f"{int(hours_ago)} hour(s) ago" if hours_ago >= 1 else f"{int(minutes_ago)} minute(s) ago"
        message = f"Not responding recently — last heard from this device {when}. Check it's powered on and connected to the network."

    return jsonify({"online": online, "last_seen_at": last_seen.isoformat(), "message": message}), 200


@bp.route("/api/admin/biometric-devices/<device_id>/enrollments", methods=["GET"])
@token_required
def list_device_enrollments(device_id):
    if not _authorized():
        return jsonify({"message": "Unauthorized"}), 403
    rows = list(biometric_enrollments_col.find({"device_id": device_id}))

    emp_ids = []
    for r in rows:
        if r.get("employee_id"):
            try:
                emp_ids.append(ObjectId(r["employee_id"]))
            except Exception:
                pass
    name_map = {str(u["_id"]): u.get("name", "Unknown") for u in users_col.find({"_id": {"$in": emp_ids}}, {"name": 1})}

    out = []
    for r in rows:
        out.append({
            "device_pin":           r.get("device_pin"),
            "device_reported_name": r.get("device_reported_name"),
            "biometric_type":       r.get("biometric_type", "fingerprint"),
            "employee_id":          r.get("employee_id"),
            "employee_name":        name_map.get(r.get("employee_id")) if r.get("employee_id") else None,
        })
    return jsonify(out), 200


@bp.route("/api/admin/biometric-devices/<device_id>/enrollments/<pin>/map", methods=["POST"])
@token_required
def map_device_enrollment(device_id, pin):
    if not _authorized(write=True):
        return jsonify({"message": "Unauthorized"}), 403
    data        = request.json or {}
    employee_id = data.get("employee_id")
    if not employee_id:
        return jsonify({"message": "employee_id is required."}), 400
    try:
        ObjectId(employee_id)
    except Exception:
        return jsonify({"message": "Invalid employee id."}), 400

    res = biometric_enrollments_col.update_one(
        {"device_id": device_id, "device_pin": pin},
        {"$set": {"employee_id": employee_id, "mapped_at": datetime.now(timezone.utc), "mapped_by": str(request.user["_id"])}},
    )
    if res.matched_count == 0:
        return jsonify({"message": "This device user was not found."}), 404
    return jsonify({"message": "Linked successfully."}), 200


@bp.route("/api/admin/biometric-devices/<device_id>/enrollments/<pin>", methods=["DELETE"])
@token_required
def unlink_device_enrollment(device_id, pin):
    if not _authorized(write=True):
        return jsonify({"message": "Unauthorized"}), 403
    res = biometric_enrollments_col.delete_one({"device_id": device_id, "device_pin": pin})
    if res.deleted_count == 0:
        return jsonify({"message": "Not found."}), 404
    return jsonify({"message": "Unlinked."}), 200
