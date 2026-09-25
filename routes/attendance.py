"""
routes/attendance.py — GDMR Connect
======================================
Attendance: check-in photo, checkout photo, employee view, admin view.
"""
import cloudinary.uploader
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import attendance_col, users_col
from decorators import token_required
from helpers import format_datetime_ist, is_offboarded, _is_admin, _has_module_grant, record_attendance_punch

bp = Blueprint("attendance", __name__)


@bp.route("/api/attendance/checkin-photo", methods=["POST"])
@token_required
def checkin_photo():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    if is_offboarded(request.user):
        return jsonify({"message": "Your employment has ended. Attendance check-in is no longer available."}), 403

    import pms_compliance as pc
    _blocked, _blocking_mgr = pc.is_employee_blocked(request.user)
    if _blocked:
        return jsonify({"message": pc.BLOCKED_MESSAGE, "blocked": True}), 403

    # Captured before the (sometimes slow) Cloudinary upload below, so the
    # shift-timing window in record_attendance_punch() reflects the moment
    # the employee actually pressed submit, not whenever the upload finishes.
    punch_time_utc = datetime.now(timezone.utc)

    data     = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image data received from frontend."}), 400

    location = data.get("location") or None

    def _upload():
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        return upload_result.get("secure_url")

    ok, message, status = record_attendance_punch(
        request.user, punch_time_utc, "checkin", "photo", upload_photo=_upload, location=location,
    )
    return jsonify({"message": message}), status


@bp.route("/api/attendance/checkout-photo", methods=["POST"])
@token_required
def checkout_photo():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    if is_offboarded(request.user):
        return jsonify({"message": "Your employment has ended. Attendance check-out is no longer available."}), 403

    import pms_compliance as pc
    _blocked, _blocking_mgr = pc.is_employee_blocked(request.user)
    if _blocked:
        return jsonify({"message": pc.BLOCKED_MESSAGE, "blocked": True}), 403

    punch_time_utc = datetime.now(timezone.utc)

    data     = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image data provided"}), 400

    location = data.get("location") or None

    def _upload():
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        return upload_result.get("secure_url")

    ok, message, status = record_attendance_punch(
        request.user, punch_time_utc, "checkout", "photo", upload_photo=_upload, location=location,
    )
    return jsonify({"message": message}), status


@bp.route("/api/my/attendance", methods=["GET"])
@token_required
def my_attendance():
    uid  = str(request.user["_id"])
    rows = []
    for a in attendance_col.find({"user_id": uid}).sort("time", -1):
        a["_id"]  = str(a["_id"])
        a["time"] = format_datetime_ist(a["time"])
        rows.append(a)
    return jsonify(rows), 200


@bp.route("/api/admin/attendance", methods=["GET"])
@token_required
def admin_all_attendance():
    """Master attendance log across every employee — backs AdminAttendancePage.jsx's
    'Complete Logs' tab. Was missing entirely (frontend called this exact path,
    api.jsx's adminAttendance(), and got a 404 every time), so that tab has
    likely been silently broken since it was built.

    Offboarded employees are excluded, per the standing admin-table convention
    (see feedback_admin_table_design) — their historical logs still exist and
    remain reachable via the per-employee endpoint below if ever needed, they
    just don't clutter the day-to-day master log.
    """
    if not (_is_admin(request.user) or _has_module_grant(request.user, "attendance")):
        return jsonify({"message": "Unauthorized"}), 403

    active_by_id = {
        str(u["_id"]): u
        for u in users_col.find({}, {"name": 1, "email": 1, "resignation": 1})
        if not is_offboarded(u)
    }

    records = []
    for a in attendance_col.find({"user_id": {"$in": list(active_by_id.keys())}}).sort("time", -1):
        emp = active_by_id.get(a["user_id"])
        a["_id"]            = str(a["_id"])
        a["time"]           = format_datetime_ist(a["time"])
        a["employee_name"]  = emp.get("name")  if emp else "Unknown"
        a["employee_email"] = emp.get("email") if emp else None
        records.append(a)
    return jsonify(records), 200


@bp.route("/api/admin/attendance/<emp_id>", methods=["GET"])
@token_required
def admin_employee_attendance(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "attendance")):
        return jsonify({"message": "Unauthorized"}), 403

    emp = users_col.find_one({"_id": ObjectId(emp_id)})
    if not emp:
        return jsonify({"message": "Employee not found"}), 404

    records = []
    for a in attendance_col.find({"user_id": emp_id}).sort("time", -1):
        a["_id"]            = str(a["_id"])
        a["time"]           = format_datetime_ist(a["time"])
        a["employee_name"]  = emp.get("name")
        a["employee_email"] = emp.get("email")
        records.append(a)
    return jsonify(records), 200


@bp.route("/api/admin/reports/late-checkins", methods=["GET"])
@token_required
def late_checkins_report():
    """HR report: every late check-in for a month — status_indicator is
    stamped "Present (Late)" at check-in time itself (see checkin_photo()
    above), across all three shifts, so this is a direct query rather than
    a recomputation from raw check-in time-of-day."""
    if not (_is_admin(request.user)
            or _has_module_grant(request.user, "attendance")
            or _has_module_grant(request.user, "summary")):
        return jsonify({"message": "Unauthorized"}), 403

    month = request.args.get("month")
    if not month:
        return jsonify({"message": "month required"}), 400

    emp_map = {
        str(u["_id"]): {"name": u.get("name"), "department": u.get("department")}
        for u in users_col.find({"role": {"$in": ["employee", "manager"]}}, {"name": 1, "department": 1})
    }

    rows = []
    for rec in attendance_col.find({
        "type":             "checkin",
        "date":             {"$regex": f"^{month}"},
        "status_indicator": "Present (Late)",
    }).sort("date", 1):
        emp = emp_map.get(rec.get("user_id"), {})
        rows.append({
            "date":           rec.get("date"),
            "user_id":        rec.get("user_id"),
            "employee_name":  emp.get("name", "Unknown"),
            "department":     emp.get("department"),
            "time":           format_datetime_ist(rec["time"]) if rec.get("time") else None,
            "method":         rec.get("method", "photo"),
        })
    return jsonify(rows), 200
