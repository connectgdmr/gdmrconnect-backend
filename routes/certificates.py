"""
routes/certificates.py — GDMR Connect
=======================================
QR-verifiable Experience Certificates (FRD: "QR Code-Based Experience
Certificate Verification").

How it works
------------
* An authorised user (admin / owner, or a "certificates" Special Access grant)
  generates a certificate for an eligible employee. The server SNAPSHOTS the
  approved HRIS data (name, code, designation, department, date of joining,
  last working day) into a certificate record — the PDF and the public page are
  both rendered from that record, so they can never disagree.
* Every certificate gets a unique reference number (GDMR-COE-2026-0001) and a
  separate random, non-guessable verification token. Only the token is in the
  QR code's URL; the reference number is never usable to look a certificate up
  publicly (it is sequential, so it would be enumerable).
* Anyone can open /verify/<token> without logging in. The public endpoint
  re-reads the record on every request, so revoking or reissuing shows
  immediately. It never returns salary, contact details, address or IDs.
* Revoke needs a reason. Reissue supersedes the old certificate and links the
  two. Every action lands in an append-only audit collection; public lookups
  are logged (status + time only) and expire after a year.
"""
import io
import re
import secrets
from datetime import datetime, timezone, timedelta

from bson import ObjectId
from pymongo import ReturnDocument
from flask import Blueprint, request, jsonify, send_file

from config import IST, DASHBOARD_URL
from database import certificates_col, certificate_audit_col, certificate_verifications_col, users_col, counters_col
from decorators import token_required
from extensions import limiter
from helpers import _is_admin, _has_module_grant

bp = Blueprint("certificates", __name__)

ORG_NAME = "GDMR Foundation"
STATUSES = ("active", "revoked", "superseded")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")


# ── small helpers ────────────────────────────────────────────────────────────

def _today():
    return datetime.now(timezone.utc).astimezone(IST).date()


def _can_view(user):
    return _is_admin(user) or _has_module_grant(user, "certificates")


def _can_write(user):
    return _is_admin(user) or _has_module_grant(user, "certificates", write=True)


def _deny():
    return jsonify({"message": "Unauthorized"}), 403


def _parse_day(v):
    """users.doj / resignation.last_working_day may be 'YYYY-MM-DD' strings or datetimes."""
    if isinstance(v, datetime):
        return v.date()
    try:
        return datetime.strptime(str(v or "")[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _dept_text(dept):
    if isinstance(dept, list):
        return ", ".join(d for d in dept if d)
    return str(dept or "")


def _fmt(d):
    return d.strftime("%d %B %Y").lstrip("0") if d else ""


def _verify_url(token):
    return f"{DASHBOARD_URL.rstrip('/')}/verify/{token}"


def _next_reference():
    year = _today().year
    doc = counters_col.find_one_and_update(
        {"_id": f"coe_{year}"}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER
    )
    return f"GDMR-COE-{year}-{doc['seq']:04d}"


def _audit(cert, action, user, reason=None, prev=None, new=None, extra=None):
    """Append-only trail (FR-08)."""
    certificate_audit_col.insert_one({
        "reference_no": cert["reference_no"], "certificate_id": str(cert["_id"]), "employee_id": cert["employee_id"],
        "action": action, "by": str(user["_id"]), "by_name": user.get("name") or "",
        "at": datetime.now(timezone.utc), "reason": reason, "previous_status": prev, "new_status": new,
        **(extra or {}),
    })


def _serialize(c, names=None):
    names = names or {}
    out = {k: c.get(k) for k in (
        "reference_no", "employee_id", "employee_name", "employee_code", "designation", "department",
        "date_of_joining", "last_working_date", "issue_date", "signatory_name", "signatory_designation",
        "status", "replaces", "superseded_by", "reissue_reason", "revoke_reason", "verify_count",
    )}
    out["_id"] = str(c["_id"])
    for f in ("issued_at", "revoked_at", "superseded_at", "last_verified_at"):
        v = c.get(f)
        out[f] = v.isoformat() if isinstance(v, datetime) else None
    out["issued_by_name"] = names.get(c.get("issued_by"), c.get("issued_by_name", ""))
    out["revoked_by_name"] = names.get(c.get("revoked_by"), "") if c.get("revoked_by") else ""
    out["verify_url"] = _verify_url(c["token"])
    out["verify_count"] = c.get("verify_count", 0)
    return out


def _user_names(ids):
    oids = []
    for i in {i for i in ids if i}:
        try:
            oids.append(ObjectId(i))
        except Exception:
            pass
    return {str(u["_id"]): u.get("name") or "" for u in users_col.find({"_id": {"$in": oids}}, {"name": 1})} if oids else {}


# ── eligibility + snapshot ───────────────────────────────────────────────────

def _employee_snapshot(emp):
    """
    Approved HRIS data for a certificate, or (None, reason) when the employee
    isn't eligible: needs a joining date and a recorded last working day that
    has already passed — certificates are issued for completed service.
    """
    doj = _parse_day(emp.get("doj"))
    lwd = _parse_day((emp.get("resignation") or {}).get("last_working_day"))
    if emp.get("role") not in ("employee", "manager"):
        return None, "Only employees and managers can be issued an experience certificate."
    if not doj:
        return None, "This employee has no date of joining recorded."
    if not lwd:
        return None, "No last working day is recorded for this employee. Record the resignation first."
    if lwd > _today():
        return None, f"The last working day ({_fmt(lwd)}) hasn't passed yet."
    if lwd < doj:
        return None, "The last working day is before the date of joining — please correct the employee record."
    if not (emp.get("name") or "").strip():
        return None, "The employee record has no name."
    return {
        "employee_name":     emp["name"].strip(),
        "employee_code":     emp.get("employee_code") or "",
        "designation":       (emp.get("position") or "").strip() or "Employee",
        "department":        _dept_text(emp.get("department")),
        "date_of_joining":   doj.isoformat(),
        "last_working_date": lwd.isoformat(),
    }, None


@bp.route("/api/admin/certificates/eligible", methods=["GET"])
@token_required
def eligible_employees():
    if not _can_view(request.user):
        return _deny()
    active_for = {c["employee_id"] for c in certificates_col.find({"status": "active"}, {"employee_id": 1})}
    rows = []
    for e in users_col.find({"role": {"$in": ["employee", "manager"]}, "resignation.last_working_day": {"$ne": None}},
                            {"name": 1, "doj": 1, "position": 1, "department": 1, "employee_code": 1, "resignation": 1, "role": 1}):
        snap, _ = _employee_snapshot(e)
        if snap:
            rows.append({"_id": str(e["_id"]), **snap, "has_active_certificate": str(e["_id"]) in active_for})
    rows.sort(key=lambda r: r["employee_name"].lower())
    return jsonify(rows), 200


# ── admin: list / generate / reissue / revoke / audit / pdf ──────────────────

@bp.route("/api/admin/certificates", methods=["GET"])
@token_required
def list_certificates():
    if not _can_view(request.user):
        return _deny()
    q = {}
    status = request.args.get("status", "").strip()
    if status in STATUSES:
        q["status"] = status
    if request.args.get("employee_id"):
        q["employee_id"] = request.args["employee_id"].strip()
    certs = list(certificates_col.find(q).sort("issued_at", -1).limit(500))
    names = _user_names([c.get("issued_by") for c in certs] + [c.get("revoked_by") for c in certs])
    return jsonify([_serialize(c, names) for c in certs]), 200


def _issue(user, emp, signatory_name, signatory_designation, replaces=None, reissue_reason=None):
    snap, err = _employee_snapshot(emp)
    if err:
        return None, err
    cert = {
        **snap,
        "reference_no": _next_reference(),
        "token": secrets.token_urlsafe(24),
        "employee_id": str(emp["_id"]),
        "issue_date": _today().isoformat(),
        "signatory_name": signatory_name, "signatory_designation": signatory_designation,
        "status": "active", "issued_by": str(user["_id"]), "issued_by_name": user.get("name") or "",
        "issued_at": datetime.now(timezone.utc), "verify_count": 0,
        "replaces": replaces["reference_no"] if replaces else None, "reissue_reason": reissue_reason,
    }
    cert["_id"] = certificates_col.insert_one(cert).inserted_id
    return cert, None


def _signatory(data, fallback=None):
    name = str(data.get("signatory_name") or (fallback or {}).get("signatory_name") or "").strip()[:80]
    desg = str(data.get("signatory_designation") or (fallback or {}).get("signatory_designation") or "").strip()[:80]
    if not name or not desg:
        return None, None, "Authorised signatory name and designation are required."
    return name, desg, None


@bp.route("/api/admin/certificates", methods=["POST"])
@token_required
def generate_certificate():
    if not _can_write(request.user):
        return _deny()
    data = request.get_json(silent=True) or {}
    try:
        emp = users_col.find_one({"_id": ObjectId(str(data.get("employee_id") or ""))})
    except Exception:
        emp = None
    if not emp:
        return jsonify({"message": "Employee not found."}), 404
    name, desg, err = _signatory(data)
    if err:
        return jsonify({"message": err}), 400
    existing = certificates_col.find_one({"employee_id": str(emp["_id"]), "status": "active"})
    if existing:
        return jsonify({"message": f"{emp.get('name')} already has an active certificate ({existing['reference_no']}). Use Reissue to replace it."}), 409
    cert, err = _issue(request.user, emp, name, desg)
    if err:
        return jsonify({"message": err}), 400
    _audit(cert, "generated", request.user, new="active")
    return jsonify(_serialize(cert)), 201


def _load(cert_id):
    try:
        return certificates_col.find_one({"_id": ObjectId(cert_id)})
    except Exception:
        return None


@bp.route("/api/admin/certificates/<cert_id>/reissue", methods=["POST"])
@token_required
def reissue_certificate(cert_id):
    if not _can_write(request.user):
        return _deny()
    old = _load(cert_id)
    if not old:
        return jsonify({"message": "Certificate not found."}), 404
    if old["status"] != "active":
        return jsonify({"message": f"Only an active certificate can be reissued (this one is {old['status']})."}), 400
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason") or "").strip()
    if len(reason) < 5:
        return jsonify({"message": "Please give a reason for the reissue."}), 400
    name, desg, err = _signatory(data, fallback=old)
    if err:
        return jsonify({"message": err}), 400
    emp = users_col.find_one({"_id": ObjectId(old["employee_id"])})
    if not emp:
        return jsonify({"message": "The employee record no longer exists."}), 404
    new, err = _issue(request.user, emp, name, desg, replaces=old, reissue_reason=reason)
    if err:
        return jsonify({"message": err}), 400
    now = datetime.now(timezone.utc)
    certificates_col.update_one({"_id": old["_id"]}, {"$set": {"status": "superseded", "superseded_by": new["reference_no"], "superseded_at": now}})
    _audit(old, "superseded", request.user, reason=reason, prev="active", new="superseded", extra={"replaced_by": new["reference_no"]})
    _audit(new, "reissued", request.user, reason=reason, new="active", extra={"replaces": old["reference_no"]})
    return jsonify(_serialize(new)), 201


@bp.route("/api/admin/certificates/<cert_id>/revoke", methods=["POST"])
@token_required
def revoke_certificate(cert_id):
    if not _can_write(request.user):
        return _deny()
    cert = _load(cert_id)
    if not cert:
        return jsonify({"message": "Certificate not found."}), 404
    if cert["status"] != "active":
        return jsonify({"message": f"Only an active certificate can be revoked (this one is {cert['status']})."}), 400
    reason = str((request.get_json(silent=True) or {}).get("reason") or "").strip()
    if len(reason) < 5:
        return jsonify({"message": "A reason is required to revoke a certificate."}), 400
    now = datetime.now(timezone.utc)
    certificates_col.update_one({"_id": cert["_id"]}, {"$set": {
        "status": "revoked", "revoke_reason": reason[:500], "revoked_by": str(request.user["_id"]), "revoked_at": now}})
    _audit(cert, "revoked", request.user, reason=reason[:500], prev="active", new="revoked")
    fresh = _load(cert_id)
    return jsonify(_serialize(fresh, _user_names([fresh.get("issued_by"), fresh.get("revoked_by")]))), 200


@bp.route("/api/admin/certificates/<cert_id>/audit", methods=["GET"])
@token_required
def certificate_audit(cert_id):
    if not _can_view(request.user):
        return _deny()
    cert = _load(cert_id)
    if not cert:
        return jsonify({"message": "Certificate not found."}), 404
    rows = []
    for a in certificate_audit_col.find({"certificate_id": str(cert["_id"])}).sort("at", 1):
        rows.append({k: (a.get(k).isoformat() if isinstance(a.get(k), datetime) else a.get(k))
                     for k in ("action", "by_name", "at", "reason", "previous_status", "new_status", "replaced_by", "replaces")})
    since = datetime.now(timezone.utc) - timedelta(days=30)
    recent = certificate_verifications_col.count_documents({"reference_no": cert["reference_no"], "at": {"$gte": since}})
    return jsonify({"reference_no": cert["reference_no"], "events": rows, "verifications_30d": recent,
                    "verify_count": cert.get("verify_count", 0)}), 200


# ── PDF ──────────────────────────────────────────────────────────────────────

def build_pdf(cert):
    """Render the certificate PDF from the stored record (never from live employee data)."""
    import segno
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER

    W, H = A4
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setTitle(f"Experience Certificate {cert['reference_no']}")
    c.setAuthor(ORG_NAME)
    RED, INK, MUTED = colors.HexColor("#ed2224"), colors.HexColor("#111111"), colors.HexColor("#555555")

    # frame
    c.setStrokeColor(RED); c.setLineWidth(1.6); c.rect(28, 28, W - 56, H - 56)
    c.setLineWidth(0.5); c.rect(34, 34, W - 68, H - 68)

    # header / branding
    c.setFillColor(RED); c.rect(W / 2 - 22, H - 118, 44, 56, stroke=0, fill=1)
    c.setFillColor(colors.white); c.setFont("Helvetica-Bold", 13); c.drawCentredString(W / 2, H - 94, "gdmr")
    c.setFillColor(INK); c.setFont("Helvetica-Bold", 14); c.drawCentredString(W / 2, H - 138, "GDMR FOUNDATION")
    c.setFillColor(MUTED); c.setFont("Helvetica-Oblique", 8.5); c.drawCentredString(W / 2, H - 151, "a precious cornerstone, a sure foundation")

    # title
    c.setFillColor(INK); c.setFont("Helvetica-Bold", 22); c.drawCentredString(W / 2, H - 205, "EXPERIENCE CERTIFICATE")
    c.setStrokeColor(RED); c.setLineWidth(1.2); c.line(W / 2 - 70, H - 214, W / 2 + 70, H - 214)

    # ref + date
    c.setFont("Helvetica", 10); c.setFillColor(INK)
    c.drawString(64, H - 250, f"Reference No: {cert['reference_no']}")
    c.drawRightString(W - 64, H - 250, f"Date of issue: {_fmt(_parse_day(cert['issue_date']))}")

    # body
    body = ParagraphStyle("b", fontName="Helvetica", fontSize=11.5, leading=19, textColor=INK, alignment=0)
    name = cert["employee_name"]; code = cert.get("employee_code")
    dept = cert.get("department")
    text = (f"This is to certify that <b>{_esc(name)}</b>"
            + (f" (Employee ID: <b>{_esc(code)}</b>)" if code else "")
            + f" was employed with {ORG_NAME} as <b>{_esc(cert['designation'])}</b>"
            + (f" in the <b>{_esc(dept)}</b> department" if dept else "")
            + f" from <b>{_fmt(_parse_day(cert['date_of_joining']))}</b> to <b>{_fmt(_parse_day(cert['last_working_date']))}</b>.")
    p = Paragraph(text, body); pw, ph = p.wrap(W - 128, 200); p.drawOn(c, 64, H - 290 - ph)
    y = H - 290 - ph - 22

    # details table
    rows = [["Employee name", name], ["Employee ID", code or "—"], ["Designation", cert["designation"]],
            ["Department", dept or "—"], ["Date of joining", _fmt(_parse_day(cert["date_of_joining"]))],
            ["Last working date", _fmt(_parse_day(cert["last_working_date"]))]]
    cell = ParagraphStyle("c", fontName="Helvetica", fontSize=10, leading=13, textColor=INK)
    cellb = ParagraphStyle("cb", parent=cell, fontName="Helvetica-Bold")
    t = Table([[Paragraph(_esc(a), cellb), Paragraph(_esc(b), cell)] for a, b in rows], colWidths=[130, W - 128 - 130])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f6f6f6")),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    tw, th = t.wrap(W - 128, 400); t.drawOn(c, 64, y - th)
    y = y - th - 28
    closing = Paragraph("This certificate is issued on the above date. We wish them every success in their future endeavours.", body)
    cw, ch = closing.wrap(W - 128, 100); closing.drawOn(c, 64, y - ch)

    # signatory
    sy = 190
    c.setStrokeColor(INK); c.setLineWidth(0.6); c.line(W - 64 - 190, sy + 30, W - 64, sy + 30)
    c.setFont("Helvetica-Bold", 10.5); c.setFillColor(INK); c.drawRightString(W - 64, sy + 15, cert["signatory_name"])
    c.setFont("Helvetica", 9.5); c.drawRightString(W - 64, sy + 2, cert["signatory_designation"])
    c.drawRightString(W - 64, sy - 11, f"For {ORG_NAME}")

    # QR — drawn as vector squares (crisp at any print size) with a quiet zone
    url = _verify_url(cert["token"])
    qr = segno.make(url, error="m", micro=False)
    mod = 3.6                       # pt per module; ~34 modules -> ~3.4 cm, well above scan minimums
    n = qr.symbol_size(border=0)[0]
    size = n * mod
    qx, qy = 64, 78
    c.setFillColor(colors.white); c.rect(qx - 8, qy - 8, size + 16, size + 16, stroke=0, fill=1)   # quiet zone
    c.setFillColor(colors.black)
    for r, row in enumerate(qr.matrix):
        for col, bit in enumerate(row):
            if bit:
                c.rect(qx + col * mod, qy + (n - 1 - r) * mod, mod + 0.15, mod + 0.15, stroke=0, fill=1)
    c.setFillColor(INK); c.setFont("Helvetica-Bold", 9.5); c.drawString(qx + size + 18, qy + size - 12, "Scan to verify this certificate")
    c.setFont("Helvetica", 8.5); c.setFillColor(MUTED)
    c.drawString(qx + size + 18, qy + size - 26, "No login or app needed. The online record is the")
    c.drawString(qx + size + 18, qy + size - 38, "official source — if it does not show “Verified”,")
    c.drawString(qx + size + 18, qy + size - 50, "this document should not be relied upon.")
    c.setFont("Helvetica", 7.5)
    short = DASHBOARD_URL.rstrip("/").replace("https://", "").replace("http://", "") + "/verify/…"
    c.drawString(qx + size + 18, qy + 2, f"{short}   Ref: {cert['reference_no']}")

    # status watermark for withdrawn certificates
    if cert["status"] != "active":
        c.saveState(); c.translate(W / 2, H / 2); c.rotate(35)
        c.setFillColor(colors.Color(0.85, 0.1, 0.1, alpha=0.18)); c.setFont("Helvetica-Bold", 78)
        c.drawCentredString(0, 0, "REVOKED" if cert["status"] == "revoked" else "SUPERSEDED")
        c.restoreState()

    c.showPage(); c.save()
    buf.seek(0)
    return buf


def _esc(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@bp.route("/api/admin/certificates/<cert_id>/pdf", methods=["GET"])
@token_required
def certificate_pdf(cert_id):
    if not _can_view(request.user):
        return _deny()
    cert = _load(cert_id)
    if not cert:
        return jsonify({"message": "Certificate not found."}), 404
    _audit(cert, "downloaded", request.user, new=cert["status"])
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", cert["employee_name"]).strip("_") or "Employee"
    return send_file(build_pdf(cert), mimetype="application/pdf", as_attachment=True,
                     download_name=f"Experience_Certificate_{safe}_{cert['reference_no']}.pdf")


# ── PUBLIC verification (no login) ───────────────────────────────────────────

def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp


@bp.route("/api/public/certificates/<token>", methods=["GET"])
@limiter.limit("60 per minute")
def public_verify(token):
    """
    Always answers 200 with a `status`: verified | revoked | superseded | invalid,
    so the page can render every case. Only approved fields are returned, and a
    withdrawn certificate reveals nothing about the employee.
    """
    cert = certificates_col.find_one({"token": token}) if _TOKEN_RE.match(token or "") else None
    now = datetime.now(timezone.utc)
    if not cert:
        # Not logged on purpose: anyone can scan made-up codes, and a log row per
        # guess would let a script fill the database. The rate limit covers abuse.
        return _no_store(jsonify({"status": "invalid", "organisation": ORG_NAME})), 200

    status = {"active": "verified", "revoked": "revoked", "superseded": "superseded"}.get(cert["status"], "invalid")
    certificates_col.update_one({"_id": cert["_id"]}, {"$inc": {"verify_count": 1}, "$set": {"last_verified_at": now}})
    certificate_verifications_col.insert_one({"reference_no": cert["reference_no"], "status": status, "at": now})

    out = {"status": status, "organisation": ORG_NAME, "reference_no": cert["reference_no"],
           "issue_date": cert.get("issue_date"), "checked_at": now.isoformat()}
    if status == "verified":
        out.update({
            "employee_name": cert["employee_name"], "designation": cert["designation"],
            "date_of_joining": cert["date_of_joining"], "last_working_date": cert["last_working_date"],
        })
    elif status == "revoked" and isinstance(cert.get("revoked_at"), datetime):
        out["status_date"] = cert["revoked_at"].astimezone(IST).date().isoformat()
    elif status == "superseded" and isinstance(cert.get("superseded_at"), datetime):
        out["status_date"] = cert["superseded_at"].astimezone(IST).date().isoformat()
    return _no_store(jsonify(out)), 200
