"""
routes/career.py — GDMR Connect
==================================
Career/Job board: admin CRUD, referrals, public listing, employee referrals.
"""
import re
import threading
import cloudinary.uploader
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import career_jobs_col, referrals_col, users_col
from decorators import token_required
from helpers import _is_admin, _has_module_grant
from utils import send_email

bp = Blueprint("career", __name__)


def _normalize_requirements(raw):
    """Always return a list of trimmed, non-empty requirement strings."""
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        items = re.split(r"[,\n]", raw)
    else:
        items = []
    return [str(item).strip() for item in items if str(item).strip()]


def _read_status(raw):
    """Tolerant read: only an explicit 'closed' (any case) reads as closed —
    everything else (including legacy 'Open' rows predating this fix, or a
    missing field) reads as active. Avoids needing a one-off DB migration."""
    return "closed" if str(raw or "").strip().lower() == "closed" else "active"


def _to_int_or_none(v):
    if v in (None, ""):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ── Admin endpoints ──────────────────────────────────────────────────────────

@bp.route("/api/admin/career/jobs", methods=["GET"])
@token_required
def list_jobs():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "career")):
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for j in career_jobs_col.find().sort("created_at", -1):
        j["_id"]            = str(j["_id"])
        j["requirements"]   = _normalize_requirements(j.get("requirements"))
        j["status"]         = _read_status(j.get("status"))
        j["employment_type"] = j.get("employment_type") or "Full-time"
        rows.append(j)
    return jsonify(rows), 200


@bp.route("/api/admin/career/jobs", methods=["POST"])
@token_required
def create_job():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "career", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    data  = request.json or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"message": "title is required"}), 400
    status = str(data.get("status", "active")).strip().lower()
    if status not in ("active", "closed"):
        return jsonify({"message": "status must be 'active' or 'closed'"}), 400
    doc = {
        "title":           title,
        "department":      str(data.get("department",  "")).strip(),
        "location":        str(data.get("location",    "")).strip(),
        "employment_type": str(data.get("employment_type", "Full-time")).strip() or "Full-time",
        "description":     str(data.get("description", "")).strip(),
        "requirements":    _normalize_requirements(data.get("requirements")),
        "salary_min":      _to_int_or_none(data.get("salary_min")),
        "salary_max":      _to_int_or_none(data.get("salary_max")),
        "status":          status,
        "created_by":      str(request.user["_id"]),
        "created_at":      datetime.now(timezone.utc),
    }
    res       = career_jobs_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@bp.route("/api/admin/career/jobs/<job_id>", methods=["PUT"])
@token_required
def update_job(job_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "career", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(job_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data   = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}
    for k in ["title", "department", "location", "employment_type", "description"]:
        if k in data:
            update[k] = str(data[k] or "").strip()
    for k in ["salary_min", "salary_max"]:
        if k in data:
            update[k] = _to_int_or_none(data.get(k))
    if "requirements" in data:
        update["requirements"] = _normalize_requirements(data.get("requirements"))
    if "status" in data:
        status = str(data["status"]).strip().lower()
        if status not in ("active", "closed"):
            return jsonify({"message": "status must be 'active' or 'closed'"}), 400
        update["status"] = status
    if "title" in update and not update["title"]:
        return jsonify({"message": "title cannot be blank"}), 400
    result = career_jobs_col.update_one({"_id": obj}, {"$set": update})
    if result.matched_count == 0:
        return jsonify({"message": "Job not found"}), 404
    return jsonify({"message": "Job updated"}), 200


@bp.route("/api/admin/career/jobs/<job_id>", methods=["DELETE"])
@token_required
def delete_job(job_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "career", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(job_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    result = career_jobs_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Job not found"}), 404
    return jsonify({"message": "Job deleted"}), 200


@bp.route("/api/admin/career/referrals", methods=["GET"])
@token_required
def admin_list_referrals():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "career")):
        return jsonify({"message": "Unauthorized"}), 403
    job_id = request.args.get("job_id")
    query  = {"job_id": job_id} if job_id else {}
    rows   = []
    for r in referrals_col.find(query).sort("submitted_at", -1):
        r["_id"] = str(r["_id"])
        # Backward-compat for any referrals submitted before the field/status
        # rename (referrer_name -> referred_by_name, Pending -> New).
        if not r.get("referred_by_name") and r.get("referrer_name"):
            r["referred_by_name"] = r["referrer_name"]
        if r.get("status") == "Pending":
            r["status"] = "New"
        rows.append(r)
    return jsonify(rows), 200


@bp.route("/api/admin/career/referrals/<referral_id>", methods=["PUT"])
@token_required
def update_referral(referral_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "career", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(referral_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data           = request.json or {}
    status         = data.get("status")
    # Must match the admin UI's REF_STATUSES exactly, or "New"/"Interview" picks
    # in the dropdown fail with a 400 the UI doesn't surface.
    valid_statuses = {"New", "Shortlisted", "Interview", "Hired", "Rejected"}
    if not status or status not in valid_statuses:
        return jsonify({"message": f"status must be one of: {', '.join(sorted(valid_statuses))}"}), 400
    result = referrals_col.update_one(
        {"_id": obj},
        {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}}
    )
    if result.matched_count == 0:
        return jsonify({"message": "Referral not found"}), 404
    return jsonify({"message": "Referral status updated"}), 200


# ── Employee endpoints ────────────────────────────────────────────────────────

@bp.route("/api/career/referrals", methods=["POST"])
@token_required
def submit_referral():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    src             = request.form if request.form else (request.json or {})
    job_id          = str(src.get("job_id",          "")).strip()
    candidate_name  = str(src.get("candidate_name",  "")).strip()
    candidate_email = str(src.get("candidate_email", "")).strip()
    candidate_phone = str(src.get("candidate_phone", "")).strip()
    resume_link     = str(src.get("resume_url",      "")).strip() or None
    notes           = str(src.get("notes",            "")).strip() or None

    if not job_id or not candidate_name or not candidate_email:
        return jsonify({"message": "job_id, candidate_name, and candidate_email are required"}), 400

    try:
        # Tolerant match: accept "active" (current scheme), "Open" (legacy),
        # or a missing status field — anything that isn't explicitly closed.
        job = career_jobs_col.find_one({"_id": ObjectId(job_id), "status": {"$nin": ["closed", "Closed"]}})
    except Exception:
        return jsonify({"message": "Invalid job ID"}), 400
    if not job:
        return jsonify({"message": "Job not found or no longer open"}), 404

    resume_file_url = None
    f = request.files.get("resume")
    if f and f.filename:
        if not f.filename.lower().endswith(".pdf"):
            return jsonify({"message": "Only PDF files are allowed."}), 400
        if f.mimetype != "application/pdf":
            return jsonify({"message": "Invalid file type."}), 400
        head = f.stream.read(5)
        f.stream.seek(0)
        if head != b"%PDF-":
            return jsonify({"message": "File is not a valid PDF."}), 400
        f.stream.seek(0, 2)
        size = f.stream.tell()
        f.stream.seek(0)
        if size > 5 * 1024 * 1024:
            return jsonify({"message": "File too large (max 5 MB)."}), 400
        try:
            res = cloudinary.uploader.upload(
                f, resource_type="raw", folder="gdmr/referral_resumes",
                format="pdf", use_filename=True, unique_filename=True,
            )
            resume_file_url = res.get("secure_url")
        except Exception as e:
            print("Resume upload error:", e)
            return jsonify({"message": "Resume upload failed. Please try again."}), 500

    doc = {
        "job_id":            job_id,
        "job_title":         job.get("title", ""),
        "referred_by":       str(request.user["_id"]),
        "referred_by_name":  request.user.get("name", ""),
        "candidate_name":    candidate_name,
        "candidate_email":   candidate_email,
        "candidate_phone":   candidate_phone,
        "resume_url":        resume_link,
        "resume_file_url":   resume_file_url,
        "notes":             notes,
        "status":            "New",
        "submitted_at":      datetime.now(timezone.utc),
    }
    res       = referrals_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)

    manager_id = request.user.get("manager_id")
    if manager_id:
        try:
            manager = users_col.find_one({"_id": ObjectId(manager_id)})
        except Exception:
            manager = None
        if manager and manager.get("email"):
            subject = f"New Referral from {doc['referred_by_name']}"
            body = (
                f"{doc['referred_by_name']} has submitted a referral.\n\n"
                f"Candidate : {candidate_name}\n"
                f"Email     : {candidate_email}\n"
                f"Phone     : {candidate_phone or '—'}\n"
                f"Position  : {doc['job_title']}\n"
                f"Resume    : {resume_file_url or resume_link or 'Not provided'}\n"
                f"Notes     : {notes or '—'}\n\n"
                f"Please review in the GDMR Connect admin panel."
            )
            threading.Thread(target=send_email, args=(manager["email"], subject, body), daemon=True).start()

    return jsonify(doc), 201


# ── Public endpoints ─────────────────────────────────────────────────────────

@bp.route("/api/career/jobs", methods=["GET"])
def public_career_jobs():
    """Open job listings — no authentication required."""
    rows = []
    # Tolerant match: "active" (current scheme), "Open" (legacy), or a
    # missing status field all count as open — only "closed" is excluded.
    for j in career_jobs_col.find({"status": {"$nin": ["closed", "Closed"]}}).sort("created_at", -1):
        j["_id"]            = str(j["_id"])
        j["requirements"]   = _normalize_requirements(j.get("requirements"))
        j["employment_type"] = j.get("employment_type") or "Full-time"
        rows.append(j)
    return jsonify(rows), 200


@bp.route("/api/my/referrals", methods=["GET"])
@token_required
def my_referrals():
    uid  = str(request.user["_id"])
    rows = []
    for r in referrals_col.find({"referred_by": uid}).sort("submitted_at", -1):
        r["_id"] = str(r["_id"])
        if r.get("status") == "Pending":
            r["status"] = "New"
        rows.append(r)
    return jsonify(rows), 200
