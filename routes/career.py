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
from helpers import _is_admin
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


# ── Admin endpoints ──────────────────────────────────────────────────────────

@bp.route("/api/admin/career/jobs", methods=["GET"])
@token_required
def list_jobs():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for j in career_jobs_col.find().sort("created_at", -1):
        j["_id"]          = str(j["_id"])
        j["requirements"] = _normalize_requirements(j.get("requirements"))
        rows.append(j)
    return jsonify(rows), 200


@bp.route("/api/admin/career/jobs", methods=["POST"])
@token_required
def create_job():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    data  = request.json or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"message": "title is required"}), 400
    doc = {
        "title":        title,
        "department":   str(data.get("department",  "")).strip(),
        "description":  str(data.get("description", "")).strip(),
        "requirements": _normalize_requirements(data.get("requirements")),
        "type":         data.get("type", "Full-time"),
        "status":       "Open",
        "created_by":   str(request.user["_id"]),
        "created_at":   datetime.now(timezone.utc),
    }
    res       = career_jobs_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@bp.route("/api/admin/career/jobs/<job_id>", methods=["PUT"])
@token_required
def update_job(job_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(job_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data   = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}
    for k in ["title", "department", "description", "type", "status"]:
        if k in data:
            update[k] = data[k]
    if "requirements" in data:
        update["requirements"] = _normalize_requirements(data.get("requirements"))
    if "status" in update and update["status"] not in ("Open", "Closed"):
        return jsonify({"message": "status must be 'Open' or 'Closed'"}), 400
    result = career_jobs_col.update_one({"_id": obj}, {"$set": update})
    if result.matched_count == 0:
        return jsonify({"message": "Job not found"}), 404
    return jsonify({"message": "Job updated"}), 200


@bp.route("/api/admin/career/jobs/<job_id>", methods=["DELETE"])
@token_required
def delete_job(job_id):
    if not _is_admin(request.user):
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
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    job_id = request.args.get("job_id")
    query  = {"job_id": job_id} if job_id else {}
    rows   = []
    for r in referrals_col.find(query).sort("submitted_at", -1):
        r["_id"] = str(r["_id"])
        rows.append(r)
    return jsonify(rows), 200


@bp.route("/api/admin/career/referrals/<referral_id>", methods=["PUT"])
@token_required
def update_referral(referral_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(referral_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data           = request.json or {}
    status         = data.get("status")
    valid_statuses = {"Pending", "Reviewed", "Shortlisted", "Rejected", "Hired"}
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
        job = career_jobs_col.find_one({"_id": ObjectId(job_id), "status": "Open"})
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
        "job_id":          job_id,
        "job_title":       job.get("title", ""),
        "referred_by":     str(request.user["_id"]),
        "referrer_name":   request.user.get("name", ""),
        "candidate_name":  candidate_name,
        "candidate_email": candidate_email,
        "candidate_phone": candidate_phone,
        "resume_url":      resume_link,
        "resume_file_url": resume_file_url,
        "notes":           notes,
        "status":          "Pending",
        "submitted_at":    datetime.now(timezone.utc),
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
            subject = f"New Referral from {doc['referrer_name']}"
            body = (
                f"{doc['referrer_name']} has submitted a referral.\n\n"
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
    for j in career_jobs_col.find({"status": "Open"}).sort("created_at", -1):
        j["_id"]          = str(j["_id"])
        j["requirements"] = _normalize_requirements(j.get("requirements"))
        rows.append(j)
    return jsonify(rows), 200


@bp.route("/api/my/referrals", methods=["GET"])
@token_required
def my_referrals():
    uid  = str(request.user["_id"])
    rows = []
    for r in referrals_col.find({"referred_by": uid}).sort("submitted_at", -1):
        r["_id"] = str(r["_id"])
        rows.append(r)
    return jsonify(rows), 200
