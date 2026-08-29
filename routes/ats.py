"""
routes/ats.py — GDMR Connect
================================
Applicant Tracking System: candidate CRUD, status pipeline, recordings, portfolio,
document request/upload (public token), stats, resume upload, admin doc review.
"""
import re
import html as _html
import secrets
import threading
import cloudinary.uploader
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId
from pymongo import ReturnDocument

from database import ats_candidates_col, users_col, counters_col
from decorators import token_required
from extensions import bcrypt
from helpers import _is_admin, _mgr_depts, parse_employment_type, _has_module_grant
from utils import send_email, generate_random_password
from config import IST

bp = Blueprint("ats", __name__)


# ── Status constants ──────────────────────────────────────────────────────────

ATS_STATUSES = (
    "New Application",
    "Resume Screening",
    "Screening Call Scheduled",
    "Screening Call Completed",
    "Technical Assessment",
    "Technical Interview",
    "HR Interview",
    "Management Interview",
    "Shortlisted",
    "Documentation Pending",
    "Offer Discussion",
    "Offer Released",
    "Offer Accepted",
    "Joined",
    "Rejected",
    "On Hold",
    "Withdrawn",
    # Legacy values kept so existing records remain valid
    "Applied",
    "Screening",
    "Interview",
    "Hired",
)

# Candidate fields the frontend Add/Edit Candidate form actually sends. Kept
# as one list so create/update/serialize can't silently drift apart again —
# that drift (this list existing nowhere, each endpoint hand-rolling its own
# subset under different names) was exactly the bug where Education/CTC/
# Location/Notice Period/Campaign/Job Role never saved.
CANDIDATE_TEXT_FIELDS = [
    "phone", "department", "job_role", "source", "campaign", "education",
    "current_company", "current_ctc", "expected_ctc", "current_location",
    "preferred_location", "notice_period", "resume_url", "remarks", "joining_date",
    "employment_type", "contract_months",
]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^(?:\+?\d{1,3}[\s-]?)?\d{10}$")

DOC_CHECKLIST_DEFAULT = [
    "Resume / CV",
    "Government ID Proof",
    "Address Proof",
    "Educational Certificates",
    "Experience / Relieving Letters",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ats_allowed(user, write=False):
    role = user.get("role")
    if role in ("admin", "owner"):
        return True
    dept = (user.get("department") or "").strip().lower()
    if "hr" in dept or "human resource" in dept:
        return True
    if role == "manager":
        return True
    if _has_module_grant(user, "ats", write=write):
        return True
    return False


def _ats_scope_query(user):
    role      = user.get("role")
    depts     = _mgr_depts(user)
    dept_lower = " ".join(d.lower() for d in depts)
    if role in ("admin", "owner") or "hr" in dept_lower or "human resource" in dept_lower:
        return {}
    # A "Recruitment" (ats) Grant Access delegation is meant to give
    # admin-equivalent visibility for that feature, not just the delegate's
    # own department — otherwise candidates outside their department (i.e.
    # most of them) silently disappear even though _ats_allowed() lets the
    # request through.
    if _has_module_grant(user, "ats"):
        return {}
    return {"department": {"$in": depts}}


def _next_applicant_code():
    """
    Atomically issue the next ATS applicant code (e.g. "APP-0007"). Uses a
    dedicated counters collection — find_one_and_update with $inc is atomic
    in MongoDB, unlike count_documents()+1, which can hand out the same
    number twice under concurrent requests or after a deletion.
    """
    doc = counters_col.find_one_and_update(
        {"_id": "ats_applicant"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return f"APP-{doc['seq']:04d}"


def _serialize_ats(c):
    c["_id"] = str(c["_id"])
    # Backward compat: candidates created before the field-name fix stored
    # the job title under the legacy key "role" — surface it as job_role too
    # so old records don't suddenly look blank.
    if not c.get("job_role") and c.get("role"):
        c["job_role"] = c["role"]
    if not c.get("experience") and c.get("experience_years"):
        c["experience"] = c["experience_years"]
    if not c.get("remarks") and c.get("notes"):
        c["remarks"] = c["notes"]
    for f in ("applied_at", "created_at", "updated_at",
              "hired_at", "offer_released_at", "offer_accepted_at"):
        if isinstance(c.get(f), datetime):
            c[f] = c[f].isoformat()
    for entry in c.get("status_history", []):
        if isinstance(entry.get("at"), datetime):
            entry["at"] = entry["at"].isoformat()
    for rec in c.get("recordings", []):
        if isinstance(rec.get("added_at"), datetime):
            rec["added_at"] = rec["added_at"].isoformat()
    for doc in c.get("documents", []):
        if isinstance(doc.get("uploaded_at"), datetime):
            doc["uploaded_at"] = doc["uploaded_at"].isoformat()
        if isinstance(doc.get("reviewed_at"), datetime):
            doc["reviewed_at"] = doc["reviewed_at"].isoformat()
    return c


# ── Email templates ───────────────────────────────────────────────────────────

_ATS_BRAND = "#34a06a"
_ATS_DASH  = "https://www.gdmrconnect.com"


def _ats_email_wrapper(inner_html, cta_label, cta_url):
    cta = (
        f'<a href="{cta_url}" style="display:inline-block;margin-top:22px;'
        f'background:{_ATS_BRAND};color:#fff;text-decoration:none;padding:11px 22px;'
        f'border-radius:8px;font-weight:600;font-size:14px">{cta_label}</a>'
        if cta_url else ""
    )
    return (
        f'<div style="font-family:\'Segoe UI\',Arial,sans-serif;max-width:600px;'
        f'margin:auto;border:1px solid #e6eaef;border-radius:12px;overflow:hidden">'
        f'<div style="background:{_ATS_BRAND};color:#fff;padding:18px 24px">'
        f'<h2 style="margin:0;font-size:18px">GDMR Foundation — Recruitment Update</h2></div>'
        f'<div style="padding:24px;color:#0f172a;font-size:14px;line-height:1.6">'
        f'{inner_html}{cta}</div>'
        f'<div style="background:#f8fafc;padding:14px 24px;font-size:12px;color:#94a3b8;text-align:center">'
        f'This is an automated message from GDMR Foundation. Do not reply directly.</div></div>'
    )


STATUS_EMAIL_TEMPLATES = {
    "Screening Call Scheduled": {
        "subject": "Next Step: Screening Call — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "Thank you for applying for the {job_role} position at GDMR Foundation.\n"
            "We have reviewed your application and would like to schedule a brief screening call "
            "to learn more about your background and experience.\n\n"
            "Our HR team will reach out shortly to confirm the date and time.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>Thank you for applying for the <strong>{job_role}</strong> role at GDMR Foundation.</p>"
            "<p>We have reviewed your application and would like to schedule a brief <strong>Screening Call</strong> "
            "to learn more about your background. Our HR team will reach out shortly to confirm the date and time.</p>"
            "<p>We look forward to speaking with you!</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "Technical Assessment": {
        "subject": "Technical Assessment — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "Congratulations on clearing the initial screening for the {job_role} role.\n"
            "The next step in your application is a Technical Assessment. "
            "Our team will share the assessment details and timeline with you shortly.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>Congratulations on clearing the initial screening for the <strong>{job_role}</strong> role!</p>"
            "<p>The next step is a <strong>Technical Assessment</strong>. "
            "Our team will share the assessment link and instructions with you shortly.</p>"
            "<p>Please keep an eye on your inbox.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "Technical Interview": {
        "subject": "Interview Invitation: Technical Round — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "We are pleased to invite you for a Technical Interview for the {job_role} position.\n"
            "Our HR team will be in touch soon with the schedule and joining details.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>We are pleased to invite you for a <strong>Technical Interview</strong> "
            "for the <strong>{job_role}</strong> position at GDMR Foundation.</p>"
            "<p>Our HR team will share the schedule and joining link shortly. "
            "Please confirm your availability when contacted.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "HR Interview": {
        "subject": "Interview Invitation: HR Round — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "We are pleased to invite you for an HR Interview for the {job_role} position.\n"
            "Our team will be in touch soon with the schedule and details.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>We are pleased to invite you for an <strong>HR Interview</strong> "
            "for the <strong>{job_role}</strong> position at GDMR Foundation.</p>"
            "<p>Our HR team will confirm the schedule and joining details shortly.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "Management Interview": {
        "subject": "Interview Invitation: Management Round — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "Congratulations on progressing to the Management Interview round for the {job_role} role.\n"
            "Our team will reach out shortly with the schedule.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>Congratulations on progressing to the <strong>Management Interview</strong> "
            "round for the <strong>{job_role}</strong> role!</p>"
            "<p>Our team will share the schedule and details shortly.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "Shortlisted": {
        "subject": "Great News — You've Been Shortlisted! | GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "We are delighted to inform you that you have been shortlisted for the {job_role} role "
            "at GDMR Foundation.\n\n"
            "Our HR team will be in touch with you shortly regarding the next steps.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>We are delighted to inform you that you have been <strong>shortlisted</strong> "
            "for the <strong>{job_role}</strong> role at GDMR Foundation! 🎉</p>"
            "<p>Our HR team will be in touch shortly with details about the next steps in the process.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "Documentation Pending": {
        "subject": "Action Required: Upload Your Documents — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "As part of your selection process for the {job_role} role at GDMR Foundation, "
            "we require you to upload certain documents.\n\n"
            "Please use the following link to access your secure document portal:\n"
            "{portal_url}\n\n"
            "Kindly upload the required documents at the earliest.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>As part of your selection process for the <strong>{job_role}</strong> role, "
            "we require you to upload certain documents via our secure portal.</p>"
            "<p>Please click the button below to access your personalised document portal and "
            "upload the requested files at the earliest.</p>",
            "Upload Documents", "{portal_url}",
        ),
    },
    "Offer Discussion": {
        "subject": "Let's Discuss Your Offer — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "Congratulations! We would like to move forward with extending you an offer "
            "for the {job_role} role at GDMR Foundation.\n\n"
            "Before we finalize the offer letter, our HR team would like to connect with you "
            "to discuss the role, compensation, and joining timeline.\n\n"
            "We will reach out shortly to schedule this conversation.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>Congratulations! We would like to move forward with extending you an offer for the "
            "<strong>{job_role}</strong> role at GDMR Foundation. 🎉</p>"
            "<p>Before we finalize the offer letter, our HR team would like to connect with you to "
            "discuss the role, compensation, and joining timeline.</p>"
            "<p>We will reach out shortly to schedule this conversation.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "Offer Released": {
        "subject": "Congratulations — Offer Letter | GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "We are thrilled to extend an offer of employment to you for the {job_role} role at GDMR Foundation.\n\n"
            "Our HR team will be in touch shortly with the formal offer letter and onboarding details.\n\n"
            "Congratulations and we look forward to welcoming you to the team!\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>We are thrilled to extend an <strong>offer of employment</strong> to you for the "
            "<strong>{job_role}</strong> role at GDMR Foundation! 🎉</p>"
            "<p>Our HR team will share the formal offer letter and onboarding details shortly. "
            "Please review and revert at your earliest convenience.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "Offer Accepted": {
        "subject": "Offer Accepted — Welcome to GDMR Foundation!",
        "plain": (
            "Dear {candidate_name},\n\n"
            "We are overjoyed that you have accepted our offer for the {job_role} role!\n\n"
            "Our HR team will reach out with your onboarding schedule and joining instructions.\n\n"
            "Welcome to the GDMR family!\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>We are overjoyed that you have <strong>accepted our offer</strong> for the "
            "<strong>{job_role}</strong> role! 🎊</p>"
            "<p>Our HR team will reach out shortly with your onboarding schedule and joining instructions. "
            "Welcome to the GDMR family — we can't wait to have you on board!</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "Joined": {
        "subject": "Welcome to GDMR Foundation!",
        "plain": (
            "Dear {candidate_name},\n\n"
            "A very warm welcome to GDMR Foundation!\n\n"
            "We are excited to have you join us as {job_role}. "
            "Your manager and HR team will guide you through the onboarding process.\n\n"
            "We look forward to a wonderful journey together.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>A very warm welcome to <strong>GDMR Foundation</strong>! 🎉</p>"
            "<p>We are thrilled to have you join us as <strong>{job_role}</strong>. "
            "Your manager and HR team will guide you through your onboarding journey.</p>"
            "<p>We look forward to achieving great things together!</p>",
            "Visit GDMR Connect", _ATS_DASH,
        ),
    },
    "Rejected": {
        "subject": "Your Application Status — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "Thank you for your interest in the {job_role} position at GDMR Foundation "
            "and for taking the time to go through our selection process.\n\n"
            "After careful consideration, we regret to inform you that we will not be moving "
            "forward with your application at this time.\n\n"
            "We appreciate your effort and encourage you to apply for future openings that match your profile.\n\n"
            "We wish you the very best in your career.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>Thank you for your interest in the <strong>{job_role}</strong> position at GDMR Foundation "
            "and for the time and effort you invested in our selection process.</p>"
            "<p>After careful consideration, we regret to inform you that we will not be moving "
            "forward with your application at this time.</p>"
            "<p>We truly appreciate your enthusiasm and encourage you to apply for future openings "
            "that align with your skills. We wish you the very best in your career ahead.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    "On Hold": {
        "subject": "Application Update — GDMR Foundation",
        "plain": (
            "Dear {candidate_name},\n\n"
            "We wanted to keep you informed that your application for the {job_role} role "
            "is currently on hold.\n\n"
            "We will get back to you as soon as there is an update. Thank you for your patience.\n\n"
            "Regards,\nGDMR Foundation HR Team"
        ),
        "html": _ats_email_wrapper(
            "<p>Dear <strong>{candidate_name}</strong>,</p>"
            "<p>We wanted to keep you informed that your application for the "
            "<strong>{job_role}</strong> role is currently <strong>on hold</strong>.</p>"
            "<p>We will reach out as soon as there is an update. Thank you for your patience.</p>",
            "Visit Our Website", _ATS_DASH,
        ),
    },
    # "Applied", "Withdrawn", "Screening", "Interview", "Hired" — no email sent
}


def _send_ats_status_email(candidate: dict, status: str):
    import traceback
    try:
        template = STATUS_EMAIL_TEMPLATES.get(status)
        if not template:
            return

        name     = candidate.get("name", "Candidate")
        job_role = (candidate.get("job_role") or candidate.get("role") or candidate.get("department") or "the advertised position")
        email    = (candidate.get("email") or "").strip()
        if not email:
            print(f"[ats-email] no email address on candidate {candidate.get('_id')} — skipping")
            return

        doc_token  = candidate.get("doc_token") or ""
        portal_url = (
            f"https://www.gdmrconnect.com/documents/{doc_token}"
            if doc_token else _ATS_DASH
        )

        subject = template["subject"].format(candidate_name=name, job_role=job_role, portal_url=portal_url)
        plain   = template["plain"].format(candidate_name=name, job_role=job_role, portal_url=portal_url)
        html    = template["html"].format(
            candidate_name=_html.escape(name),
            job_role=_html.escape(job_role),
            portal_url=portal_url,
        )

        ok = send_email(to_email=email, subject=subject, body=plain, html_body=html)
        print(f"[ats-email] status={status!r} to={email!r} sent={ok}")
    except Exception as exc:
        print(f"[ats-email] EXCEPTION for status={status!r}: {exc}\n{traceback.format_exc()}")


# ── Admin endpoints ───────────────────────────────────────────────────────────

@bp.route("/api/admin/ats/candidates", methods=["GET"])
@token_required
def ats_list_candidates():
    if not _ats_allowed(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    query      = _ats_scope_query(request.user)
    candidates = list(ats_candidates_col.find(query).sort("applied_at", -1))
    serialized = [_serialize_ats(c) for c in candidates]

    sourced_ids  = {c["sourced_by"]  for c in serialized if c.get("sourced_by")}
    referred_ids = {c["referred_by"] for c in serialized if c.get("referred_by")}
    name_map = {}
    all_ids  = sourced_ids | referred_ids
    if all_ids:
        try:
            obj_ids = [ObjectId(uid) for uid in all_ids]
            for u in users_col.find({"_id": {"$in": obj_ids}}, {"name": 1}):
                name_map[str(u["_id"])] = u["name"]
        except Exception:
            pass
    for c in serialized:
        c["sourced_by_name"]  = name_map.get(c.get("sourced_by") or "")
        c["referred_by_name"] = name_map.get(c.get("referred_by") or "")

    return jsonify(serialized), 200


@bp.route("/api/admin/ats/candidates/<candidate_id>", methods=["GET"])
@token_required
def ats_get_candidate(candidate_id):
    if not _ats_allowed(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    candidate = ats_candidates_col.find_one({"_id": obj})
    if not candidate:
        return jsonify({"message": "Candidate not found"}), 404

    scope = _ats_scope_query(request.user)
    if scope and candidate.get("department") not in _mgr_depts(request.user):
        return jsonify({"message": "Access denied"}), 403

    result = _serialize_ats(candidate)
    for field, name_field in (("sourced_by", "sourced_by_name"), ("referred_by", "referred_by_name")):
        val = result.get(field)
        if val:
            try:
                person = users_col.find_one({"_id": ObjectId(val)}, {"name": 1})
                result[name_field] = person["name"] if person else None
            except Exception:
                result[name_field] = None
        else:
            result[name_field] = None
    return jsonify(result), 200


@bp.route("/api/admin/ats/candidates", methods=["POST"])
@token_required
def ats_create_candidate():
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    data  = request.json or {}
    name  = str(data.get("name",  "")).strip()
    email = str(data.get("email", "")).strip()
    if not name:
        return jsonify({"message": "name is required"}), 400
    if email and not EMAIL_RE.match(email):
        return jsonify({"message": "Please enter a valid email address."}), 400
    phone = str(data.get("phone", "")).strip()
    if phone and not PHONE_RE.match(phone.replace(" ", "")):
        return jsonify({"message": "Please enter a valid 10-digit phone number."}), 400

    # One entry per phone number / email — reject outright rather than
    # silently creating a second "New Application" for someone already in
    # the pipeline. PHONE_RE guarantees the last 10 chars of a valid phone
    # are the bare local number with no separators, regardless of whether
    # a country code/space/hyphen prefix was typed, so comparing on that
    # tail catches "9876543210" vs "+91 9876543210" as the same number.
    if email and ats_candidates_col.find_one({"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}):
        return jsonify({"message": "A candidate with this email already exists."}), 400
    if phone and ats_candidates_col.find_one({"phone": {"$regex": re.escape(phone[-10:]) + "$"}}):
        return jsonify({"message": "A candidate with this phone number already exists."}), 400

    skills = data.get("skills", [])
    if isinstance(skills, str):
        skills = [s.strip() for s in skills.split(",") if s.strip()]

    sourced_by = str(data.get("sourced_by", "")).strip() or None
    if sourced_by:
        try:
            ObjectId(sourced_by)
        except Exception:
            return jsonify({"message": "Invalid sourced_by employee ID"}), 400

    referred_by = str(data.get("referred_by", "")).strip() or None
    if referred_by:
        try:
            ObjectId(referred_by)
        except Exception:
            return jsonify({"message": "Invalid referred_by employee ID"}), 400

    now = datetime.now(timezone.utc)
    doc = {
        "applicant_code": _next_applicant_code(),
        "name":   name,
        "email":  email,
        "sourced_by": sourced_by,
        "referred_by": referred_by,
        "status": "New Application",
        "skills": skills,
        "experience": data.get("experience"),
        **{f: str(data.get(f, "") or "").strip() for f in CANDIDATE_TEXT_FIELDS},
        "status_history":   [{"status": "New Application", "at": now, "by": str(request.user["_id"])}],
        "recordings":       [],
        "portfolio_links":  [],
        "documents":        [],
        "doc_token":        None,
        "applied_at":       now,
        "created_by":       str(request.user["_id"]),
        "created_at":       now,
        "updated_at":       now,
    }
    res        = ats_candidates_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@bp.route("/api/admin/ats/candidates/<candidate_id>", methods=["PUT"])
@token_required
def ats_update_candidate(candidate_id):
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    before = ats_candidates_col.find_one({"_id": obj})
    if not before:
        return jsonify({"message": "Candidate not found"}), 404

    data = request.json or {}
    if "email" in data and data["email"] and not EMAIL_RE.match(str(data["email"]).strip()):
        return jsonify({"message": "Please enter a valid email address."}), 400
    if "phone" in data and data["phone"] and not PHONE_RE.match(str(data["phone"]).strip().replace(" ", "")):
        return jsonify({"message": "Please enter a valid 10-digit phone number."}), 400

    new_email = str(data.get("email", "")).strip()
    if "email" in data and new_email and ats_candidates_col.find_one({
        "_id": {"$ne": obj}, "email": {"$regex": f"^{re.escape(new_email)}$", "$options": "i"},
    }):
        return jsonify({"message": "A candidate with this email already exists."}), 400
    new_phone = str(data.get("phone", "")).strip()
    if "phone" in data and new_phone and ats_candidates_col.find_one({
        "_id": {"$ne": obj}, "phone": {"$regex": re.escape(new_phone[-10:]) + "$"},
    }):
        return jsonify({"message": "A candidate with this phone number already exists."}), 400

    # "sourced_by"/"referred_by" must be in this list, not just handled below —
    # the loop right after only copies fields that are IN `editable` into
    # `update`, so a field validated-but-not-listed here silently never saves
    # (this is exactly the CANDIDATE_TEXT_FIELDS drift bug described above,
    # just for the two employee-reference fields instead of the text ones).
    editable = ["name", "email", "skills", "experience", "source", "sourced_by", "referred_by", *CANDIDATE_TEXT_FIELDS]
    update = {"updated_at": datetime.now(timezone.utc)}
    for f in editable:
        if f in data:
            update[f] = data[f]
    if "skills" in update and isinstance(update["skills"], str):
        update["skills"] = [s.strip() for s in update["skills"].split(",") if s.strip()]
    for ref_field, label in (("sourced_by", "sourced_by"), ("referred_by", "referred_by")):
        if ref_field in update:
            val = str(update[ref_field]).strip() if update[ref_field] else None
            if val:
                try:
                    ObjectId(val)
                except Exception:
                    return jsonify({"message": f"Invalid {label} employee ID"}), 400
            update[ref_field] = val

    result = ats_candidates_col.update_one({"_id": obj}, {"$set": update})
    if result.matched_count == 0:
        return jsonify({"message": "Candidate not found"}), 404

    updated = ats_candidates_col.find_one({"_id": obj})

    # Recruitment ↔ Employees sync — if this candidate was already onboarded,
    # push any changed profile fields (job role, department, phone, CTC,
    # education, etc.) onto their linked employee record and log what
    # changed so it shows up in their employee history timeline.
    if before.get("onboarded_employee_id"):
        _sync_candidate_to_employee(before, updated, str(request.user["_id"]))

    return jsonify(_serialize_ats(updated)), 200


@bp.route("/api/admin/ats/candidates/<candidate_id>", methods=["DELETE"])
@token_required
def ats_delete_candidate(candidate_id):
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    candidate = ats_candidates_col.find_one({"_id": obj}, {"resume_url": 1})
    if not candidate:
        return jsonify({"message": "Candidate not found"}), 404

    try:
        import cloudinary.api as _capi
        _capi.delete_resources_by_prefix(f"gdmr/ats_docs/{candidate_id}")
    except Exception as _e:
        print(f"[ats-delete] Cloudinary doc folder cleanup failed: {_e}")

    resume_url = candidate.get("resume_url") or ""
    if resume_url and "cloudinary.com" in resume_url:
        try:
            m = re.search(r"/upload/(?:v\d+/)?(.+?)(?:\.[^./?]+)?$", resume_url)
            if m:
                cloudinary.uploader.destroy(m.group(1), resource_type="raw")
        except Exception as _e:
            print(f"[ats-delete] Cloudinary resume cleanup failed: {_e}")

    ats_candidates_col.delete_one({"_id": obj})
    return jsonify({"message": "deleted"}), 200


# Recruitment-only detail that doesn't otherwise exist on an employee record
# (education, CTC, notice period, etc.) — carried onto the employee as one
# sub-document, plus kept in sync afterwards. {candidate field: display label}
RECRUITMENT_PROFILE_FIELDS = {
    "education":          "Education",
    "experience":         "Experience",
    "current_ctc":        "Current CTC",
    "expected_ctc":       "Expected CTC",
    "current_location":   "Current Location",
    "preferred_location": "Preferred Location",
    "notice_period":      "Notice Period",
    "campaign":           "Recruitment Campaign",
}


def _job_role_of(candidate: dict) -> str:
    return candidate.get("job_role") or candidate.get("role") or ""


def _recruitment_profile_of(candidate: dict) -> dict:
    return {k: candidate.get(k, "") for k in RECRUITMENT_PROFILE_FIELDS}


def _sync_candidate_to_employee(before: dict, after: dict, actor_id: str):
    """
    Keeps an already-onboarded employee's record in sync with later edits to
    their original candidate profile — e.g. HR corrects the job role or CTC
    after joining. Only touches fields that actually changed, and logs a
    human-readable line into employee.profile_history so it shows up on
    their Employee profile timeline (see EmployeeJourneyModal).
    """
    emp_id = after.get("onboarded_employee_id")
    if not emp_id:
        return
    try:
        emp_obj = ObjectId(emp_id)
    except Exception:
        return

    changes = []
    update  = {}

    new_role = _job_role_of(after)
    if new_role and new_role != _job_role_of(before):
        update["position"] = new_role
        changes.append(f"Job Role → {new_role}")

    new_dept = after.get("department", "")
    if new_dept and new_dept != before.get("department", ""):
        update["department"] = new_dept
        changes.append(f"Department → {new_dept}")

    new_phone = after.get("phone", "")
    if new_phone and new_phone != before.get("phone", ""):
        update["phone"] = new_phone
        changes.append("Phone updated")

    new_emp_type   = after.get("employment_type") or "Permanent"
    emp_type_changed = new_emp_type != (before.get("employment_type") or "Permanent")
    if emp_type_changed:
        update["employment_type"] = new_emp_type
        changes.append(f"Employment Type → {new_emp_type}")

    new_contract_months = after.get("contract_months") if new_emp_type == "Contract" else None
    if new_contract_months != before.get("contract_months"):
        update["contract_months"] = new_contract_months
        if not emp_type_changed:
            changes.append("Contract Duration updated")

    new_profile = _recruitment_profile_of(after)
    if new_profile != _recruitment_profile_of(before):
        update["recruitment_profile"] = new_profile
        changed_labels = [
            label for field, label in RECRUITMENT_PROFILE_FIELDS.items()
            if after.get(field, "") != before.get(field, "")
        ]
        if changed_labels:
            changes.append(f"{', '.join(changed_labels)} updated")

    if not update:
        return

    now = datetime.now(timezone.utc)
    history_entry = {
        "at": now, "by": actor_id, "type": "recruitment_sync",
        "summary": "Synced from recruitment: " + "; ".join(changes),
    }
    users_col.update_one(
        {"_id": emp_obj},
        {"$set": update, "$push": {"profile_history": history_entry}},
    )


def _auto_onboard_employee(candidate: dict, actor_id: str):
    """
    Recruitment → Employees bridge: the moment a candidate's status flips to
    'Hired'/'Joined', spin up their real employee account automatically,
    carrying over name/email/phone/department/position and every document
    on file (resume + anything they uploaded via the doc-collection link) —
    no manual re-entry. Idempotent: does nothing if an employee account
    already exists for this candidate (matched by onboarded_employee_id
    first, then by email as a fallback for older candidates).

    Returns the new employee's ObjectId, or None if one already existed /
    onboarding couldn't proceed (e.g. missing email — caller just logs it).
    """
    if candidate.get("onboarded_employee_id"):
        return None

    email = (candidate.get("email") or "").strip()
    name  = (candidate.get("name") or "").strip()
    if not email or not name:
        return None

    existing = users_col.find_one({"email": email}, {"_id": 1})
    if existing:
        ats_candidates_col.update_one(
            {"_id": candidate["_id"]},
            {"$set": {"onboarded_employee_id": str(existing["_id"])}},
        )
        return None

    now = datetime.now(timezone.utc)
    doj = candidate.get("joining_date") or str(datetime.now(IST).date())

    documents = []
    doc_names_added = set()
    if candidate.get("resume_url"):
        documents.append({
            "id": secrets.token_hex(8), "name": "Resume / CV",
            "url": candidate["resume_url"], "uploaded_at": now,
            "uploaded_by": actor_id, "source": "ats",
        })
        doc_names_added.add("Resume / CV")
    for d in candidate.get("documents") or []:
        if not d.get("url"):
            continue
        # The checklist can carry its own "Resume / CV" entry (auto-filled
        # from resume_url when a doc request is sent — see ats_doc_request)
        # — skip it here so it isn't copied a second time alongside the one
        # already added above from candidate.resume_url directly.
        doc_display_name = d.get("name") or "Document"
        if doc_display_name in doc_names_added:
            continue
        documents.append({
            "id": secrets.token_hex(8), "name": doc_display_name,
            "url": d["url"], "uploaded_at": d.get("uploaded_at") or now,
            "uploaded_by": actor_id, "source": "ats",
        })
        doc_names_added.add(doc_display_name)

    # Employment Type / Contract Duration, set on the candidate record (Add/Edit
    # Candidate form). Falls back to Permanent if unset or invalid — this is an
    # automatic bridge triggered by a status change, not a form submission the
    # recruiter can immediately fix, so it stays lenient rather than blocking.
    employment_type, contract_months, _emp_type_err = parse_employment_type(candidate)
    if _emp_type_err:
        employment_type, contract_months = "Permanent", None

    user_doc = {
        "name": name, "email": email,
        "password_changed": False, "role": "employee",
        "department": candidate.get("department", ""),
        "position":   _job_role_of(candidate),
        "phone":      candidate.get("phone", ""),
        "doj": doj, "employee_code": "",
        "created_at": now, "manager_id": None, "shift": "morning",
        "late_checkin_count_monthly": 0, "last_late_checkin_month": None,
        "documents": documents,
        "source_candidate_id": str(candidate["_id"]),
        "recruitment_profile": _recruitment_profile_of(candidate),
        "employment_type": employment_type, "contract_months": contract_months,
        "profile_history": [{
            "at": now, "by": actor_id, "type": "onboarding",
            "summary": "Onboarded from Recruitment — profile carried over from candidate record.",
        }],
    }

    # Only Contract hires are stored as records only (no password, no
    # welcome email) — Permanent and Internship both get portal login
    # credentials.
    password = None
    if employment_type != "Contract":
        password = generate_random_password()
        user_doc["password"] = bcrypt.generate_password_hash(password).decode("utf-8")

    res = users_col.insert_one(user_doc)

    ats_candidates_col.update_one(
        {"_id": candidate["_id"]},
        {"$set": {"onboarded_employee_id": str(res.inserted_id)}},
    )

    if employment_type != "Contract":
        subject = "Welcome to GDMR Connect: Your New Account Credentials"
        body    = (
            f"Dear {name},\n\n"
            "Congratulations, and welcome aboard! Your employee account for the GDMR Connect "
            "app has been created automatically as part of your onboarding.\n\n"
            "Please use the following credentials to log in:\n"
            f"Username (Email): {email}\n"
            f"Temporary Password: {password}\n\n"
            "We recommend logging in as soon as possible and updating your password.\n\n"
            "Thank you,\nThe GDMR Connect Team"
        )
        try:
            threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()
        except Exception as e:
            print("Failed to dispatch onboarding welcome email:", e)

    return res.inserted_id


@bp.route("/api/admin/ats/candidates/<candidate_id>/status", methods=["PUT"])
@token_required
def ats_update_status(candidate_id):
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    status = (request.json or {}).get("status", "")
    if status not in ATS_STATUSES:
        return jsonify({"message": f"status must be one of: {', '.join(ATS_STATUSES)}"}), 400

    now           = datetime.now(timezone.utc)
    history_entry = {"status": status, "at": now, "by": str(request.user["_id"])}
    set_fields    = {"status": status, "updated_at": now}
    if status in ("Hired", "Joined"):  set_fields["hired_at"]          = now
    elif status == "Offer Released":   set_fields["offer_released_at"] = now
    elif status == "Offer Accepted":   set_fields["offer_accepted_at"] = now

    result = ats_candidates_col.update_one(
        {"_id": obj},
        {"$set": set_fields, "$push": {"status_history": history_entry}}
    )
    if result.matched_count == 0:
        return jsonify({"message": "Candidate not found"}), 404

    updated = ats_candidates_col.find_one({"_id": obj})

    # Recruitment → Employees bridge — auto-create the real employee account
    # the moment someone is marked Hired/Joined, carrying over their details
    # and every document on file. See _auto_onboard_employee for details.
    if status in ("Hired", "Joined"):
        try:
            _auto_onboard_employee(updated, str(request.user["_id"]))
            updated = ats_candidates_col.find_one({"_id": obj})
        except Exception as e:
            print("Auto-onboarding error:", e)

    return jsonify(_serialize_ats(updated)), 200


@bp.route("/api/admin/ats/candidates/<candidate_id>/send-status-email", methods=["POST"])
@token_required
def ats_send_status_email(candidate_id):
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    status = str((request.json or {}).get("status", "")).strip()
    if not status:
        return jsonify({"message": "status is required"}), 400
    if status not in STATUS_EMAIL_TEMPLATES:
        available = ", ".join(sorted(STATUS_EMAIL_TEMPLATES))
        return jsonify({"message": f"No email template for '{status}'. Available: {available}"}), 400

    candidate = ats_candidates_col.find_one({"_id": obj})
    if not candidate:
        return jsonify({"message": "Candidate not found"}), 404

    threading.Thread(
        target=_send_ats_status_email,
        args=(dict(candidate), status),
        daemon=True,
    ).start()
    return jsonify({"message": f"Status email for '{status}' queued"}), 200


@bp.route("/api/admin/ats/candidates/<candidate_id>/recording", methods=["POST"])
@token_required
def ats_add_recording(candidate_id):
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    data = request.json or {}
    url  = str(data.get("url", "")).strip()
    if not url:
        return jsonify({"message": "url is required"}), 400
    entry  = {
        "type":     str(data.get("type", "")).strip(),
        "url":      url,
        "added_at": datetime.now(timezone.utc),
        "added_by": str(request.user["_id"]),
    }
    result = ats_candidates_col.update_one({"_id": obj}, {"$push": {"recordings": entry}})
    if result.matched_count == 0:
        return jsonify({"message": "Candidate not found"}), 404
    return jsonify({"message": "Recording added"}), 200


@bp.route("/api/admin/ats/candidates/<candidate_id>/portfolio", methods=["POST"])
@token_required
def ats_add_portfolio(candidate_id):
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    url = str((request.json or {}).get("url", "")).strip()
    if not url:
        return jsonify({"message": "url is required"}), 400
    result = ats_candidates_col.update_one({"_id": obj}, {"$addToSet": {"portfolio_links": url}})
    if result.matched_count == 0:
        return jsonify({"message": "Candidate not found"}), 404
    return jsonify({"message": "Portfolio link added"}), 200


@bp.route("/api/admin/ats/candidates/<candidate_id>/doc-request", methods=["POST"])
@token_required
def ats_doc_request(candidate_id):
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    candidate = ats_candidates_col.find_one({"_id": obj}, {"email": 1, "name": 1, "doc_token": 1, "documents": 1, "resume_url": 1})
    if not candidate:
        return jsonify({"message": "Candidate not found"}), 404

    token         = candidate.get("doc_token") or secrets.token_urlsafe(32)
    data          = request.json or {}
    required_docs = data.get("required_docs") or DOC_CHECKLIST_DEFAULT
    resume_url    = candidate.get("resume_url")

    docs = list(candidate.get("documents") or [])

    # A resume uploaded at application time (candidate.resume_url) lives
    # completely separately from the documents checklist — without this,
    # "Resume / CV" always shows Pending on the checklist even when the
    # candidate already has one on file. Auto-fulfil it here instead of
    # asking them to upload the same file again.
    if resume_url and "Resume / CV" in required_docs:
        matched = False
        for d in docs:
            if d.get("name") == "Resume / CV" and not d.get("url"):
                d.update({"url": resume_url, "status": "Submitted"})
                matched = True
        if not matched and not any(d.get("name") == "Resume / CV" for d in docs):
            docs.append({"name": "Resume / CV", "url": resume_url, "status": "Submitted", "required": True, "uploaded_at": datetime.now(timezone.utc)})

    existing_names = {d.get("name") for d in docs}
    new_entries    = [
        {"name": doc, "url": None, "status": "Pending", "required": True}
        for doc in required_docs if doc not in existing_names
    ]
    docs.extend(new_entries)

    now = datetime.now(timezone.utc)
    ats_candidates_col.update_one(
        {"_id": obj},
        {"$set": {"doc_token": token, "documents": docs, "updated_at": now}},
    )

    upload_link = f"https://www.gdmrconnect.com/documents/{token}"
    doc_list    = "\n".join(f"  • {d}" for d in required_docs)
    body        = (
        f"Dear {candidate.get('name', 'Candidate')},\n\n"
        f"As part of the hiring process at GDMR Foundation, please upload the following documents:\n\n"
        f"{doc_list}\n\n"
        f"Upload link: {upload_link}\n\n"
        f"Regards,\nGDMR Foundation HR Team"
    )
    threading.Thread(
        target=send_email,
        args=(candidate["email"], "Action Required: Upload Your Documents – GDMR Foundation", body),
        daemon=True,
    ).start()

    return jsonify({"message": "Document request sent", "upload_link": upload_link, "token": token}), 200


@bp.route("/api/admin/ats/stats", methods=["GET"])
@token_required
def ats_stats():
    if not _ats_allowed(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    query = _ats_scope_query(request.user)
    all_c = list(ats_candidates_col.find(query, {
        "status": 1, "source": 1, "department": 1, "role": 1, "job_role": 1,
        "applied_at": 1, "hired_at": 1,
    }))

    HIRED_STATUSES = ("Joined", "Hired")
    total           = len(all_c)
    offers_released = sum(1 for c in all_c if c.get("status") in ("Offer Released", "Offer Accepted", *HIRED_STATUSES))
    offers_accepted = sum(1 for c in all_c if c.get("status") in ("Offer Accepted", *HIRED_STATUSES))
    hired           = sum(1 for c in all_c if c.get("status") in HIRED_STATUSES)
    joining_ratio   = round(hired / offers_released * 100) if offers_released else 0

    by_status, by_source, by_dept, by_role = {}, {}, {}, {}
    hired_by_src, hire_days = {}, []

    for c in all_c:
        s   = c.get("status") or "Unknown"
        src = c.get("source")     or "Unknown"
        dpt = c.get("department") or "Unknown"
        rl  = _job_role_of(c)     or "Unknown"
        by_status[s]   = by_status.get(s,   0) + 1
        by_source[src] = by_source.get(src, 0) + 1
        by_dept[dpt]   = by_dept.get(dpt,   0) + 1
        by_role[rl]    = by_role.get(rl,    0) + 1
        if c.get("status") in HIRED_STATUSES:
            hired_by_src[src] = hired_by_src.get(src, 0) + 1
            if c.get("applied_at") and c.get("hired_at"):
                days = (c["hired_at"] - c["applied_at"]).days
                if days >= 0:
                    hire_days.append(days)

    time_to_hire         = round(sum(hire_days) / len(hire_days)) if hire_days else None
    source_effectiveness = [
        {
            "source": src,
            "total":  by_source[src],
            "hired":  hired_by_src.get(src, 0),
            "rate":   round(hired_by_src.get(src, 0) / by_source[src] * 100),
        }
        for src in by_source
    ]

    return jsonify({
        "total":                total,
        "offers_released":      offers_released,
        "offers_accepted":      offers_accepted,
        "hired":                hired,
        "joining_ratio":        joining_ratio,
        "by_status":            [{"status": k, "count": v} for k, v in by_status.items()],
        "by_source":            [{"source": k, "count": v} for k, v in by_source.items()],
        "by_department":        [{"department": k, "count": v} for k, v in by_dept.items()],
        "by_role":              [{"role": k, "count": v} for k, v in by_role.items()],
        "time_to_hire":         time_to_hire,
        "source_effectiveness": source_effectiveness,
    }), 200


@bp.route("/api/admin/ats/candidates/upload", methods=["POST"])
@token_required
def ats_upload_resume():
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    file = request.files.get("file")
    if not file:
        return jsonify({"message": "file is required"}), 400

    try:
        import cloudinary.uploader as _cu
        # use_filename/unique_filename preserve the original extension in the
        # delivered URL (e.g. "...ats_resumes/resume_ab12cd.docx") — without
        # them Cloudinary generates a bare public_id with NO extension at
        # all, which is why "View" couldn't tell the browser what kind of
        # file it was and just downloaded a nameless blob.
        result     = _cu.upload(file, resource_type="raw", folder="ats_resumes", use_filename=True, unique_filename=True)
        resume_url = result.get("secure_url", "")
    except Exception as e:
        return jsonify({"message": f"Upload failed: {str(e)}"}), 500

    parsed = {"name": "", "email": "", "phone": "", "skills": []}
    try:
        import pdfplumber, io as _io
        file.seek(0)
        with pdfplumber.open(_io.BytesIO(file.read())) as pdf:
            text = "\n".join(p.extract_text() or "" for p in pdf.pages)
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
        phones = re.findall(r"(?:\+91[\s-]?)?[6-9]\d{9}", text)
        lines  = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if emails: parsed["email"] = emails[0]
        if phones: parsed["phone"] = phones[0]
        if lines:  parsed["name"]  = lines[0]
    except Exception:
        pass

    return jsonify({"resume_url": resume_url, "parsed": parsed}), 200


@bp.route("/api/admin/ats/candidates/<candidate_id>/document", methods=["PUT"])
@token_required
def ats_review_document(candidate_id):
    if not _ats_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(candidate_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    data       = request.json or {}
    doc_name   = (data.get("name") or "").strip()
    new_status = (data.get("status") or "").strip()
    allowed    = ("Approved", "Rejected", "Re-upload Requested")
    if not doc_name:
        return jsonify({"message": "name is required"}), 400
    if new_status not in allowed:
        return jsonify({"message": f"status must be one of: {', '.join(allowed)}"}), 400

    candidate = ats_candidates_col.find_one({"_id": obj}, {"documents": 1})
    if not candidate:
        return jsonify({"message": "Candidate not found"}), 404

    docs    = list(candidate.get("documents") or [])
    matched = False
    for d in docs:
        if d.get("name") == doc_name:
            d["status"]      = new_status
            d["reviewed_at"] = datetime.now(timezone.utc)
            d["reviewed_by"] = str(request.user["_id"])
            matched = True
            break
    if not matched:
        return jsonify({"message": f"Document '{doc_name}' not found on this candidate"}), 404

    ats_candidates_col.update_one(
        {"_id": obj},
        {"$set": {"documents": docs, "updated_at": datetime.now(timezone.utc)}}
    )
    return jsonify({"documents": docs}), 200


# ── Candidate-facing (public, token-based) ────────────────────────────────────

@bp.route("/api/ats/documents/<doc_token>", methods=["GET"])
def ats_get_doc_checklist(doc_token):
    c = ats_candidates_col.find_one(
        {"doc_token": doc_token},
        {"name": 1, "role": 1, "job_role": 1, "documents": 1}
    )
    if not c:
        return jsonify({"message": "Invalid or expired link"}), 404
    docs = c.get("documents") or []
    return jsonify({
        "candidate_name": c.get("name", ""),
        "job_role":       _job_role_of(c),
        "required":       [d["name"] for d in docs if d.get("required")],
        "documents":      [
            {"name": d.get("name"), "url": d.get("url"), "status": d.get("status")}
            for d in docs if d.get("url")
        ],
    }), 200


@bp.route("/api/ats/documents/<doc_token>", methods=["POST"])
def ats_upload_doc(doc_token):
    c = ats_candidates_col.find_one({"doc_token": doc_token}, {"_id": 1, "documents": 1, "onboarded_employee_id": 1})
    if not c:
        return jsonify({"message": "Invalid or expired link"}), 404

    doc_name = (request.form.get("doc_name") or "").strip()
    file     = request.files.get("document")
    if not doc_name or not file:
        return jsonify({"message": "doc_name and document are required"}), 400

    file.seek(0, 2)
    if file.tell() > 15 * 1024 * 1024:
        return jsonify({"message": "File too large (max 15 MB)"}), 400
    file.seek(0)

    header = file.read(8)
    file.seek(0)
    MAGIC = {
        b"%PDF-":             "application/pdf",
        b"\xff\xd8\xff":      "image/jpeg",
        b"\x89PNG\r\n\x1a\n": "image/png",
    }
    magic_ok = any(header[:len(sig)] == sig for sig in MAGIC)
    mime_ok  = file.content_type in {"application/pdf", "image/jpeg", "image/png", "image/jpg"}
    if not magic_ok or not mime_ok:
        return jsonify({"message": "Only PDF and image files (JPEG, PNG) are accepted"}), 400

    candidate_id = str(c["_id"])
    try:
        import cloudinary.uploader as _cu
        res = _cu.upload(
            file,
            resource_type="auto",
            folder=f"gdmr/ats_docs/{candidate_id}",
            use_filename=True,
            unique_filename=True,
        )
        url = res.get("secure_url")
    except Exception as e:
        return jsonify({"message": f"Upload failed: {str(e)}"}), 500

    now      = datetime.now(timezone.utc)
    docs     = list(c.get("documents") or [])
    replaced = False
    for d in docs:
        if d.get("name") == doc_name:
            d.update({"url": url, "status": "Pending", "uploaded_at": now})
            replaced = True
            break
    if not replaced:
        docs.append({"name": doc_name, "url": url, "status": "Pending", "required": False, "uploaded_at": now})

    ats_candidates_col.update_one(
        {"_id": c["_id"]},
        {"$set": {"documents": docs, "updated_at": now}}
    )

    # If this candidate was already onboarded (status flipped to Hired/Joined
    # before they finished uploading every requested document), carry this
    # one over to their employee record too — otherwise it only ever shows
    # up on the candidate, and their Employee profile's Documents section
    # stays stuck at whatever existed at the moment they were hired.
    emp_id = c.get("onboarded_employee_id")
    if emp_id:
        try:
            emp_obj = ObjectId(emp_id)
        except Exception:
            emp_obj = None
        if emp_obj:
            emp = users_col.find_one({"_id": emp_obj}, {"documents": 1})
            if emp is not None:
                emp_docs = list(emp.get("documents") or [])
                matched  = False
                for d in emp_docs:
                    if d.get("name") == doc_name:
                        d.update({"url": url, "uploaded_at": now})
                        matched = True
                        break
                if not matched:
                    emp_docs.append({
                        "id": secrets.token_hex(8), "name": doc_name, "url": url,
                        "uploaded_at": now, "uploaded_by": "candidate", "source": "ats",
                    })
                users_col.update_one({"_id": emp_obj}, {"$set": {"documents": emp_docs}})

    safe_docs = []
    for d in docs:
        if not d.get("url"):
            continue
        d2 = dict(d)
        for f in ("uploaded_at", "reviewed_at"):
            if isinstance(d2.get(f), datetime):
                d2[f] = d2[f].isoformat()
        safe_docs.append(d2)
    return jsonify({"url": url, "documents": safe_docs}), 200
