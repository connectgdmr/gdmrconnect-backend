"""
routes/assessment.py — GDMR Connect
========================================
Assessment creation (admin), candidate invites, and public token-based submission.
"""
import secrets
import threading
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import assessments_col, candidates_col
from decorators import token_required
from helpers import _is_admin, _has_module_grant
from utils import send_email

bp = Blueprint("assessment", __name__)


@bp.route("/api/admin/assessments", methods=["GET"])
@token_required
def list_assessments():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assessment")):
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for a in assessments_col.find().sort("created_at", -1):
        a["_id"] = str(a["_id"])
        rows.append(a)
    return jsonify(rows), 200


@bp.route("/api/admin/assessments", methods=["POST"])
@token_required
def create_assessment():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assessment", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    data  = request.json or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"message": "title is required"}), 400
    # AdminAssessment.jsx's builder sends "duration"/"passing_score" (not
    # "duration_minutes") — this endpoint only ever read the latter, so a
    # freshly created assessment's Duration/Passing Score fields were
    # silently discarded (duration_minutes always defaulted to 0, and
    # passing_score was never stored at all). duration_minutes is kept as a
    # duplicate for get_assessment_by_token()'s existing fallback read and
    # the invite-email text below, which both already accept either key.
    duration      = int(data.get("duration", data.get("duration_minutes", 30)) or 30)
    passing_score = int(data.get("passing_score", 60) or 60)
    doc = {
        "title":            title,
        "description":      str(data.get("description", "")).strip(),
        "questions":        data.get("questions", []),
        "duration":         duration,
        "duration_minutes": duration,
        "passing_score":    passing_score,
        "created_by":       str(request.user["_id"]),
        "created_at":       datetime.now(timezone.utc),
    }
    res      = assessments_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@bp.route("/api/admin/assessments/<assessment_id>", methods=["PUT"])
@token_required
def update_assessment(assessment_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assessment", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(assessment_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data   = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}
    for k in ["title", "description", "questions"]:
        if k in data:
            update[k] = data[k]
    # Same field-name mismatch as create_assessment() above — the builder
    # sends "duration"/"passing_score", never "duration_minutes", so this
    # loop previously never touched either field on an edit.
    if "duration" in data or "duration_minutes" in data:
        duration = int(data.get("duration", data.get("duration_minutes", 30)) or 30)
        update["duration"] = duration
        update["duration_minutes"] = duration
    if "passing_score" in data:
        update["passing_score"] = int(data.get("passing_score", 60) or 60)
    result = assessments_col.update_one({"_id": obj}, {"$set": update})
    if result.matched_count == 0:
        return jsonify({"message": "Assessment not found"}), 404
    return jsonify({"message": "Assessment updated"}), 200


@bp.route("/api/admin/assessments/<assessment_id>", methods=["DELETE"])
@token_required
def delete_assessment(assessment_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assessment", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(assessment_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    result = assessments_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Assessment not found"}), 404
    candidates_col.delete_many({"assessment_id": assessment_id})
    return jsonify({"message": "Assessment deleted"}), 200


@bp.route("/api/admin/assessments/invite", methods=["POST"])
@token_required
def invite_candidate():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assessment", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    data          = request.json or {}
    name          = str(data.get("name",          "")).strip()
    email         = str(data.get("email",         "")).strip()
    phone         = str(data.get("phone",         "")).strip()
    assessment_id = str(data.get("assessmentId",  "")).strip()
    if not name or not email or not assessment_id:
        return jsonify({"message": "name, email, and assessmentId are required"}), 400

    assessment = assessments_col.find_one({"_id": ObjectId(assessment_id)})
    if not assessment:
        return jsonify({"message": "Assessment not found"}), 404

    token = secrets.token_urlsafe(32)
    doc   = {
        "assessment_id": assessment_id,
        "name":          name,
        "email":         email,
        "phone":         phone,
        "token":         token,
        "status":        "pending",
        "invited_at":    datetime.now(timezone.utc),
    }
    res       = candidates_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)

    assessment_link = f"https://www.gdmrconnect.com/assessment/{token}"
    duration        = assessment.get("duration", assessment.get("duration_minutes", 30))
    subject         = "You've Been Invited to Take an Assessment — GDMR Connect"
    body            = (
        f"Hello {name},\n\n"
        f"You have been invited to complete an assessment: \"{assessment.get('title', '')}\".\n\n"
        f"Click the link below to begin:\n{assessment_link}\n\n"
        + (f"Duration: {duration} minutes\n\n" if duration else "")
        + "This link is unique to you — please do not share it.\n\n"
        "Best regards,\nGDMR Connect Team"
    )
    threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()
    return jsonify(doc), 201


@bp.route("/api/admin/assessments/candidates", methods=["GET"])
@token_required
def list_candidates():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assessment")):
        return jsonify({"message": "Unauthorized"}), 403
    assessment_id = request.args.get("assessmentId")
    query         = {"assessment_id": assessment_id} if assessment_id else {}
    rows = []
    for c in candidates_col.find(query).sort("invited_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows), 200


@bp.route("/api/admin/assessments/candidates/<candidate_id>/result", methods=["GET"])
@token_required
def candidate_result(candidate_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assessment")):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        invite = candidates_col.find_one({"_id": ObjectId(candidate_id)})
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    if not invite:
        return jsonify({"message": "Candidate not found"}), 404

    invite["_id"] = str(invite["_id"])

    try:
        assessment = assessments_col.find_one({"_id": ObjectId(invite.get("assessment_id", ""))})
    except Exception:
        assessment = None

    if assessment and invite.get("answers"):
        questions        = assessment.get("questions", [])
        answers_enriched = []
        for ans in invite["answers"]:
            qi          = ans.get("question_index", 0)
            q           = questions[qi] if qi < len(questions) else {}
            given       = str(ans.get("answer", ""))
            correct_idx = str(q.get("correctIndex", ""))
            is_correct  = (given == correct_idx) if q.get("type") == "mcq" else None

            options      = q.get("options", [])
            given_text   = options[int(given)]       if q.get("type") == "mcq" and given.isdigit()       and int(given)       < len(options) else given
            correct_text = options[int(correct_idx)] if q.get("type") == "mcq" and correct_idx.isdigit() and int(correct_idx) < len(options) else None

            answers_enriched.append({
                "question_index": qi,
                "question":       q.get("text", f"Question {qi + 1}"),
                "given_answer":   given_text,
                "correct_answer": correct_text,
                "correct":        is_correct,
            })
        invite["answers"] = answers_enriched

    return jsonify(invite), 200


# =============================================================================
# PUBLIC (token-based, no auth)
# =============================================================================

@bp.route("/api/assessment/<token>", methods=["GET"])
def get_assessment_by_token(token):
    """Safe-to-call-repeatedly preview: title/description/duration/question
    COUNT only — never the actual question text/options, and never mutates
    `status`. Deliberately idempotent: corporate email security scanners
    (e.g. Microsoft Defender Safe Links) routinely pre-fetch every URL in an
    inbound email the moment it arrives, before the candidate ever opens it —
    if this endpoint marked the token "started" (as it used to), that
    automated pre-fetch alone would burn the one-time attempt before the
    real candidate ever saw the link. The actual one-shot "begin" transition
    lives in POST .../start below instead."""
    invite = candidates_col.find_one({"token": token})
    if not invite:
        return jsonify({"message": "Link is invalid or has already been used."}), 404
    if invite.get("status") == "completed":
        return jsonify({"message": "This assessment has already been submitted."}), 404
    if invite.get("status") == "started":
        return jsonify({"message": "This assessment was already started and can only be attempted once. Contact HR if you were disconnected."}), 404

    try:
        assessment = assessments_col.find_one({"_id": ObjectId(invite["assessment_id"])})
    except Exception:
        assessment = None
    if not assessment:
        return jsonify({"message": "Assessment not found."}), 404

    return jsonify({
        "title":          assessment.get("title"),
        "description":    assessment.get("description", ""),
        "duration":       assessment.get("duration", assessment.get("duration_minutes", 30)),
        "passing_score":  assessment.get("passing_score", 60),
        "question_count": len(assessment.get("questions", [])),
    }), 200


@bp.route("/api/assessment/<token>/start", methods=["POST"])
def start_assessment_by_token(token):
    """The one-shot "Begin Assessment" action — the only place `status`
    transitions to "started" and the only place the actual question
    text/options are ever transmitted. Re-firing this (accidental
    double-click, or the candidate closing the tab and reopening the same
    link) is rejected once a first call has already succeeded, so the exam
    can only genuinely be attempted once per invite."""
    invite = candidates_col.find_one({"token": token})
    if not invite:
        return jsonify({"message": "Link is invalid or has already been used."}), 404
    if invite.get("status") == "completed":
        return jsonify({"message": "This assessment has already been submitted."}), 404
    if invite.get("status") == "started":
        return jsonify({"message": "This assessment was already started and can only be attempted once. Contact HR if you were disconnected."}), 404

    try:
        assessment = assessments_col.find_one({"_id": ObjectId(invite["assessment_id"])})
    except Exception:
        assessment = None
    if not assessment:
        return jsonify({"message": "Assessment not found."}), 404

    # Atomic compare-and-set — only the request that actually flips
    # "invited"/whatever-it-was -> "started" gets the questions back; a
    # near-simultaneous second request (e.g. a fast double-click) matches
    # zero documents here and falls through to the 409 below instead of
    # both requests racing to read the question content.
    result = candidates_col.update_one(
        {"token": token, "status": {"$ne": "started"}},
        {"$set": {"status": "started", "started_at": datetime.now(timezone.utc)}},
    )
    if result.modified_count == 0:
        return jsonify({"message": "This assessment was already started and can only be attempted once. Contact HR if you were disconnected."}), 409

    questions = []
    for q in assessment.get("questions", []):
        q_clean = {"type": q.get("type"), "text": q.get("text")}
        if q.get("type") == "mcq":
            q_clean["options"] = q.get("options", [])
        questions.append(q_clean)

    return jsonify({
        "title":         assessment.get("title"),
        "description":   assessment.get("description", ""),
        "duration":      assessment.get("duration", assessment.get("duration_minutes", 30)),
        "passing_score": assessment.get("passing_score", 60),
        "questions":     questions,
    }), 200


@bp.route("/api/assessment/submit", methods=["POST"])
def submit_assessment():
    data      = request.json or {}
    token     = data.get("token", "")
    answers   = data.get("answers", [])
    forced    = bool(data.get("forced",    False))
    timed_out = bool(data.get("timed_out", False))

    if not token:
        return jsonify({"message": "token is required"}), 400

    invite = candidates_col.find_one({"token": token})
    if not invite:
        return jsonify({"message": "Invalid submission token."}), 400
    if invite.get("status") == "completed":
        return jsonify({"message": "This assessment has already been submitted."}), 400

    try:
        assessment = assessments_col.find_one({"_id": ObjectId(invite["assessment_id"])})
    except Exception:
        assessment = None
    if not assessment:
        return jsonify({"message": "Assessment not found."}), 404

    questions     = assessment.get("questions", [])
    passing_score = int(assessment.get("passing_score", 60))

    total_mcq = sum(1 for q in questions if q.get("type") == "mcq")
    correct   = 0
    for ans in answers:
        qi = ans.get("question_index")
        if qi is None or qi >= len(questions):
            continue
        q = questions[qi]
        if q.get("type") == "mcq":
            try:
                if str(ans.get("answer")) == str(q.get("correctIndex")):
                    correct += 1
            except Exception:
                pass

    score  = round((correct / total_mcq) * 100) if total_mcq > 0 else 0
    passed = score >= passing_score

    candidates_col.update_one(
        {"token": token},
        {"$set": {
            "status":       "completed",
            "score":        score,
            "passed":       passed,
            "answers":      answers,
            "submitted_at": datetime.now(timezone.utc),
            "forced":       forced,
            "timed_out":    timed_out,
        }}
    )
    return jsonify({"score": score, "passed": passed}), 200
