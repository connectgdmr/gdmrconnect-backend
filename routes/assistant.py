"""
routes/assistant.py — GDMR Connect
=====================================
Rexor in-app AI assistant backed by the Groq API.
"""
from datetime import datetime

import requests
from bson import ObjectId
from flask import Blueprint, request, jsonify

from database import leaves_col, users_col, access_grants_col
from decorators import token_required
from extensions import limiter
from config import GROQ_API_KEY, GROQ_MODEL, IST

bp = Blueprint("assistant", __name__)


@bp.route("/api/assistant/chat", methods=["POST"])
@token_required
@limiter.limit("15 per minute")
def assistant_chat():
    """
    LLM-backed fallback for the Rexor in-app assistant, used only when the
    client-side keyword knowledge base has no match for the user's question.
    Returns 503 if no GROQ_API_KEY is configured.
    """
    if not GROQ_API_KEY:
        return jsonify({"message": "Assistant not configured."}), 503

    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"message": "message is required."}), 400
    if len(message) > 500:
        return jsonify({"message": "Message is too long."}), 400

    client_context = data.get("context") if isinstance(data.get("context"), dict) else {}
    next_holiday   = client_context.get("next_holiday") if isinstance(client_context.get("next_holiday"), dict) else None

    user            = request.user
    uid             = str(user["_id"])
    pending_leaves  = leaves_col.count_documents({"user_id": uid, "status": "Pending"})
    approved_leaves = leaves_col.count_documents({"user_id": uid, "status": "Approved"})

    facts = [
        f"Employee first name: {(user.get('name') or 'there').split(' ')[0]}",
        f"Role: {user.get('role', 'employee')}",
        f"Department: {user.get('department') or 'not set'}",
        f"Pending leave requests: {pending_leaves}",
        f"Approved leave requests: {approved_leaves}",
    ]
    if next_holiday and next_holiday.get("name"):
        facts.append(
            f"Next upcoming company holiday: {next_holiday.get('name')} on {next_holiday.get('date')} "
            f"({next_holiday.get('days_away')} day(s) away)"
        )

    system_prompt = (
        "You are Rexor, the friendly in-app assistant for GDMR Connect, an internal employee ERP. "
        "Answer the employee's question in 2-4 short sentences using ONLY the facts listed below plus "
        "general HR/workplace knowledge. Never invent company-specific data you weren't given (exact "
        "policies, leave balances, dates). If the question needs data you don't have, say so and point "
        "them to HR at info@gdmrfoundation.com or the relevant section of the app.\n\nKnown facts:\n"
        + "\n".join(f"- {f}" for f in facts)
    )

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model":       GROQ_MODEL,
                "messages":    [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": message},
                ],
                "temperature": 0.4,
                "max_tokens":  300,
            },
            timeout=12,
        )
        resp.raise_for_status()
        reply_text = resp.json()["choices"][0]["message"]["content"].strip()
        return jsonify({"reply": reply_text}), 200
    except Exception as e:
        return jsonify({"message": "Assistant is temporarily unavailable.", "error": str(e)}), 502


@bp.route("/api/assistant/voice", methods=["POST"])
@token_required
@limiter.limit("20 per minute")
def assistant_voice():
    """
    Admin-scoped voice assistant ("Rexor voice mode") — answers spoken
    questions about LIVE company data (e.g. "who is on leave today?") in
    either English or Malayalam. The reply is meant to be read aloud by the
    client via SpeechSynthesis, so it's kept to short, plain, TTS-friendly
    sentences (no markdown/emojis).

    Admin/owner/delegated-access only — this surfaces company-wide data,
    unlike /api/assistant/chat which only ever sees the caller's own facts.
    """
    role          = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    if role not in ("admin", "owner") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    if not GROQ_API_KEY:
        return jsonify({"message": "Assistant not configured."}), 503

    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    lang    = (data.get("lang") or "en").strip().lower()
    if lang not in ("en", "ml"):
        lang = "en"
    if not message:
        return jsonify({"message": "message is required."}), 400
    if len(message) > 500:
        return jsonify({"message": "Message is too long."}), 400

    # ---- Live fact: who's on leave today ----------------------------------
    # Same rule as the admin dashboard's "On Leave" KPI: date range covers
    # today (IST), status not Rejected/Cancelled, plus anyone on an active
    # extended leave. Keeping this in sync with stats.py/AdminDashboard.jsx
    # matters — the voice answer should never contradict what's on screen.
    today = str(datetime.now(IST).date())

    leaves_today = list(leaves_col.find(
        {"from_date": {"$lte": today}, "to_date": {"$gte": today},
         "status": {"$nin": ["Rejected", "Cancelled"]}},
        {"user_id": 1},
    ))
    leave_uids = {l["user_id"] for l in leaves_today if l.get("user_id")}
    valid_oids = [ObjectId(uid) for uid in leave_uids if ObjectId.is_valid(uid)]

    name_docs = list(users_col.find({"_id": {"$in": valid_oids}}, {"name": 1, "department": 1})) if valid_oids else []
    leave_names = [d.get("name") for d in name_docs if d.get("name")]

    ext_leave_users = list(users_col.find(
        {"role": {"$in": ["employee", "manager"]},
         "extended_leaves": {"$elemMatch": {"from_date": {"$lte": today}, "to_date": {"$gte": today}}}},
        {"name": 1},
    ))
    ext_leave_names = [u.get("name") for u in ext_leave_users if u.get("name")]

    all_names   = sorted(set(leave_names) | set(ext_leave_names))
    leave_count = len(all_names)

    facts = [
        f"Today's date: {today}",
        f"Number of employees on leave today: {leave_count}",
        f"Names of employees on leave today: {', '.join(all_names) if all_names else 'None — nobody is on leave today'}",
    ]

    lang_label = "Malayalam" if lang == "ml" else "English"
    system_prompt = (
        "You are Rexor, GDMR Connect's admin voice assistant. Answer the admin's spoken question "
        f"in {lang_label} ONLY, in 1-3 short natural sentences meant to be read aloud by text-to-speech "
        "— no markdown, no bullet points, no emojis, no headings. Use ONLY the facts listed below; never "
        "invent names, numbers, or company data you weren't given. Keep employee names exactly as given, "
        "in Latin script — do not translate or transliterate names even when replying in Malayalam.\n\n"
        "Facts:\n" + "\n".join(f"- {f}" for f in facts)
    )

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model":       GROQ_MODEL,
                "messages":    [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": message},
                ],
                "temperature": 0.3,
                "max_tokens":  200,
            },
            timeout=12,
        )
        resp.raise_for_status()
        reply_text = resp.json()["choices"][0]["message"]["content"].strip()
        return jsonify({"reply": reply_text, "lang": lang}), 200
    except Exception as e:
        return jsonify({"message": "Assistant is temporarily unavailable.", "error": str(e)}), 502
