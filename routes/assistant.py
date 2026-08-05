"""
routes/assistant.py — GDMR Connect
=====================================
Rexor in-app AI assistant backed by the Groq API.
"""
import requests
from flask import Blueprint, request, jsonify

from database import leaves_col
from decorators import token_required
from extensions import limiter
from config import GROQ_API_KEY, GROQ_MODEL

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
