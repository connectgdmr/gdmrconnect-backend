"""
routes/assistant.py — GDMR Connect
=====================================
Rexor — the AI orchestration layer for the whole ERP, backed by the Groq
API's tool-calling.

This is NOT a fixed "assemble some facts, ask once" chatbot. Every turn,
the model is handed a registry of typed tools (routes/assistant_tools.py)
covering attendance, leave, work plans, approvals, holidays, and
announcements. It decides which tool(s) it needs — possibly several, in
sequence, reading one result before deciding whether to call another — we
execute each one server-side against LIVE data, feed the results back,
and only return a final answer once the model has everything it needs.
The model never touches the database directly and can't see past what a
tool hands back, so it can't invent data or bypass the access rules baked
into each tool (see assistant_tools.py's _can_view_detail).

Both routes below (the employee/manager text widget and the admin voice
console) share this exact same orchestration core — the only difference
is tone (voice replies are short and TTS-friendly) and which language.
RBAC comes entirely from who's asking, enforced inside each tool, not
from which route was hit.
"""
import json
from datetime import datetime

import requests
from flask import Blueprint, request, jsonify

from database import access_grants_col
from decorators import token_required
from extensions import limiter
from config import GROQ_API_KEY, GROQ_MODEL, IST
from routes.assistant_tools import TOOL_SCHEMAS, TOOL_FUNCS

bp = Blueprint("assistant", __name__)

MAX_TOOL_ITERATIONS = 5
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

BASE_SYSTEM_PROMPT = """You are Rexor, the AI assistant built into GDMR Connect, an internal \
company ERP. You are not a search box or a report generator — you are a sharp, warm colleague \
who happens to have live access to the company's HR/attendance/work data through a set of tools.

How you work:
- Use the tools to look anything up. Never guess, estimate, or invent a name, date, status, or \
number — if a tool doesn't give you something, say plainly that you don't have that, don't make \
it up.
- When the user names someone, call find_person first to resolve exactly who they mean before \
looking anything else up. If find_person returns more than one match, ask which person they mean \
instead of picking one.
- Chain tools when a question genuinely needs more than one fact — e.g. "why is X absent" may \
need their leave status AND a correction request AND their check-in record before you can give a \
real answer, not just the first thing you found.
- Every answer must be built ONLY from what the tools returned this conversation. Don't reuse \
facts from earlier in the chat unless they're still relevant — re-check if a question is about a \
new day or new person.

How you talk:
- Sound like a capable human colleague, not a system. Never say "no data found", "unable to \
retrieve", or anything that sounds like an error message — instead say things like "Akshay hasn't \
checked in yet today" or "She's on approved sick leave today" or "There's no work plan from him \
yet today, so I can't say what he's on."
- Be concise — a couple of natural sentences, not a report. No markdown, no bullet lists, no \
headings, unless the user is asking for an actual list of several people (then plain comma-separated \
names is fine).
- If something is genuinely missing or nobody's touched it yet, explain that plainly instead of \
apologizing or sounding broken — e.g. "He hasn't submitted a work plan today, so there's nothing to \
show yet" rather than "No data available."
- Never expose implementation details (tool names, field names, "the database says...") — just \
answer like you already knew it.
- If you don't have permission to see someone's detail (a tool marks it "coarse"), say what you \
can see plainly and note the rest needs their manager or admin — don't apologize for it.
"""


def _call_groq(messages, temperature=0.4, max_tokens=400):
    resp = requests.post(
        GROQ_URL,
        headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
        json={
            "model": GROQ_MODEL, "messages": messages, "tools": TOOL_SCHEMAS,
            "tool_choice": "auto", "temperature": temperature, "max_tokens": max_tokens,
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]


def run_orchestrator(user, message, history=None, extra_system=""):
    """
    The tool-calling loop. `history` is a list of {role, content} dicts
    from earlier in this conversation (already trimmed/sanitized by the
    caller). Returns the final natural-language reply string.
    """
    system = BASE_SYSTEM_PROMPT
    if extra_system:
        system += "\n" + extra_system
    system += f"\n\nRight now it is {datetime.now(IST).strftime('%A, %Y-%m-%d %H:%M')} IST. " \
              f"The person you're talking to is {user.get('name') or 'a user'} ({user.get('role', 'employee')})."

    messages = [{"role": "system", "content": system}] + (history or []) + [{"role": "user", "content": message}]

    for _ in range(MAX_TOOL_ITERATIONS):
        try:
            msg = _call_groq(messages)
        except Exception as e:
            print("[assistant] Groq call failed:", e)
            return "I'm having trouble reaching the assistant service right now — try again in a moment."

        tool_calls = msg.get("tool_calls")
        if not tool_calls:
            return (msg.get("content") or "").strip() or "I'm not sure how to answer that yet."

        messages.append(msg)
        for tc in tool_calls:
            name = tc.get("function", {}).get("name")
            raw_args = tc.get("function", {}).get("arguments") or "{}"
            try:
                args = json.loads(raw_args)
            except (json.JSONDecodeError, TypeError):
                args = {}
            fn = TOOL_FUNCS.get(name)
            if not fn:
                result = {"error": f"No such tool: {name}"}
            else:
                try:
                    result = fn(user, **args)
                except TypeError as e:
                    result = {"error": f"Bad arguments for {name}: {e}"}
                except Exception as e:
                    print(f"[assistant] tool {name} failed:", e)
                    result = {"error": "That lookup failed unexpectedly."}
            messages.append({
                "role": "tool", "tool_call_id": tc.get("id"), "name": name,
                "content": json.dumps(result, default=str),
            })

    return "That took more steps than expected to look up — could you ask again, maybe a bit more specifically?"


def _sanitize_history(raw_history, limit=10):
    history = []
    for turn in (raw_history if isinstance(raw_history, list) else [])[-limit:]:
        if not isinstance(turn, dict):
            continue
        role = "assistant" if turn.get("role") == "assistant" else "user"
        content = str(turn.get("content") or "").strip()[:800]
        if content:
            history.append({"role": role, "content": content})
    return history


@bp.route("/api/assistant/chat", methods=["POST"])
@token_required
@limiter.limit("20 per minute")
def assistant_chat():
    """Text-mode Rexor — every role. Same orchestration core as voice mode,
    just without the TTS/short-sentence constraints."""
    if not GROQ_API_KEY:
        return jsonify({"message": "Assistant not configured."}), 503

    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"message": "message is required."}), 400
    if len(message) > 500:
        return jsonify({"message": "Message is too long."}), 400

    history = _sanitize_history(data.get("history"))
    reply = run_orchestrator(request.user, message, history)
    return jsonify({"reply": reply}), 200


@bp.route("/api/assistant/voice", methods=["POST"])
@token_required
@limiter.limit("20 per minute")
def assistant_voice():
    """Admin/owner/delegated-access voice mode — same orchestrator, tuned
    for text-to-speech: short, plain sentences, a chosen language, no
    markdown. Access to company-wide data (vs. just the caller's own) is
    controlled entirely by the tools' own RBAC — an admin naturally gets
    more back than an employee would asking the same question."""
    role = request.user.get("role")
    if role not in ("admin", "owner"):
        has_delegated = bool(access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True}))
        if not has_delegated:
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

    history = _sanitize_history(data.get("history"), limit=8)
    lang_label = "Malayalam" if lang == "ml" else "English"
    extra = (
        f"This reply will be read aloud by text-to-speech, so keep it to 1-3 short natural "
        f"sentences — no markdown, no bullet points, no emojis, no headings. Reply in {lang_label} "
        f"ONLY, but keep employee names exactly as given, in Latin script — never translate or "
        f"transliterate a person's name even when replying in Malayalam."
    )
    reply = run_orchestrator(request.user, message, history, extra_system=extra)
    return jsonify({"reply": reply, "lang": lang}), 200
