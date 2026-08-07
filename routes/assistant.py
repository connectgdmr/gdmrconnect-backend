"""
routes/assistant.py — GDMR Connect
=====================================
Rexor in-app AI assistant backed by the Groq API.
"""
from datetime import datetime

import requests
from flask import Blueprint, request, jsonify

from bson import ObjectId

from database import (
    leaves_col, users_col, access_grants_col, attendance_col,
    work_plans_col, lms_progress_col, lms_courses_col,
)
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


def _names_summary(ids, active_by_id, limit=20):
    """Sorted display names for a set of user-id strings, capped so the LLM
    prompt can't blow up on a huge company — returns (joined_string, total_count)."""
    names = sorted({active_by_id[i]["name"] for i in ids if i in active_by_id and active_by_id[i].get("name")})
    if not names:
        return "None", 0
    shown = names[:limit]
    extra = len(names) - len(shown)
    s = ", ".join(shown)
    if extra > 0:
        s += f", and {extra} more"
    return s, len(names)


def _admin_today_snapshot():
    """
    Live company snapshot for today, IST — mirrors stats.py's today_stats()
    counting rules exactly (same active-roster/offboarding/leave logic the
    dashboard KPIs use), but also resolves display names so Rexor can name
    people instead of only counting them.
    """
    today    = str(datetime.now(IST).date())
    today_dt = datetime.strptime(today, "%Y-%m-%d")

    all_staff = list(users_col.find(
        {"role": {"$in": ["employee", "manager"]}},
        {"_id": 1, "name": 1, "department": 1, "resignation": 1},
    ))
    active_by_id = {}
    for u in all_staff:
        lwd = (u.get("resignation") or {}).get("last_working_day")
        if lwd:
            lwd_str = lwd.date().isoformat() if hasattr(lwd, "date") else str(lwd)[:10]
            if lwd_str < today:
                continue
        active_by_id[str(u["_id"])] = u
    active_ids = set(active_by_id.keys())

    present_ids = {
        r["user_id"] for r in attendance_col.find(
            {"date": today, "type": "checkin"}, {"user_id": 1}
        )
    } & active_ids

    std_leave_ids = {
        l["user_id"] for l in leaves_col.find(
            {"from_date": {"$lte": today}, "to_date": {"$gte": today},
             "status": {"$nin": ["Rejected", "Cancelled"]}},
            {"user_id": 1},
        )
    } & active_ids
    ext_leave_ids = {
        str(u["_id"]) for u in users_col.find(
            {"role": {"$in": ["employee", "manager"]},
             "extended_leaves": {"$elemMatch": {
                 "from_date": {"$lte": today_dt}, "to_date": {"$gte": today_dt},
             }}},
            {"_id": 1},
        )
    } & active_ids
    leave_ids = std_leave_ids | ext_leave_ids

    not_in_ids = active_ids - present_ids - leave_ids

    present_str, present_n = _names_summary(present_ids, active_by_id)
    leave_str,   leave_n   = _names_summary(leave_ids,   active_by_id)
    not_in_str,  not_in_n  = _names_summary(not_in_ids,  active_by_id)

    return [
        f"Today's date: {today}",
        f"Total active workforce: {len(active_ids)}",
        f"Present today (checked in): {present_n} — {present_str}",
        f"On leave today: {leave_n} — {leave_str}",
        f"Not checked in yet today: {not_in_n} — {not_in_str}",
    ]


def _find_employees(text, roster):
    """
    Fuzzy-match employee name(s) mentioned in free text against the active
    roster. Whole-word first-name match OR full-name substring match.
    Returns a dict {first_name_lower: [matching user dicts]} — a list with
    >1 entry means the first name is ambiguous (e.g. two "Anjali"s) and the
    caller should surface both rather than silently guessing.
    """
    words = set(w.strip(".,!?'\"") for w in text.lower().split())
    hits = {}
    for u in roster:
        name = (u.get("name") or "").strip()
        if not name:
            continue
        full_lower = name.lower()
        first_lower = name.split()[0].lower()
        if len(first_lower) < 3:
            continue  # too short to match reliably against stray words
        if full_lower in text.lower() or first_lower in words:
            hits.setdefault(first_lower, []).append(u)
    return hits


def _employee_dossier(emp, today):
    """
    Everything Rexor might get asked about ONE employee, gathered in one
    pass: role/department, today's + recent leave status (with manager/admin
    approval breakdown), today's work-plan tasks ("what are they doing right
    now"), and LMS course progress. This is the retrieval half of the
    assistant's RAG loop — Groq only ever sees what's assembled here, never
    queries the DB itself.
    """
    uid  = str(emp["_id"])
    name = emp.get("name", "Unknown")
    dept = emp.get("department") or "not set"
    role = emp.get("role", "employee")
    position = emp.get("position") or ""

    lines = [f"=== {name} ===", f"Department: {dept}. Role: {role}{f' ({position})' if position else ''}."]

    # Offboarding status
    resignation = emp.get("resignation") or {}
    lwd = resignation.get("last_working_day")
    if resignation.get("notice_date") and lwd:
        lwd_str = lwd.date().isoformat() if hasattr(lwd, "date") else str(lwd)[:10]
        if lwd_str < today:
            lines.append(f"{name} has already left the company (last working day {lwd_str}).")
        else:
            lines.append(f"{name} is serving notice period, last working day {lwd_str}.")

    # Attendance today
    checkin = attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today})
    lines.append(f"Checked in today: {'Yes' if checkin else 'No'}.")

    # Leave — today's status + recent history
    recent_leaves = list(leaves_col.find({"user_id": uid}).sort("applied_at", -1).limit(5))
    on_leave_today = None
    for lv in recent_leaves:
        fd, td = str(lv.get("from_date", "")), str(lv.get("to_date", ""))
        st = lv.get("status", "Pending")
        if fd <= today <= td and st not in ("Rejected", "Cancelled"):
            on_leave_today = lv
            break
    if on_leave_today:
        lines.append(
            f"On leave TODAY ({today}): {on_leave_today.get('from_date')} to {on_leave_today.get('to_date')}, "
            f"type={on_leave_today.get('type','full')}, overall status={on_leave_today.get('status','Pending')} "
            f"(manager: {on_leave_today.get('manager_status','Pending')}, admin: {on_leave_today.get('admin_status','Pending')})."
        )
    else:
        lines.append(f"Not on leave today ({today}).")
    if recent_leaves:
        lines.append("Recent leave requests (most recent first):")
        for lv in recent_leaves:
            lines.append(
                f"  - {lv.get('from_date')} to {lv.get('to_date')}: status={lv.get('status','Pending')} "
                f"(manager: {lv.get('manager_status','Pending')}, admin: {lv.get('admin_status','Pending')}), "
                f"reason: {lv.get('reason') or 'not given'}."
            )
    else:
        lines.append("No leave requests on record.")

    # Current work — today's submitted/draft work plan
    plan = work_plans_col.find_one({"employee_id": uid, "date": today})
    if plan and plan.get("tasks"):
        lines.append(f"Today's work plan ({plan.get('status', 'draft')}):")
        for t in plan["tasks"][:8]:
            title = t.get("title") or "Untitled task"
            wtype = t.get("work_type")
            client = t.get("client")
            extra = " · ".join(x for x in [wtype, f"client: {client}" if client else None] if x)
            lines.append(f"  - {title}{f' ({extra})' if extra else ''} — status: {t.get('status', 'Pending')}.")
    else:
        lines.append(f"No work plan submitted for today ({today}) — unknown what they're currently working on.")

    # LMS course progress
    progress_rows = list(lms_progress_col.find({"user_id": uid}))
    if progress_rows:
        course_ids = list({r["course_id"] for r in progress_rows})
        course_oids = [ObjectId(c) for c in course_ids if ObjectId.is_valid(c)]
        courses = {str(c["_id"]): c.get("title", "Untitled course") for c in lms_courses_col.find({"_id": {"$in": course_oids}}, {"title": 1})}
        completed = sum(1 for r in progress_rows if r.get("status") == "Completed")
        lines.append(f"Courses assigned: {len(progress_rows)}, completed: {completed}.")
        for r in progress_rows[:8]:
            title = courses.get(r["course_id"], "Untitled course")
            lines.append(f"  - {title}: {r.get('status', 'Assigned')} ({r.get('progress_pct', 0)}% complete).")
    else:
        lines.append("No courses assigned.")

    return lines


@bp.route("/api/assistant/voice", methods=["POST"])
@token_required
@limiter.limit("20 per minute")
def assistant_voice():
    """
    Admin-scoped voice assistant ("Rexor voice mode") — answers spoken
    questions about LIVE company data in either English or Malayalam. The
    reply is meant to be read aloud by the client via SpeechSynthesis, so
    it's kept to short, plain, TTS-friendly sentences (no markdown/emojis).

    Retrieval (the "RAG" half — deterministic, not LLM-driven): if the
    question mentions an employee by name, we fetch a full per-employee
    dossier (department/role, today's + recent leave status with manager/
    admin approval, today's work-plan tasks, LMS course progress). If no
    name is found in the current message, we also check the last couple of
    USER turns from history so follow-ups ("is it approved?" right after
    asking about someone) still resolve to the right person. With no name
    at all, falls back to the company-wide today snapshot (present/leave/
    not-checked-in headcounts). Groq only ever sees what's assembled here —
    it never queries the DB itself.

    Accepts an optional `history` (last few {role, content} turns) so
    follow-up questions resolve naturally instead of every question being
    answered in isolation.

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

    # Recent conversation turns, for natural follow-ups — trusted only as
    # conversational context, never as a source of facts (the system prompt
    # still restricts the model to the live facts block below).
    raw_history = data.get("history") if isinstance(data.get("history"), list) else []
    history = []
    for turn in raw_history[-8:]:
        if not isinstance(turn, dict):
            continue
        turn_role = "assistant" if turn.get("role") == "assistant" else "user"
        content   = str(turn.get("content") or "").strip()[:500]
        if content:
            history.append({"role": turn_role, "content": content})

    today  = str(datetime.now(IST).date())
    roster = list(users_col.find({"role": {"$in": ["employee", "manager", "admin", "owner"]}}, {"name": 1}))

    hits = _find_employees(message, roster)
    if not hits:
        # No name in the current question — check the last couple of user
        # turns so a bare follow-up ("is it approved?") still resolves.
        user_turns = [t["content"] for t in history if t["role"] == "user"]
        for content in reversed(user_turns[-2:]):
            hits = _find_employees(content, roster)
            if hits:
                break

    facts = []
    ambiguous_notes = []
    for first_name, matches in hits.items():
        if len(matches) > 1:
            names = ", ".join(sorted(m.get("name", "?") for m in matches))
            ambiguous_notes.append(
                f"There are {len(matches)} people whose first name is '{first_name.title()}': {names}. "
                f"Ask the admin which one they mean instead of guessing."
            )
        else:
            facts.extend(_employee_dossier(matches[0], today))

    if ambiguous_notes:
        facts.extend(ambiguous_notes)
    if not facts:
        facts = _admin_today_snapshot()

    lang_label = "Malayalam" if lang == "ml" else "English"
    system_prompt = (
        "You are Rexor, GDMR Connect's admin voice assistant — warm, brisk, and conversational, like a "
        "sharp EA speaking out loud, not a report generator. Continue the conversation naturally using the "
        "chat history for context (e.g. resolve 'what about them' / follow-up questions against the prior "
        f"turn). Reply in {lang_label} ONLY, in 1-3 short natural sentences meant to be read aloud by "
        "text-to-speech — no markdown, no bullet points, no emojis, no headings, no restating the question. "
        "Use ONLY the facts listed below; never invent names, numbers, or company data you weren't given — "
        "if something isn't in the facts, say you don't have that yet rather than guessing, and if a name "
        "is ambiguous, ask which person they mean instead of picking one. Keep employee names exactly as "
        "given, in Latin script — do not translate or transliterate names even when replying in Malayalam."
        "\n\nLive facts (as of right now):\n" + "\n".join(f"- {f}" for f in facts)
    )

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model":       GROQ_MODEL,
                "messages":    [
                    {"role": "system", "content": system_prompt},
                    *history,
                    {"role": "user",   "content": message},
                ],
                "temperature": 0.4,
                "max_tokens":  260,
            },
            timeout=12,
        )
        resp.raise_for_status()
        reply_text = resp.json()["choices"][0]["message"]["content"].strip()
        return jsonify({"reply": reply_text, "lang": lang}), 200
    except Exception as e:
        return jsonify({"message": "Assistant is temporarily unavailable.", "error": str(e)}), 502
