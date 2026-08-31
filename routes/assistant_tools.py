"""
routes/assistant_tools.py — GDMR Connect
===========================================
The tool registry for Rexor's AI orchestration layer. Every function here
is a "tool" the LLM can choose to call — it takes the CALLING user plus
typed arguments, enforces exactly the same access rules the real REST
endpoints use, queries live data, and returns a small structured dict.
The LLM never touches the database directly; it only ever sees what these
functions decide to hand back, and it can't override the RBAC checks
below no matter what the user's message says.

Visibility rule used throughout (`_can_view_detail`):
  - Anyone can see their own full detail.
  - Admin/Owner and anyone with an active delegated-access grant see
    everyone's full detail.
  - A manager sees full detail for their own direct reports.
  - Otherwise (an employee asking about a non-report colleague) they get
    a COARSE view only — name, department, whether checked in today,
    whether on leave today — never leave reasons, approval chains, tasks,
    or course progress. This mirrors what's already visible elsewhere in
    the app (Team Leaves/attendance detail are manager+ only) rather than
    inventing a new, broader data-exposure rule through the assistant.
"""
import difflib
from datetime import datetime

from bson import ObjectId

from database import (
    leaves_col, users_col, access_grants_col, attendance_col,
    work_plans_col, corrections_col,
    announcements_col, holidays_col, assets_col,
)
from helpers import is_offboarded
from config import IST


def _today():
    return str(datetime.now(IST).date())


def _oid(v):
    try:
        return ObjectId(v)
    except Exception:
        return None


def _can_view_detail(caller, target):
    if str(caller["_id"]) == str(target["_id"]):
        return True
    role = caller.get("role")
    if role in ("admin", "owner"):
        return True
    if role == "manager" and str(target.get("manager_id") or "") == str(caller["_id"]):
        return True
    if access_grants_col.find_one({"employee_id": str(caller["_id"]), "is_active": True}):
        return True
    return False


def _visible_roster_for(caller):
    """Every active person the caller is allowed to see AT LEAST the coarse
    view of — for admin/owner/delegated that's everyone; for a manager,
    their reports; for an employee, their own department (so 'who's on
    leave today' means something without exposing the whole company)."""
    role = caller.get("role")
    query = {"role": {"$in": ["employee", "manager"]}}
    if role in ("admin", "owner") or access_grants_col.find_one({"employee_id": str(caller["_id"]), "is_active": True}):
        pass
    elif role == "manager":
        query["manager_id"] = str(caller["_id"])
    else:
        depts = caller.get("department")
        depts = depts if isinstance(depts, list) else ([depts] if depts else [])
        query["department"] = {"$in": depts} if depts else "__none__"
    rows = list(users_col.find(query, {"name": 1, "department": 1, "manager_id": 1, "resignation": 1}))
    return [u for u in rows if not is_offboarded(u)]


def _person_brief(u):
    return {"id": str(u["_id"]), "name": u.get("name"), "department": u.get("department")}


# ── find_person ──────────────────────────────────────────────────────────────

def find_person(caller, name):
    """Resolve a name mentioned in conversation to one specific person.
    Always call this first when the user names someone, before asking
    about their attendance/leave/tasks — it tells you their id and warns
    you if the name is ambiguous (more than one match) instead of letting
    you guess which person was meant."""
    if not name or not name.strip():
        return {"error": "No name given."}
    q = name.strip().lower()
    roster = list(users_col.find(
        {"role": {"$in": ["employee", "manager", "admin", "owner"]}},
        {"name": 1, "department": 1, "manager_id": 1, "resignation": 1},
    ))
    roster = [u for u in roster if not is_offboarded(u)]
    exact  = [u for u in roster if (u.get("name") or "").strip().lower() == q]
    if exact:
        return {"match": _person_brief(exact[0])}
    partial = [u for u in roster if q in (u.get("name") or "").lower() or (u.get("name") or "").lower().split(" ")[0] == q]
    if len(partial) == 1:
        return {"match": _person_brief(partial[0])}
    if len(partial) > 1:
        return {"ambiguous": [_person_brief(u) for u in partial], "note": "More than one person matches — ask which one before answering."}

    # Nothing matched literally — voice transcription and typos routinely
    # mangle names ("Naveen Nawaz" for "Navin Navas"), so fall back to a
    # similarity match against full names before giving up. difflib is
    # forgiving of exactly this kind of near-miss.
    names   = [u.get("name") or "" for u in roster]
    by_name = {u.get("name"): u for u in roster}
    close = difflib.get_close_matches(name.strip(), names, n=3, cutoff=0.6)
    if len(close) == 1:
        return {"match": _person_brief(by_name[close[0]])}
    if len(close) > 1:
        return {"ambiguous": [_person_brief(by_name[n]) for n in close],
                "note": f"No exact match for '{name}', but these are close — confirm which one before answering."}
    return {"not_found": True, "note": f"No active employee named '{name}' found."}


# ── attendance / leave / today ──────────────────────────────────────────────

def get_person_today(caller, person_id, date=None):
    """Everything about ONE person for a given day (default today): did
    they check in and at what time, are they on approved leave, what's on
    their work plan / task list, and if they simply have no record for a
    working day, that itself is the answer (don't guess a reason). Use
    this for questions like 'did X punch in', 'what is X working on',
    'why is X absent', or 'is X on leave'."""
    target = users_col.find_one({"_id": _oid(person_id)})
    if not target:
        return {"error": "Unknown person_id."}
    day = date or _today()
    detail = _can_view_detail(caller, target)
    name = target.get("name")

    checkin = attendance_col.find_one({"user_id": str(target["_id"]), "type": "checkin", "date": day})
    result = {
        "name": name,
        "date": day,
        "checked_in": bool(checkin),
        "checkin_time": checkin.get("time").isoformat() if checkin and checkin.get("time") else None,
    }

    leave = None
    for lv in leaves_col.find({"user_id": str(target["_id"]), "from_date": {"$lte": day}, "to_date": {"$gte": day},
                                "status": {"$nin": ["Rejected", "Cancelled"]}}):
        leave = lv
        break
    result["on_leave"] = bool(leave)

    if not detail:
        # Coarse view stops here — no reasons, approvals, or task detail
        # for someone who isn't the caller, their manager, or an admin.
        result["visibility"] = "coarse — full detail only visible to this person, their manager, or an admin"
        return result

    resignation = target.get("resignation") or {}
    lwd = resignation.get("last_working_day")
    lwd_str = lwd.date().isoformat() if hasattr(lwd, "date") else (str(lwd)[:10] if lwd else None)
    if resignation.get("notice_date") and lwd_str and lwd_str < day:
        result["employment_status"] = f"left the company (last working day {lwd_str})"

    if leave:
        result["leave_detail"] = {
            "type": leave.get("type", "full"),
            "from": leave.get("from_date"), "to": leave.get("to_date"),
            "reason": leave.get("reason"),
            "manager_status": leave.get("manager_status", "Pending"),
            "admin_status": leave.get("admin_status", "Pending"),
            "overall_status": leave.get("status", "Pending"),
        }

    if not checkin and not leave and day <= _today():
        # Genuinely unaccounted for — check for a pending/approved correction
        # request before calling it a flat "no record", since that's often
        # the actual explanation for an absence.
        corr = corrections_col.find_one(
            {"user_id": str(target["_id"])},
            sort=[("created_at", -1)],
        )
        if corr and (corr.get("new_time") or "")[:10] == day:
            result["correction_request"] = {"status": corr.get("status", "Pending"), "reason": corr.get("reason")}

    plan = work_plans_col.find_one({"employee_id": str(target["_id"]), "date": day})
    if plan and plan.get("tasks"):
        result["work_plan_status"] = plan.get("status", "draft")
        result["tasks"] = [
            {"title": t.get("title") or "Untitled task", "status": t.get("status", "Pending"),
             "client": t.get("client"), "work_type": t.get("work_type")}
            for t in plan["tasks"][:10]
        ]
    else:
        result["tasks"] = []
        result["work_plan_submitted"] = False

    return result


def list_on_leave_today(caller, date=None):
    """Everyone currently visible to this caller who is on approved leave
    on the given day (default today) — use for 'who's on leave today',
    'who is out this week' (call once per day if a range is asked)."""
    day = date or _today()
    roster = _visible_roster_for(caller)
    if not roster:
        return {"date": day, "people": [], "note": "No one in view."}
    ids = [str(u["_id"]) for u in roster]
    by_id = {str(u["_id"]): u for u in roster}
    leave_ids = {lv["user_id"] for lv in leaves_col.find(
        {"user_id": {"$in": ids}, "from_date": {"$lte": day}, "to_date": {"$gte": day},
         "status": {"$nin": ["Rejected", "Cancelled"]}},
        {"user_id": 1},
    )}
    people = [{"name": by_id[i].get("name"), "department": by_id[i].get("department")} for i in leave_ids if i in by_id]
    return {"date": day, "people": sorted(people, key=lambda p: p["name"] or "")}


def list_not_checked_in_today(caller, date=None):
    """Everyone visible to this caller who has NOT checked in and is NOT
    on approved leave for the given day (default today) — use for 'who
    hasn't checked in', 'who is missing today'. Only meaningful for today
    or a past working day."""
    day = date or _today()
    roster = _visible_roster_for(caller)
    if not roster:
        return {"date": day, "people": []}
    ids = [str(u["_id"]) for u in roster]
    by_id = {str(u["_id"]): u for u in roster}
    present_ids = {r["user_id"] for r in attendance_col.find({"user_id": {"$in": ids}, "type": "checkin", "date": day}, {"user_id": 1})}
    leave_ids = {lv["user_id"] for lv in leaves_col.find(
        {"user_id": {"$in": ids}, "from_date": {"$lte": day}, "to_date": {"$gte": day},
         "status": {"$nin": ["Rejected", "Cancelled"]}},
        {"user_id": 1},
    )}
    missing = [i for i in ids if i not in present_ids and i not in leave_ids]
    people = [{"name": by_id[i].get("name"), "department": by_id[i].get("department")} for i in missing]
    return {"date": day, "people": sorted(people, key=lambda p: p["name"] or "")}


def list_no_work_update_today(caller, date=None):
    """Everyone visible to this caller who has NOT submitted a Daily Work
    Plan / status update for the given day (default today) — use for
    'who hasn't updated their status', 'who hasn't submitted their plan'.
    Someone on leave is excluded — they're not expected to update."""
    day = date or _today()
    roster = _visible_roster_for(caller)
    if not roster:
        return {"date": day, "people": []}
    ids = [str(u["_id"]) for u in roster]
    by_id = {str(u["_id"]): u for u in roster}
    submitted_ids = {p["employee_id"] for p in work_plans_col.find({"employee_id": {"$in": ids}, "date": day, "tasks": {"$exists": True, "$ne": []}}, {"employee_id": 1})}
    leave_ids = {lv["user_id"] for lv in leaves_col.find(
        {"user_id": {"$in": ids}, "from_date": {"$lte": day}, "to_date": {"$gte": day},
         "status": {"$nin": ["Rejected", "Cancelled"]}},
        {"user_id": 1},
    )}
    missing = [i for i in ids if i not in submitted_ids and i not in leave_ids]
    people = [{"name": by_id[i].get("name"), "department": by_id[i].get("department")} for i in missing]
    return {"date": day, "people": sorted(people, key=lambda p: p["name"] or "")}


def get_my_leave_summary(caller):
    """The caller's own leave picture — pending/approved counts and their
    most recent requests. Use for 'how many leaves do I have pending',
    'what's the status of my leave'."""
    uid = str(caller["_id"])
    pending  = leaves_col.count_documents({"user_id": uid, "status": "Pending"})
    approved = leaves_col.count_documents({"user_id": uid, "status": "Approved"})
    recent = list(leaves_col.find({"user_id": uid}).sort("applied_at", -1).limit(5))
    return {
        "pending_count": pending, "approved_count": approved,
        "recent": [
            {"from": lv.get("from_date"), "to": lv.get("to_date"), "status": lv.get("status", "Pending"),
             "manager_status": lv.get("manager_status"), "admin_status": lv.get("admin_status"),
             "reason": lv.get("reason")}
            for lv in recent
        ],
    }


def get_pending_approvals(caller):
    """Things waiting on the CALLER right now: for a manager/admin, leave
    and correction requests awaiting their approval; for anyone, their own
    requests still awaiting someone else's approval. Use for 'what's
    pending for me', 'what do I need to approve', 'what am I waiting on'."""
    role = caller.get("role")
    uid  = str(caller["_id"])
    out = {}
    if role == "manager":
        reports = [str(u["_id"]) for u in users_col.find({"manager_id": uid}, {"_id": 1})]
        out["leaves_awaiting_my_approval"] = leaves_col.count_documents({"user_id": {"$in": reports}, "manager_status": "Pending"})
        out["corrections_awaiting_my_approval"] = corrections_col.count_documents(
            {"user_id": {"$in": reports}, "approval_target": {"$ne": "admin"}, "status": "Pending"}
        )
    elif role in ("admin", "owner"):
        out["leaves_awaiting_admin"] = leaves_col.count_documents({"manager_status": "Approved", "admin_status": "Pending"})
        out["corrections_awaiting_admin"] = corrections_col.count_documents({"approval_target": "admin", "status": "Pending"})
        out["assets_awaiting_admin"] = assets_col.count_documents({"manager_status": "Approved", "admin_status": "Pending"})
    out["my_own_pending_leaves"] = leaves_col.count_documents({"user_id": uid, "status": "Pending"})
    return out


def get_next_holiday(caller):
    """The next upcoming company holiday. Use for 'when's the next holiday'."""
    today = _today()
    rows = list(holidays_col.find({"date": {"$gte": today}}).sort("date", 1).limit(1))
    if not rows:
        return {"none_upcoming": True}
    h = rows[0]
    days_away = (datetime.strptime(h["date"], "%Y-%m-%d").date() - datetime.strptime(today, "%Y-%m-%d").date()).days
    return {"name": h.get("name"), "date": h.get("date"), "days_away": days_away}


def get_recent_announcements(caller, limit=5):
    """The most recent company announcements. Use for 'any updates', 'what's new'."""
    rows = list(announcements_col.find().sort("created_at", -1).limit(min(limit, 10)))
    return {"announcements": [{"title": a.get("title"), "body": (a.get("body") or "")[:200]} for a in rows]}


def get_team_snapshot(caller, date=None):
    """A quick headcount snapshot (present / on leave / not checked in) for
    everyone visible to this caller — use for a broad 'how's the team doing
    today' / 'give me today's overview' question, before drilling into
    specific people with the list_* tools if more detail is asked for."""
    day = date or _today()
    roster = _visible_roster_for(caller)
    ids = [str(u["_id"]) for u in roster]
    present = attendance_col.count_documents({"user_id": {"$in": ids}, "type": "checkin", "date": day})
    on_leave = leaves_col.count_documents({"user_id": {"$in": ids}, "from_date": {"$lte": day}, "to_date": {"$gte": day}, "status": {"$nin": ["Rejected", "Cancelled"]}})
    return {"date": day, "total_in_view": len(ids), "present": present, "on_leave": on_leave, "not_checked_in": max(0, len(ids) - present - on_leave)}


# ── Registry: (schema, python function) ─────────────────────────────────────

TOOLS = [
    (find_person, {
        "type": "function", "function": {
            "name": "find_person", "description": find_person.__doc__,
            "parameters": {"type": "object", "properties": {"name": {"type": "string", "description": "The person's name as mentioned by the user"}}, "required": ["name"]},
        },
    }),
    (get_person_today, {
        "type": "function", "function": {
            "name": "get_person_today", "description": get_person_today.__doc__,
            "parameters": {"type": "object", "properties": {
                "person_id": {"type": "string", "description": "The person's id from find_person"},
                "date": {"type": "string", "description": "YYYY-MM-DD, omit for today"},
            }, "required": ["person_id"]},
        },
    }),
    (list_on_leave_today, {
        "type": "function", "function": {
            "name": "list_on_leave_today", "description": list_on_leave_today.__doc__,
            "parameters": {"type": "object", "properties": {"date": {"type": "string", "description": "YYYY-MM-DD, omit for today"}}},
        },
    }),
    (list_not_checked_in_today, {
        "type": "function", "function": {
            "name": "list_not_checked_in_today", "description": list_not_checked_in_today.__doc__,
            "parameters": {"type": "object", "properties": {"date": {"type": "string", "description": "YYYY-MM-DD, omit for today"}}},
        },
    }),
    (list_no_work_update_today, {
        "type": "function", "function": {
            "name": "list_no_work_update_today", "description": list_no_work_update_today.__doc__,
            "parameters": {"type": "object", "properties": {"date": {"type": "string", "description": "YYYY-MM-DD, omit for today"}}},
        },
    }),
    (get_my_leave_summary, {
        "type": "function", "function": {
            "name": "get_my_leave_summary", "description": get_my_leave_summary.__doc__,
            "parameters": {"type": "object", "properties": {}},
        },
    }),
    (get_pending_approvals, {
        "type": "function", "function": {
            "name": "get_pending_approvals", "description": get_pending_approvals.__doc__,
            "parameters": {"type": "object", "properties": {}},
        },
    }),
    (get_next_holiday, {
        "type": "function", "function": {
            "name": "get_next_holiday", "description": get_next_holiday.__doc__,
            "parameters": {"type": "object", "properties": {}},
        },
    }),
    (get_recent_announcements, {
        "type": "function", "function": {
            "name": "get_recent_announcements", "description": get_recent_announcements.__doc__,
            "parameters": {"type": "object", "properties": {"limit": {"type": "integer"}}},
        },
    }),
    (get_team_snapshot, {
        "type": "function", "function": {
            "name": "get_team_snapshot", "description": get_team_snapshot.__doc__,
            "parameters": {"type": "object", "properties": {"date": {"type": "string"}}},
        },
    }),
]

TOOL_SCHEMAS = [schema for _, schema in TOOLS]
TOOL_FUNCS   = {schema["function"]["name"]: fn for fn, schema in TOOLS}
