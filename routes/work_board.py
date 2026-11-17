"""
routes/work_board.py — GDMR Connect
=====================================
One simple picture of everybody's work, built from the two places work is kept:
  - assigned work (work_tasks)  : created by anyone, deadline mandatory, one or more assignees
  - the daily plan (work_plans) : the quick list people write after checking in

Every piece of work is returned as the same "item": title, deadline, status, remarks, who gave it, flags.

  GET  /api/work/board     my own items + (managers: their department / admins & owners: everyone) per person
  POST /api/work/update    update the status + remarks of one of MY items (either kind)
  GET  /api/work/summary   a short plain-English read on what is happening (admins, owners, managers)
"""
import time
import requests
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import work_plans_col, work_tasks_col, users_col, leaves_col
from decorators import token_required
from helpers import (
    _is_admin, _mgr_depts, _has_module_grant, _today_ist, _checkin_map, is_offboarded, is_weekend_day,
    get_company_holiday_dates, _sanitize, _serialize_plan,
)
from config import GROQ_API_KEY, GROQ_MODEL
from routes.work_tasks import apply_daily_update

bp = Blueprint("work_board", __name__)
PLAN_STATUSES = ("Pending", "Started", "In Progress", "Blocked", "Completed")


def _done(status):
    return str(status or "").strip().lower() in ("completed", "done")


def _aware(dt):
    if isinstance(dt, datetime) and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _last_comment(updates):
    for u in reversed(updates or []):
        if u.get("type") == "comment":
            return {"text": u.get("remarks", ""), "by": u.get("name", "")}
    return None


def _assigned_item(t, uid, today):
    me = next((a for a in t.get("assignees", []) if a.get("user_id") == uid), None)
    if not me:
        return None
    status = me.get("status", "Pending")
    upd = _aware(me.get("updated_at"))
    done_today = _done(status) and isinstance(upd, datetime) and upd.astimezone(timezone.utc).date().isoformat() >= (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
    if _done(status) and not done_today:
        return None
    dl = t.get("deadline")
    updated_today = any(u.get("user_id") == uid and u.get("date") == today and u.get("type") != "comment" for u in t.get("updates") or [])
    return {
        "key": f"a-{t['_id']}", "kind": "assigned", "id": str(t["_id"]), "plan_id": None, "title": t.get("title", ""), "deadline": dl,
        "status": status, "remarks": me.get("remarks", ""), "client": t.get("client", ""),
        "by": t.get("created_by_name") if t.get("created_by") != uid else None, "priority": t.get("priority", "Medium"),
        "comment": _last_comment(t.get("updates")), "done": _done(status),
        "overdue": bool(not _done(status) and dl and dl < today), "due_today": bool(not _done(status) and dl == today), "updated_today": updated_today,
        "others": [a["name"] for a in t.get("assignees", []) if a.get("user_id") != uid][:6],
    }


def _plan_items(plan, today):
    out = []
    if not plan:
        return out
    pdate = plan.get("date") or today
    for t in plan.get("tasks") or []:
        if not str(t.get("title", "")).strip():
            continue
        dl = t.get("deadline") or pdate
        dn = _done(t.get("status"))
        mc = t.get("manager_comment")
        out.append({
            "key": f"p-{plan['_id']}-{t.get('id') or t.get('_id')}", "kind": "plan", "id": str(t.get("id") or t.get("_id", "")), "plan_id": str(plan["_id"]),
            "title": t.get("title", ""), "deadline": dl, "status": t.get("status") or "Pending", "remarks": t.get("remarks", ""), "client": t.get("client", ""),
            "by": None, "priority": t.get("priority", "Medium"), "comment": ({"text": mc.get("text", ""), "by": mc.get("by", "")} if isinstance(mc, dict) and mc.get("text") else None),
            "done": dn, "overdue": bool(not dn and dl < today), "due_today": bool(not dn and dl == today), "updated_today": bool(plan.get("evening_submitted_at")) or bool(t.get("remarks")),
            "others": [],
        })
    return out


def _sort_items(items):
    return sorted(items, key=lambda i: (i["done"], not i["overdue"], not i["due_today"], i.get("deadline") or "9999"))


def _build(ids, date_str):
    """{uid: {items, plan}} for many people with three queries."""
    today = _today_ist().isoformat()
    plans = {p["employee_id"]: p for p in work_plans_col.find({"employee_id": {"$in": ids}, "date": date_str})}
    cutoff = datetime.now(timezone.utc) - timedelta(days=2)
    tasks_by = {}
    for t in work_tasks_col.find({"assignees.user_id": {"$in": ids}, "$or": [{"status": {"$ne": "Completed"}}, {"updated_at": {"$gte": cutoff}}]}):
        for a in t.get("assignees", []):
            if a.get("user_id") in ids:
                tasks_by.setdefault(a["user_id"], []).append(t)
    out = {}
    for uid in ids:
        items = _plan_items(plans.get(uid), today) if date_str else []
        items += [i for i in (_assigned_item(t, uid, today) for t in tasks_by.get(uid, [])) if i]
        out[uid] = {"items": _sort_items(items)[:60], "plan": plans.get(uid)}
    return out


def _day_updated(plan, items):
    """Has this person done their end-of-day update? Plan people: the evening update. Others: every open assigned item updated today."""
    assigned_open = [i for i in items if i["kind"] == "assigned" and not i["done"]]
    plan_tasks = [i for i in items if i["kind"] == "plan"]
    if assigned_open and not all(i["updated_today"] for i in assigned_open):
        return False
    if plan_tasks:
        return bool(plan and plan.get("evening_submitted_at"))
    return bool(assigned_open) or any(i["kind"] == "assigned" for i in items)


def day_update_state(uid, date_str):
    """Shared with the check-out gate (helpers.evening_update_block): ('ok'|'no_work'|'plan'|'assigned', detail)."""
    b = _build([uid], date_str)[uid]
    items, plan = b["items"], b["plan"]
    plan_tasks = [i for i in items if i["kind"] == "plan"]
    pending_assigned = [i for i in items if i["kind"] == "assigned" and not i["done"] and not i["updated_today"]]
    if not items:
        return "no_work", []
    if plan_tasks and not (plan and plan.get("status") == "submitted" and plan.get("evening_submitted_at")):
        return "plan", []
    if pending_assigned:
        return "assigned", [i["title"] for i in pending_assigned]
    return "ok", []


def _person_status(uid, items, plan, checked_in, on_leave, day_off):
    if checked_in:
        if not items:
            return "no_work"
        return "updated" if _day_updated(plan, items) else "working"
    if on_leave:
        return "on_leave"
    if day_off:
        return "off"
    return "not_in"


def _scope_query(user):
    role = user.get("role")
    has_delegated = _has_module_grant(user, "work-by-team")
    if role in ("admin", "owner") or has_delegated:
        return {"role": {"$in": ["employee", "manager"]}}
    if role == "manager":
        return {"role": {"$in": ["employee", "manager"]}, "department": {"$in": _mgr_depts(user)}}
    return None


def _team(user, date_str):
    q = _scope_query(user)
    if q is None:
        return None
    people = [u for u in users_col.find(q, {"name": 1, "department": 1, "role": 1, "resignation": 1}) if not is_offboarded(u) and str(u["_id"]) != str(user["_id"])]
    ids = [str(u["_id"]) for u in people]
    built = _build(ids, date_str)
    checkins = _checkin_map(ids, date_str)
    on_leave = {lv["user_id"] for lv in leaves_col.find({"user_id": {"$in": ids}, "status": "Approved", "from_date": {"$lte": date_str}, "to_date": {"$gte": date_str}}, {"user_id": 1})}
    day_off = is_weekend_day(date_str, get_company_holiday_dates())
    rows = []
    totals = {"people": 0, "working": 0, "updated": 0, "no_work": 0, "not_in": 0, "on_leave": 0, "off": 0, "open": 0, "overdue": 0, "done": 0, "blocked": 0}
    for u in sorted(people, key=lambda x: (str((x.get("department")[0] if isinstance(x.get("department"), list) and x.get("department") else x.get("department")) or ""), x.get("name", ""))):
        uid = str(u["_id"])
        items, plan = built[uid]["items"], built[uid]["plan"]
        st = _person_status(uid, items, plan, uid in checkins, uid in on_leave, day_off)
        d = u.get("department")
        openi = [i for i in items if not i["done"]]
        row = {"user_id": uid, "name": u.get("name", ""), "role": u.get("role"), "department": (d[0] if isinstance(d, list) and d else d) or "Unassigned",
               "status": st, "check_in_time": checkins.get(uid), "items": items, "plan_id": str(plan["_id"]) if plan else None,
               "plan_comment": (plan or {}).get("manager_comment"), "open": len(openi), "overdue": sum(1 for i in openi if i["overdue"]),
               "done": sum(1 for i in items if i["done"]), "day_note": (plan or {}).get("evening_summary", "")}
        rows.append(row)
        if st != "off":
            totals["people"] += 1
        totals[st] = totals.get(st, 0) + 1
        totals["open"] += row["open"]; totals["overdue"] += row["overdue"]; totals["done"] += row["done"]
        totals["blocked"] += sum(1 for i in openi if str(i["status"]).lower() == "blocked")
    return {"people": rows, "totals": totals}


@bp.route("/api/work/board", methods=["GET"])
@token_required
def work_board():
    user, uid = request.user, str(request.user["_id"])
    date_str = str(request.args.get("date") or _today_ist().isoformat())[:10]
    mine = _build([uid], date_str)[uid]
    plan = mine["plan"]
    state, detail = day_update_state(uid, date_str) if date_str == _today_ist().isoformat() else ("ok", [])
    return jsonify({
        "date": date_str,
        "me": {"items": mine["items"], "plan_submitted": bool(plan and plan.get("status") == "submitted"), "evening_done": bool(plan and plan.get("evening_submitted_at")),
               "day_state": state, "day_pending": detail, "can_assign": True},
        "team": _team(user, date_str),
    }), 200


@bp.route("/api/work/update", methods=["POST"])
@token_required
def work_update():
    """Update the status + remarks of one of MY items. kind=assigned -> daily update on the task; kind=plan -> the task in today's plan."""
    user, uid = request.user, str(request.user["_id"])
    data = request.get_json(silent=True) or {}
    kind, status, remarks = data.get("kind"), str(data.get("status") or "").strip()[:40], _sanitize(data.get("remarks"), 1000)
    if not status:
        return jsonify({"message": "Choose a status."}), 400
    if kind == "assigned":
        ok, msg, code = apply_daily_update(user, str(data.get("id")), status, remarks)
        return (jsonify({"message": "Updated"}), 200) if ok else (jsonify({"message": msg}), code)
    if kind == "plan":
        try:
            plan = work_plans_col.find_one({"_id": ObjectId(str(data.get("plan_id"))), "employee_id": uid})
        except Exception:
            plan = None
        if not plan:
            return jsonify({"message": "Plan not found."}), 404
        hit = False
        for t in plan.get("tasks") or []:
            if str(t.get("id") or t.get("_id", "")) == str(data.get("id")):
                if not _done(status) and len(remarks) < 3 and status.lower() != "pending":
                    return jsonify({"message": "Add a short remark (what you did / what is pending)."}), 400
                t["status"], t["remarks"] = status, remarks
                hit = True
        if not hit:
            return jsonify({"message": "Task not found."}), 404
        work_plans_col.update_one({"_id": plan["_id"]}, {"$set": {"tasks": plan["tasks"], "updated_at": datetime.now(timezone.utc)}})
        return jsonify({"message": "Updated"}), 200
    return jsonify({"message": "kind must be 'assigned' or 'plan'."}), 400


# ── plain-English summary ───────────────────────────────────────────────────

_CACHE = {}


def _summary_facts(team):
    t = team["totals"]
    lines = [f"{t['people']} people on a working day: {t['updated']} have updated their day, {t['working']} are working and haven't updated yet, "
             f"{t['no_work']} checked in with no work added, {t['not_in']} not in, {t['on_leave']} on leave.",
             f"Open work: {t['open']}; overdue: {t['overdue']}; blocked: {t['blocked']}; completed recently: {t['done']}."]
    over = [(p["department"], p["name"], i["title"], i["deadline"]) for p in team["people"] for i in p["items"] if i["overdue"]]
    for d, n, title, dl in over[:8]:
        lines.append(f"Overdue — {d}: {n} — {title} (was due {dl})")
    for p in team["people"]:
        for i in p["items"]:
            if str(i["status"]).lower() == "blocked" and not i["done"]:
                lines.append(f"Blocked — {p['department']}: {p['name']} — {i['title']}" + (f" ({i['remarks']})" if i["remarks"] else ""))
    nw = [p["name"] for p in team["people"] if p["status"] == "no_work"]
    if nw:
        lines.append("Checked in but no work added: " + ", ".join(nw[:8]))
    return "\n".join(lines)


def _rule_summary(team):
    t = team["totals"]
    s = f"{t['updated']} of {t['people']} people have updated their day and {t['open']} piece(s) of work are open."
    if t["overdue"]:
        s += f" {t['overdue']} overdue."
    if t["blocked"]:
        s += f" {t['blocked']} blocked and needing help."
    if t["no_work"]:
        s += f" {t['no_work']} checked in without adding any work."
    if not (t["overdue"] or t["blocked"] or t["no_work"]):
        s += " Nothing needs attention right now."
    return s


@bp.route("/api/work/summary", methods=["GET"])
@token_required
def work_summary():
    user = request.user
    team = _team(user, _today_ist().isoformat())
    if team is None:
        return jsonify({"message": "Unauthorized"}), 403
    facts = _summary_facts(team)
    key = (str(user["_id"]), hash(facts))
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < 600:
        return jsonify({"summary": hit[1], "ai": hit[2]}), 200
    text, ai = None, False
    if GROQ_API_KEY:
        try:
            r = requests.post("https://api.groq.com/openai/v1/chat/completions", headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                              json={"model": GROQ_MODEL, "temperature": 0.3, "max_tokens": 200, "messages": [{"role": "user", "content":
                                    "You brief a business owner. From the facts, write 3-4 plain sentences on what is happening in the team's work today: overall health, "
                                    "the main things needing attention (name people/departments when listed), and one suggested action. No headings or bullets, no invented facts.\n\n" + facts}]}, timeout=12)
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"].strip() or None
            ai = bool(text)
        except Exception as e:
            print(f"[work_board] AI summary failed: {e}")
    text = text or _rule_summary(team)
    _CACHE[key] = (time.time(), text, ai)
    return jsonify({"summary": text, "ai": ai}), 200
