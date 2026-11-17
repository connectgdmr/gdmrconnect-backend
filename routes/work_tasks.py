"""
routes/work_tasks.py — GDMR Connect
=====================================
Assigned work. Anyone (admin, manager, employee) can create a piece of work, a DEADLINE is mandatory, and it can
be assigned to other people. Each assignee posts a status + remarks every day; the history is kept.

Who can be assigned (see _assignable_filter):
  - admin / owner : any active person
  - manager       : their department(s), their direct reports, and themselves
  - employee      : people in their own department(s), their manager, and themselves
"""
import threading
import requests
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import work_tasks_col, users_col
from decorators import token_required
from helpers import _is_admin, _mgr_depts, _today_ist, is_offboarded, _sanitize
from utils import send_email
from config import GROQ_API_KEY, GROQ_MODEL

bp = Blueprint("work_tasks", __name__)

STATUSES = ("Pending", "Started", "In Progress", "Blocked", "Completed")
PRIORITIES = ("Low", "Medium", "High")


# ── helpers ─────────────────────────────────────────────────────────────────

def _uid(user):
    return str(user["_id"])


def _valid_date(s):
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def _dept_label(u):
    d = u.get("department")
    if isinstance(d, list):
        return ", ".join(x for x in d if x)
    return d or ""


def _can_assign_to(user, target):
    if str(target["_id"]) == _uid(user):
        return True
    if is_offboarded(target):
        return False
    if _is_admin(user):
        return True
    mine = {d.lower() for d in _mgr_depts(user)}
    theirs = {d.lower() for d in _mgr_depts(target)}
    if mine & theirs:
        return True
    if user.get("role") == "manager" and target.get("manager_id") == _uid(user):
        return True
    if user.get("role") != "manager" and target.get("role") == "manager" and user.get("manager_id") == str(target["_id"]):
        return True
    return False


def _serialize(t, viewer_id=None):
    today = _today_ist().isoformat()
    out = {
        "_id": str(t["_id"]),
        "title": t.get("title", ""),
        "description": t.get("description", ""),
        "deadline": t.get("deadline"),
        "priority": t.get("priority", "Medium"),
        "client": t.get("client", ""),
        "work_type": t.get("work_type", ""),
        "created_by": t.get("created_by"),
        "created_by_name": t.get("created_by_name", ""),
        "created_at": t["created_at"].isoformat() if isinstance(t.get("created_at"), datetime) else None,
        "status": t.get("status", "Open"),
        "assignees": t.get("assignees", []),
        "updates": [
            {**u, "at": u["at"].isoformat() if isinstance(u.get("at"), datetime) else u.get("at")}
            for u in (t.get("updates") or [])[-30:]
        ],
    }
    for a in out["assignees"]:
        if isinstance(a.get("updated_at"), datetime):
            a["updated_at"] = a["updated_at"].isoformat()
    open_ = out["status"] != "Completed"
    out["overdue"] = bool(open_ and t.get("deadline") and t["deadline"] < today)
    out["due_today"] = bool(open_ and t.get("deadline") == today)
    if viewer_id:
        me = next((a for a in out["assignees"] if a.get("user_id") == viewer_id), None)
        out["created_by_me"] = t.get("created_by") == viewer_id
        out["my_status"] = me.get("status") if me else None
        out["updated_today"] = bool(me and any(u.get("user_id") == viewer_id and u.get("date") == today and u.get("type") != "comment" for u in t.get("updates") or []))
    return out


def _notify(assignees, task, creator):
    for a in assignees:
        email = a.get("email")
        if not email or a["user_id"] == _uid(creator):
            continue
        body = (f"Hi {a['name']},\n\n{creator.get('name', 'A colleague')} has assigned you a piece of work.\n\n"
                f"Title: {task['title']}\nDeadline: {task['deadline']}\nPriority: {task['priority']}\n"
                + (f"Client: {task['client']}\n" if task.get("client") else "")
                + (f"\n{task['description']}\n" if task.get("description") else "")
                + "\nPlease post your status and remarks daily from Work → Tasks.\n")
        threading.Thread(target=send_email, args=(email, f"New work assigned: {task['title']} (due {task['deadline']})", body), daemon=True).start()


def apply_daily_update(user, task_id, status, remarks):
    """Record `user`'s status + remarks on an assigned task. Returns (ok, message, http_status)."""
    try:
        oid = ObjectId(task_id)
    except Exception:
        return False, "Invalid task ID.", 400
    task = work_tasks_col.find_one({"_id": oid})
    uid = _uid(user)
    if not task or not any(a.get("user_id") == uid for a in task.get("assignees", [])):
        return False, "Task not found or not assigned to you.", 404
    status = str(status or "").strip()
    remarks = _sanitize(remarks, 1000)
    if status not in STATUSES:
        return False, f"Status must be one of: {', '.join(STATUSES)}.", 400
    if status != "Completed" and len(remarks) < 3:
        return False, "Please add a remark (what you did today / what is pending) for tasks that are not completed.", 400
    now = datetime.now(timezone.utc)
    today = _today_ist().isoformat()
    assignees = task["assignees"]
    for a in assignees:
        if a.get("user_id") == uid:
            a["status"], a["remarks"], a["updated_at"] = status, remarks, now
    overall = "Completed" if all(a.get("status") == "Completed" for a in assignees) else "Open"
    entry = {"user_id": uid, "name": user.get("name", ""), "date": today, "status": status, "remarks": remarks, "at": now}
    work_tasks_col.update_one({"_id": oid}, {"$set": {"assignees": assignees, "status": overall, "updated_at": now}, "$push": {"updates": entry}})
    return True, "Updated.", 200


def open_assigned_for(uid):
    """Open tasks where `uid` is an assignee who has not completed their part."""
    out = []
    for t in work_tasks_col.find({"assignees.user_id": uid, "status": {"$ne": "Completed"}}):
        me = next((a for a in t.get("assignees", []) if a.get("user_id") == uid), None)
        if me and me.get("status") != "Completed":
            out.append(t)
    return out


# ── routes ──────────────────────────────────────────────────────────────────

@bp.route("/api/work-tasks/assignable", methods=["GET"])
@token_required
def assignable_people():
    user = request.user
    rows = []
    for u in users_col.find({"role": {"$in": ["employee", "manager", "admin", "owner"]}}, {"name": 1, "department": 1, "role": 1, "manager_id": 1, "resignation": 1, "email": 1}):
        if _can_assign_to(user, u):
            rows.append({"_id": str(u["_id"]), "name": u.get("name", ""), "department": _dept_label(u), "role": u.get("role"), "me": str(u["_id"]) == _uid(user)})
    rows.sort(key=lambda r: (not r["me"], r["name"].lower()))
    return jsonify(rows), 200


@bp.route("/api/work-tasks", methods=["GET"])
@token_required
def list_work_tasks():
    user, uid = request.user, _uid(request.user)
    view = request.args.get("view", "mine")
    if view == "created":
        q = {"created_by": uid}
    elif view in ("team", "ongoing"):
        if _is_admin(user):
            q = {}
        elif user.get("role") == "manager":
            depts = _mgr_depts(user)
            q = {"$or": [{"created_by": uid}, {"assignees.department_list": {"$in": depts}}, {"assignees.user_id": uid}]}
        else:
            return jsonify({"message": "Unauthorized"}), 403
        if view == "ongoing":
            q = {"$and": [q, {"status": {"$ne": "Completed"}}]}
    else:
        q = {"assignees.user_id": uid}
    rows = [_serialize(t, uid) for t in work_tasks_col.find(q).sort([("status", -1), ("deadline", 1)]).limit(500)]
    return jsonify(rows), 200


@bp.route("/api/work-tasks", methods=["POST"])
@token_required
def create_work_task():
    user, uid = request.user, _uid(request.user)
    data = request.get_json(silent=True) or {}
    title = _sanitize(data.get("title"), 200)
    if not title:
        return jsonify({"message": "Title is required."}), 400
    deadline = _valid_date(data.get("deadline"))
    if not str(data.get("deadline") or "").strip():
        return jsonify({"message": "A deadline is required."}), 400
    if not deadline:
        return jsonify({"message": "Deadline must be a valid date (YYYY-MM-DD)."}), 400
    if deadline < _today_ist():
        return jsonify({"message": "Deadline can't be in the past."}), 400
    priority = data.get("priority") if data.get("priority") in PRIORITIES else "Medium"

    ids = data.get("assignee_ids")
    ids = [str(i) for i in ids] if isinstance(ids, list) else []
    if not ids:
        ids = [uid]
    ids = list(dict.fromkeys(ids))[:25]
    assignees, notify = [], []
    for i in ids:
        try:
            target = users_col.find_one({"_id": ObjectId(i)})
        except Exception:
            target = None
        if not target or not _can_assign_to(user, target):
            return jsonify({"message": "You can't assign work to one of the selected people."}), 403
        a = {"user_id": i, "name": target.get("name", ""), "department": _dept_label(target),
             "department_list": _mgr_depts(target), "status": "Pending", "remarks": "", "updated_at": None}
        assignees.append(a)
        notify.append({**a, "email": target.get("email")})

    now = datetime.now(timezone.utc)
    doc = {
        "title": title, "description": _sanitize(data.get("description"), 2000), "deadline": deadline.isoformat(),
        "priority": priority, "client": _sanitize(data.get("client"), 200), "work_type": _sanitize(data.get("work_type"), 100),
        "created_by": uid, "created_by_name": user.get("name", ""), "created_at": now, "updated_at": now,
        "status": "Open", "assignees": assignees, "updates": [],
    }
    doc["_id"] = work_tasks_col.insert_one(doc).inserted_id
    _notify(notify, doc, user)
    return jsonify(_serialize(doc, uid)), 201


def _load_editable(task_id, user):
    try:
        t = work_tasks_col.find_one({"_id": ObjectId(task_id)})
    except Exception:
        return None, (jsonify({"message": "Invalid ID"}), 400)
    if not t:
        return None, (jsonify({"message": "Task not found"}), 404)
    if t.get("created_by") != _uid(user) and not _is_admin(user):
        return None, (jsonify({"message": "Only the person who created this work (or an admin) can change it."}), 403)
    return t, None


@bp.route("/api/work-tasks/<task_id>", methods=["PUT"])
@token_required
def edit_work_task(task_id):
    t, err = _load_editable(task_id, request.user)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    upd = {}
    if "title" in data:
        title = _sanitize(data.get("title"), 200)
        if not title:
            return jsonify({"message": "Title is required."}), 400
        upd["title"] = title
    if "description" in data:
        upd["description"] = _sanitize(data.get("description"), 2000)
    if "deadline" in data:
        d = _valid_date(data.get("deadline"))
        if not d:
            return jsonify({"message": "A valid deadline is required."}), 400
        upd["deadline"] = d.isoformat()
    if data.get("priority") in PRIORITIES:
        upd["priority"] = data["priority"]
    if "client" in data:
        upd["client"] = _sanitize(data.get("client"), 200)
    if isinstance(data.get("assignee_ids"), list):
        ids = list(dict.fromkeys(str(i) for i in data["assignee_ids"]))[:25]
        if not ids:
            return jsonify({"message": "At least one person must be assigned."}), 400
        current = {a["user_id"]: a for a in t.get("assignees", [])}
        new_list, notify = [], []
        for i in ids:
            if i in current:
                new_list.append(current[i])
                continue
            try:
                target = users_col.find_one({"_id": ObjectId(i)})
            except Exception:
                target = None
            if not target or not _can_assign_to(request.user, target):
                return jsonify({"message": "You can't assign work to one of the selected people."}), 403
            a = {"user_id": i, "name": target.get("name", ""), "department": _dept_label(target), "department_list": _mgr_depts(target),
                 "status": "Pending", "remarks": "", "updated_at": None}
            new_list.append(a)
            notify.append({**a, "email": target.get("email")})
        upd["assignees"] = new_list
        upd["status"] = "Completed" if all(a.get("status") == "Completed" for a in new_list) else "Open"
    upd["updated_at"] = datetime.now(timezone.utc)
    work_tasks_col.update_one({"_id": t["_id"]}, {"$set": upd})
    t = work_tasks_col.find_one({"_id": t["_id"]})
    return jsonify(_serialize(t, _uid(request.user))), 200


@bp.route("/api/work-tasks/<task_id>", methods=["DELETE"])
@token_required
def delete_work_task(task_id):
    t, err = _load_editable(task_id, request.user)
    if err:
        return err
    work_tasks_col.delete_one({"_id": t["_id"]})
    return jsonify({"message": "Deleted"}), 200


def _can_view(user, t):
    uid = _uid(user)
    if _is_admin(user) or t.get("created_by") == uid or any(a.get("user_id") == uid for a in t.get("assignees", [])):
        return True
    if user.get("role") == "manager":
        mine = {d.lower() for d in _mgr_depts(user)}
        return any(mine & {x.lower() for x in a.get("department_list", [])} for a in t.get("assignees", []))
    return False


def _days_left(deadline):
    d = _valid_date(deadline)
    return (d - _today_ist()).days if d else None


def _rule_insight(t):
    left = _days_left(t.get("deadline"))
    people = t.get("assignees", [])
    done = [a for a in people if a.get("status") == "Completed"]
    parts = []
    if left is None:
        parts.append("No valid deadline is set.")
    elif left < 0:
        parts.append(f"This is {abs(left)} day(s) overdue.")
    elif left == 0:
        parts.append("This is due today.")
    else:
        parts.append(f"{left} day(s) left until the deadline.")
    parts.append(f"{len(done)} of {len(people)} assignee(s) have finished their part.")
    blocked = [a for a in people if a.get("status") == "Blocked"]
    if blocked:
        parts.append("Blocked: " + "; ".join(f"{a['name']}" + (f" ({a['remarks']})" if a.get("remarks") else "") for a in blocked) + ". Needs a follow-up.")
    silent = [a["name"] for a in people if a.get("status") != "Completed" and not a.get("updated_at")]
    if silent:
        parts.append("No update yet from " + ", ".join(silent) + ".")
    return " ".join(parts)


def _ai_insight(t):
    if not GROQ_API_KEY:
        return None
    lines = [f"Work: {t.get('title')}", f"Deadline: {t.get('deadline')} ({_days_left(t.get('deadline'))} days left)", f"Priority: {t.get('priority')}"]
    for a in t.get("assignees", []):
        lines.append(f"- {a.get('name')} ({a.get('department')}): {a.get('status')}" + (f" — {a.get('remarks')}" if a.get("remarks") else ""))
    for u in (t.get("updates") or [])[-8:]:
        if u.get("type") != "comment":
            lines.append(f"Update {u.get('date')} {u.get('name')}: {u.get('status')} — {u.get('remarks')}")
    prompt = ("You advise a manager. From the facts below write 2-3 plain sentences: how this work is going, the main risk (if any), "
              "and one concrete next step. Name people only when needed. No headings or bullets, no invented facts.\n\n" + "\n".join(lines))
    try:
        r = requests.post("https://api.groq.com/openai/v1/chat/completions", headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                          json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.3, "max_tokens": 180}, timeout=12)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip() or None
    except Exception as e:
        print(f"[work_tasks] AI insight failed: {e}")
        return None


@bp.route("/api/work-tasks/<task_id>/insight", methods=["GET"])
@token_required
def task_insight(task_id):
    """Short plain-English read on how a piece of work is going. Cached per task until it gets a new update or the day changes."""
    try:
        t = work_tasks_col.find_one({"_id": ObjectId(task_id)})
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    if not t or not _can_view(request.user, t):
        return jsonify({"message": "Task not found"}), 404
    today, n = _today_ist().isoformat(), len(t.get("updates") or [])
    cached = t.get("insight") or {}
    if cached.get("text") and cached.get("n") == n and cached.get("date") == today:
        return jsonify({"insight": cached["text"], "ai": cached.get("ai", False)}), 200
    text = _ai_insight(t)
    ai = bool(text)
    text = text or _rule_insight(t)
    work_tasks_col.update_one({"_id": t["_id"]}, {"$set": {"insight": {"text": text, "n": n, "date": today, "ai": ai}}})
    return jsonify({"insight": text, "ai": ai}), 200


@bp.route("/api/work-tasks/<task_id>/comment", methods=["POST"])
@token_required
def comment_on_task(task_id):
    """Admins/owners, the person who created the work, and managers of the assignees' departments can comment."""
    user = request.user
    try:
        t = work_tasks_col.find_one({"_id": ObjectId(task_id)})
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    if not t:
        return jsonify({"message": "Task not found"}), 404
    allowed = _is_admin(user) or t.get("created_by") == _uid(user)
    if not allowed and user.get("role") == "manager":
        mine = {d.lower() for d in _mgr_depts(user)}
        allowed = any(mine & {x.lower() for x in a.get("department_list", [])} for a in t.get("assignees", []))
    if not allowed:
        return jsonify({"message": "Only the creator, a manager of the assignees, or an admin can comment."}), 403
    text = _sanitize((request.get_json(silent=True) or {}).get("comment"), 600)
    if not text:
        return jsonify({"message": "Write a comment first."}), 400
    entry = {"type": "comment", "user_id": _uid(user), "name": user.get("name", ""), "date": _today_ist().isoformat(), "remarks": text, "status": "", "at": datetime.now(timezone.utc)}
    work_tasks_col.update_one({"_id": t["_id"]}, {"$push": {"updates": entry}})
    return jsonify(_serialize(work_tasks_col.find_one({"_id": t["_id"]}), _uid(user))), 200


@bp.route("/api/work-tasks/<task_id>/update", methods=["POST"])
@token_required
def daily_update(task_id):
    data = request.get_json(silent=True) or {}
    ok, msg, code = apply_daily_update(request.user, task_id, data.get("status"), data.get("remarks"))
    if not ok:
        return jsonify({"message": msg}), code
    t = work_tasks_col.find_one({"_id": ObjectId(task_id)})
    return jsonify(_serialize(t, _uid(request.user))), 200
