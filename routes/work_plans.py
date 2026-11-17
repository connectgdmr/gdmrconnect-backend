"""
routes/work_plans.py — GDMR Connect
========================================
Employee daily work plans: draft/submit, task status updates, analytics, sharing.
Manager/Admin: view plans, comment, team analytics.
AI analytics via Groq.
"""
import secrets
import threading
import requests
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import work_plans_col, attendance_col, users_col, leaves_col, work_tasks_col
from helpers import _sanitize, is_offboarded, is_weekend_day, get_company_holiday_dates
from decorators import token_required
from helpers import (
    _is_admin, _mgr_depts, _is_task_done, _has_module_grant,
    _checkin_map, _serialize_plan, _range_start, _build_analytics, _today_ist,
    format_datetime_ist, resolve_employee_manager_emails,
)
from config import GROQ_API_KEY, GROQ_MODEL, OWNER_EMAILS
from utils import send_email

bp = Blueprint("work_plans", __name__)

TASK_STATUSES = ("Pending", "Started", "In Progress", "Completed")


# ── Employee routes ──────────────────────────────────────────────────────────

@bp.route("/api/my/work-plan", methods=["GET"])
@token_required
def get_my_work_plan():
    uid      = str(request.user["_id"])
    date_str = request.args.get("date") or _today_ist().isoformat()
    plan     = work_plans_col.find_one({"employee_id": uid, "date": date_str})
    if not plan:
        return jsonify(None), 200
    return jsonify(_serialize_plan(plan)), 200


@bp.route("/api/my/work-plan", methods=["POST"])
@token_required
def upsert_my_work_plan():
    uid      = str(request.user["_id"])
    data     = request.json or {}
    date_str = str(data.get("date") or _today_ist().isoformat())[:10]
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"message": "Invalid date. Use YYYY-MM-DD."}), 400

    status = data.get("status", "draft")
    if status not in ("draft", "submitted"):
        return jsonify({"message": "status must be 'draft' or 'submitted'"}), 400

    notify = data.get("notify", True)
    tasks  = data.get("tasks", [])
    if not isinstance(tasks, list):
        return jsonify({"message": "tasks must be a list"}), 400

    for task in tasks:
        if isinstance(task, dict):
            if not task.get("id"):
                task["id"] = secrets.token_hex(8)
            task["remarks"] = _sanitize(task.get("remarks"), 1000)
            dl = str(task.get("deadline") or "")[:10]
            try:
                datetime.strptime(dl, "%Y-%m-%d")
            except ValueError:
                dl = date_str                      # every piece of work has a deadline: default to the plan's day
            task["deadline"] = dl

    now        = datetime.now(timezone.utc)
    set_fields = {
        "employee_id":   uid,
        "employee_name": request.user.get("name", ""),
        "department":    request.user.get("department", ""),
        "date":          date_str,
        "tasks":         tasks,
        "status":        status,
        "updated_at":    now,
    }
    if status == "submitted" and notify is not False:
        set_fields["submitted_at"] = now

    work_plans_col.update_one(
        {"employee_id": uid, "date": date_str},
        {"$set": set_fields, "$setOnInsert": {"created_at": now, "manager_comment": None}},
        upsert=True
    )

    plan = work_plans_col.find_one({"employee_id": uid, "date": date_str})
    return jsonify(_serialize_plan(plan)), 200


@bp.route("/api/my/work-plan/evening-update", methods=["POST"])
@token_required
def evening_update():
    """End-of-day status update: a status for every task on today's plan (remarks required for anything not
    completed) plus a daily update on every open task assigned to this person. Unlocks photo check-out."""
    from routes.work_tasks import apply_daily_update, open_assigned_for
    from database import work_tasks_col
    user, uid = request.user, str(request.user["_id"])
    data     = request.get_json(silent=True) or {}
    date_str = str(data.get("date") or _today_ist().isoformat())[:10]
    plan     = work_plans_col.find_one({"employee_id": uid, "date": date_str})
    has_plan = bool(plan and plan.get("status") == "submitted")
    if not has_plan and not open_assigned_for(uid):
        return jsonify({"message": "Add today's work first (Work → Add work, or submit your work plan), then do the end-of-day update."}), 400

    incoming = {str(x.get("id")): x for x in (data.get("tasks") or []) if isinstance(x, dict)}
    tasks, problems = ((plan.get("tasks") if has_plan else None) or []), []
    for t in tasks:
        if not str(t.get("title", "")).strip():
            continue
        tid = str(t.get("id") or t.get("_id", ""))
        x = incoming.get(tid)
        if not x:
            problems.append(f"“{t.get('title')}” has no status.")
            continue
        status  = str(x.get("status") or "").strip()[:40]
        remarks = _sanitize(x.get("remarks"), 1000)
        if not status:
            problems.append(f"“{t.get('title')}” needs a status.")
        elif not _is_task_done({"status": status}) and len(remarks) < 3:
            problems.append(f"“{t.get('title')}” isn't completed — add a remark (what is pending / why).")
        if t.get("remarks") and not t.get("plan_remarks"):
            t["plan_remarks"] = t["remarks"]          # keep the morning planning note next to the end-of-day remark
        t["status"], t["remarks"] = status, remarks

    assigned_in = {str(x.get("task_id")): x for x in (data.get("assigned") or []) if isinstance(x, dict)}
    today_iso = _today_ist().isoformat()
    for at in open_assigned_for(uid):
        tid = str(at["_id"])
        already = any(u.get("user_id") == uid and u.get("date") == today_iso and u.get("type") != "comment" for u in at.get("updates") or [])
        x = assigned_in.get(tid)
        if not x:
            if not already:
                problems.append(f"Assigned work “{at.get('title')}” needs today's status.")
            continue
        ok, msg, _code = apply_daily_update(user, tid, x.get("status"), x.get("remarks"))
        if not ok:
            problems.append(f"“{at.get('title')}”: {msg}")
    if problems:
        return jsonify({"message": "Please fix these before submitting:\n• " + "\n• ".join(problems), "problems": problems}), 400

    now = datetime.now(timezone.utc)
    if not has_plan:
        return jsonify({"ok": True, "assigned_only": True}), 200
    work_plans_col.update_one({"_id": plan["_id"]}, {"$set": {
        "tasks": tasks, "evening_submitted_at": now, "evening_summary": _sanitize(data.get("summary"), 1500), "updated_at": now}})
    return jsonify(_serialize_plan(work_plans_col.find_one({"_id": plan["_id"]}))), 200


@bp.route("/api/my/work-plan/<plan_id>/task/<task_id>", methods=["PUT"])
@token_required
def update_my_task(plan_id, task_id):
    uid = str(request.user["_id"])
    try:
        obj = ObjectId(plan_id)
    except Exception:
        return jsonify({"message": "Invalid plan ID"}), 400

    status = (request.json or {}).get("status")
    if not status:
        return jsonify({"message": "status is required"}), 400
    if status not in TASK_STATUSES:
        return jsonify({"message": f"status must be one of: {', '.join(TASK_STATUSES)}"}), 400

    now        = datetime.now(timezone.utc)
    update_doc = {"$set": {"tasks.$[t].status": status, "updated_at": now}}

    result = work_plans_col.update_one(
        {"_id": obj, "employee_id": uid},
        update_doc,
        array_filters=[{"t.id": task_id}],
    )
    if result.matched_count == 0:
        return jsonify({"message": "Plan not found or not yours"}), 404

    if result.modified_count == 0:
        result2 = work_plans_col.update_one(
            {"_id": obj, "employee_id": uid},
            update_doc,
            array_filters=[{"t._id": task_id}],
        )
        if result2.modified_count == 0:
            return jsonify({"message": "Task not found in plan"}), 404

    plan = work_plans_col.find_one({"_id": obj})
    return jsonify(_serialize_plan(plan)), 200


@bp.route("/api/my/work-plans", methods=["GET"])
@token_required
def my_work_plans_history():
    uid       = str(request.user["_id"])
    range_key = request.args.get("range", "week")
    today     = _today_ist()

    query: dict = {"employee_id": uid}
    if range_key == "week":
        query["date"] = {"$gte": (today - timedelta(days=6)).isoformat(), "$lte": today.isoformat()}
    elif range_key == "month":
        query["date"] = {"$gte": (today - timedelta(days=29)).isoformat(), "$lte": today.isoformat()}

    plans  = work_plans_col.find(query, {"_id": 1, "date": 1, "status": 1, "tasks": 1}).sort("date", -1)
    result = []
    for p in plans:
        result.append({
            "_id":    str(p["_id"]),
            "date":   p.get("date"),
            "status": p.get("status"),
            "tasks":  [
                {
                    "id":        t.get("id") or t.get("_id", ""),
                    "title":     t.get("title", ""),
                    "priority":  t.get("priority", ""),
                    "project":   t.get("project", ""),
                    "client":    t.get("client", ""),
                    "est_time":  t.get("est_time", ""),
                    "status":    t.get("status", "Pending"),
                    "work_type": t.get("work_type", ""),
                    "remarks":   t.get("remarks", ""),
                }
                for t in (p.get("tasks") or [])
            ],
        })
    return jsonify(result), 200


@bp.route("/api/my/work-plan/share", methods=["POST"])
@token_required
def share_work_plan():
    uid      = str(request.user["_id"])
    data     = request.get_json(silent=True) or {}
    date_str = str(data.get("date") or _today_ist().isoformat())[:10]

    plan = work_plans_col.find_one({"employee_id": uid, "date": date_str})
    if not plan or not plan.get("tasks"):
        return jsonify({"message": "No work plan found for that date"}), 404

    raw_dept  = request.user.get("department")
    dept      = ", ".join(raw_dept) if isinstance(raw_dept, list) else (raw_dept or "").strip()
    user_name = request.user.get("name", "")

    lines = [
        f"Work Plan — {user_name}",
        f"Date: {date_str}",
        f"Department: {dept}",
        "",
    ]
    ci_map = _checkin_map([uid], date_str)
    ci     = ci_map.get(uid) or "—"
    lines.append(f"Check-in: {ci}")
    lines.append("")
    for t in plan.get("tasks", []):
        done = "✓" if _is_task_done(t) else " "
        lines.append(
            f"  [{done}] {t.get('title', '')}"
            f"  | type: {t.get('work_type', '-')}"
            f"  | priority: {t.get('priority', '-')}"
            f"  | est: {t.get('est_time', '-')}"
            f"  | project: {t.get('project', '-')}"
        )
    if plan.get("manager_comment"):
        lines.append(f"\nManager comment: {plan['manager_comment']}")
    body    = "\n".join(lines)
    subject = f"Work Plan — {user_name} ({date_str})"

    # Every eligible manager-approver (direct manager, any other manager in
    # the department, and the department head(s) — same "who can act as this
    # employee's manager" resolution leave/asset/referral notifications use)
    # plus every owner. The old version here matched on `dept`, a
    # comma-joined display string — for a multi-department employee that
    # string never equals any single manager's stored department, so their
    # share silently reached nobody but the owners.
    #
    # Resolved here, in the request thread, and passed in as plain values —
    # request.user is a Flask context-local; a background thread has no
    # request context of its own, so touching request.user from inside one
    # (the previous version's whole _send_share() closure did, on every
    # line) raises "Working outside of request context" the instant the
    # thread actually runs. Silently: this endpoint had returned "shared
    # successfully" 200 on every call while the daemon thread died on its
    # first line and no email ever went out.
    recipients = set(OWNER_EMAILS) | set(resolve_employee_manager_emails(request.user))

    def _send_share(to_emails, mail_subject, mail_body):
        for email in to_emails:
            try:
                send_email(email, mail_subject, mail_body)
            except Exception as e:
                print(f"[share-plan] email to {email} failed: {e}")

    threading.Thread(target=_send_share, args=(recipients, subject, body), daemon=True).start()
    return jsonify({"message": "Work plan shared successfully"}), 200


@bp.route("/api/my/work-analytics", methods=["GET"])
@token_required
def my_work_analytics():
    uid        = str(request.user["_id"])
    range_key  = request.args.get("range", "week")
    today_date = _today_ist()
    start_date = _range_start(range_key, today_date)

    plans = list(work_plans_col.find({
        "employee_id": uid,
        "date": {"$gte": start_date.isoformat(), "$lte": today_date.isoformat()}
    }))
    return jsonify(_build_analytics(plans, start_date, today_date)), 200


@bp.route("/api/my/work-analytics-ai", methods=["GET"])
@token_required
def my_work_analytics_ai():
    if not GROQ_API_KEY:
        return jsonify({"message": "AI analytics not configured."}), 503

    uid       = str(request.user["_id"])
    range_key = request.args.get("range", "week")
    today     = _today_ist()
    start     = _range_start(range_key, today)

    plans = list(work_plans_col.find({
        "employee_id": uid,
        "date": {"$gte": start.isoformat(), "$lte": today.isoformat()},
    }))

    total_tasks = completed_tasks = 0
    work_type_counts: dict = {}
    client_counts:    dict = {}
    active_days = set()

    for p in plans:
        if p.get("tasks"):
            active_days.add(p.get("date"))
        for t in (p.get("tasks") or []):
            total_tasks += 1
            if _is_task_done(t):
                completed_tasks += 1
            wt = (t.get("work_type") or "").strip()
            if wt:
                work_type_counts[wt] = work_type_counts.get(wt, 0) + 1
            cl = (t.get("client") or "").strip()
            if cl:
                client_counts[cl] = client_counts.get(cl, 0) + 1

    completion_rate = round(completed_tasks / total_tasks * 100) if total_tasks else 0
    top_work_type   = max(work_type_counts, key=work_type_counts.get) if work_type_counts else "N/A"
    top_client      = max(client_counts,    key=client_counts.get)    if client_counts    else "N/A"

    facts = (
        f"Period: {start.isoformat()} to {today.isoformat()} ({range_key})\n"
        f"Active days with tasks: {len(active_days)}\n"
        f"Total tasks: {total_tasks}\n"
        f"Completed tasks: {completed_tasks} ({completion_rate}%)\n"
        f"Most common work type: {top_work_type}\n"
        f"Most common client: {top_client}\n"
    )

    system_prompt = (
        "You are a helpful productivity coach. Based on the employee's work-plan stats below, "
        "write a 3–5 sentence plain-English summary. Cover: overall productivity, completion rate, "
        "focus areas, and one concrete observation or encouragement. Be specific and friendly.\n\n"
        f"Stats:\n{facts}"
    )

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model":       GROQ_MODEL,
                "messages":    [{"role": "user", "content": system_prompt}],
                "temperature": 0.5,
                "max_tokens":  250,
            },
            timeout=12,
        )
        resp.raise_for_status()
        summary = resp.json()["choices"][0]["message"]["content"].strip()
        return jsonify({"summary": summary}), 200
    except Exception as e:
        return jsonify({"message": "AI analytics temporarily unavailable.", "error": str(e)}), 502


@bp.route("/api/admin/work-reports/<kind>", methods=["POST"])
@token_required
def work_report_preview(kind):
    """Admin: build a department-wise work report right now. Default is a preview (nothing emailed);
    {"send_to_me": true} emails it to the requesting admin only."""
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    if kind not in ("morning", "evening", "weekly", "monthly"):
        return jsonify({"message": "kind must be morning, evening, weekly or monthly"}), 400
    from jobs import work_reports as wr
    data = request.get_json(silent=True) or {}
    subject, html, text = wr.preview(kind, (data.get("department") or None))
    if data.get("send_to_me") and request.user.get("email"):
        wr._mail(request.user["email"], subject, html, text)
    return jsonify({"subject": subject, "html": html, "sent_to_me": bool(data.get("send_to_me"))}), 200


# ── Admin / Manager routes ────────────────────────────────────────────────────

@bp.route("/api/admin/work-plans", methods=["GET"])
@token_required
def admin_work_plans():
    role          = request.user.get("role")
    has_delegated = _has_module_grant(request.user, "work-by-team")
    if role not in ("admin", "owner", "manager") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    date_str = request.args.get("date") or _today_ist().isoformat()
    query    = {"date": date_str}
    if role == "manager" and not has_delegated:
        query["department"] = {"$in": _mgr_depts(request.user)}

    plans    = list(work_plans_col.find(query).sort("employee_name", 1))
    checkins = _checkin_map([p["employee_id"] for p in plans], date_str)
    rows     = [_serialize_plan(p, checkin=checkins.get(p["employee_id"])) for p in plans]
    return jsonify(rows), 200


@bp.route("/api/admin/work-overview", methods=["GET"])
@token_required
def admin_work_overview():
    """One row per person in scope for a day — including people who have NOT planned — so a manager/owner sees
    at a glance who is planned, who still needs to plan, who is on leave and who is not in."""
    role          = request.user.get("role")
    has_delegated = _has_module_grant(request.user, "work-by-team")
    if role not in ("admin", "owner", "manager") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    date_str = str(request.args.get("date") or _today_ist().isoformat())[:10]
    uq = {"role": {"$in": ["employee", "manager"]}}
    if role == "manager" and not has_delegated:
        uq["department"] = {"$in": _mgr_depts(request.user)}
    people = [u for u in users_col.find(uq, {"name": 1, "department": 1, "role": 1, "resignation": 1}) if not is_offboarded(u)]
    ids = [str(u["_id"]) for u in people]

    plans    = {p["employee_id"]: p for p in work_plans_col.find({"employee_id": {"$in": ids}, "date": date_str})}
    checkins = _checkin_map(ids, date_str)
    on_leave = {lv["user_id"] for lv in leaves_col.find({"user_id": {"$in": ids}, "status": "Approved", "from_date": {"$lte": date_str}, "to_date": {"$gte": date_str}}, {"user_id": 1})}
    day_off  = is_weekend_day(date_str, get_company_holiday_dates())

    rows, totals = [], {"planned": 0, "needs_plan": 0, "on_leave": 0, "not_in": 0, "off": 0, "tasks": 0, "done": 0, "evening_done": 0}
    for u in sorted(people, key=lambda x: (str((x.get("department") if not isinstance(x.get("department"), list) else (x.get("department") or [""])[0]) or ""), x.get("name", ""))):
        uid  = str(u["_id"])
        plan = plans.get(uid)
        if plan and plan.get("status") == "submitted":
            status = "planned"
        elif uid in checkins:
            status = "needs_plan"
        elif uid in on_leave:
            status = "on_leave"
        elif day_off:
            status = "off"
        else:
            status = "not_in"
        totals[status] += 1
        tasks = [t for t in ((plan or {}).get("tasks") or []) if str(t.get("title", "")).strip()]
        if status == "planned":
            totals["tasks"] += len(tasks)
            totals["done"]  += sum(1 for t in tasks if _is_task_done(t))
            totals["evening_done"] += 1 if plan.get("evening_submitted_at") else 0
        dept = u.get("department")
        rows.append({
            "user_id": uid, "name": u.get("name", ""), "role": u.get("role"),
            "department": (dept[0] if isinstance(dept, list) and dept else dept) or "",
            "check_in_time": checkins.get(uid), "status": status,
            "plan": _serialize_plan(plan, checkin=checkins.get(uid)) if plan else None,
        })

    today = _today_ist().isoformat()
    overdue = work_tasks_col.count_documents({"assignees.user_id": {"$in": ids}, "status": {"$ne": "Completed"}, "deadline": {"$lt": today}})
    totals["assigned_overdue"] = overdue
    return jsonify({"date": date_str, "people": rows, "totals": totals}), 200


@bp.route("/api/admin/work-plans/<plan_id>/task/<task_id>/comment", methods=["POST"])
@token_required
def comment_work_task(plan_id, task_id):
    """A manager/owner/admin leaves a short comment on one task of someone's plan (shown to that person)."""
    role          = request.user.get("role")
    has_delegated = _has_module_grant(request.user, "work-by-team")
    if role not in ("admin", "owner", "manager") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(plan_id)
    except Exception:
        return jsonify({"message": "Invalid plan ID"}), 400
    plan = work_plans_col.find_one({"_id": obj})
    if not plan:
        return jsonify({"message": "Plan not found"}), 404
    if role == "manager" and not has_delegated and plan.get("department") not in _mgr_depts(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    text = _sanitize((request.get_json(silent=True) or {}).get("comment"), 600)
    now  = datetime.now(timezone.utc)
    hit  = False
    for t in plan.get("tasks") or []:
        if str(t.get("id") or t.get("_id", "")) == str(task_id):
            t["manager_comment"] = {"text": text, "by": request.user.get("name", ""), "at": now.isoformat()} if text else None
            hit = True
    if not hit:
        return jsonify({"message": "Task not found in plan"}), 404
    work_plans_col.update_one({"_id": obj}, {"$set": {"tasks": plan["tasks"], "updated_at": now}})
    return jsonify({"message": "Comment saved"}), 200


@bp.route("/api/admin/work-analytics", methods=["GET"])
@token_required
def admin_work_analytics():
    role          = request.user.get("role")
    has_delegated = _has_module_grant(request.user, "work-by-team")
    if role not in ("admin", "owner", "manager") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    range_key  = request.args.get("range", "week")
    today_date = _today_ist()
    start_date = _range_start(range_key, today_date)

    query = {"date": {"$gte": start_date.isoformat(), "$lte": today_date.isoformat()}}
    if role == "manager" and not has_delegated:
        query["department"] = {"$in": _mgr_depts(request.user)}

    plans = list(work_plans_col.find(query))
    return jsonify(_build_analytics(plans, start_date, today_date)), 200


@bp.route("/api/admin/work-plans/<plan_id>/comment", methods=["POST"])
@token_required
def comment_work_plan(plan_id):
    role          = request.user.get("role")
    has_delegated = _has_module_grant(request.user, "work-by-team")
    if role not in ("admin", "owner", "manager") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    try:
        obj = ObjectId(plan_id)
    except Exception:
        return jsonify({"message": "Invalid plan ID"}), 400

    plan = work_plans_col.find_one({"_id": obj})
    if not plan:
        return jsonify({"message": "Plan not found"}), 404
    if role == "manager" and not has_delegated and plan.get("department") not in _mgr_depts(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    comment = str((request.json or {}).get("comment", "")).strip()
    work_plans_col.update_one(
        {"_id": obj},
        {"$set": {"manager_comment": comment, "updated_at": datetime.now(timezone.utc)}}
    )
    return jsonify({"message": "Comment saved"}), 200
