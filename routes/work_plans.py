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

from database import work_plans_col, access_grants_col, users_col, attendance_col
from decorators import token_required
from helpers import (
    _is_admin, _mgr_depts, _is_task_done,
    _checkin_map, _serialize_plan, _range_start, _build_analytics, _today_ist,
    format_datetime_ist,
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
        if isinstance(task, dict) and not task.get("id"):
            task["id"] = secrets.token_hex(8)

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

    dept = (request.user.get("department") or "").strip()

    def _build_body(plan_doc, date_s):
        lines  = [
            f"Work Plan — {request.user.get('name', '')}",
            f"Date: {date_s}",
            f"Department: {dept}",
            "",
        ]
        ci_map = _checkin_map([uid], date_s)
        ci     = ci_map.get(uid) or "—"
        lines.append(f"Check-in: {ci}")
        lines.append("")
        for t in plan_doc.get("tasks", []):
            done = "✓" if _is_task_done(t) else " "
            lines.append(
                f"  [{done}] {t.get('title', '')}"
                f"  | type: {t.get('work_type', '-')}"
                f"  | priority: {t.get('priority', '-')}"
                f"  | est: {t.get('est_time', '-')}"
                f"  | project: {t.get('project', '-')}"
            )
        if plan_doc.get("manager_comment"):
            lines.append(f"\nManager comment: {plan_doc['manager_comment']}")
        return "\n".join(lines)

    def _send_share():
        subject    = f"Work Plan — {request.user.get('name', '')} ({date_str})"
        body       = _build_body(plan, date_str)
        recipients = set(OWNER_EMAILS)
        if dept:
            for mgr in users_col.find({"role": "manager", "department": dept}, {"email": 1}):
                if mgr.get("email"):
                    recipients.add(mgr["email"])
            for mgr in users_col.find({"role": "manager", "department": {"$in": [dept]}}, {"email": 1}):
                if mgr.get("email"):
                    recipients.add(mgr["email"])
        for email in recipients:
            try:
                send_email(email, subject, body)
            except Exception as e:
                print(f"[share-plan] email to {email} failed: {e}")

    threading.Thread(target=_send_share, daemon=True).start()
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


# ── Admin / Manager routes ────────────────────────────────────────────────────

@bp.route("/api/admin/work-plans", methods=["GET"])
@token_required
def admin_work_plans():
    role          = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
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


@bp.route("/api/admin/work-analytics", methods=["GET"])
@token_required
def admin_work_analytics():
    role          = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
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
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
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
