"""
routes/stats.py — GDMR Connect
=================================
Dashboard stats, monthly attendance summary, and auto-absent cron endpoint.
"""
import os
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import (attendance_col, leaves_col, users_col)
from decorators import token_required
from helpers import _is_admin, _has_module_grant, classify_attendance_day, get_company_holiday_dates
from config import IST

bp = Blueprint("stats", __name__)


@bp.route("/api/admin/today-stats", methods=["GET"])
@token_required
def today_stats():
    if not (_is_admin(request.user)
            or _has_module_grant(request.user, "summary")
            or _has_module_grant(request.user, "attendance")):
        return jsonify({"message": "Unauthorized"}), 403

    today    = str(datetime.now(IST).date())
    today_dt = datetime.strptime(today, "%Y-%m-%d")

    all_staff = list(users_col.find(
        {"role": {"$in": ["employee", "manager"]}},
        {"_id": 1, "role": 1, "department": 1, "resignation": 1}
    ))
    active_users = []
    for u in all_staff:
        lwd = (u.get("resignation") or {}).get("last_working_day")
        if lwd:
            lwd_str = lwd.date().isoformat() if hasattr(lwd, "date") else str(lwd)[:10]
            if lwd_str < today:
                continue
        active_users.append(u)
    active_ids = {str(e["_id"]) for e in active_users}

    present_ids = {
        r["user_id"] for r in attendance_col.find(
            {"date": today, "type": "checkin"}, {"user_id": 1}
        )
    }
    std_leave_ids = {
        l["user_id"] for l in leaves_col.find(
            {"from_date": {"$lte": today}, "to_date": {"$gte": today},
             "status": {"$nin": ["Rejected", "Cancelled"]}},
            {"user_id": 1}
        )
    }
    ext_leave_ids = {
        str(e["_id"]) for e in users_col.find(
            {"role": {"$in": ["employee", "manager"]},
             "extended_leaves": {"$elemMatch": {
                 "from_date": {"$lte": today_dt},
                 "to_date":   {"$gte": today_dt},
             }}},
            {"_id": 1}
        )
    }
    all_leave_ids   = std_leave_ids | ext_leave_ids
    present_count   = len(present_ids & active_ids)
    leave_count     = len((all_leave_ids - present_ids) & active_ids)
    not_in_count    = len(active_ids - present_ids - all_leave_ids)
    employee_count  = sum(1 for u in active_users if u.get("role") == "employee")
    manager_count   = sum(1 for u in active_users if u.get("role") == "manager")
    by_department: dict = {}
    for u in active_users:
        dept = (u.get("department") or "").strip()
        if dept:
            by_department[dept] = by_department.get(dept, 0) + 1

    return jsonify({
        "present":         present_count,
        "leave":           leave_count,
        "not_checked_in":  not_in_count,
        "total_workforce": len(active_ids),
        "employee_count":  employee_count,
        "manager_count":   manager_count,
        "by_department":   by_department,
    }), 200


@bp.route("/api/admin/attendance-summary", methods=["GET"])
@token_required
def attendance_summary():
    # "summary" — AdminAttendanceSummary.jsx (the "View Reports" delegated
    # module) is this endpoint's main consumer; without it here a
    # summary-only delegate's whole Reports page reads as all-zero (every
    # stat on that page is ultimately derived from this one call).
    if not (_is_admin(request.user)
            or _has_module_grant(request.user, "attendance")
            or _has_module_grant(request.user, "summary")):
        return jsonify({"message": "Unauthorized"}), 403

    month_param = request.args.get("month")
    if not month_param:
        return jsonify({"message": "month required"}), 400

    year, month_num = map(int, month_param.split("-"))
    start     = IST.localize(datetime(year, month_num, 1))
    end       = IST.localize(datetime(year + (month_num // 12), (month_num % 12) + 1, 1))
    start_str = start.date().isoformat()
    end_str   = (end - timedelta(days=1)).date().isoformat()
    today_str = str(datetime.now(IST).date())

    employees = list(users_col.find(
        {"role": {"$in": ["employee", "manager"]}},
        {"name": 1, "doj": 1, "resignation": 1, "extended_leaves": 1}
    ))
    emp_names = {str(e["_id"]): e.get("name", "") for e in employees}

    all_recs = attendance_col.find({"date": {"$regex": f"^{month_param}"}, "type": "checkin"})
    checkins_by_date: dict = {}
    for rec in all_recs:
        checkins_by_date.setdefault(rec["date"], set()).add(rec["user_id"])

    all_leaves = list(leaves_col.find({
        "from_date": {"$lte": end_str},
        "to_date":   {"$gte": start_str},
        "status":    {"$nin": ["Rejected", "Cancelled"]},
    }))
    leaves_by_uid: dict = {}
    for lv in all_leaves:
        leaves_by_uid.setdefault(lv["user_id"], []).append(lv)

    holiday_dates = get_company_holiday_dates()  # one query for the whole month, not per-day
    summary: dict = {"total_employees": len(employees), "days": {}}
    curr = start
    while curr < end:
        day_str   = curr.date().isoformat()
        curr     += timedelta(days=1)
        if day_str > today_str:
            continue

        is_weekend   = datetime.strptime(day_str, "%Y-%m-%d").weekday() >= 5 or day_str in holiday_dates
        is_today     = day_str == today_str
        day_checkins = checkins_by_date.get(day_str, set())

        present_ids, leave_ids, absent_ids, nci_ids = [], [], [], []

        for emp in employees:
            uid    = str(emp["_id"])
            status = classify_attendance_day(emp, day_str, day_checkins, leaves_by_uid, is_weekend, is_today)
            if status == "present":
                present_ids.append(uid)
            elif status == "leave":
                leave_ids.append(uid)
            elif status == "not_checked_in":
                nci_ids.append(uid)
            elif status == "absent":
                absent_ids.append(uid)
                # A finalized no-show (day over, no checkin, no leave, not a
                # weekend) is exactly what "not_checked_in" already meant
                # while the day was still in progress — HR wants that kept
                # visible here too, instead of collapsing to 0 the moment
                # the day ends. Deliberately overlaps with Absent (still
                # what LOP/payroll reads, unchanged) rather than being
                # spun off into its own separate headcount bucket.
                nci_ids.append(uid)
            # status is None: not yet joined / already offboarded / weekend with nothing recorded — no bucket

        def _names(ids):
            return [emp_names[uid] for uid in ids if emp_names.get(uid)]

        summary["days"][day_str] = {
            "present":            present_ids,  "present_count":        len(present_ids),  "present_names":        _names(present_ids),
            "leave":              leave_ids,    "leave_count":          len(leave_ids),    "leave_names":          _names(leave_ids),
            "absent":             absent_ids,   "absent_count":         len(absent_ids),   "absent_names":         _names(absent_ids),
            "not_checked_in":     nci_ids,      "not_checked_in_count": len(nci_ids),      "not_checked_in_names": _names(nci_ids),
            "is_weekend":         is_weekend,
        }

    return jsonify(summary), 200


@bp.route("/api/attendance/auto-absent", methods=["POST"])
def auto_mark_absent():
    """Cron endpoint — marks absent users who didn't punch in. Requires CRON_SECRET header."""
    cron_secret = os.getenv("CRON_SECRET")
    provided    = request.headers.get("X-Cron-Secret", "")
    if not cron_secret or provided != cron_secret:
        return jsonify({"message": "Unauthorized"}), 401

    today     = datetime.now(IST).date()
    today_str = str(today)
    if today_str in get_company_holiday_dates():
        # Nobody is expected to check in on a declared company holiday —
        # same reasoning as classify_attendance_day() below, just applied
        # before this cron writes a permanent "absent" record instead of
        # after the fact.
        return jsonify({"message": "Skipped — today is a company holiday"}), 200
    all_users = users_col.find({"role": {"$in": ["employee", "manager"]}})

    for emp in all_users:
        uid = str(emp["_id"])
        if not attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today_str}):
            if not leaves_col.find_one({"user_id": uid, "status": "Approved",
                                        "from_date": {"$lte": today_str}, "to_date": {"$gte": today_str}}):
                if not attendance_col.find_one({"user_id": uid, "type": "absent", "date": today_str}):
                    attendance_col.insert_one({
                        "user_id": uid, "type": "absent",
                        "date": today_str, "time": datetime.now(timezone.utc),
                    })
                if not leaves_col.find_one({"user_id": uid, "type": "System Absent", "date": today_str}):
                    leaves_col.insert_one({
                        "user_id":   uid,
                        "from_date": today_str, "to_date": today_str, "date": today_str,
                        "type":      "System Absent",
                        "reason":    "Not checked in by cutoff time",
                        "status":    "Absent",
                        "applied_at": datetime.now(timezone.utc),
                    })

    return jsonify({"message": "Absent auto-marking completed"}), 200
