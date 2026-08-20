"""
routes/calendar.py — GDMR Connect
====================================
Monthly attendance calendar — self, manager (for a direct report), and
admin/delegate (for any employee). All three share one implementation
(_month_calendar_for_employee), which in turn reuses the exact same
per-day classification helpers.classify_attendance_day() that
routes/stats.py's attendance_summary() uses — so this calendar and the
existing admin attendance summary can never disagree on what a given day
"was" for an employee, they just render the same underlying status
differently:

  classify_attendance_day() -> this endpoint's "status"
  "present"                 -> "present"         (spec: green)
  "leave"                   -> "approved_leave"   (spec: orange)
  "absent"                  -> "lop"              (spec: red — unauthorized
                                                    absence / failed check-in
                                                    *is* loss-of-pay)
  "not_checked_in" (today)  -> "pending"          (day isn't over yet)
  None + weekend             -> "weekly_off"       (spec: grey)
  None, not weekend          -> omitted entirely   (before DOJ / after LWD)

Company holidays (helpers.COMPANY_HOLIDAYS) are treated exactly like
weekends here — excluded from "absent"/LOP the same way — so a weekday
holiday with no check-ins shows as "weekly_off" (spec: grey) instead of
LOP, and payroll's auto-LOP fill (routes/payroll.py's payroll_lop_preview,
which calls _month_calendar_for_employee directly) stops deducting pay
for them too.
"""
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import attendance_col, leaves_col, users_col
from decorators import token_required
from helpers import (_is_admin, _has_module_grant, _mgr_depts,
                      classify_attendance_day, _date_str, format_datetime_ist,
                      COMPANY_HOLIDAYS, COMPANY_HOLIDAY_DATES)
from config import IST

bp = Blueprint("calendar", __name__)


def _month_calendar_for_employee(uid, month_str):
    """Build one employee's day-by-day calendar for `month_str` ("YYYY-MM").
    Returns None if the employee doesn't exist or month_str is malformed."""
    try:
        obj = ObjectId(uid)
        year, month_num = map(int, month_str.split("-"))
    except (ValueError, TypeError):
        return None

    emp = users_col.find_one(
        {"_id": obj}, {"name": 1, "doj": 1, "resignation": 1, "extended_leaves": 1}
    )
    if not emp:
        return None

    start     = IST.localize(datetime(year, month_num, 1))
    end       = IST.localize(datetime(year + (month_num // 12), (month_num % 12) + 1, 1))
    start_str = start.date().isoformat()
    end_str   = (end - timedelta(days=1)).date().isoformat()
    today_str = str(datetime.now(IST).date())

    checkin_times = {}
    for rec in attendance_col.find(
        {"user_id": uid, "type": "checkin", "date": {"$regex": f"^{month_str}"}},
        {"date": 1, "time": 1}
    ):
        checkin_times[rec["date"]] = rec.get("time")

    leaves = list(leaves_col.find({
        "user_id":   uid,
        "from_date": {"$lte": end_str},
        "to_date":   {"$gte": start_str},
        "status":    {"$nin": ["Rejected", "Cancelled"]},
    }))
    leaves_by_uid = {uid: leaves}

    joined      = _date_str(emp.get("doj"))
    resignation = emp.get("resignation") or {}
    lwd         = _date_str(resignation.get("last_working_day"))

    days: dict = {}
    counts = {"present": 0, "approved_leave": 0, "lop": 0, "weekly_off": 0}
    curr = start
    while curr < end:
        day_str = curr.date().isoformat()
        curr   += timedelta(days=1)
        if day_str > today_str:
            continue
        # Outside the employment window entirely — omit rather than mis-render
        # as a weekly-off/LOP day that never applied to this employee.
        if joined and day_str < joined:
            continue
        if lwd and day_str > lwd:
            continue

        is_weekend   = datetime.strptime(day_str, "%Y-%m-%d").weekday() >= 5 or day_str in COMPANY_HOLIDAY_DATES
        is_today     = day_str == today_str
        day_checkins = {uid} if day_str in checkin_times else set()

        status = classify_attendance_day(emp, day_str, day_checkins, leaves_by_uid, is_weekend, is_today)

        if status == "present":
            display = "present"
            counts["present"] += 1
        elif status == "leave":
            display = "approved_leave"
            counts["approved_leave"] += 1
        elif status == "absent":
            display = "lop"
            counts["lop"] += 1
        elif status == "not_checked_in":
            display = "pending"
        else:
            # classify_attendance_day() only returns None here for a weekend
            # with nothing recorded — the join/exit-window cases were already
            # filtered out above via `continue`.
            display = "weekly_off"
            counts["weekly_off"] += 1

        entry = {"status": display}
        if display == "present" and checkin_times.get(day_str):
            entry["checkin_time"] = format_datetime_ist(checkin_times[day_str])
        days[day_str] = entry

    return {
        "month":         month_str,
        "employee_id":   uid,
        "employee_name": emp.get("name", ""),
        "days":          days,
        "summary":       counts,
    }


@bp.route("/api/holidays", methods=["GET"])
@token_required
def list_holidays():
    # Any authenticated role — the Holiday Calendar tab and the Attendance
    # Calendar's grey-out overlay both read this same list, so they can
    # never drift the way the old frontend-only static file and this
    # backend's own LOP math implicitly did.
    return jsonify(COMPANY_HOLIDAYS), 200


@bp.route("/api/my/attendance/calendar", methods=["GET"])
@token_required
def my_attendance_calendar():
    month_str = request.args.get("month")
    if not month_str:
        return jsonify({"message": "month required"}), 400
    result = _month_calendar_for_employee(str(request.user["_id"]), month_str)
    if result is None:
        return jsonify({"message": "Invalid month"}), 400
    return jsonify(result), 200


@bp.route("/api/manager/attendance/calendar", methods=["GET"])
@token_required
def manager_attendance_calendar():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403
    employee_id = request.args.get("employee_id")
    month_str   = request.args.get("month")
    if not employee_id or not month_str:
        return jsonify({"message": "employee_id and month are required"}), 400
    if not ObjectId.is_valid(employee_id):
        return jsonify({"message": "Invalid employee_id"}), 400

    # Manager can only view direct reports — same dept-scoped ownership check
    # routes/lms.py's manager_lms_progress() already uses.
    manager_depts = _mgr_depts(request.user)
    owned = users_col.find_one(
        {"_id": ObjectId(employee_id), "department": {"$in": manager_depts}, "role": "employee"},
        {"_id": 1}
    )
    if not owned:
        return jsonify({"message": "Employee not in your department"}), 403

    result = _month_calendar_for_employee(employee_id, month_str)
    if result is None:
        return jsonify({"message": "Invalid month"}), 400
    return jsonify(result), 200


@bp.route("/api/admin/attendance/calendar", methods=["GET"])
@token_required
def admin_attendance_calendar():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "attendance")):
        return jsonify({"message": "Unauthorized"}), 403
    employee_id = request.args.get("employee_id")
    month_str   = request.args.get("month")
    if not employee_id or not month_str:
        return jsonify({"message": "employee_id and month are required"}), 400

    result = _month_calendar_for_employee(employee_id, month_str)
    if result is None:
        return jsonify({"message": "Employee not found or invalid month"}), 404
    return jsonify(result), 200
