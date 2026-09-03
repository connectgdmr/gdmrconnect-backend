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

Company holidays (database.holidays_col) are treated exactly like weekends
here — excluded from "absent"/LOP the same way — so a weekday holiday with
no check-ins shows as "weekly_off" (spec: grey) instead of LOP, and
payroll's auto-LOP fill (routes/payroll.py's payroll_lop_preview, which
calls _month_calendar_for_employee directly) stops deducting pay for them
too.
"""
import re
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import DuplicateKeyError

from database import attendance_col, leaves_col, users_col, holidays_col, corrections_col
from decorators import token_required
from helpers import (_is_admin, _has_module_grant, _mgr_depts,
                      classify_attendance_day, _date_str, format_datetime_ist,
                      get_company_holiday_dates, is_weekend_day)
from config import IST

bp = Blueprint("calendar", __name__)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _holiday_allowed(user, write=False):
    # Holidays don't have their own grantable module — they're an
    # attendance-adjacent concept (they change how attendance/LOP is
    # computed), so the existing "attendance" grant covers managing them too.
    return _is_admin(user) or _has_module_grant(user, "attendance", write=write)


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

    checkin_times  = {}
    checkout_times = {}
    for rec in attendance_col.find(
        {"user_id": uid, "type": {"$in": ["checkin", "checkout"]}, "date": {"$regex": f"^{month_str}"}},
        {"date": 1, "time": 1, "type": 1}
    ):
        (checkin_times if rec["type"] == "checkin" else checkout_times)[rec["date"]] = rec.get("time")

    leaves = list(leaves_col.find({
        "user_id":   uid,
        "from_date": {"$lte": end_str},
        "to_date":   {"$gte": start_str},
        "status":    {"$nin": ["Rejected", "Cancelled"]},
    }))
    leaves_by_uid = {uid: leaves}

    # Correction requests filed this month, keyed by the calendar day they
    # target (new_time is "YYYY-MM-DDTHH:MM") — a day can carry its
    # correction's status even when it's also present/LOP, so the calendar
    # click-through can show "you requested a correction here" regardless
    # of what the day otherwise displays as.
    corrections_by_day = {}
    for c in corrections_col.find({"user_id": uid, "month": month_str}):
        new_time = c.get("new_time") or ""
        if len(new_time) < 10:
            continue
        corrections_by_day.setdefault(new_time[:10], []).append({
            "status":    c.get("status", "Pending"),
            "new_time":  new_time,
            "reason":    c.get("reason"),
        })

    joined      = _date_str(emp.get("doj"))
    resignation = emp.get("resignation") or {}
    lwd         = _date_str(resignation.get("last_working_day"))
    holiday_dates = get_company_holiday_dates()  # one query for the whole month, not per-day
    # Named holidays specifically (a plain Sat/Sun has no name) — so a
    # "weekly_off" day on the calendar can show which holiday it actually
    # was, not just a generic "Off", the same name the Holiday Calendar
    # tab already shows for it.
    holiday_names = {h["date"]: h.get("name") for h in holidays_col.find(
        {"date": {"$in": list(holiday_dates)}}, {"date": 1, "name": 1}
    )}

    days: dict = {}
    counts = {"present": 0, "approved_leave": 0, "lop": 0, "weekly_off": 0}
    curr = start
    while curr < end:
        day_str = curr.date().isoformat()
        curr   += timedelta(days=1)
        # Outside the employment window entirely — omit rather than mis-render
        # as a weekly-off/LOP day that never applied to this employee.
        if joined and day_str < joined:
            continue
        if lwd and day_str > lwd:
            continue

        is_weekend = is_weekend_day(day_str, holiday_dates)

        if day_str > today_str:
            # Future day: whether the employee will be present/on leave
            # isn't knowable yet, so classify_attendance_day() doesn't apply
            # — but a weekend/holiday IS known in advance, shown the same as
            # a past one. A future regular working day still can't say what
            # will happen, but it's given a lightweight "future" entry (not
            # counted in any summary bucket) purely so it's clickable —
            # applying for leave ahead of time is a normal thing to want to
            # do from here, unlike a correction, which only ever makes sense
            # after the day is already over.
            if is_weekend:
                entry = {"status": "weekly_off"}
                if holiday_names.get(day_str):
                    entry["holiday_name"] = holiday_names[day_str]
                counts["weekly_off"] += 1
            else:
                # A leave request (approved by a manager or admin — or still
                # pending; anything not Rejected/Cancelled, same rule the
                # past-day path uses) that already covers a future working day
                # is known now: show it as leave and count it, instead of a
                # blank "future" cell that reads as upcoming LOP. Planned time
                # off — including leave taken while in a previous department,
                # which is matched here by user_id, not department — is
                # visible ahead of the day this way.
                lv = next((l for l in leaves if l.get("from_date", "") <= day_str <= l.get("to_date", "")), None)
                if lv:
                    entry = {
                        "status":       "approved_leave",
                        "leave_type":   lv.get("type", "full"),
                        "leave_period": lv.get("period"),
                        "leave_reason": lv.get("reason"),
                    }
                    counts["approved_leave"] += 1
                else:
                    entry = {"status": "future"}
            days[day_str] = entry
            continue

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
        if display == "weekly_off" and holiday_names.get(day_str):
            entry["holiday_name"] = holiday_names[day_str]
        if display == "present":
            if checkin_times.get(day_str):
                entry["checkin_time"] = format_datetime_ist(checkin_times[day_str])
            if checkout_times.get(day_str):
                entry["checkout_time"] = format_datetime_ist(checkout_times[day_str])
        elif display == "approved_leave":
            # Find the specific leave covering this day (leaves is normally
            # a handful of rows, not worth indexing for a per-day loop).
            lv = next((l for l in leaves if l.get("from_date", "") <= day_str <= l.get("to_date", "")), None)
            if lv:
                entry["leave_type"]   = lv.get("type", "full")
                entry["leave_period"] = lv.get("period")
                entry["leave_reason"] = lv.get("reason")
        if day_str in corrections_by_day:
            entry["corrections"] = corrections_by_day[day_str]
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
    rows = list(holidays_col.find().sort("date", 1))
    for h in rows:
        h["_id"] = str(h["_id"])
    return jsonify(rows), 200


@bp.route("/api/admin/holidays", methods=["POST"])
@token_required
def add_holiday():
    if not _holiday_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json or {}
    date = str(data.get("date", "")).strip()
    name = str(data.get("name", "")).strip()
    if not DATE_RE.match(date):
        return jsonify({"message": "date must be in YYYY-MM-DD format"}), 400
    if not name:
        return jsonify({"message": "Holiday name is required"}), 400
    try:
        day_name = datetime.strptime(date, "%Y-%m-%d").strftime("%A")
    except ValueError:
        return jsonify({"message": "Invalid date"}), 400

    doc = {"date": date, "day": day_name, "name": name}
    try:
        res = holidays_col.insert_one(doc)
    except DuplicateKeyError:
        return jsonify({"message": "A holiday is already set on this date."}), 400
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@bp.route("/api/admin/holidays/<holiday_id>", methods=["DELETE"])
@token_required
def delete_holiday(holiday_id):
    if not _holiday_allowed(request.user, write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(holiday_id)
    except InvalidId:
        return jsonify({"message": "Invalid holiday ID"}), 400
    result = holidays_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Holiday not found"}), 404
    return jsonify({"message": "Holiday deleted."}), 200


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
