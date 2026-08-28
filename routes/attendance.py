"""
routes/attendance.py — GDMR Connect
======================================
Attendance: check-in photo, checkout photo, employee view, admin view.
"""
import cloudinary.uploader
from datetime import datetime, timezone, timedelta, time
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import attendance_col, leaves_col, users_col
from decorators import token_required
from helpers import utc_to_ist, format_datetime_ist, is_offboarded, _is_admin, _has_module_grant
from config import IST

bp = Blueprint("attendance", __name__)


@bp.route("/api/attendance/checkin-photo", methods=["POST"])
@token_required
def checkin_photo():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    if is_offboarded(request.user):
        return jsonify({"message": "Your employment has ended. Attendance check-in is no longer available."}), 403

    uid            = str(request.user["_id"])
    now_ist        = datetime.now(IST)
    current_time   = now_ist.time()
    employee_shift = request.user.get("shift", "morning")

    if employee_shift == "night" and now_ist.hour < 4:
        today = (now_ist - timedelta(days=1)).date()
    else:
        today = now_ist.date()
    today_str = str(today)

    if leaves_col.find_one({"user_id": uid, "status": "Approved",
                             "from_date": {"$lte": today_str}, "to_date": {"$gte": today_str}}):
        return jsonify({"message": "You have an approved leave for today. Attendance not required."}), 200

    if attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today_str}):
        return jsonify({"message": "Already checked in!"}), 400

    status_indicator = "Unknown"
    day_type         = "full"

    if employee_shift == "morning":
        TIME_1000 = time(10, 0)
        TIME_1015 = time(10, 15)
        TIME_1300 = time(13, 0)
        TIME_1400 = time(14, 0)

        if current_time < TIME_1000:
            status_indicator = "Present (On-Time)"
            day_type         = "full"
        elif TIME_1000 <= current_time < TIME_1015:
            status_indicator = "Present (Late)"
            day_type         = "full"
        elif TIME_1015 <= current_time < TIME_1300:
            return jsonify({"message": "Check-in blocked. You missed the morning window (ended 10:15 AM). Please wait until 1:00 PM for Half Day check-in."}), 400
        elif TIME_1300 <= current_time < TIME_1400:
            status_indicator = "Half Day"
            day_type         = "half-day"
        else:
            return jsonify({"message": "Check-in closed for the day. Marked as Absent (Full Day)."}), 400

    elif employee_shift == "general":
        TIME_0800 = time(8, 0)
        TIME_0900 = time(9, 0)
        TIME_0915 = time(9, 15)
        if current_time < TIME_0800 or current_time >= TIME_0915:
            return jsonify({"message": "Check-in is allowed 8:00 AM – 9:15 AM for General Shift."}), 400
        status_indicator = "Present (On-Time)" if current_time < TIME_0900 else "Present (Late)"
        day_type = "full"

    else:  # night shift
        TIME_1630 = time(16, 30)
        TIME_1900 = time(19, 0)
        TIME_2000 = time(20, 0)

        if current_time < TIME_1630:
            return jsonify({"message": "Check-in opens at 4:30 PM for Night Shift."}), 400
        elif current_time < TIME_1900:
            status_indicator = "Present (On-Time)"
        elif current_time < TIME_2000:
            status_indicator = "Present (Late)"
        else:
            return jsonify({"message": "Check-in closed for Night Shift (window ended 8:00 PM)."}), 400
        day_type = "full"

    data     = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image data received from frontend."}), 400

    location = data.get("location") or None
    print("CHECKIN LOCATION:", location)

    try:
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        photo_url     = upload_result.get("secure_url")
    except Exception as e:
        print("Cloudinary Upload Error:", e)
        return jsonify({"message": "Image upload failed. Check connection."}), 500

    attendance_col.insert_one({
        "user_id":          uid,
        "type":             "checkin",
        "date":             today_str,
        "day_type":         day_type,
        "time":             datetime.now(timezone.utc),
        "photo_url":        photo_url,
        "status_indicator": status_indicator,
        "location":         location,
    })
    return jsonify({"message": f"Checked in successfully ({status_indicator})"}), 200


@bp.route("/api/attendance/checkout-photo", methods=["POST"])
@token_required
def checkout_photo():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    if is_offboarded(request.user):
        return jsonify({"message": "Your employment has ended. Attendance check-out is no longer available."}), 403

    uid            = str(request.user["_id"])
    now_ist        = datetime.now(IST)
    current_time   = now_ist.time()
    employee_shift = request.user.get("shift", "morning")

    if employee_shift == "night" and now_ist.hour < 7:
        today = (now_ist - timedelta(days=1)).date()
    else:
        today = now_ist.date()

    checkin = attendance_col.find_one({"user_id": uid, "type": "checkin", "date": str(today)})
    if not checkin:
        return jsonify({"message": "You must Check-In first before Checking Out."}), 400

    if attendance_col.find_one({"user_id": uid, "type": "checkout", "date": str(today)}):
        return jsonify({"message": "Already checked out for today!"}), 400

    final_day_type   = checkin.get("day_type", "full")
    status_indicator = "On Time"

    if employee_shift == "morning":
        HALF_DAY_OUT_START  = time(13, 0)
        HALF_DAY_OUT_END    = time(14, 0)
        FULL_DAY_OUT_START  = time(18, 0)
        LATE_CHECKOUT_START = time(20, 0)

        checkin_dt   = utc_to_ist(checkin["time"])
        checkin_time = checkin_dt.time()

        if checkin_time < time(13, 0) and (HALF_DAY_OUT_START <= current_time <= HALF_DAY_OUT_END):
            final_day_type = "half-day"
            attendance_col.update_one({"_id": checkin["_id"]}, {"$set": {"day_type": "half-day"}})

        if current_time > LATE_CHECKOUT_START:
            status_indicator = "Late Checkout"
        elif current_time < FULL_DAY_OUT_START:
            if final_day_type == "half-day" and (HALF_DAY_OUT_START <= current_time <= HALF_DAY_OUT_END):
                status_indicator = "On Time"
            else:
                status_indicator = "Early"
        else:
            status_indicator = "On Time"

    elif employee_shift == "general":
        if current_time < time(17, 0):
            return jsonify({"message": "Check-out opens at 5:00 PM for General Shift."}), 400
        status_indicator = "Late Checkout" if current_time >= time(20, 0) else "On Time"

    else:  # night shift
        hour = now_ist.hour
        if not (hour >= 19 or hour < 7):
            return jsonify({"message": "Check-out is not allowed outside your shift hours (Night Shift: 7 PM – 7 AM)"}), 400
        status_indicator = "On Time"

    data     = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image data provided"}), 400

    location = data.get("location") or None
    print("CHECKOUT LOCATION:", location)

    try:
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        photo_url     = upload_result.get("secure_url")
    except Exception as e:
        print("Cloudinary Upload Error:", e)
        return jsonify({"message": "Image upload failed"}), 500

    attendance_col.insert_one({
        "user_id":          uid,
        "type":             "checkout",
        "date":             str(today),
        "time":             datetime.now(timezone.utc),
        "photo_url":        photo_url,
        "day_type":         final_day_type,
        "status_indicator": status_indicator,
        "location":         location,
    })
    return jsonify({"message": f"Checked out successfully ({final_day_type}, {status_indicator})"}), 200


@bp.route("/api/my/attendance", methods=["GET"])
@token_required
def my_attendance():
    uid  = str(request.user["_id"])
    rows = []
    for a in attendance_col.find({"user_id": uid}).sort("time", -1):
        a["_id"]  = str(a["_id"])
        a["time"] = format_datetime_ist(a["time"])
        rows.append(a)
    return jsonify(rows), 200


@bp.route("/api/admin/attendance", methods=["GET"])
@token_required
def admin_all_attendance():
    """Master attendance log across every employee — backs AdminAttendancePage.jsx's
    'Complete Logs' tab. Was missing entirely (frontend called this exact path,
    api.jsx's adminAttendance(), and got a 404 every time), so that tab has
    likely been silently broken since it was built.

    Offboarded employees are excluded, per the standing admin-table convention
    (see feedback_admin_table_design) — their historical logs still exist and
    remain reachable via the per-employee endpoint below if ever needed, they
    just don't clutter the day-to-day master log.
    """
    if not (_is_admin(request.user) or _has_module_grant(request.user, "attendance")):
        return jsonify({"message": "Unauthorized"}), 403

    active_by_id = {
        str(u["_id"]): u
        for u in users_col.find({}, {"name": 1, "email": 1, "resignation": 1})
        if not is_offboarded(u)
    }

    records = []
    for a in attendance_col.find({"user_id": {"$in": list(active_by_id.keys())}}).sort("time", -1):
        emp = active_by_id.get(a["user_id"])
        a["_id"]            = str(a["_id"])
        a["time"]           = format_datetime_ist(a["time"])
        a["employee_name"]  = emp.get("name")  if emp else "Unknown"
        a["employee_email"] = emp.get("email") if emp else None
        records.append(a)
    return jsonify(records), 200


@bp.route("/api/admin/attendance/<emp_id>", methods=["GET"])
@token_required
def admin_employee_attendance(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "attendance")):
        return jsonify({"message": "Unauthorized"}), 403

    emp = users_col.find_one({"_id": ObjectId(emp_id)})
    if not emp:
        return jsonify({"message": "Employee not found"}), 404

    records = []
    for a in attendance_col.find({"user_id": emp_id}).sort("time", -1):
        a["_id"]            = str(a["_id"])
        a["time"]           = format_datetime_ist(a["time"])
        a["employee_name"]  = emp.get("name")
        a["employee_email"] = emp.get("email")
        records.append(a)
    return jsonify(records), 200


@bp.route("/api/admin/reports/late-checkins", methods=["GET"])
@token_required
def late_checkins_report():
    """HR report: every late check-in for a month — status_indicator is
    stamped "Present (Late)" at check-in time itself (see checkin_photo()
    above), across all three shifts, so this is a direct query rather than
    a recomputation from raw check-in time-of-day."""
    if not (_is_admin(request.user)
            or _has_module_grant(request.user, "attendance")
            or _has_module_grant(request.user, "summary")):
        return jsonify({"message": "Unauthorized"}), 403

    month = request.args.get("month")
    if not month:
        return jsonify({"message": "month required"}), 400

    emp_map = {
        str(u["_id"]): {"name": u.get("name"), "department": u.get("department")}
        for u in users_col.find({"role": {"$in": ["employee", "manager"]}}, {"name": 1, "department": 1})
    }

    rows = []
    for rec in attendance_col.find({
        "type":             "checkin",
        "date":             {"$regex": f"^{month}"},
        "status_indicator": "Present (Late)",
    }).sort("date", 1):
        emp = emp_map.get(rec.get("user_id"), {})
        rows.append({
            "date":           rec.get("date"),
            "user_id":        rec.get("user_id"),
            "employee_name":  emp.get("name", "Unknown"),
            "department":     emp.get("department"),
            "time":           format_datetime_ist(rec["time"]) if rec.get("time") else None,
        })
    return jsonify(rows), 200
