"""
routes/announcements.py — GDMR Connect
=========================================
Announcements CRUD, attendance corrections, user profile.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import (announcements_col, corrections_col, attendance_col,
                      users_col)
from decorators import token_required
from helpers import _is_admin, is_offboarded, _has_module_grant
from config import IST

bp = Blueprint("announcements", __name__)


# =============================================================================
# ANNOUNCEMENTS
# =============================================================================

@bp.route("/api/announcements", methods=["POST"])
@token_required
def create_announcement():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "announcements", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    announcements_col.insert_one({
        "title":      data.get("title"),
        "message":    data.get("message"),
        "created_at": datetime.now(timezone.utc),
    })
    return jsonify({"message": "Announcement broadcasted"}), 201


@bp.route("/api/announcements", methods=["GET"])
@token_required
def get_announcements():
    rows = []
    for a in announcements_col.find().sort("created_at", -1):
        a["_id"] = str(a["_id"])
        rows.append(a)
    return jsonify(rows), 200


@bp.route("/api/announcements/<ann_id>", methods=["PUT"])
@token_required
def update_announcement(ann_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "announcements", write=True)):
        return jsonify({"message": "Unauthorized access. Admins only."}), 403
    data    = request.json
    title   = data.get("title")
    message = data.get("message")
    if not title or not message:
        return jsonify({"message": "Title and message are required fields."}), 400

    result = announcements_col.update_one(
        {"_id": ObjectId(ann_id)},
        {"$set": {"title": title, "message": message, "updated_at": datetime.now(timezone.utc)}}
    )
    if result.matched_count == 0:
        return jsonify({"message": "Announcement not found in the database."}), 404
    return jsonify({"message": "Announcement successfully updated."}), 200


@bp.route("/api/announcements/<ann_id>", methods=["DELETE"])
@token_required
def delete_announcement(ann_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "announcements", write=True)):
        return jsonify({"message": "Unauthorized access. Admins only."}), 403
    result = announcements_col.delete_one({"_id": ObjectId(ann_id)})
    if result.deleted_count == 0:
        return jsonify({"message": "Announcement not found or already deleted."}), 404
    return jsonify({"message": "Announcement recalled and deleted successfully."}), 200


# =============================================================================
# ATTENDANCE CORRECTIONS
# =============================================================================

@bp.route("/api/attendance/request-correction", methods=["POST"])
@token_required
def request_correction():
    uid       = str(request.user["_id"])
    now_ist   = datetime.now(IST)
    month_str = now_ist.strftime("%Y-%m")

    usage_count = corrections_col.count_documents({"user_id": uid, "month": month_str})
    if usage_count >= 3:
        return jsonify({"message": "Monthly limit of 3 corrections reached"}), 400

    data          = request.json or {}
    employee_name = str(data.get("employee_name") or request.user.get("name") or "").strip() or None

    submitted_by_role = request.user.get("role", "employee")
    approval_target   = "admin" if submitted_by_role in ("manager", "admin", "owner") else "manager"

    correction = {
        "user_id":           uid,
        "employee_name":     employee_name,
        "manager_id":        request.user.get("manager_id"),
        "attendance_id":     data.get("attendance_id"),
        "new_time":          data.get("new_time"),
        "reason":            data.get("reason"),
        "status":            "Pending",
        "month":             month_str,
        "submitted_by_role": submitted_by_role,
        "approval_target":   approval_target,
        "created_at":        datetime.now(timezone.utc),
    }
    corrections_col.insert_one(correction)
    return jsonify({"message": "Correction request dispatched"}), 201


@bp.route("/api/manager/corrections", methods=["GET"])
@token_required
def manager_corrections():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403

    mgr_id           = str(request.user["_id"])
    managed_emp_list = list(users_col.find({"manager_id": mgr_id}, {"name": 1}))
    managed_users    = [str(u["_id"]) for u in managed_emp_list]
    emp_map          = {str(u["_id"]): u["name"] for u in managed_emp_list}

    query = {
        "user_id":         {"$in": managed_users},
        "approval_target": {"$ne": "admin"},
    }
    rows = []
    for c in corrections_col.find(query).sort("created_at", -1):
        c["_id"]           = str(c["_id"])
        uid                = c.get("user_id")
        c["employee_name"] = emp_map.get(uid) or c.get("employee_name") or "Unknown"
        c["user_id"]       = uid
        rows.append(c)
    return jsonify(rows), 200


@bp.route("/api/my/corrections", methods=["GET"])
@token_required
def my_corrections():
    uid  = str(request.user["_id"])
    rows = []
    for c in corrections_col.find({"user_id": uid}).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows), 200


@bp.route("/api/manager/approve-correction", methods=["POST"])
@token_required
def approve_correction():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403

    data   = request.json
    cid    = data.get("id")
    action = data.get("action")
    if action not in ("Approved", "Rejected"):
        return jsonify({"message": "action must be 'Approved' or 'Rejected'"}), 400

    correction = corrections_col.find_one({"_id": ObjectId(cid)})
    if not correction:
        return jsonify({"message": "Not found"}), 404

    corr_owner = users_col.find_one({"_id": ObjectId(correction["user_id"])}, {"manager_id": 1})
    if not corr_owner or str(corr_owner.get("manager_id")) != str(request.user["_id"]):
        return jsonify({"message": "Unauthorized: employee is not in your team"}), 403

    corrections_col.update_one({"_id": ObjectId(cid)}, {"$set": {"status": action}})

    if action == "Approved":
        try:
            new_time_str = correction["new_time"]
            if "T" in new_time_str and not new_time_str.endswith("Z") and "+" not in new_time_str:
                new_dt = datetime.fromisoformat(new_time_str)
            else:
                new_dt = datetime.fromisoformat(new_time_str.replace("Z", "+00:00"))

            original_record = (
                attendance_col.find_one({"_id": ObjectId(correction["attendance_id"])})
                if correction.get("attendance_id") else None
            )
            record_type = original_record.get("type", "checkin") if original_record else "checkin"

            attendance_col.insert_one({
                "user_id":          correction["user_id"],
                "type":             record_type,
                "date":             str(new_dt.date()),
                "time":             new_dt,
                "photo_url":        None,
                "status_indicator": "Corrected",
                "correction_ref":   cid,
            })
        except Exception as e:
            print("Error updating attendance log:", e)

    return jsonify({"message": f"Correction {action}"}), 200


@bp.route("/api/admin/corrections", methods=["GET"])
@token_required
def admin_corrections():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    rows = []
    for c in corrections_col.find({"approval_target": "admin"}).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        uid = c.get("user_id")
        try:
            emp = users_col.find_one({"_id": ObjectId(uid)}, {"name": 1}) if uid else None
        except Exception:
            emp = None
        c["employee_name"] = (emp.get("name") if emp else None) or c.get("employee_name") or "Unknown"
        c["user_id"] = uid
        rows.append(c)
    return jsonify(rows), 200


@bp.route("/api/admin/approve-correction", methods=["POST"])
@token_required
def admin_approve_correction():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    data   = request.json or {}
    cid    = data.get("id")
    action = data.get("action")
    if not cid or not action:
        return jsonify({"message": "id and action are required"}), 400

    try:
        correction = corrections_col.find_one({"_id": ObjectId(cid)})
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    if not correction:
        return jsonify({"message": "Not found"}), 404

    corrections_col.update_one({"_id": ObjectId(cid)}, {"$set": {"status": action}})

    if action == "Approved":
        try:
            new_time_str = correction["new_time"]
            if "T" in new_time_str and not new_time_str.endswith("Z") and "+" not in new_time_str:
                new_dt = datetime.fromisoformat(new_time_str)
            else:
                new_dt = datetime.fromisoformat(new_time_str.replace("Z", "+00:00"))

            original_record = (
                attendance_col.find_one({"_id": ObjectId(correction["attendance_id"])})
                if correction.get("attendance_id") else None
            )
            record_type = original_record.get("type", "checkin") if original_record else "checkin"

            attendance_col.insert_one({
                "user_id":          correction["user_id"],
                "type":             record_type,
                "date":             str(new_dt.date()),
                "time":             new_dt,
                "photo_url":        None,
                "status_indicator": "Corrected",
                "correction_ref":   cid,
            })
        except Exception as e:
            print("Error updating attendance log:", e)

    return jsonify({"message": f"Correction {action}"}), 200


@bp.route("/api/admin/reports/corrections", methods=["GET"])
@token_required
def corrections_report():
    """HR report: EVERY correction request for a month, regardless of
    approval_target — unlike /api/admin/corrections (an approval queue that
    deliberately only shows requests routed to admin), this is a superset
    covering both manager-approved and admin-approved requests, with each
    employee's department resolved for the HR Reports filter/export."""
    if not (_is_admin(request.user) or _has_module_grant(request.user, "attendance")):
        return jsonify({"message": "Unauthorized"}), 403

    month = request.args.get("month")
    if not month:
        return jsonify({"message": "month required"}), 400

    rows = []
    for c in corrections_col.find({"month": month}).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        uid = c.get("user_id")
        emp = None
        try:
            emp = users_col.find_one({"_id": ObjectId(uid)}, {"name": 1, "department": 1}) if uid else None
        except Exception:
            pass
        c["employee_name"] = (emp.get("name") if emp else None) or c.get("employee_name") or "Unknown"
        c["department"]    = emp.get("department") if emp else None
        c["user_id"]       = uid
        rows.append(c)
    return jsonify(rows), 200


# =============================================================================
# USER PROFILE
# =============================================================================

@bp.route("/api/my/profile", methods=["GET"])
@token_required
def get_my_profile():
    user     = request.user
    birthday = user.get("birthday")
    return jsonify({
        "birthday":   birthday.strftime("%Y-%m-%d") if isinstance(birthday, datetime) else birthday,
        "phone":      user.get("phone"),
        "bio":        user.get("bio"),
        "offboarded": is_offboarded(user),
    }), 200


@bp.route("/api/my/profile", methods=["PUT"])
@token_required
def update_my_profile():
    data   = request.json or {}
    update = {}

    if "birthday" in data:
        raw = data["birthday"]
        if raw:
            try:
                update["birthday"] = datetime.strptime(str(raw)[:10], "%Y-%m-%d")
            except ValueError:
                return jsonify({"message": "Invalid birthday format. Use YYYY-MM-DD."}), 400
        else:
            update["birthday"] = None

    if "phone" in data:
        update["phone"] = str(data["phone"]).strip() if data["phone"] else None

    if "bio" in data:
        update["bio"] = str(data["bio"]).strip() if data["bio"] else None

    if update:
        users_col.update_one({"_id": request.user["_id"]}, {"$set": update})
    return jsonify({"success": True}), 200
