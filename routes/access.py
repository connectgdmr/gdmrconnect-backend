"""
routes/access.py — GDMR Connect
==================================
Delegated admin access grants (grant, list, revoke, my-delegated-access).
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import access_grants_col, users_col
from decorators import token_required
from helpers import _is_admin, utc_to_ist
from config import IST

bp = Blueprint("access", __name__)


@bp.route("/api/admin/grant-access", methods=["POST"])
@token_required
def grant_access():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    data               = request.json
    emp_id             = data.get("employeeId")
    access_level       = data.get("accessLevel", "view_only")
    scope              = data.get("scope", "today")
    custom_date        = data.get("customDate", "")
    expiry             = data.get("expiry", "end_of_day")
    custom_expiry_time = data.get("customExpiryTime", "")

    if not emp_id:
        return jsonify({"message": "Employee ID is required"}), 400

    emp = users_col.find_one({"_id": ObjectId(emp_id)})
    if not emp or _is_admin(emp):
        return jsonify({"message": "Invalid employee or employee is already an admin."}), 400

    module = data.get("module", "attendance")
    if module not in ("attendance", "lms"):
        module = "attendance"

    grant_record = {
        "employee_id":       emp_id,
        "module":            module,
        "access_level":      access_level,
        "scope":             scope,
        "custom_date":       custom_date,
        "expiry":            expiry,
        "custom_expiry_time": custom_expiry_time,
        "granted_by":        str(request.user["_id"]),
        "granted_at":        datetime.now(timezone.utc),
        "is_active":         True,
    }
    res = access_grants_col.insert_one(grant_record)
    return jsonify({"message": "Temporary access granted successfully", "id": str(res.inserted_id)}), 201


@bp.route("/api/admin/active-grants", methods=["GET"])
@token_required
def get_active_grants():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    raw_grants = list(access_grants_col.find({"is_active": True}).sort("granted_at", -1))
    emp_ids    = []
    for g in raw_grants:
        try:
            emp_ids.append(ObjectId(g["employee_id"]))
        except Exception:
            pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": emp_ids}}, {"name": 1})}

    grants = []
    for g in raw_grants:
        g["_id"]           = str(g["_id"])
        g["employee_name"] = emp_map.get(g.get("employee_id"), "Unknown Employee")
        grants.append(g)

    return jsonify(grants), 200


@bp.route("/api/admin/revoke-access/<grant_id>", methods=["DELETE"])
@token_required
def revoke_access(grant_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    result = access_grants_col.update_one({"_id": ObjectId(grant_id)}, {"$set": {"is_active": False}})
    if result.modified_count > 0:
        return jsonify({"message": "Access revoked successfully"}), 200
    return jsonify({"message": "Access grant not found or already inactive."}), 404


@bp.route("/api/my/delegated-access", methods=["GET"])
@token_required
def my_delegated_access():
    uid           = str(request.user["_id"])
    now           = datetime.now(IST)
    active_grants = []

    for g in access_grants_col.find({"employee_id": uid, "is_active": True}):
        expired = False
        if g.get("expiry") == "end_of_day":
            if now.date() > utc_to_ist(g["granted_at"]).date():
                expired = True
        elif g.get("expiry") == "custom_time":
            custom_time_str = g.get("custom_expiry_time")
            if custom_time_str:
                try:
                    expiry_dt = IST.localize(datetime.strptime(custom_time_str, "%Y-%m-%dT%H:%M"))
                    if now >= expiry_dt:
                        expired = True
                except Exception as e:
                    print(f"Error parsing custom time: {e}")

        if expired:
            access_grants_col.update_one({"_id": g["_id"]}, {"$set": {"is_active": False}})
        else:
            g["_id"] = str(g["_id"])
            active_grants.append(g)

    return jsonify(active_grants), 200
