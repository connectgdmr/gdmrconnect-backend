"""
routes/notifications.py — GDMR Connect
=========================================
Notification counts (sidebar badges) and birthday alerts.
"""
from datetime import datetime
from flask import Blueprint, request, jsonify

from database import (leaves_col, pms_reviews_col, corrections_col,
                      assets_col, access_grants_col, users_col)
from decorators import token_required
from helpers import _mgr_depts
from config import IST

bp = Blueprint("notifications", __name__)


@bp.route("/api/notifications/counts", methods=["GET"])
@token_required
def get_notification_counts():
    role          = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    counts = {"leaves": 0, "pms": 0, "corrections": 0, "assets": 0, "announcements": 0}

    if role == "manager":
        mgr_id    = str(request.user["_id"])
        mgr_users = [str(u["_id"]) for u in users_col.find({"manager_id": mgr_id}, {"_id": 1})]
        mgr_depts = _mgr_depts(request.user)

        counts["leaves"] = leaves_col.count_documents({
            "user_id": {"$in": mgr_users}, "status": "Pending", "manager_status": "Pending"
        })
        counts["pms"] = pms_reviews_col.count_documents({
            "user_id": {"$in": mgr_users}, "status": "Pending Review"
        })
        counts["corrections"] = corrections_col.count_documents({
            "user_id": {"$in": mgr_users}, "status": "Pending"
        })
        counts["assets"] = assets_col.count_documents({
            "department": {"$in": mgr_depts}, "manager_status": "Pending"
        })

    elif role in ("admin", "owner") or has_delegated:
        counts["leaves"] = leaves_col.count_documents({
            "status": "Pending", "admin_status": "Pending"
        })
        counts["assets"] = assets_col.count_documents({
            "status": "Pending", "admin_status": "Pending"
        })
        # Manager/admin/owner-submitted corrections are routed to admin for
        # approval (see request_correction() in announcements.py) — same
        # "Pending" badge pattern as leaves/assets above.
        counts["corrections"] = corrections_col.count_documents({
            "approval_target": "admin", "status": "Pending"
        })

    return jsonify(counts), 200


@bp.route("/api/notifications/birthdays", methods=["GET"])
@token_required
def birthday_notifications():
    """Return users whose birthday (month + day) matches today, scoped by role."""
    try:
        today = datetime.now(IST)
        uid   = str(request.user["_id"])
        role  = request.user.get("role")
        dept  = request.user.get("department")

        base_filter = {
            "birthday": {"$type": "date"},
            "$expr": {
                "$and": [
                    {"$eq": [{"$month":      "$birthday"}, today.month]},
                    {"$eq": [{"$dayOfMonth": "$birthday"}, today.day]},
                ]
            },
        }
        if role == "employee":
            base_filter["department"] = dept
        elif role == "manager":
            base_filter["department"] = {"$in": _mgr_depts(request.user)}

        celebrants = list(users_col.find(base_filter, {"name": 1}))
        return jsonify([
            {"name": u["name"], "is_self": str(u["_id"]) == uid}
            for u in celebrants
        ]), 200

    except Exception as e:
        print(f"Birthday notification error: {e}")
        return jsonify([]), 200
