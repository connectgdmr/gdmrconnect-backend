"""
routes/assets.py — GDMR Connect
==================================
Asset request and dual-approval workflow (employee → manager → admin).
"""
import threading
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import assets_col, users_col
from decorators import token_required
from helpers import _is_admin, _mgr_depts, _has_module_grant
from utils import send_email

bp = Blueprint("assets", __name__)


@bp.route("/api/assets/request", methods=["POST"])
@token_required
def request_asset():
    uid        = str(request.user["_id"])
    data       = request.json
    asset_name = data.get("asset_name")
    reason     = data.get("reason")

    if not asset_name or not reason:
        return jsonify({"message": "Asset name and reason are strictly required."}), 400

    asset_request = {
        "user_id":       uid,
        "employee_name": request.user.get("name"),
        "department":    request.user.get("department"),
        "asset_name":    asset_name,
        "reason":        reason,
        "manager_status": "Pending",
        "admin_status":  "Pending",
        "status":        "Pending",
        "created_at":    datetime.now(timezone.utc),
    }
    res = assets_col.insert_one(asset_request)
    return jsonify({"message": "Asset requested successfully.", "id": str(res.inserted_id)}), 201


@bp.route("/api/assets/my-requests", methods=["GET"])
@token_required
def get_my_assets():
    uid  = str(request.user["_id"])
    rows = []
    for asset in assets_col.find({"user_id": uid}).sort("created_at", -1):
        asset["_id"] = str(asset["_id"])
        rows.append(asset)
    return jsonify(rows), 200


@bp.route("/api/manager/assets", methods=["GET"])
@token_required
def manager_get_assets():
    if request.user.get("role") not in ["manager", "admin", "owner"]:
        return jsonify({"message": "Unauthorized access to team assets."}), 403

    depts = _mgr_depts(request.user)
    query = {"department": {"$in": depts}} if request.user.get("role") == "manager" else {}

    rows = []
    for asset in assets_col.find(query).sort("created_at", -1):
        asset["_id"] = str(asset["_id"])
        rows.append(asset)
    return jsonify(rows), 200


@bp.route("/api/manager/assets/<asset_id>", methods=["PUT"])
@token_required
def manager_update_asset(asset_id):
    if request.user.get("role") not in ["manager", "admin", "owner"]:
        return jsonify({"message": "Unauthorized action."}), 403

    data           = request.json
    manager_status = data.get("manager_status")
    if manager_status not in ["Approved", "Rejected"]:
        return jsonify({"message": "Invalid manager status provided."}), 400

    asset = assets_col.find_one({"_id": ObjectId(asset_id)})
    if not asset:
        return jsonify({"message": "Asset request not found in database."}), 404

    if request.user.get("role") == "manager":
        asset_dept = (asset.get("department") or "").strip().lower()
        mgr_depts  = [d.strip().lower() for d in _mgr_depts(request.user)]
        if mgr_depts and asset_dept and asset_dept not in mgr_depts:
            return jsonify({"message": "Unauthorized: asset belongs to a different department"}), 403

    update_data = {"manager_status": manager_status}
    if manager_status == "Rejected":
        update_data["status"] = "Rejected"

    assets_col.update_one({"_id": ObjectId(asset_id)}, {"$set": update_data})
    return jsonify({"message": f"Asset successfully marked as {manager_status} by Manager."}), 200


@bp.route("/api/admin/assets", methods=["GET"])
@token_required
def admin_get_assets():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assets")):
        return jsonify({"message": "Unauthorized access. Admins only."}), 403

    rows = []
    for asset in assets_col.find().sort("created_at", -1):
        asset["_id"] = str(asset["_id"])
        rows.append(asset)
    return jsonify(rows), 200


@bp.route("/api/admin/assets/<asset_id>", methods=["PUT"])
@token_required
def admin_update_asset(asset_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assets", write=True)):
        return jsonify({"message": "Unauthorized action. Admins only."}), 403

    data         = request.json
    admin_status = data.get("admin_status")
    if admin_status not in ["Approved", "Rejected"]:
        return jsonify({"message": "Invalid admin status provided."}), 400

    asset = assets_col.find_one({"_id": ObjectId(asset_id)})
    if not asset:
        return jsonify({"message": "Asset request not found in database."}), 404

    update_data = {"admin_status": admin_status}
    mgr_status  = asset.get("manager_status", "Pending")

    if admin_status == "Rejected" or mgr_status == "Rejected":
        update_data["status"] = "Rejected"
    elif admin_status == "Approved" and mgr_status == "Approved":
        update_data["status"] = "Approved"
    else:
        update_data["status"] = "Pending"

    assets_col.update_one({"_id": ObjectId(asset_id)}, {"$set": update_data})
    return jsonify({"message": f"Asset successfully marked as {admin_status} by Master Admin."}), 200


@bp.route("/api/admin/assets/<asset_id>/assign", methods=["POST"])
@token_required
def assign_asset_to_office_admin(asset_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "assets", write=True)):
        return jsonify({"message": "Unauthorized"}), 403

    data   = request.json or {}
    emails = data.get("emails", [])
    asset  = data.get("asset", {})

    if not emails:
        return jsonify({"message": "At least one recipient email is required."}), 400

    subject = f"Asset Request Approved — {asset.get('asset_name', 'Asset')}"
    body = (
        f"Dear Office Admin,\n\n"
        f"An asset request has been approved and requires your processing.\n\n"
        f"Employee  : {asset.get('employee_name', '—')}\n"
        f"Department: {asset.get('department', '—')}\n"
        f"Asset     : {asset.get('asset_name', '—')}\n"
        f"Reason    : {asset.get('reason', '—')}\n\n"
        f"Please proceed with the procurement or allocation of the above asset.\n\n"
        f"Regards,\nGDMR Connect HRMS"
    )
    for email in emails:
        threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()
    return jsonify({"message": "Assignment emails sent successfully."}), 200


@bp.route("/api/manager/assets/<asset_id>/assign", methods=["POST"])
@token_required
def manager_assign_asset(asset_id):
    role = request.user.get("role")
    if role not in ("admin", "owner", "manager"):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        obj = ObjectId(asset_id)
    except Exception:
        return jsonify({"message": "Invalid asset ID"}), 400

    data   = request.json or {}
    emails = data.get("emails") or []
    if not emails:
        return jsonify({"message": "At least one recipient email is required"}), 400

    asset = assets_col.find_one({"_id": obj})
    if not asset:
        return jsonify({"message": "Asset not found"}), 404

    if role == "manager":
        mgr_depts  = [d.strip().lower() for d in _mgr_depts(request.user)]
        asset_dept = (asset.get("department") or "").strip().lower()
        if mgr_depts and asset_dept and asset_dept not in mgr_depts:
            return jsonify({"message": "You can only assign assets for your own department"}), 403

    subject = f"Asset Request Approved — {asset.get('asset_name', 'Asset')}"
    body = (
        f"Dear Office Admin,\n\n"
        f"An asset request has been approved and requires your processing.\n\n"
        f"Employee  : {asset.get('employee_name', '—')}\n"
        f"Department: {asset.get('department', '—')}\n"
        f"Asset     : {asset.get('asset_name', '—')}\n"
        f"Reason    : {asset.get('reason', '—')}\n\n"
        f"Please proceed with the procurement or allocation of the above asset.\n\n"
        f"Regards,\nGDMR Connect HRMS"
    )
    for email in emails:
        threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()

    assets_col.update_one(
        {"_id": obj},
        {"$set": {
            "assigned_at":        datetime.now(timezone.utc),
            "assigned_by":        str(request.user["_id"]),
            "assigned_to_emails": emails,
        }}
    )
    return jsonify({"message": "Assignment emails sent successfully."}), 200
