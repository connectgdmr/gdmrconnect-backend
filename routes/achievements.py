"""
routes/achievements.py — GDMR Connect
==========================================
Employee achievements: Employee of Month/Quarter/Year, awards, hike records.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import achievements_col
from decorators import token_required
from helpers import _is_admin

bp = Blueprint("achievements", __name__)


@bp.route("/api/admin/achievements", methods=["GET"])
@token_required
def get_achievements():
    """Return all achievements, optionally filtered by employee_id."""
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    employee_id = request.args.get("employee_id", "").strip()
    query       = {"employee_id": employee_id} if employee_id else {}

    results = []
    for doc in achievements_col.find(query).sort("created_at", -1):
        doc["_id"] = str(doc["_id"])
        results.append(doc)
    return jsonify(results), 200


@bp.route("/api/admin/achievements", methods=["POST"])
@token_required
def create_achievement():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    data        = request.json or {}
    employee_id = str(data.get("employee_id", "")).strip()
    title       = str(data.get("title", "")).strip()

    if not employee_id or not title:
        return jsonify({"message": "employee_id and title are required"}), 400

    doc = {
        "employee_id":   employee_id,
        "employee_name": data.get("employee_name", ""),
        "type":          data.get("type", ""),
        "title":         title,
        "description":   data.get("description", ""),
        "month":         data.get("month", ""),
        "created_at":    datetime.now(timezone.utc),
    }
    res              = achievements_col.insert_one(doc)
    doc["_id"]       = str(res.inserted_id)
    doc["created_at"] = doc["created_at"].isoformat()
    return jsonify(doc), 201


@bp.route("/api/admin/achievements/<achievement_id>", methods=["DELETE"])
@token_required
def delete_achievement(achievement_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        obj = ObjectId(achievement_id)
    except Exception:
        return jsonify({"message": "Invalid achievement ID"}), 400

    result = achievements_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Achievement not found"}), 404
    return jsonify({"success": True}), 200
