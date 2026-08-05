"""
routes/clients.py — GDMR Connect
====================================
Client list CRUD. All authenticated roles can read; admin/owner/manager can create/delete.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import clients_col, work_plans_col
from decorators import token_required

bp = Blueprint("clients", __name__)


@bp.route("/api/clients", methods=["GET"])
@token_required
def list_clients():
    """All authenticated roles can read the client list."""
    rows = []
    for c in clients_col.find().sort("name", 1):
        task_count = work_plans_col.count_documents({"tasks.client": c.get("name")})
        rows.append({
            "_id":         str(c["_id"]),
            "name":        c.get("name", ""),
            "description": c.get("description", ""),
            "task_count":  task_count,
        })
    return jsonify(rows), 200


@bp.route("/api/admin/clients", methods=["POST"])
@token_required
def create_client():
    role = request.user.get("role")
    if role not in ("admin", "owner", "manager"):
        return jsonify({"message": "Unauthorized"}), 403
    data = request.json or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"message": "name is required"}), 400
    try:
        res = clients_col.insert_one({
            "name":        name,
            "description": str(data.get("description", "")).strip(),
            "created_by":  str(request.user["_id"]),
            "created_at":  datetime.now(timezone.utc),
        })
    except Exception:
        return jsonify({"message": "A client with that name already exists"}), 409
    return jsonify({"message": "Client created", "_id": str(res.inserted_id), "name": name}), 201


@bp.route("/api/admin/clients/<client_id>", methods=["DELETE"])
@token_required
def delete_client(client_id):
    role = request.user.get("role")
    if role not in ("admin", "owner", "manager"):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(client_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    result = clients_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Client not found"}), 404
    return jsonify({"message": "Client deleted"}), 200
