"""
routes/pms_compliance.py — GDMR Connect
===========================================
HR/Admin dashboard + controls for PMS Compliance & Department Attendance
Blocking (see pms_compliance.py for the underlying engine). Gated behind the
existing "pms" grantable module — the same permission that already covers
PMSWorkspace.jsx, since this dashboard is a new tab inside that workspace.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

import pms_compliance as pc
from database import (
    users_col, pms_compliance_col, pms_compliance_audit_col, pms_compliance_settings_col,
)
from decorators import token_required
from helpers import _has_module_grant
from config import IST

bp = Blueprint("pms_compliance", __name__)


def _authorized(write=False):
    if request.user.get("role") in ("admin", "owner"):
        return True
    return _has_module_grant(request.user, "pms", write=write)


def _serialize_record(rec):
    override = rec.get("override") or {}
    override_active = bool(override.get("active"))
    blocked = bool(rec.get("blocked")) and not override_active

    # "Completed" is technically correct here (compliance = finalize whatever
    # was submitted, and nothing has been submitted yet), but it reads as a
    # false positive next to "0 / 0" on the dashboard — no PMS form has even
    # been assigned to this manager's team for the month. Display-only
    # relabel; the stored status (used by the scheduler/auto-unblock logic)
    # is untouched.
    review_status = rec.get("status", "Pending")
    if review_status == "Completed" and rec.get("team_size", 0) > 0 \
            and rec.get("reviews_completed", 0) == 0 and rec.get("reviews_pending", 0) == 0:
        review_status = "Not Started"

    return {
        "manager_id":          rec.get("manager_id"),
        "manager":             rec.get("manager_name", ""),
        "department":          rec.get("department", ""),
        "review_month":        rec.get("month", ""),
        "team_strength":       rec.get("team_size", 0),
        "reviews_completed":   rec.get("reviews_completed", 0),
        "reviews_pending":     rec.get("reviews_pending", 0),
        "review_status":       review_status,
        "attendance_status":   "Blocked" if blocked else "Active",
        "block_date":          rec.get("blocked_at"),
        "last_reminder_sent":  rec.get("overdue_notice_sent_at") or rec.get("first_warning_sent_at"),
        "override_status":     "Yes" if override_active else "No",
        "override_reason":     override.get("reason") if override_active else None,
        "override_by":         override.get("by_name") if override_active else None,
        "deadline_override":   rec.get("deadline_override"),
    }


@bp.route("/api/admin/pms-compliance", methods=["GET"])
@token_required
def get_pms_compliance():
    if not _authorized():
        return jsonify({"message": "Unauthorized"}), 403

    month = request.args.get("month") or datetime.now(IST).strftime("%Y-%m")
    settings = pc.get_settings()

    # Make sure every currently-active manager has a row for this month, even
    # one the daily job hasn't touched yet (e.g. a manager promoted mid-month,
    # or an admin looking at a month before the feature shipped).
    for manager in pc.active_managers():
        pc.set_status(manager, month, settings)

    records = list(pms_compliance_col.find({"month": month}).sort("manager_name", 1))
    return jsonify({
        "month": month,
        "blocking_enabled": settings.get("blocking_enabled", False),
        "rows": [_serialize_record(r) for r in records],
    }), 200


@bp.route("/api/admin/pms-compliance/<manager_id>/team", methods=["GET"])
@token_required
def get_pms_compliance_team(manager_id):
    """FRD §10 — 'View the employees affected by the block' for one manager+month."""
    if not _authorized():
        return jsonify({"message": "Unauthorized"}), 403

    month = request.args.get("month") or datetime.now(IST).strftime("%Y-%m")
    try:
        manager = users_col.find_one({"_id": ObjectId(manager_id)})
    except Exception:
        return jsonify({"message": "Invalid manager ID"}), 400
    if not manager:
        return jsonify({"message": "Manager not found"}), 404

    return jsonify({
        "manager": manager.get("name", ""),
        "month": month,
        "roster": pc.team_roster(manager, month),
    }), 200


@bp.route("/api/admin/pms-compliance/settings", methods=["GET"])
@token_required
def get_pms_compliance_settings():
    if not _authorized():
        return jsonify({"message": "Unauthorized"}), 403
    settings = pc.get_settings()
    settings["_id"] = str(settings.get("_id"))
    return jsonify(settings), 200


@bp.route("/api/admin/pms-compliance/settings", methods=["PUT"])
@token_required
def update_pms_compliance_settings():
    if not _authorized(write=True):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json or {}
    fields = {}
    if "blocking_enabled" in data:
        fields["blocking_enabled"] = bool(data["blocking_enabled"])
    if "exempt_employee_ids" in data:
        fields["exempt_employee_ids"] = [str(x) for x in (data["exempt_employee_ids"] or [])]
    if "exempt_department_names" in data:
        fields["exempt_department_names"] = [str(x) for x in (data["exempt_department_names"] or [])]
    if "new_joiner_grace_days" in data:
        try:
            fields["new_joiner_grace_days"] = max(0, int(data["new_joiner_grace_days"]))
        except (TypeError, ValueError):
            return jsonify({"message": "new_joiner_grace_days must be a number"}), 400

    settings = pc.update_settings(fields, actor=request.user)
    settings["_id"] = str(settings.get("_id"))
    return jsonify(settings), 200


@bp.route("/api/admin/pms-compliance/<manager_id>/unblock", methods=["POST"])
@token_required
def unblock_pms_compliance(manager_id):
    if not _authorized(write=True):
        return jsonify({"message": "Unauthorized"}), 403

    data  = request.json or {}
    month = data.get("month") or datetime.now(IST).strftime("%Y-%m")
    try:
        manager = users_col.find_one({"_id": ObjectId(manager_id)})
    except Exception:
        return jsonify({"message": "Invalid manager ID"}), 400
    if not manager:
        return jsonify({"message": "Manager not found"}), 404

    pc.override_unblock(
        manager, month, actor=request.user,
        reason=data.get("reason"), until=data.get("until"),
    )
    return jsonify({"message": "Attendance check-in restored for this manager's team."}), 200


@bp.route("/api/admin/pms-compliance/<manager_id>/extend", methods=["POST"])
@token_required
def extend_pms_compliance_deadline(manager_id):
    if not _authorized(write=True):
        return jsonify({"message": "Unauthorized"}), 403

    data  = request.json or {}
    until = data.get("until")
    if not until:
        return jsonify({"message": "until (YYYY-MM-DD) is required"}), 400
    month = data.get("month") or datetime.now(IST).strftime("%Y-%m")
    try:
        manager = users_col.find_one({"_id": ObjectId(manager_id)})
    except Exception:
        return jsonify({"message": "Invalid manager ID"}), 400
    if not manager:
        return jsonify({"message": "Manager not found"}), 404

    pc.extend_deadline(manager, month, until, actor=request.user, reason=data.get("reason"))
    return jsonify({"message": f"Deadline extended to {until}."}), 200


@bp.route("/api/admin/pms-compliance/audit", methods=["GET"])
@token_required
def get_pms_compliance_audit():
    if not _authorized():
        return jsonify({"message": "Unauthorized"}), 403

    query = {}
    if request.args.get("manager_id"):
        query["manager_id"] = request.args["manager_id"]
    if request.args.get("month"):
        query["month"] = request.args["month"]

    limit = min(int(request.args.get("limit", 200) or 200), 500)
    entries = list(pms_compliance_audit_col.find(query).sort("at", -1).limit(limit))
    for e in entries:
        e["_id"] = str(e["_id"])
    return jsonify(entries), 200
