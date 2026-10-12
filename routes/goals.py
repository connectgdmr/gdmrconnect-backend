"""
routes/goals.py — GDMR Connect
================================
Personal sticky-note goals (daily / weekly) with a deadline. Each user only
ever sees and edits their own. A goal that is not done and due within 3 days
(or already overdue) is returned by /api/my/goals/reminders, which the
dashboards show as a banner at login.
"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from config import IST
from database import goals_col
from decorators import token_required

bp = Blueprint("goals", __name__)

GOAL_TYPES    = ("daily", "weekly")
GOAL_COLORS   = ("yellow", "pink", "blue", "green", "orange")
REMIND_DAYS   = 3      # start reminding this many days before the deadline
MAX_OPEN      = 100    # per user, so a runaway client can't fill the collection


def _today():
    return datetime.now(timezone.utc).astimezone(IST).date()


def _parse_date(raw):
    try:
        return datetime.strptime(str(raw or "").strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def _serialize(g):
    deadline  = _parse_date(g.get("deadline"))
    days_left = (deadline - _today()).days if deadline else None
    done_at   = g.get("done_at")
    return {
        "_id":       str(g["_id"]),
        "title":     g.get("title", ""),
        "notes":     g.get("notes", ""),
        "type":      g.get("type", "daily"),
        "color":     g.get("color", "yellow"),
        "deadline":  g.get("deadline"),
        "done":      bool(g.get("done")),
        "done_at":   done_at.isoformat() if isinstance(done_at, datetime) else None,
        "days_left": days_left,
    }


def _clean(data, partial=False):
    """Validate + normalise the editable fields. Returns (fields, error)."""
    out = {}
    if not partial or "title" in data:
        title = str(data.get("title") or "").strip()
        if not title:
            return None, "Please add a title."
        out["title"] = title[:120]
    if "notes" in data:
        out["notes"] = str(data.get("notes") or "").strip()[:1000]
    if not partial or "type" in data:
        t = str(data.get("type") or "daily").strip().lower()
        if t not in GOAL_TYPES:
            return None, "type must be 'daily' or 'weekly'."
        out["type"] = t
    if "color" in data:
        c = str(data.get("color") or "yellow").strip().lower()
        out["color"] = c if c in GOAL_COLORS else "yellow"
    if not partial or "deadline" in data:
        d = _parse_date(data.get("deadline"))
        if not d:
            return None, "Please pick a deadline."
        out["deadline"] = d.isoformat()
    return out, None


@bp.route("/api/my/goals", methods=["GET"])
@token_required
def list_goals():
    uid  = str(request.user["_id"])
    rows = [_serialize(g) for g in goals_col.find({"user_id": uid, "done": {"$ne": True}})]
    # soonest deadline first, undated last
    rows.sort(key=lambda g: (g["deadline"] is None, g["deadline"] or ""))
    # Recently completed ones stay visible for a week so "done" feels reversible.
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    done   = [
        _serialize(g) for g in goals_col.find({"user_id": uid, "done": True, "done_at": {"$gte": cutoff}}).sort("done_at", -1).limit(50)
    ]
    return jsonify({"open": rows, "done": done}), 200


@bp.route("/api/my/goals", methods=["POST"])
@token_required
def create_goal():
    uid = str(request.user["_id"])
    fields, err = _clean(request.get_json(silent=True) or {})
    if err:
        return jsonify({"message": err}), 400
    if goals_col.count_documents({"user_id": uid, "done": {"$ne": True}}) >= MAX_OPEN:
        return jsonify({"message": f"You have {MAX_OPEN} open goals — finish or delete some first."}), 400
    doc = {"user_id": uid, "done": False, "color": "yellow", "notes": "", "created_at": datetime.now(timezone.utc), **fields}
    doc["_id"] = goals_col.insert_one(doc).inserted_id
    return jsonify(_serialize(doc)), 201


def _own_goal(goal_id):
    try:
        oid = ObjectId(goal_id)
    except Exception:
        return None
    return goals_col.find_one({"_id": oid, "user_id": str(request.user["_id"])})


@bp.route("/api/my/goals/<goal_id>", methods=["PUT"])
@token_required
def update_goal(goal_id):
    goal = _own_goal(goal_id)
    if not goal:
        return jsonify({"message": "Goal not found."}), 404
    data = request.get_json(silent=True) or {}
    fields, err = _clean(data, partial=True)
    if err:
        return jsonify({"message": err}), 400
    if "done" in data:
        fields["done"]    = bool(data["done"])
        fields["done_at"] = datetime.now(timezone.utc) if fields["done"] else None
    if not fields:
        return jsonify({"message": "Nothing to update."}), 400
    fields["updated_at"] = datetime.now(timezone.utc)
    goals_col.update_one({"_id": goal["_id"]}, {"$set": fields})
    return jsonify(_serialize({**goal, **fields})), 200


@bp.route("/api/my/goals/<goal_id>", methods=["DELETE"])
@token_required
def delete_goal(goal_id):
    goal = _own_goal(goal_id)
    if not goal:
        return jsonify({"message": "Goal not found."}), 404
    goals_col.delete_one({"_id": goal["_id"]})
    return jsonify({"message": "Deleted."}), 200


@bp.route("/api/my/goals/reminders", methods=["GET"])
@token_required
def goal_reminders():
    """Open goals due within REMIND_DAYS days, or already overdue — most urgent first."""
    uid    = str(request.user["_id"])
    limit  = (_today() + timedelta(days=REMIND_DAYS)).isoformat()
    # deadlines are ISO date strings, so string comparison is date comparison
    rows   = [_serialize(g) for g in goals_col.find({"user_id": uid, "done": {"$ne": True}, "deadline": {"$lte": limit}})]
    rows.sort(key=lambda g: g["deadline"] or "")
    return jsonify(rows), 200
