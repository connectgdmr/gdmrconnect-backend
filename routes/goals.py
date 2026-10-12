"""
routes/goals.py — GDMR Connect
================================
Sticky-note goals (daily / weekly) with an optional start date and a deadline.

Ownership model:
  * The creator owns a goal: only they can edit, reshare or delete it.
  * `shared_with` lists colleagues it is shared with. They see it on their own
    My Goals tab (read-only) and can mark it Done for themselves — their
    completion is tracked per person in `done_by`, so it never flips the
    owner's own state.

A goal that is not done (for the viewer), has started, and is due within 3
days (or already overdue) is returned by /api/my/goals/reminders, which the
dashboards show as a banner at login.
"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from config import IST
from database import goals_col, users_col
from decorators import token_required
from helpers import is_offboarded

bp = Blueprint("goals", __name__)

GOAL_TYPES    = ("daily", "weekly")
GOAL_COLORS   = ("yellow", "pink", "blue", "green", "orange")
REMIND_DAYS   = 3      # start reminding this many days before the deadline
MAX_OPEN      = 100    # per user, so a runaway client can't fill the collection
MAX_SHARED    = 30     # people one note can be shared with


def _today():
    return datetime.now(timezone.utc).astimezone(IST).date()


def _parse_date(raw):
    try:
        return datetime.strptime(str(raw or "").strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def _uid():
    return str(request.user["_id"])


def _names(user_ids):
    """{id: name} for a set of user-id strings (silently skips malformed ids)."""
    oids = []
    for i in set(user_ids):
        try:
            oids.append(ObjectId(i))
        except Exception:
            pass
    if not oids:
        return {}
    return {str(u["_id"]): u.get("name") or "" for u in users_col.find({"_id": {"$in": oids}}, {"name": 1})}


def _serialize(g, viewer, names):
    deadline  = _parse_date(g.get("deadline"))
    start     = _parse_date(g.get("start_date"))
    today     = _today()
    is_owner  = g.get("user_id") == viewer
    done      = bool(g.get("done")) if is_owner else viewer in (g.get("done_by") or [])
    done_at   = g.get("done_at")
    shared    = g.get("shared_with") or []
    return {
        "_id":        str(g["_id"]),
        "title":      g.get("title", ""),
        "notes":      g.get("notes", ""),
        "type":       g.get("type", "daily"),
        "color":      g.get("color", "yellow"),
        "start_date": g.get("start_date"),
        "deadline":   g.get("deadline"),
        "done":       done,
        "done_at":    done_at.isoformat() if (is_owner and isinstance(done_at, datetime)) else None,
        "days_left":  (deadline - today).days if deadline else None,
        "starts_in":  (start - today).days if start and start > today else 0,
        "is_owner":   is_owner,
        "owner_id":   g.get("user_id"),
        "owner_name": names.get(g.get("user_id"), ""),
        "shared_with": [{"_id": s, "name": names.get(s, "")} for s in shared] if is_owner else [],
        "shared_count": len(shared),
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
    if "start_date" in data:
        raw = data.get("start_date")
        if raw in (None, ""):
            out["start_date"] = None
        else:
            s = _parse_date(raw)
            if not s:
                return None, "Start date is not valid."
            out["start_date"] = s.isoformat()
    if "shared_with" in data:
        ids, seen = [], set()
        for i in (data.get("shared_with") if isinstance(data.get("shared_with"), list) else []):
            i = str(i)
            if i and i != _uid() and i not in seen:
                seen.add(i); ids.append(i)
        if len(ids) > MAX_SHARED:
            return None, f"You can share a note with up to {MAX_SHARED} people."
        known = set(_names(ids))
        out["shared_with"] = [i for i in ids if i in known]   # drop ids that aren't real users
    return out, None


def _check_dates(start, deadline):
    if start and deadline and start > deadline:
        return "The start date can't be after the deadline."
    return None


def _visible_goal(goal_id):
    """A goal the caller owns or that is shared with them."""
    try:
        oid = ObjectId(goal_id)
    except Exception:
        return None
    g = goals_col.find_one({"_id": oid})
    if g and (g.get("user_id") == _uid() or _uid() in (g.get("shared_with") or [])):
        return g
    return None


def _all_names(goals):
    ids = set()
    for g in goals:
        ids.add(g.get("user_id"))
        ids.update(g.get("shared_with") or [])
    return _names(i for i in ids if i)


# ── People picker ────────────────────────────────────────────────────────────

@bp.route("/api/my/goals/people", methods=["GET"])
@token_required
def goal_people():
    """Colleagues a note can be shared with — id, name, department only."""
    rows = []
    for u in users_col.find({"_id": {"$ne": request.user["_id"]}}, {"name": 1, "department": 1, "resignation": 1, "role": 1}):
        try:
            if is_offboarded(u) or not u.get("name"):
                continue
            dept = u.get("department") or ""
            if isinstance(dept, list):
                dept = ", ".join(d for d in dept if d)
            rows.append({"_id": str(u["_id"]), "name": u["name"], "department": dept})
        except Exception:
            continue
    rows.sort(key=lambda r: r["name"].lower())
    return jsonify(rows), 200


# ── CRUD ─────────────────────────────────────────────────────────────────────

@bp.route("/api/my/goals", methods=["GET"])
@token_required
def list_goals():
    uid    = _uid()
    mine   = list(goals_col.find({"user_id": uid}))
    shared = list(goals_col.find({"shared_with": uid}))
    names  = _all_names(mine + shared)

    open_rows = [_serialize(g, uid, names) for g in mine if not g.get("done")]
    shared_rows = [_serialize(g, uid, names) for g in shared]
    open_rows.sort(key=lambda g: (g["deadline"] is None, g["deadline"] or ""))

    # Recently completed stay visible for a week so "done" feels reversible.
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)

    def recent(g):
        d = g.get("done_at")
        if isinstance(d, datetime):
            return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)) >= cutoff
        return False

    done_rows = [_serialize(g, uid, names) for g in mine if g.get("done") and recent(g)]
    done_rows.sort(key=lambda g: g["done_at"] or "", reverse=True)

    return jsonify({
        "open":   open_rows,
        "done":   done_rows[:50],
        "shared": sorted([s for s in shared_rows if not s["done"]], key=lambda g: g["deadline"] or ""),
        "shared_done": [s for s in shared_rows if s["done"]][:50],
    }), 200


@bp.route("/api/my/goals", methods=["POST"])
@token_required
def create_goal():
    uid  = _uid()
    data = request.get_json(silent=True) or {}
    fields, err = _clean(data)
    if err:
        return jsonify({"message": err}), 400
    err = _check_dates(fields.get("start_date"), fields.get("deadline"))
    if err:
        return jsonify({"message": err}), 400
    if goals_col.count_documents({"user_id": uid, "done": {"$ne": True}}) >= MAX_OPEN:
        return jsonify({"message": f"You have {MAX_OPEN} open goals — finish or delete some first."}), 400
    doc = {"user_id": uid, "done": False, "done_by": [], "shared_with": [], "color": "yellow", "notes": "",
           "start_date": None, "created_at": datetime.now(timezone.utc), **fields}
    doc["_id"] = goals_col.insert_one(doc).inserted_id
    return jsonify(_serialize(doc, uid, _all_names([doc]))), 201


@bp.route("/api/my/goals/<goal_id>", methods=["PUT"])
@token_required
def update_goal(goal_id):
    uid  = _uid()
    goal = _visible_goal(goal_id)
    if not goal:
        return jsonify({"message": "Goal not found."}), 404
    data = request.get_json(silent=True) or {}
    now  = datetime.now(timezone.utc)

    if goal.get("user_id") != uid:
        # A colleague the note is shared with: they can only tick it off for themselves.
        if set(data) - {"done"} or "done" not in data:
            return jsonify({"message": "Only the person who created this note can change it."}), 403
        done_by = [i for i in (goal.get("done_by") or []) if i != uid]
        if data["done"]:
            done_by.append(uid)
        goals_col.update_one({"_id": goal["_id"]}, {"$set": {"done_by": done_by, "updated_at": now}})
        return jsonify(_serialize({**goal, "done_by": done_by}, uid, _all_names([goal]))), 200

    fields, err = _clean(data, partial=True)
    if err:
        return jsonify({"message": err}), 400
    err = _check_dates(fields.get("start_date", goal.get("start_date")), fields.get("deadline", goal.get("deadline")))
    if err:
        return jsonify({"message": err}), 400
    if "done" in data:
        fields["done"]    = bool(data["done"])
        fields["done_at"] = now if fields["done"] else None
    if not fields:
        return jsonify({"message": "Nothing to update."}), 400
    fields["updated_at"] = now
    goals_col.update_one({"_id": goal["_id"]}, {"$set": fields})
    merged = {**goal, **fields}
    return jsonify(_serialize(merged, uid, _all_names([merged]))), 200


@bp.route("/api/my/goals/<goal_id>", methods=["DELETE"])
@token_required
def delete_goal(goal_id):
    goal = _visible_goal(goal_id)
    if not goal:
        return jsonify({"message": "Goal not found."}), 404
    if goal.get("user_id") != _uid():
        return jsonify({"message": "Only the person who created this note can delete it."}), 403
    goals_col.delete_one({"_id": goal["_id"]})
    return jsonify({"message": "Deleted."}), 200


@bp.route("/api/my/goals/reminders", methods=["GET"])
@token_required
def goal_reminders():
    """Started, not-done goals (own or shared with me) due within REMIND_DAYS or overdue — most urgent first."""
    uid   = _uid()
    today = _today().isoformat()
    limit = (_today() + timedelta(days=REMIND_DAYS)).isoformat()
    # deadlines/start dates are ISO date strings, so string comparison is date comparison
    cands = list(goals_col.find({"user_id": uid, "done": {"$ne": True}, "deadline": {"$lte": limit}})) + \
            list(goals_col.find({"shared_with": uid, "deadline": {"$lte": limit}}))
    live  = [g for g in cands
             if not (g.get("start_date") and g["start_date"] > today)          # hasn't started yet
             and not (g.get("user_id") != uid and uid in (g.get("done_by") or []))]
    names = _all_names(live)
    rows  = [_serialize(g, uid, names) for g in live]
    rows.sort(key=lambda g: g["deadline"] or "")
    return jsonify(rows), 200
