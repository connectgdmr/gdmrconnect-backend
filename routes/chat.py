"""
routes/chat.py — GDMR Connect
================================
Team Chat: DMs, channels, messages CRUD, read, unread, heartbeat, online,
typing indicators, hide/clear for me, leave channel, delete conversation.
"""
import time as _time
import threading
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import conversations_col, messages_col, users_col
from decorators import token_required
from helpers import _is_admin

bp = Blueprint("chat", __name__)

# In-memory typing indicators: {conv_id: {user_id: monotonic_timestamp}}
# Works correctly for single-worker deployments (Railway default).
_typing_state: dict = {}
_typing_lock        = threading.Lock()


# ── Internal helpers ──────────────────────────────────────────────────────────

def _member_check(conversation_id, uid):
    """Return the conversation doc if uid is a member, else None."""
    try:
        obj = ObjectId(conversation_id)
    except Exception:
        return None
    return conversations_col.find_one({"_id": obj, "members": uid})


def _refresh_conv_preview(conv_id_str):
    """Recompute last_message/last_at from the most recent remaining message."""
    latest = messages_col.find_one(
        {"conversation_id": conv_id_str},
        sort=[("created_at", -1)]
    )
    if latest:
        update = {"last_message": latest.get("text", "")[:120], "last_at": latest.get("created_at")}
    else:
        update = {"last_message": None, "last_at": None}
    conversations_col.update_one({"_id": ObjectId(conv_id_str)}, {"$set": update})


# ── User listing ──────────────────────────────────────────────────────────────

@bp.route("/api/chat/users", methods=["GET"])
@token_required
def chat_users():
    """All staff the caller may message, excluding themselves."""
    uid  = str(request.user["_id"])
    rows = []
    for u in users_col.find(
        {"_id": {"$ne": ObjectId(uid)}},
        {"name": 1, "role": 1, "department": 1}
    ):
        dept = u.get("department") or ""
        if isinstance(dept, list):
            dept = ", ".join(d for d in dept if d)
        rows.append({
            "_id":        str(u["_id"]),
            "name":       u.get("name") or "",
            "role":       u.get("role") or "",
            "department": dept,
        })
    return jsonify({"users": rows}), 200


# ── Conversations ─────────────────────────────────────────────────────────────

@bp.route("/api/chat/conversations", methods=["GET"])
@token_required
def chat_conversations():
    """Current user's DMs + channels, sorted newest-first, with per-conversation unread count."""
    uid   = str(request.user["_id"])
    convs = list(conversations_col.find({"members": uid}).sort("last_at", -1))
    if not convs:
        return jsonify({"conversations": []}), 200

    conv_ids = [str(c["_id"]) for c in convs]

    unread_map = {
        r["_id"]: r["count"]
        for r in messages_col.aggregate([
            {"$match": {"conversation_id": {"$in": conv_ids}, "read_by": {"$nin": [uid]}}},
            {"$group": {"_id": "$conversation_id", "count": {"$sum": 1}}},
        ])
    }

    all_member_ids  = {m for c in convs for m in c.get("members", [])}
    member_name_map = {uid: request.user.get("name") or ""}
    oids = []
    for m in all_member_ids:
        if m != uid:
            try:
                oids.append(ObjectId(m))
            except Exception:
                pass
    for u in users_col.find({"_id": {"$in": oids}}, {"name": 1}):
        member_name_map[str(u["_id"])] = u.get("name") or ""

    result = []
    for c in convs:
        cid     = str(c["_id"])
        last_at = c.get("last_at")
        if isinstance(last_at, datetime):
            last_at_iso = last_at.isoformat()
        elif isinstance(last_at, str):
            last_at_iso = last_at
        else:
            last_at_iso = None
        members_out = [{"_id": m, "name": member_name_map.get(m, "")} for m in c.get("members", [])]

        peer_id_out   = None
        peer_name_out = None
        if c.get("type") == "dm":
            for m in c.get("members", []):
                if m != uid:
                    peer_id_out   = m
                    peer_name_out = member_name_map.get(m, "")
                    break

        result.append({
            "_id":          cid,
            "type":         c.get("type"),
            "name":         c.get("name"),
            "members":      members_out,
            "peer_id":      peer_id_out,
            "peer_name":    peer_name_out,
            "last_message": c.get("last_message"),
            "last_at":      last_at_iso,
            "unread":       unread_map.get(cid, 0),
        })
    return jsonify({"conversations": result}), 200


@bp.route("/api/chat/dm", methods=["POST"])
@token_required
def chat_create_dm():
    """Find-or-create the 1-to-1 DM between the caller and another user (idempotent)."""
    uid     = str(request.user["_id"])
    peer_id = str((request.json or {}).get("user_id", ""))
    if not peer_id:
        return jsonify({"message": "user_id is required"}), 400
    if peer_id == uid:
        return jsonify({"message": "Cannot DM yourself"}), 400

    try:
        peer = users_col.find_one({"_id": ObjectId(peer_id)}, {"name": 1})
    except Exception:
        peer = None
    if not peer:
        return jsonify({"message": "User not found"}), 404

    existing = conversations_col.find_one(
        {"type": "dm", "members": {"$all": [uid, peer_id], "$size": 2}},
        sort=[("created_at", 1)],
    )
    if existing:
        existing["_id"] = str(existing["_id"])
        for f in ("last_at", "created_at"):
            if isinstance(existing.get(f), datetime):
                existing[f] = existing[f].isoformat()
        return jsonify({"conversation": existing}), 200

    now = datetime.now(timezone.utc)
    doc = {
        "type":         "dm",
        "name":         None,
        "members":      [uid, peer_id],
        "created_by":   uid,
        "last_message": None,
        "last_at":      now,
        "created_at":   now,
    }
    res              = conversations_col.insert_one(doc)
    doc["_id"]       = str(res.inserted_id)
    doc["last_at"]   = now.isoformat()
    doc["created_at"] = now.isoformat()
    return jsonify({"conversation": doc}), 201


@bp.route("/api/chat/channels", methods=["POST"])
@token_required
def chat_create_channel():
    uid  = str(request.user["_id"])
    data = request.json or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"message": "name is required"}), 400

    members = list(data.get("members") or [])
    if uid not in members:
        members.append(uid)

    now = datetime.now(timezone.utc)
    doc = {
        "type":         "channel",
        "name":         name,
        "members":      members,
        "created_by":   uid,
        "last_message": None,
        "last_at":      now,
        "created_at":   now,
    }
    res               = conversations_col.insert_one(doc)
    doc["_id"]        = str(res.inserted_id)
    doc["last_at"]    = now.isoformat()
    doc["created_at"] = now.isoformat()
    return jsonify({"conversation": doc}), 201


# ── Messages ──────────────────────────────────────────────────────────────────

@bp.route("/api/chat/conversations/<conv_id>/messages", methods=["GET"])
@token_required
def chat_get_messages(conv_id):
    uid  = str(request.user["_id"])
    conv = _member_check(conv_id, uid)
    if not conv:
        return jsonify({"message": "Conversation not found or access denied"}), 404

    query: dict = {
        "conversation_id": conv_id,
        "hidden_for":      {"$nin": [uid]},
    }
    user_cleared_at = (conv.get("cleared_at") or {}).get(uid)
    if user_cleared_at:
        query["created_at"] = {"$gt": user_cleared_at}

    msgs = list(messages_col.find(query).sort("created_at", 1).limit(200))
    for m in msgs:
        m["_id"] = str(m["_id"])
        if isinstance(m.get("created_at"), datetime):
            m["created_at"] = m["created_at"].isoformat()
        if isinstance(m.get("edited_at"), datetime):
            m["edited_at"] = m["edited_at"].isoformat()
        m.pop("hidden_for", None)
    return jsonify({"messages": msgs}), 200


@bp.route("/api/chat/conversations/<conv_id>/messages", methods=["POST"])
@token_required
def chat_send_message(conv_id):
    uid  = str(request.user["_id"])
    conv = _member_check(conv_id, uid)
    if not conv:
        return jsonify({"message": "Conversation not found or access denied"}), 404

    text = str((request.json or {}).get("text", "")).strip()
    if not text:
        return jsonify({"message": "text is required"}), 400

    now = datetime.now(timezone.utc)
    msg = {
        "conversation_id": conv_id,
        "sender_id":       uid,
        "sender_name":     request.user.get("name") or "",
        "text":            text,
        "created_at":      now,
        "read_by":         [uid],
    }
    res                = messages_col.insert_one(msg)
    msg["_id"]         = str(res.inserted_id)
    msg["created_at"]  = now.isoformat()

    conversations_col.update_one(
        {"_id": conv["_id"]},
        {"$set": {"last_message": text[:120], "last_at": now}}
    )
    return jsonify(msg), 201


@bp.route("/api/chat/conversations/<conv_id>/read", methods=["POST"])
@token_required
def chat_mark_read(conv_id):
    uid = str(request.user["_id"])
    if not _member_check(conv_id, uid):
        return jsonify({"message": "Conversation not found or access denied"}), 404

    messages_col.update_many(
        {"conversation_id": conv_id, "read_by": {"$nin": [uid]}},
        {"$addToSet": {"read_by": uid}}
    )
    return jsonify({"message": "Marked as read"}), 200


@bp.route("/api/chat/conversations/<conv_id>/messages/<msg_id>", methods=["PUT"])
@token_required
def chat_edit_message(conv_id, msg_id):
    uid = str(request.user["_id"])
    if not _member_check(conv_id, uid):
        return jsonify({"message": "Conversation not found or access denied"}), 404

    try:
        msg_obj = ObjectId(msg_id)
    except Exception:
        return jsonify({"message": "Invalid message ID"}), 400

    msg = messages_col.find_one({"_id": msg_obj, "conversation_id": conv_id})
    if not msg:
        return jsonify({"message": "Message not found"}), 404
    if msg.get("sender_id") != uid:
        return jsonify({"message": "You can only edit your own messages"}), 403

    text = str((request.json or {}).get("text", "")).strip()
    if not text:
        return jsonify({"message": "text is required"}), 400

    now = datetime.now(timezone.utc)
    messages_col.update_one(
        {"_id": msg_obj},
        {"$set": {"text": text, "edited": True, "edited_at": now}}
    )
    _refresh_conv_preview(conv_id)

    updated = messages_col.find_one({"_id": msg_obj})
    updated["_id"] = str(updated["_id"])
    for f in ("created_at", "edited_at"):
        if isinstance(updated.get(f), datetime):
            updated[f] = updated[f].isoformat()
    return jsonify(updated), 200


@bp.route("/api/chat/conversations/<conv_id>/messages/<msg_id>", methods=["DELETE"])
@token_required
def chat_delete_message(conv_id, msg_id):
    uid      = str(request.user["_id"])
    is_admin = _is_admin(request.user)

    if not is_admin and not _member_check(conv_id, uid):
        return jsonify({"message": "Conversation not found or access denied"}), 404

    try:
        msg_obj = ObjectId(msg_id)
    except Exception:
        return jsonify({"message": "Invalid message ID"}), 400

    msg = messages_col.find_one({"_id": msg_obj, "conversation_id": conv_id})
    if not msg:
        return jsonify({"message": "Message not found"}), 404

    if msg.get("sender_id") != uid and not is_admin:
        return jsonify({"message": "You can only delete your own messages"}), 403

    messages_col.delete_one({"_id": msg_obj})
    _refresh_conv_preview(conv_id)
    return jsonify({"message": "deleted"}), 200


@bp.route("/api/chat/conversations/<conv_id>/messages", methods=["DELETE"])
@token_required
def chat_clear_messages(conv_id):
    uid = str(request.user["_id"])
    if not _member_check(conv_id, uid):
        return jsonify({"message": "Conversation not found or access denied"}), 404

    messages_col.delete_many({"conversation_id": conv_id})
    conversations_col.update_one(
        {"_id": ObjectId(conv_id)},
        {"$set": {"last_message": None, "last_at": None}}
    )
    return jsonify({"message": "cleared"}), 200


@bp.route("/api/chat/conversations/<conv_id>", methods=["DELETE"])
@token_required
def chat_delete_conversation(conv_id):
    uid = str(request.user["_id"])
    try:
        obj = ObjectId(conv_id)
    except Exception:
        return jsonify({"message": "Invalid conversation ID"}), 400

    conv = conversations_col.find_one({"_id": obj})
    if not conv:
        return jsonify({"message": "Conversation not found"}), 404

    is_admin   = _is_admin(request.user)
    is_creator = conv.get("created_by") == uid
    is_member  = uid in conv.get("members", [])

    if not is_member and not is_admin and not is_creator:
        return jsonify({"message": "Conversation not found"}), 404

    if conv.get("type") != "channel":
        return jsonify({"message": "Only channels can be deleted. DMs cannot be removed."}), 400

    if not is_admin and not is_creator:
        return jsonify({"message": "Only the channel creator or an admin may delete this channel"}), 403

    messages_col.delete_many({"conversation_id": conv_id})
    conversations_col.delete_one({"_id": obj})
    return jsonify({"message": "deleted"}), 200


# ── Unread count ──────────────────────────────────────────────────────────────

@bp.route("/api/chat/unread", methods=["GET"])
@token_required
def chat_unread_count():
    uid      = str(request.user["_id"])
    conv_ids = [str(c["_id"]) for c in conversations_col.find({"members": uid}, {"_id": 1})]
    if not conv_ids:
        return jsonify({"count": 0}), 200
    count = messages_col.count_documents({
        "conversation_id": {"$in": conv_ids},
        "read_by":         {"$nin": [uid]},
    })
    return jsonify({"count": count}), 200


# ── Presence ──────────────────────────────────────────────────────────────────

@bp.route("/api/chat/heartbeat", methods=["POST"])
@token_required
def chat_heartbeat():
    uid = str(request.user["_id"])
    now = datetime.now(timezone.utc)
    users_col.update_one({"_id": ObjectId(uid)}, {"$set": {"last_seen": now}})
    return jsonify({"ok": True}), 200


@bp.route("/api/chat/online", methods=["GET"])
@token_required
def chat_online():
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    online = [
        str(u["_id"])
        for u in users_col.find({"last_seen": {"$gte": cutoff}}, {"_id": 1})
    ]
    return jsonify({"online": online}), 200


# ── Typing indicators ─────────────────────────────────────────────────────────

@bp.route("/api/chat/conversations/<conv_id>/typing", methods=["POST"])
@token_required
def chat_typing_post(conv_id):
    uid = str(request.user["_id"])
    if not _member_check(conv_id, uid):
        return jsonify({"message": "Conversation not found or access denied"}), 404
    with _typing_lock:
        if conv_id not in _typing_state:
            _typing_state[conv_id] = {}
        _typing_state[conv_id][uid] = _time.monotonic()
    return jsonify({"ok": True}), 200


@bp.route("/api/chat/conversations/<conv_id>/typing", methods=["GET"])
@token_required
def chat_typing_get(conv_id):
    uid = str(request.user["_id"])
    if not _member_check(conv_id, uid):
        return jsonify({"message": "Conversation not found or access denied"}), 404

    cutoff     = _time.monotonic() - 6.0
    active_ids = []
    with _typing_lock:
        for user_id, ts in list(_typing_state.get(conv_id, {}).items()):
            if ts >= cutoff and user_id != uid:
                active_ids.append(user_id)

    typing = []
    if active_ids:
        oids = []
        for aid in active_ids:
            try:
                oids.append(ObjectId(aid))
            except Exception:
                pass
        for u in users_col.find({"_id": {"$in": oids}}, {"name": 1}):
            typing.append({"_id": str(u["_id"]), "name": u.get("name", "")})

    return jsonify({"typing": typing}), 200


# ── Per-user hide / clear ─────────────────────────────────────────────────────

@bp.route("/api/chat/conversations/<conv_id>/messages/<msg_id>/hide", methods=["POST"])
@token_required
def chat_hide_message(conv_id, msg_id):
    uid = str(request.user["_id"])
    if not _member_check(conv_id, uid):
        return jsonify({"message": "Conversation not found or access denied"}), 404

    try:
        msg_obj = ObjectId(msg_id)
    except Exception:
        return jsonify({"message": "Invalid message ID"}), 400

    result = messages_col.update_one(
        {"_id": msg_obj, "conversation_id": conv_id},
        {"$addToSet": {"hidden_for": uid}},
    )
    if result.matched_count == 0:
        return jsonify({"message": "Message not found"}), 404
    return jsonify({"ok": True}), 200


@bp.route("/api/chat/conversations/<conv_id>/clear", methods=["POST"])
@token_required
def chat_clear_for_me(conv_id):
    uid  = str(request.user["_id"])
    conv = _member_check(conv_id, uid)
    if not conv:
        return jsonify({"message": "Conversation not found or access denied"}), 404

    now = datetime.now(timezone.utc)
    conversations_col.update_one(
        {"_id": ObjectId(conv_id)},
        {"$set": {f"cleared_at.{uid}": now}},
    )
    return jsonify({"ok": True}), 200


# ── Channel membership ────────────────────────────────────────────────────────

@bp.route("/api/chat/conversations/<conv_id>/leave", methods=["POST"])
@token_required
def chat_leave_channel(conv_id):
    uid  = str(request.user["_id"])
    conv = _member_check(conv_id, uid)
    if not conv:
        return jsonify({"message": "Conversation not found or access denied"}), 404
    if conv.get("type") == "dm":
        return jsonify({"message": "You cannot leave a DM conversation"}), 400

    conversations_col.update_one(
        {"_id": ObjectId(conv_id)},
        {"$pull": {"members": uid}},
    )
    return jsonify({"ok": True}), 200
