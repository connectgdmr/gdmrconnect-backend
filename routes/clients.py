"""
routes/clients.py — GDMR Connect
====================================
Clients: department-scoped client directory, a per-client "Drive" (nested
folders + files, Cloudinary-backed — same upload pattern as
routes/employees.py::upload_employee_document), and a per-client work
timeline (Daily Work Plan tasks tagged to this client, auto-pulled — never a
separate copy to fall out of sync — plus a manual "Post an Update" log for
things that aren't a formal task).

Visibility/write rules (mirrors the department-membership pattern used
throughout the app, e.g. routes/work_plans.py):
  - admin/owner, or an active "clients" grant (any access_level): see and act
    on every client, all departments — same "admin-scope" treatment every
    other delegated module gets this session (AdminDepartments.jsx etc.).
  - manager/employee: only clients whose `departments` intersects their own
    department(s) (helpers._mgr_depts() — role-agnostic despite the name).
    Same rights as each other within that scope (create/edit/delete client,
    folders, files, updates) — not read-only for employees.
  - Writing specifically requires a write-level "clients" grant (view_only
    delegates can look but not touch), or department membership.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId
import cloudinary.uploader

from database import clients_col, client_drive_col, client_updates_col, work_plans_col
from decorators import token_required
from helpers import _is_admin, _mgr_depts, _has_module_grant

bp = Blueprint("clients", __name__)

MAX_FILE_BYTES = 15 * 1024 * 1024  # 15 MB, matches employee document uploads


# ── Authorization helpers ───────────────────────────────────────────────────

def _dept_scope(user):
    """None = unrestricted (admin/owner, or any active "clients" grant —
    read or write level both get full org-wide visibility, matching every
    other delegated module's admin-scope treatment). Otherwise the list of
    departments this manager/employee belongs to, used to filter queries."""
    if _is_admin(user) or _has_module_grant(user, "clients"):
        return None
    return _mgr_depts(user)


def _can_read_client(user, client_departments):
    scope = _dept_scope(user)
    return scope is None or bool(set(scope) & set(client_departments or []))


def _can_write_client(user, client_departments):
    """Create/edit/delete this client, or add folders/files/updates to it."""
    if _is_admin(user) or _has_module_grant(user, "clients", write=True):
        return True
    return bool(set(_mgr_depts(user)) & set(client_departments or []))


def _normalize_departments(raw):
    if not isinstance(raw, list):
        raw = [raw] if raw else []
    return [str(d).strip() for d in raw if str(d).strip()]


# ── Client directory ─────────────────────────────────────────────────────────

@bp.route("/api/clients", methods=["GET"])
@token_required
def list_clients():
    scope = _dept_scope(request.user)
    query = {} if scope is None else {"departments": {"$in": scope}}
    rows = []
    for c in clients_col.find(query).sort("name", 1):
        name = c.get("name", "")
        task_count = work_plans_col.count_documents({"tasks.client": name})
        rows.append({
            "_id":         str(c["_id"]),
            "name":        name,
            "description": c.get("description", ""),
            "departments": c.get("departments", []),
            "task_count":  task_count,
            "can_write":   _can_write_client(request.user, c.get("departments", [])),
        })
    return jsonify(rows), 200


@bp.route("/api/clients/<client_id>", methods=["GET"])
@token_required
def get_client(client_id):
    try:
        obj = ObjectId(client_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    client = clients_col.find_one({"_id": obj})
    if not client:
        return jsonify({"message": "Client not found"}), 404
    if not _can_read_client(request.user, client.get("departments", [])):
        return jsonify({"message": "Unauthorized"}), 403

    name = client.get("name", "")
    return jsonify({
        "_id":         str(client["_id"]),
        "name":        name,
        "description": client.get("description", ""),
        "departments": client.get("departments", []),
        "task_count":  work_plans_col.count_documents({"tasks.client": name}),
        "can_write":   _can_write_client(request.user, client.get("departments", [])),
    }), 200


@bp.route("/api/admin/clients", methods=["POST"])
@token_required
def create_client():
    is_privileged = _is_admin(request.user) or _has_module_grant(request.user, "clients", write=True)
    own = _mgr_depts(request.user)
    if not is_privileged and not own:
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"message": "name is required"}), 400

    raw_depts = _normalize_departments(data.get("departments"))
    if is_privileged:
        departments = raw_depts
    else:
        # Manager/employee: can only tag departments they belong to;
        # default to all of their own if none were explicitly given.
        departments = [d for d in raw_depts if d in own] or own

    try:
        res = clients_col.insert_one({
            "name":        name,
            "description": str(data.get("description", "")).strip(),
            "departments": departments,
            "created_by":  str(request.user["_id"]),
            "created_at":  datetime.now(timezone.utc),
        })
    except Exception:
        return jsonify({"message": "A client with that name already exists"}), 409
    return jsonify({
        "message": "Client created", "_id": str(res.inserted_id),
        "name": name, "departments": departments,
    }), 201


@bp.route("/api/admin/clients/<client_id>", methods=["PUT"])
@token_required
def update_client(client_id):
    try:
        obj = ObjectId(client_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    client = clients_col.find_one({"_id": obj})
    if not client:
        return jsonify({"message": "Client not found"}), 404
    if not _can_write_client(request.user, client.get("departments", [])):
        return jsonify({"message": "Unauthorized"}), 403

    data   = request.json or {}
    update = {}
    if "name" in data:
        new_name = str(data["name"]).strip()
        if not new_name:
            return jsonify({"message": "name cannot be empty"}), 400
        update["name"] = new_name
    if "description" in data:
        update["description"] = str(data["description"]).strip()
    if "departments" in data:
        raw = _normalize_departments(data["departments"])
        is_privileged = _is_admin(request.user) or _has_module_grant(request.user, "clients", write=True)
        if not is_privileged:
            own = _mgr_depts(request.user)
            raw = [d for d in raw if d in own]
            if not raw:
                return jsonify({"message": "You must keep this client in at least one of your own departments."}), 400
        update["departments"] = raw
    if not update:
        return jsonify({"message": "Nothing to update"}), 400
    update["updated_at"] = datetime.now(timezone.utc)

    try:
        clients_col.update_one({"_id": obj}, {"$set": update})
    except Exception:
        return jsonify({"message": "A client with that name already exists"}), 409

    updated = clients_col.find_one({"_id": obj})
    return jsonify({
        "_id":         str(updated["_id"]),
        "name":        updated.get("name", ""),
        "description": updated.get("description", ""),
        "departments": updated.get("departments", []),
    }), 200


@bp.route("/api/admin/clients/<client_id>", methods=["DELETE"])
@token_required
def delete_client(client_id):
    try:
        obj = ObjectId(client_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    client = clients_col.find_one({"_id": obj})
    if not client:
        return jsonify({"message": "Client not found"}), 404
    if not _can_write_client(request.user, client.get("departments", [])):
        return jsonify({"message": "Unauthorized"}), 403

    # Cascade — a client's drive items and update log are only ever reached
    # through the client itself; leaving them behind would just be permanent,
    # unreachable orphan data.
    client_drive_col.delete_many({"client_id": client_id})
    client_updates_col.delete_many({"client_id": client_id})
    clients_col.delete_one({"_id": obj})
    return jsonify({"message": "Client deleted"}), 200


# ── Drive (nested folders + files) ──────────────────────────────────────────

def _load_client_or_403(client_id, write=False):
    """Shared guard for every drive/update sub-route. Returns (client, None)
    or (None, (response, status)) on failure."""
    try:
        obj = ObjectId(client_id)
    except Exception:
        return None, (jsonify({"message": "Invalid ID"}), 400)
    client = clients_col.find_one({"_id": obj})
    if not client:
        return None, (jsonify({"message": "Client not found"}), 404)
    allowed = _can_write_client(request.user, client.get("departments", [])) if write \
        else _can_read_client(request.user, client.get("departments", []))
    if not allowed:
        return None, (jsonify({"message": "Unauthorized"}), 403)
    return client, None


@bp.route("/api/clients/<client_id>/drive", methods=["GET"])
@token_required
def list_drive(client_id):
    client, err = _load_client_or_403(client_id)
    if err:
        return err

    parent_id = request.args.get("parent_id") or None

    breadcrumb, walk_id, seen = [], parent_id, set()
    while walk_id and walk_id not in seen:
        seen.add(walk_id)
        try:
            node = client_drive_col.find_one({"_id": ObjectId(walk_id), "client_id": client_id})
        except Exception:
            node = None
        if not node:
            break
        breadcrumb.insert(0, {"_id": str(node["_id"]), "name": node.get("name", "")})
        walk_id = node.get("parent_id")

    items = []
    # Folders before files (Drive convention), then alphabetical within each.
    for it in client_drive_col.find({"client_id": client_id, "parent_id": parent_id}).sort([("type", -1), ("name", 1)]):
        created_at = it.get("created_at")
        items.append({
            "_id":        str(it["_id"]),
            "type":       it.get("type"),
            "name":       it.get("name", ""),
            "url":        it.get("url"),
            "size":       it.get("size"),
            "mime_type":  it.get("mime_type"),
            "created_by": it.get("created_by"),
            "created_at": created_at.isoformat() if created_at else None,
        })
    return jsonify({"items": items, "breadcrumb": breadcrumb, "parent_id": parent_id}), 200


def _resolve_parent(client_id, parent_id):
    """None if no parent given (root); the folder doc if valid; raises via
    returning False if parent_id was given but doesn't resolve to a real folder."""
    if not parent_id:
        return None
    try:
        parent = client_drive_col.find_one({"_id": ObjectId(parent_id), "client_id": client_id, "type": "folder"})
    except Exception:
        parent = None
    return parent if parent else False


@bp.route("/api/clients/<client_id>/drive/folders", methods=["POST"])
@token_required
def create_folder(client_id):
    client, err = _load_client_or_403(client_id, write=True)
    if err:
        return err

    data = request.json or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"message": "name is required"}), 400
    parent_id = data.get("parent_id") or None
    if parent_id and _resolve_parent(client_id, parent_id) is False:
        return jsonify({"message": "Invalid parent folder"}), 400

    now = datetime.now(timezone.utc)
    res = client_drive_col.insert_one({
        "client_id": client_id, "parent_id": parent_id, "type": "folder",
        "name": name, "created_by": str(request.user["_id"]), "created_at": now,
    })
    return jsonify({"_id": str(res.inserted_id), "type": "folder", "name": name, "parent_id": parent_id}), 201


@bp.route("/api/clients/<client_id>/drive/files", methods=["POST"])
@token_required
def upload_client_file(client_id):
    client, err = _load_client_or_403(client_id, write=True)
    if err:
        return err

    file = request.files.get("file")
    if not file:
        return jsonify({"message": "file is required"}), 400
    parent_id = request.form.get("parent_id") or None
    if parent_id and _resolve_parent(client_id, parent_id) is False:
        return jsonify({"message": "Invalid parent folder"}), 400

    file.seek(0, 2)
    size = file.tell()
    if size > MAX_FILE_BYTES:
        return jsonify({"message": "File too large (max 15 MB)"}), 400
    file.seek(0)

    try:
        res = cloudinary.uploader.upload(
            file, resource_type="auto", folder=f"gdmr/client_files/{client_id}",
            use_filename=True, unique_filename=True,
        )
        url = res.get("secure_url")
    except Exception as e:
        return jsonify({"message": f"Upload failed: {str(e)}"}), 500

    now  = datetime.now(timezone.utc)
    name = (request.form.get("name") or file.filename or "Untitled").strip()
    doc = {
        "client_id": client_id, "parent_id": parent_id, "type": "file",
        "name": name, "url": url, "size": size, "mime_type": file.mimetype,
        "created_by": str(request.user["_id"]), "created_at": now,
    }
    ins = client_drive_col.insert_one(doc)
    return jsonify({
        "_id": str(ins.inserted_id), "type": "file", "name": name, "url": url,
        "size": size, "mime_type": file.mimetype, "parent_id": parent_id,
    }), 201


def _delete_drive_subtree(client_id, root_id):
    """Recursively delete a drive item — if it's a folder, every descendant
    folder/file goes with it (breadth-first collect, then one bulk delete)."""
    to_delete = [root_id]
    frontier  = [root_id]
    while frontier:
        children = list(client_drive_col.find(
            {"client_id": client_id, "parent_id": {"$in": frontier}}, {"_id": 1}
        ))
        child_ids = [str(c["_id"]) for c in children]
        if not child_ids:
            break
        to_delete.extend(child_ids)
        frontier = child_ids
    client_drive_col.delete_many({
        "client_id": client_id,
        "_id": {"$in": [ObjectId(i) for i in to_delete]},
    })
    return len(to_delete)


@bp.route("/api/clients/<client_id>/drive/<item_id>", methods=["DELETE"])
@token_required
def delete_drive_item(client_id, item_id):
    client, err = _load_client_or_403(client_id, write=True)
    if err:
        return err
    try:
        item_obj = ObjectId(item_id)
    except Exception:
        return jsonify({"message": "Invalid item ID"}), 400
    item = client_drive_col.find_one({"_id": item_obj, "client_id": client_id})
    if not item:
        return jsonify({"message": "Item not found"}), 404

    removed = _delete_drive_subtree(client_id, item_id)
    return jsonify({"message": "Deleted", "removed": removed}), 200


# ── Work timeline: auto-pulled Daily Work Plan tasks + manual updates ───────

@bp.route("/api/clients/<client_id>/updates", methods=["GET"])
@token_required
def list_updates(client_id):
    client, err = _load_client_or_403(client_id)
    if err:
        return err

    try:
        limit = min(max(int(request.args.get("limit", 50)), 1), 200)
    except (TypeError, ValueError):
        limit = 50
    name = client.get("name", "")

    manual = []
    for u in client_updates_col.find({"client_id": client_id}).sort("posted_at", -1).limit(limit):
        posted_at = u.get("posted_at")
        manual.append({
            "kind":           "manual",
            "_id":            str(u["_id"]),
            "text":           u.get("text", ""),
            "posted_by":      u.get("posted_by"),
            "posted_by_name": u.get("posted_by_name", ""),
            "at":             posted_at.isoformat() if posted_at else None,
        })

    # Auto-pulled: every Daily Work Plan task anyone has tagged with this
    # client's name — reads work_plans_col directly (routes/work_plans.py's
    # system of record), so this list can never drift out of sync with what
    # Daily Work Plan itself shows.
    pipeline = [
        {"$match": {"tasks.client": name}},
        {"$unwind": "$tasks"},
        {"$match": {"tasks.client": name}},
        {"$sort": {"date": -1}},
        {"$limit": limit},
        {"$project": {
            "_id": 0, "date": 1, "employee_name": 1, "department": 1,
            "title": "$tasks.title", "work_type": "$tasks.work_type", "status": "$tasks.status",
        }},
    ]
    auto = []
    for r in work_plans_col.aggregate(pipeline):
        # Tasks only carry a date, not a time — pin sorting to end-of-day so a
        # same-day task reliably ranks alongside/after that day's manual posts
        # (full ISO timestamps) instead of a bare "YYYY-MM-DD" string prefix
        # always sorting as "earlier" than any timestamped string on that date.
        date = r.get("date") or ""
        auto.append({
            "kind":          "task",
            "at":            f"{date}T23:59:59" if date else "",
            "date":          date,
            "employee_name": r.get("employee_name", ""),
            "department":    r.get("department", ""),
            "title":         r.get("title", ""),
            "work_type":     r.get("work_type", ""),
            "status":        r.get("status", ""),
        })

    merged = sorted(manual + auto, key=lambda x: x.get("at") or "", reverse=True)[:limit]
    return jsonify(merged), 200


@bp.route("/api/clients/<client_id>/updates", methods=["POST"])
@token_required
def post_update(client_id):
    client, err = _load_client_or_403(client_id, write=True)
    if err:
        return err

    text = str((request.json or {}).get("text", "")).strip()
    if not text:
        return jsonify({"message": "text is required"}), 400

    now = datetime.now(timezone.utc)
    doc = {
        "client_id": client_id, "text": text,
        "posted_by": str(request.user["_id"]), "posted_by_name": request.user.get("name", ""),
        "posted_at": now,
    }
    ins = client_updates_col.insert_one(doc)
    return jsonify({
        "kind": "manual", "_id": str(ins.inserted_id), "text": text,
        "posted_by": doc["posted_by"], "posted_by_name": doc["posted_by_name"], "at": now.isoformat(),
    }), 201


@bp.route("/api/clients/<client_id>/updates/<update_id>", methods=["DELETE"])
@token_required
def delete_update(client_id, update_id):
    try:
        obj = ObjectId(update_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    entry = client_updates_col.find_one({"_id": obj, "client_id": client_id})
    if not entry:
        return jsonify({"message": "Update not found"}), 404

    is_owner = entry.get("posted_by") == str(request.user["_id"])
    if not is_owner and not (_is_admin(request.user) or _has_module_grant(request.user, "clients", write=True)):
        return jsonify({"message": "Unauthorized"}), 403

    client_updates_col.delete_one({"_id": obj})
    return jsonify({"message": "Update removed"}), 200
