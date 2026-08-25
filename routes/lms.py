"""
routes/lms.py — GDMR Connect
================================
Learning Management System: admin courses, manager courses, employee learning.
"""
import threading
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import (lms_courses_col, lms_progress_col,
                      access_grants_col, users_col)
from decorators import token_required
from helpers import _is_admin, _mgr_depts, _today_ist
from config import IST
from utils import send_email

bp = Blueprint("lms", __name__)


# ── Internal helpers ─────────────────────────────────────────────────────────

def _get_lms_grant(user):
    """
    Return active LMS grant for this user, or None. "modules" (a list) is
    the current field — Mongo matches "modules": "lms" against any document
    whose modules array contains "lms". "module" (a single string) is kept
    for grants created before the multi-module Grant Access picker existed.
    """
    return access_grants_col.find_one({
        "employee_id": str(user["_id"]),
        "is_active":   True,
        "$or": [{"modules": "lms"}, {"module": "lms"}],
    })


def _require_lms(user, write=False):
    """
    Check LMS access for non-admin users.
    Returns (grant, error_response) — error_response is None if access is allowed.
    """
    if _is_admin(user):
        return None, None
    grant = _get_lms_grant(user)
    if not grant:
        return None, (jsonify({"message": "Unauthorized"}), 403)
    if write and grant.get("access_level") != "view_edit":
        return None, (jsonify({"message": "Read-only LMS access — cannot modify"}), 403)
    return grant, None


def _normalize_modules(modules):
    """Ensure every lesson has a stable string _id so progress tracking works."""
    if not isinstance(modules, list):
        return []
    for m in modules:
        for l in m.get("lessons", []):
            if not l.get("_id") and not l.get("id"):
                l["_id"] = str(ObjectId())
            elif l.get("_id"):
                l["_id"] = str(l["_id"])
    return modules


def _notify_course_assigned(employee_ids, course_title, expiry_date, scheduled_at=None):
    """Fire-and-forget email to each newly-assigned employee. Looks up
    name/email itself so both the admin and manager assign endpoints can
    share this without duplicating the lookup + email copy."""
    if not employee_ids:
        return
    uid_objs = []
    for uid in employee_ids:
        try:
            uid_objs.append(ObjectId(uid))
        except Exception:
            pass
    if not uid_objs:
        return

    starts_line = ""
    if scheduled_at:
        sched = scheduled_at
        if sched.tzinfo is None:
            sched = sched.replace(tzinfo=timezone.utc)
        starts_line = f"It becomes available to you on {sched.astimezone(IST).strftime('%d %b %Y, %I:%M %p')} IST.\n"

    expiry_line = f"Please complete it before it expires on {expiry_date}.\n" if expiry_date else ""

    for u in users_col.find({"_id": {"$in": uid_objs}}, {"name": 1, "email": 1}):
        if not u.get("email"):
            continue
        subject = f"New Course Assigned: {course_title}"
        body = (
            f"Hello {u.get('name', '')},\n\n"
            f"You've been assigned a new course on GDMR Connect: \"{course_title}\".\n"
            f"{starts_line}"
            f"{expiry_line}\n"
            f"Log in to GDMR Connect to start learning.\n"
        )
        try:
            threading.Thread(target=send_email, args=(u["email"], subject, body), daemon=True).start()
        except Exception as e:
            print(f"LMS assignment email failed for {u.get('email')}: {e}")


# ── Admin endpoints ──────────────────────────────────────────────────────────

@bp.route("/api/admin/lms/courses", methods=["GET"])
@token_required
def list_courses():
    _, err = _require_lms(request.user)
    if err: return err
    rows = []
    for c in lms_courses_col.find().sort("created_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows), 200


@bp.route("/api/admin/lms/courses", methods=["POST"])
@token_required
def create_course():
    _, err = _require_lms(request.user, write=True)
    if err: return err
    data       = request.json or {}
    title      = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"message": "title is required"}), 400
    expiry_raw = data.get("expiry_date")
    doc = {
        "title":           title,
        "description":     str(data.get("description",      "")).strip(),
        "category":        str(data.get("category",         "Technical")).strip(),
        "thumbnail_url":   str(data.get("thumbnail_url",    "")).strip(),
        "content_url":     str(data.get("content_url",      "")).strip(),
        "tags":            data.get("tags", []),
        "modules":         _normalize_modules(data.get("modules", [])),
        "expiry_date":     str(expiry_raw)[:10] if expiry_raw else None,
        "course_code":     str(data.get("course_code",      "")).strip(),
        "created_by_name": str(data.get("created_by_name",  request.user.get("name", ""))).strip(),
        "created_by_role": "admin",
        "department":      str(data.get("department",        "")).strip(),
        "created_by":      str(request.user["_id"]),
        "created_at":      datetime.now(timezone.utc),
    }
    res       = lms_courses_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@bp.route("/api/admin/lms/courses/<course_id>", methods=["PUT"])
@token_required
def update_course(course_id):
    _, err = _require_lms(request.user, write=True)
    if err: return err
    try:
        obj = ObjectId(course_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data   = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}
    for k in ["title", "description", "category", "thumbnail_url", "content_url",
              "tags", "course_code", "created_by_name", "department"]:
        if k in data:
            update[k] = data[k]
    if "modules" in data:
        update["modules"] = _normalize_modules(data.get("modules", []))
    if "expiry_date" in data:
        expiry_raw = data["expiry_date"]
        update["expiry_date"] = str(expiry_raw)[:10] if expiry_raw else None
    result = lms_courses_col.update_one({"_id": obj}, {"$set": update})
    if result.matched_count == 0:
        return jsonify({"message": "Course not found"}), 404
    return jsonify({"message": "Course updated"}), 200


@bp.route("/api/admin/lms/courses/<course_id>", methods=["DELETE"])
@token_required
def delete_course(course_id):
    _, err = _require_lms(request.user, write=True)
    if err: return err
    try:
        obj = ObjectId(course_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    result = lms_courses_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Course not found"}), 404
    lms_progress_col.delete_many({"course_id": course_id})
    return jsonify({"message": "Course deleted"}), 200


@bp.route("/api/admin/lms/courses/<course_id>/assign", methods=["POST"])
@token_required
def assign_course(course_id):
    _, err = _require_lms(request.user, write=True)
    if err: return err
    try:
        course_obj = ObjectId(course_id)
    except Exception:
        return jsonify({"message": "Invalid course ID"}), 400
    course_doc = lms_courses_col.find_one({"_id": course_obj})
    if not course_doc:
        return jsonify({"message": "Course not found"}), 404

    data             = request.json or {}
    employee_ids     = list(data.get("employee_ids") or [])
    scheduled_at_raw = data.get("scheduled_at")

    scheduled_at = None
    if scheduled_at_raw:
        try:
            scheduled_at = IST.localize(
                datetime.strptime(scheduled_at_raw[:16], "%Y-%m-%dT%H:%M")
            ).astimezone(timezone.utc)
        except Exception:
            pass

    departments = list(data.get("departments") or [])
    single_dept = data.get("department")
    if single_dept and single_dept not in departments:
        departments.append(single_dept)

    if departments:
        emps = users_col.find(
            {"role": {"$in": ["employee", "manager"]}, "department": {"$in": departments}},
            {"_id": 1}
        )
        dept_emp_ids = [str(e["_id"]) for e in emps]
        employee_ids = list({*employee_ids, *dept_emp_ids})

        dept_update: dict = {"$addToSet": {"assigned_departments": {"$each": departments}}}
        if scheduled_at:
            dept_update["$set"] = {"dept_scheduled_at": scheduled_at}
        lms_courses_col.update_one({"_id": course_obj}, dept_update)

    if not employee_ids:
        return jsonify({"message": "No employees to assign"}), 400

    now = datetime.now(timezone.utc)
    assigned = skipped = 0
    newly_assigned_ids = []
    failed = []  # [uid] — any upsert that actually errored, previously swallowed silently
    for uid in employee_ids:
        try:
            result = lms_progress_col.update_one(
                {"course_id": course_id, "user_id": uid},
                {"$setOnInsert": {
                    "course_id":    course_id,
                    "user_id":      uid,
                    "status":       "Assigned",
                    "progress_pct": 0,
                    "assigned_at":  now,
                    "scheduled_at": scheduled_at,
                    "completed_at": None,
                }},
                upsert=True
            )
            if result.upserted_id:
                assigned += 1
                newly_assigned_ids.append(uid)
            else:
                skipped += 1
        except Exception:
            # Previously silent — a per-user failure here (e.g. a bad ID)
            # meant that one person just never got assigned, with the admin
            # seeing a normal-looking "assigned to N" success message and no
            # way to know someone was missing. Now surfaced in the response.
            failed.append(uid)

    _notify_course_assigned(newly_assigned_ids, course_doc.get("title", "this course"),
                             course_doc.get("expiry_date"), scheduled_at)

    msg = f"Course assigned to {assigned} employee(s)"
    if skipped:
        msg += f" ({skipped} already assigned, skipped)"
    if failed:
        msg += f" — {len(failed)} failed to assign, please retry for them"
    return jsonify({"message": msg, "assigned": assigned, "skipped": skipped}), 200


@bp.route("/api/admin/lms/progress", methods=["GET"])
@token_required
def lms_progress():
    _, err = _require_lms(request.user)
    if err: return err
    course_id = request.args.get("course_id")
    query     = {"course_id": course_id} if course_id else {}
    rows      = list(lms_progress_col.find(query))

    uids = []
    for r in rows:
        try: uids.append(ObjectId(r["user_id"]))
        except Exception: pass
    emp_map = {str(e["_id"]): e for e in users_col.find({"_id": {"$in": uids}}, {"name": 1, "department": 1})}

    cids = list({r["course_id"] for r in rows})
    course_objs = []
    for c in cids:
        try: course_objs.append(ObjectId(c))
        except Exception: pass
    course_map = {str(c["_id"]): c for c in lms_courses_col.find({"_id": {"$in": course_objs}})}

    result = []
    for r in rows:
        course = course_map.get(r.get("course_id"))
        emp    = emp_map.get(r.get("user_id"))

        completed_set = set(r.get("completed_lessons", []))
        total = done = 0
        if course:
            for m_idx, mod in enumerate(course.get("modules", [])):
                for l_idx, ls in enumerate(mod.get("lessons", [])):
                    total += 1
                    ls_id     = str(ls.get("_id", ls.get("id", "")))
                    key_byidx = f"{m_idx}_{l_idx}"
                    if (ls_id and ls_id in completed_set) or (key_byidx in completed_set):
                        done += 1
        pct = round(done / total * 100) if total else 0

        result.append({
            "_id":               str(r["_id"]),
            "employee_name":     emp.get("name")       if emp else "Unknown",
            "department":        emp.get("department")  if emp else None,
            "course_id":         r.get("course_id"),
            "course_title":      course.get("title")    if course else "Unknown",
            "total_lessons":     total,
            "completed_lessons": done,
            "percent_complete":  pct,
            "status":            r.get("status", "Assigned"),
            "last_activity":     r.get("last_activity"),
            "assigned_at":       r.get("assigned_at"),
            "completed_at":      r.get("completed_at"),
        })
    return jsonify(result), 200


# ── Manager endpoints ────────────────────────────────────────────────────────

@bp.route("/api/manager/lms/courses", methods=["GET"])
@token_required
def manager_list_courses():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403
    manager_uid = str(request.user["_id"])
    query = {"$or": [{"created_by_role": "admin"}, {"created_by": manager_uid}]}
    rows = []
    for c in lms_courses_col.find(query).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows), 200


@bp.route("/api/manager/lms/courses", methods=["POST"])
@token_required
def manager_create_course():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403
    data  = request.json or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"message": "title is required"}), 400
    expiry_raw = data.get("expiry_date")
    doc = {
        "title":           title,
        "description":     str(data.get("description",  "")).strip(),
        "category":        str(data.get("category",     "Technical")).strip(),
        "thumbnail_url":   str(data.get("thumbnail_url", "")).strip(),
        "modules":         _normalize_modules(data.get("modules", [])),
        "expiry_date":     str(expiry_raw)[:10] if expiry_raw else None,
        "course_code":     str(data.get("course_code",  "")).strip(),
        "created_by_name": str(data.get("created_by_name", request.user.get("name", ""))).strip(),
        "created_by_role": "manager",
        "department":      str(data.get("department", request.user.get("department", ""))).strip(),
        "created_by":      str(request.user["_id"]),
        "created_at":      datetime.now(timezone.utc),
    }
    res       = lms_courses_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@bp.route("/api/manager/lms/courses/<course_id>", methods=["PUT"])
@token_required
def manager_update_course(course_id):
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(course_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    course = lms_courses_col.find_one({"_id": obj})
    if not course:
        return jsonify({"message": "Course not found"}), 404
    if course.get("created_by") != str(request.user["_id"]):
        return jsonify({"message": "You can only edit courses you created"}), 403

    data   = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}
    for k in ["title", "description", "category", "thumbnail_url",
              "course_code", "created_by_name", "department"]:
        if k in data:
            update[k] = data[k]
    if "modules" in data:
        update["modules"] = _normalize_modules(data.get("modules", []))
    if "expiry_date" in data:
        expiry_raw = data["expiry_date"]
        update["expiry_date"] = str(expiry_raw)[:10] if expiry_raw else None

    lms_courses_col.update_one({"_id": obj}, {"$set": update})
    return jsonify({"message": "Course updated"}), 200


@bp.route("/api/manager/lms/courses/<course_id>", methods=["DELETE"])
@token_required
def manager_delete_course(course_id):
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(course_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    course = lms_courses_col.find_one({"_id": obj})
    if not course:
        return jsonify({"message": "Course not found"}), 404
    if course.get("created_by") != str(request.user["_id"]):
        return jsonify({"message": "You can only delete courses you created"}), 403

    lms_courses_col.delete_one({"_id": obj})
    lms_progress_col.delete_many({"course_id": course_id})
    return jsonify({"message": "Course deleted"}), 200


@bp.route("/api/manager/lms/courses/<course_id>/assign", methods=["POST"])
@token_required
def manager_assign_course(course_id):
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        course_obj = ObjectId(course_id)
    except Exception:
        return jsonify({"message": "Invalid course ID"}), 400

    course = lms_courses_col.find_one({"_id": course_obj})
    if not course:
        return jsonify({"message": "Course not found"}), 404

    manager_uid = str(request.user["_id"])
    if course.get("created_by_role") != "admin" and course.get("created_by") != manager_uid:
        return jsonify({"message": "Access denied"}), 403

    manager_depts = _mgr_depts(request.user)
    data          = request.json or {}
    employee_ids  = list(data.get("employee_ids") or [])
    if not employee_ids:
        return jsonify({"message": "employee_ids is required"}), 400

    dept_emp_ids = {
        str(e["_id"])
        for e in users_col.find({"department": {"$in": manager_depts}, "role": "employee"}, {"_id": 1})
    }
    invalid = [eid for eid in employee_ids if eid not in dept_emp_ids]
    if invalid:
        return jsonify({"message": f"Employees not in your department: {', '.join(invalid)}"}), 400

    scheduled_at_raw = data.get("scheduled_at")
    scheduled_at = None
    if scheduled_at_raw:
        try:
            scheduled_at = IST.localize(
                datetime.strptime(scheduled_at_raw[:16], "%Y-%m-%dT%H:%M")
            ).astimezone(timezone.utc)
        except Exception:
            pass

    now = datetime.now(timezone.utc)
    assigned = skipped = 0
    newly_assigned_ids = []
    for uid in employee_ids:
        try:
            result = lms_progress_col.update_one(
                {"course_id": course_id, "user_id": uid},
                {"$setOnInsert": {
                    "course_id":    course_id,
                    "user_id":      uid,
                    "status":       "Assigned",
                    "progress_pct": 0,
                    "assigned_at":  now,
                    "scheduled_at": scheduled_at,
                    "completed_at": None,
                }},
                upsert=True
            )
            if result.upserted_id:
                assigned += 1
                newly_assigned_ids.append(uid)
            else:
                skipped += 1
        except Exception:
            pass

    _notify_course_assigned(newly_assigned_ids, course.get("title", "this course"),
                             course.get("expiry_date"), scheduled_at)

    msg = f"Course assigned to {assigned} employee(s)"
    if skipped:
        msg += f" ({skipped} already assigned, skipped)"
    return jsonify({"message": msg, "assigned": assigned, "skipped": skipped}), 200


@bp.route("/api/manager/lms/progress", methods=["GET"])
@token_required
def manager_lms_progress():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403

    manager_depts = _mgr_depts(request.user)
    dept_emp_ids  = [
        str(e["_id"])
        for e in users_col.find({"department": {"$in": manager_depts}, "role": "employee"}, {"_id": 1})
    ]
    course_id = request.args.get("course_id")
    query     = {"user_id": {"$in": dept_emp_ids}}
    if course_id:
        query["course_id"] = course_id

    rows = list(lms_progress_col.find(query))

    uids = []
    for r in rows:
        try: uids.append(ObjectId(r["user_id"]))
        except Exception: pass
    emp_map = {str(e["_id"]): e for e in users_col.find({"_id": {"$in": uids}}, {"name": 1, "department": 1})}

    cids = list({r["course_id"] for r in rows})
    course_objs = []
    for c in cids:
        try: course_objs.append(ObjectId(c))
        except Exception: pass
    course_map = {str(c["_id"]): c for c in lms_courses_col.find({"_id": {"$in": course_objs}})}

    result = []
    for r in rows:
        course = course_map.get(r.get("course_id"))
        emp    = emp_map.get(r.get("user_id"))

        completed_set = set(r.get("completed_lessons", []))
        total = done = 0
        if course:
            for m_idx, mod in enumerate(course.get("modules", [])):
                for l_idx, ls in enumerate(mod.get("lessons", [])):
                    total += 1
                    ls_id     = str(ls.get("_id", ls.get("id", "")))
                    key_byidx = f"{m_idx}_{l_idx}"
                    if (ls_id and ls_id in completed_set) or (key_byidx in completed_set):
                        done += 1
        pct = round(done / total * 100) if total else 0

        result.append({
            "_id":               str(r["_id"]),
            "employee_name":     emp.get("name")      if emp else "Unknown",
            "department":        emp.get("department") if emp else None,
            "course_id":         r.get("course_id"),
            "course_title":      course.get("title")   if course else "Unknown",
            "total_lessons":     total,
            "completed_lessons": done,
            "percent_complete":  pct,
            "status":            r.get("status", "Assigned"),
            "last_activity":     r.get("last_activity"),
            "assigned_at":       r.get("assigned_at"),
            "completed_at":      r.get("completed_at"),
        })
    return jsonify(result), 200


# ── Employee endpoints ────────────────────────────────────────────────────────

@bp.route("/api/my/lms/courses", methods=["GET"])
@token_required
def my_lms_courses():
    uid       = str(request.user["_id"])
    # A manager can oversee more than one department, so their own
    # `department` field is sometimes a list rather than a single string
    # (same reason _mgr_depts() exists) — an exact-match query against the
    # raw field silently matched nothing for any such manager, which is
    # why a department-wide-assigned course never showed up for them here.
    depts     = _mgr_depts(request.user)
    now_utc   = datetime.now(timezone.utc)
    today_iso = _today_ist().isoformat()
    not_expired = {"$or": [
        {"expiry_date": None},
        {"expiry_date": {"$exists": False}},
        {"expiry_date": {"$gte": today_iso}},
    ]}

    progress_records = list(lms_progress_col.find({"user_id": uid}))

    def _is_available(sched):
        if not sched:
            return True
        if sched.tzinfo is None:
            sched = sched.replace(tzinfo=timezone.utc)
        return sched <= now_utc

    progress_records = [r for r in progress_records if _is_available(r.get("scheduled_at"))]

    assigned_course_ids = {r["course_id"] for r in progress_records}
    if depts:
        for c in lms_courses_col.find({"assigned_departments": {"$in": depts}, **not_expired}, {"_id": 1, "dept_scheduled_at": 1}):
            cid = str(c["_id"])
            if cid in assigned_course_ids:
                continue
            dept_sched = c.get("dept_scheduled_at")
            if not _is_available(dept_sched):
                continue
            progress_records.append({
                "course_id":         cid,
                "user_id":           uid,
                "status":            "Assigned",
                "progress_pct":      0,
                "completed_lessons": [],
                "assigned_at":       None,
                "scheduled_at":      dept_sched,
                "completed_at":      None,
                "last_activity":     None,
            })

    if not progress_records:
        return jsonify([]), 200

    course_ids = []
    for r in progress_records:
        try: course_ids.append(ObjectId(r["course_id"]))
        except Exception: pass

    # No not_expired filter here on purpose — this hydrates every course the
    # user already has a progress record for (direct assignment or
    # department-wide), and a course expiring after assignment shouldn't make
    # it silently vanish from "my courses" with zero explanation. not_expired
    # only gates which NEW department-wide courses get auto-discovered above.
    courses = {
        str(c["_id"]): c
        for c in lms_courses_col.find({"_id": {"$in": course_ids}})
    }

    result = []
    for prog in progress_records:
        course = courses.get(prog.get("course_id"))
        if not course:
            continue

        completed_set   = set(prog.get("completed_lessons", []))
        modules         = []
        total_lessons   = 0
        completed_count = 0

        for m_idx, mod in enumerate(course.get("modules", [])):
            lessons = []
            for l_idx, ls in enumerate(mod.get("lessons", [])):
                ls_id     = str(ls.get("_id", ls.get("id", "")))
                key_byidx = f"{m_idx}_{l_idx}"
                done      = (ls_id and ls_id in completed_set) or (key_byidx in completed_set)
                if done:
                    completed_count += 1
                total_lessons += 1
                lessons.append({
                    "_id":       ls_id,
                    "title":     ls.get("title", ""),
                    "type":      ls.get("type",  "Video"),
                    "url":       ls.get("url",   ""),
                    "content":   ls.get("content", ""),
                    "completed": done,
                })
            modules.append({"title": mod.get("title", ""), "lessons": lessons})

        pct = round(completed_count / total_lessons * 100) if total_lessons > 0 else 0

        result.append({
            "_id":               str(course["_id"]),
            "title":             course.get("title"),
            "description":       course.get("description", ""),
            "category":          course.get("category",    ""),
            "thumbnail_url":     course.get("thumbnail_url", ""),
            "content_url":       course.get("content_url",  ""),
            "tags":              course.get("tags", []),
            "modules":           modules,
            "total_lessons":     total_lessons,
            "completed_lessons": completed_count,
            "percent_complete":  pct,
            "status":            prog.get("status", "Assigned"),
            "last_activity":     prog.get("last_activity"),
            "assigned_at":       prog.get("assigned_at"),
            "scheduled_at":      prog.get("scheduled_at"),
            "completed_at":      prog.get("completed_at"),
        })

    return jsonify(result), 200


@bp.route("/api/my/lms/lessons/<lesson_id>/complete", methods=["POST"])
@token_required
def complete_lesson(lesson_id):
    uid  = str(request.user["_id"])
    data = request.json or {}

    course_id = str(data.get("course_id", "")).strip()
    course    = None

    if course_id:
        try:
            course = lms_courses_col.find_one({"_id": ObjectId(course_id)})
        except Exception:
            pass

    if not course:
        try:
            course = lms_courses_col.find_one({"modules.lessons._id": ObjectId(lesson_id)})
        except Exception:
            pass
        if not course:
            course = lms_courses_col.find_one({"modules.lessons._id": lesson_id})
        if not course:
            course = lms_courses_col.find_one({"modules.lessons.id": lesson_id})

    if not course:
        return jsonify({"message": "Lesson not found"}), 404

    course_id = str(course["_id"])
    now       = datetime.now(timezone.utc)

    module_index = data.get("module_index")
    lesson_index = data.get("lesson_index")
    lesson_key   = lesson_id if lesson_id and lesson_id != "by-index" else f"{module_index}_{lesson_index}"

    lms_progress_col.update_one(
        {"course_id": course_id, "user_id": uid},
        {"$addToSet": {"completed_lessons": lesson_key},
         "$set":      {"status": "In Progress", "last_activity": now},
         "$setOnInsert": {
             "course_id":    course_id,
             "user_id":      uid,
             "assigned_at":  now,
             "completed_at": None,
             "progress_pct": 0,
         }},
        upsert=True
    )

    prog          = lms_progress_col.find_one({"course_id": course_id, "user_id": uid})
    completed_set = set(prog.get("completed_lessons", []))
    total = done  = 0
    for m_idx, mod in enumerate(course.get("modules", [])):
        for l_idx, ls in enumerate(mod.get("lessons", [])):
            total += 1
            ls_id     = str(ls.get("_id", ls.get("id", "")))
            key_byidx = f"{m_idx}_{l_idx}"
            if (ls_id and ls_id in completed_set) or (key_byidx in completed_set):
                done += 1
    pct = round((done / total) * 100) if total > 0 else 0

    is_complete  = total > 0 and done >= total
    final_status = "Completed" if is_complete else "In Progress"
    final_update = {"progress_pct": pct, "status": final_status}
    if is_complete:
        final_update["completed_at"] = now

    lms_progress_col.update_one({"course_id": course_id, "user_id": uid}, {"$set": final_update})
    return jsonify({"message": "Lesson marked complete", "progress_pct": pct, "status": final_status}), 200
