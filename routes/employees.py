"""
routes/employees.py — GDMR Connect
=====================================
Employee & manager directory, department management, work-types, access grants.
"""
import re
import secrets
import threading
import cloudinary.uploader
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import (
    users_col, access_grants_col, attendance_col, leaves_col,
    pms_reviews_col, corrections_col, departments_col,
)
from decorators import token_required
from extensions import bcrypt
from helpers import _is_admin, _mgr_depts, _serialize_emp_status, parse_employment_type, _has_module_grant
from utils import send_email, generate_random_password
from config import IST

bp = Blueprint("employees", __name__)


# ── Admin management ──────────────────────────────────────────────────────────

@bp.route("/api/admin/admins", methods=["GET"])
@token_required
def list_admins():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    admins = []
    for u in users_col.find({"role": "admin"}, {"name": 1, "email": 1, "created_at": 1}):
        admins.append({
            "_id":       str(u["_id"]),
            "name":      u.get("name", ""),
            "email":     u.get("email", ""),
            "createdAt": u["created_at"].isoformat() if u.get("created_at") else None,
        })
    return jsonify(admins), 200


@bp.route("/api/admin/admins/<admin_id>", methods=["DELETE"])
@token_required
def delete_admin(admin_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    if admin_id == str(request.user["_id"]):
        return jsonify({"message": "You cannot delete your own admin account"}), 403
    try:
        obj = ObjectId(admin_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    target = users_col.find_one({"_id": obj}, {"role": 1})
    if not target:
        return jsonify({"message": "Admin not found"}), 404
    if target.get("role") != "admin":
        return jsonify({"message": "User is not an admin"}), 400
    users_col.delete_one({"_id": obj})
    return jsonify({"message": "Admin account deleted"}), 200


@bp.route("/api/register-admin", methods=["POST"])
def register_admin():
    """Bootstrap + capped admin registration — max 3 admin accounts allowed."""
    admin_count = users_col.count_documents({"role": "admin"})
    if admin_count >= 3:
        return jsonify({"message": "Maximum of 3 admin accounts allowed."}), 403

    data     = request.json
    email    = data.get("email")
    name     = data.get("name", "Admin")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required."}), 400

    from helpers import is_strong_password
    if not is_strong_password(password):
        return jsonify({"message": "Password must be at least 8 characters with uppercase, lowercase, number, and special character."}), 400

    if users_col.find_one({"email": email}):
        return jsonify({"message": "Admin with this email already exists"}), 400

    hashed   = bcrypt.generate_password_hash(password).decode("utf-8")
    user_doc = {
        "name": name, "email": email, "password": hashed,
        "password_changed": True, "role": "admin",
        "department": "Administration", "position": "System Admin",
        "late_checkin_count_monthly": 0, "last_late_checkin_month": None,
    }
    res = users_col.insert_one(user_doc)
    return jsonify({"message": "Master Admin created successfully", "id": str(res.inserted_id)}), 201


@bp.route("/api/register-manager", methods=["POST"])
@token_required
def register_manager():
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized access."}), 403

    data       = request.get_json()
    name       = data.get("name")
    email      = data.get("email")
    password   = data.get("password")
    department = data.get("department", "Management")

    if not name or not email or not password or not department:
        return jsonify({"message": "Name, Email, Password, and Department are required"}), 400
    if users_col.find_one({"email": email}):
        return jsonify({"message": "Email already registered in the system."}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user  = {
        "name": name, "email": email, "password": hashed_pw,
        "password_changed": False, "role": "manager", "department": department,
        "position": "Manager", "created_at": datetime.now(timezone.utc),
        "late_checkin_count_monthly": 0, "last_late_checkin_month": None,
    }
    users_col.insert_one(new_user)
    return jsonify({"message": "Manager created successfully!"}), 201


@bp.route("/api/admin/employees", methods=["POST"])
@token_required
def add_employee():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees", write=True)):
        return jsonify({"message": "Unauthorized access."}), 403

    data          = request.json
    name          = data.get("name")
    email         = data.get("email")
    phone         = (data.get("phone") or "").strip()
    department    = data.get("department", "")
    position      = data.get("position", "")
    manager_id    = data.get("manager_id")
    doj           = data.get("doj", "")
    employee_code = (data.get("employee_code") or "").strip()

    if not name or not email:
        return jsonify({"message": "Name and Email are required."}), 400
    if users_col.find_one({"email": email}):
        return jsonify({"message": "User with this email already exists"}), 400

    employment_type, contract_months, emp_type_err = parse_employment_type(data)
    if emp_type_err:
        return jsonify({"message": emp_type_err}), 400

    shift = data.get("shift", "morning")
    if shift not in ("morning", "night", "general"):
        shift = "morning"

    user_doc = {
        "name": name, "email": email, "phone": phone,
        "password_changed": False, "role": "employee",
        "department": department, "position": position, "doj": doj,
        "employee_code": employee_code, "created_at": datetime.now(timezone.utc),
        "manager_id": manager_id, "shift": shift,
        "late_checkin_count_monthly": 0, "last_late_checkin_month": None,
        "employment_type": employment_type, "contract_months": contract_months,
    }

    # Only Permanent employees get portal login credentials — Contract
    # employees are stored as records only (no password, no welcome email).
    password = None
    if employment_type == "Permanent":
        password = generate_random_password()
        user_doc["password"] = bcrypt.generate_password_hash(password).decode("utf-8")

    res = users_col.insert_one(user_doc)

    if employment_type == "Permanent":
        subject = "Welcome to GDMR Connect: Your New Account Credentials"
        body    = (
            f"Dear {name},\n\n"
            "Your new employee account for the GDMR Connect Attendance App has been successfully created.\n\n"
            "Please use the following credentials to log in:\n"
            f"Username (Email): {email}\n"
            f"Temporary Password: {password}\n\n"
            "We recommend logging in as soon as possible and updating your password to a strong format.\n\n"
            "Thank you,\nThe GDMR Connect Team"
        )
        try:
            threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()
        except Exception as e:
            print("Failed to dispatch welcome email:", e)
        message = "Employee created successfully"
    else:
        message = "Employee record created (Contract — no login access)."

    return jsonify({"message": message, "id": str(res.inserted_id)}), 201


# ── Employee / Manager directory ──────────────────────────────────────────────

@bp.route("/api/admin/employees", methods=["GET"])
@token_required
def list_employees():
    # A read-only "Attendance" grant needs the roster too — AdminAttendancePage
    # uses this endpoint to build its employee grid and to resolve names for
    # the Present/Absent/Not-Checked-In detail modals.
    if not (_is_admin(request.user)
            or _has_module_grant(request.user, "employees")
            or _has_module_grant(request.user, "attendance")):
        return jsonify({"message": "Unauthorized access."}), 403

    emp_query: dict = {"role": {"$in": ["employee", "manager", "owner"]}}
    if request.args.get("active_only", "").lower() == "true":
        emp_query["$or"] = [
            {"resignation.last_working_day": None},
            {"resignation.last_working_day": {"$gte": str(datetime.now(IST).date())}},
            {"resignation": None},
        ]

    all_users = list(users_col.find(emp_query, {"password": 0}))
    managers  = {str(u["_id"]): u["name"] for u in all_users if u.get("role") == "manager"}

    rows = []
    for u in all_users:
        u["_id"]          = str(u["_id"])
        manager_id        = u.get("manager_id")
        u["manager_name"] = managers.get(manager_id) if manager_id else None
        u.setdefault("shift", "morning")
        _serialize_emp_status(u)
        rows.append(u)

    return jsonify(rows), 200


@bp.route("/api/admin/managers", methods=["GET"])
@token_required
def list_managers():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "manager")):
        return jsonify({"message": "Unauthorized"}), 403
    managers = []
    for m in users_col.find({"role": {"$in": ["manager", "owner"]}}, {"password": 0}):
        m["_id"] = str(m["_id"])
        managers.append(m)
    return jsonify(managers), 200


@bp.route("/api/admin/managers/<man_id>/role", methods=["PUT"])
@token_required
def update_manager_role(man_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "manager", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    data     = request.get_json(silent=True) or {}
    new_role = (data.get("role") or "").strip().lower()
    if new_role not in ("manager", "owner"):
        return jsonify({"message": "role must be 'manager' or 'owner'"}), 400
    try:
        obj = ObjectId(man_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    target = users_col.find_one({"_id": obj})
    if not target:
        return jsonify({"message": "User not found"}), 404
    if target.get("role") not in ("manager", "owner"):
        return jsonify({"message": "User is not a manager or owner"}), 400
    users_col.update_one({"_id": obj}, {"$set": {"role": new_role}})
    return jsonify({"message": f"Role updated to '{new_role}'"}), 200


# ── Department management ─────────────────────────────────────────────────────

@bp.route("/api/admin/departments", methods=["GET"])
@token_required
def list_departments():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "departments")):
        return jsonify({"message": "Unauthorized"}), 403
    depts = []
    for d in departments_col.find().sort("name", 1):
        d["_id"] = str(d["_id"])
        if d.get("head_id"):
            d["head_id"] = str(d["head_id"])
        depts.append(d)
    return jsonify(depts), 200


@bp.route("/api/admin/departments", methods=["POST"])
@token_required
def create_department():
    if not (_is_admin(request.user) or _has_module_grant(request.user, "departments", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    data = request.json or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"message": "Department name is required."}), 400
    if departments_col.find_one({"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}):
        return jsonify({"message": f"Department '{name}' already exists."}), 400
    head_id = data.get("head_id")
    doc = {
        "name":        name,
        "description": str(data.get("description", "")).strip(),
        "head_id":     ObjectId(head_id) if head_id else None,
        "created_at":  datetime.now(timezone.utc),
        "updated_at":  datetime.now(timezone.utc),
    }
    res       = departments_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    if doc.get("head_id"):
        doc["head_id"] = str(doc["head_id"])
    return jsonify(doc), 201


@bp.route("/api/admin/departments/<dept_id>", methods=["PUT"])
@token_required
def update_department(dept_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "departments", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        dept = departments_col.find_one({"_id": ObjectId(dept_id)})
    except Exception:
        return jsonify({"message": "Invalid department ID."}), 400
    if not dept:
        return jsonify({"message": "Department not found."}), 404

    data   = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}

    if "name" in data:
        new_name = str(data["name"]).strip()
        if not new_name:
            return jsonify({"message": "Department name cannot be empty."}), 400
        clash = departments_col.find_one({
            "name": {"$regex": f"^{re.escape(new_name)}$", "$options": "i"},
            "_id":  {"$ne": ObjectId(dept_id)},
        })
        if clash:
            return jsonify({"message": f"Department '{new_name}' already exists."}), 400
        old_name       = dept["name"]
        update["name"] = new_name
        if old_name != new_name:
            users_col.update_many({"department": old_name}, {"$set": {"department": new_name}})

    if "description" in data:
        update["description"] = str(data["description"]).strip()
    if "head_id" in data:
        raw = data["head_id"]
        try:
            update["head_id"] = ObjectId(raw) if raw else None
        except Exception:
            return jsonify({"message": "Invalid head_id."}), 400

    departments_col.update_one({"_id": ObjectId(dept_id)}, {"$set": update})
    updated        = departments_col.find_one({"_id": ObjectId(dept_id)})
    updated["_id"] = str(updated["_id"])
    if updated.get("head_id"):
        updated["head_id"] = str(updated["head_id"])
    return jsonify(updated), 200


@bp.route("/api/admin/departments/<dept_id>", methods=["DELETE"])
@token_required
def delete_department(dept_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        dept = departments_col.find_one({"_id": ObjectId(dept_id)})
    except Exception:
        return jsonify({"message": "Invalid department ID."}), 400
    if not dept:
        return jsonify({"message": "Department not found."}), 404
    departments_col.delete_one({"_id": ObjectId(dept_id)})
    return jsonify({"message": f"Department '{dept['name']}' metadata deleted."}), 200


@bp.route("/api/departments/<dept_name>/work-types", methods=["GET"])
@token_required
def get_dept_work_types(dept_name):
    dept = departments_col.find_one({"name": {"$regex": f"^{re.escape(dept_name)}$", "$options": "i"}})
    if not dept:
        return jsonify({"types": []}), 200
    return jsonify({"types": dept.get("work_types") or []}), 200


@bp.route("/api/admin/departments/<dept_name>/work-types", methods=["PUT"])
@token_required
def set_dept_work_types(dept_name):
    user = request.user
    role = user.get("role")
    if not _is_admin(user) and role != "manager":
        return jsonify({"message": "Unauthorized"}), 403
    if role == "manager":
        mgr_depts = [d.strip().lower() for d in _mgr_depts(user)]
        if dept_name.strip().lower() not in mgr_depts:
            return jsonify({"message": "Unauthorized: not your department"}), 403
    data  = request.get_json(silent=True) or {}
    types = data.get("types")
    if not isinstance(types, list):
        return jsonify({"message": "types must be a list"}), 400
    types = [str(t).strip() for t in types if str(t).strip()]
    result = departments_col.update_one(
        {"name": {"$regex": f"^{re.escape(dept_name)}$", "$options": "i"}},
        {"$set": {"work_types": types, "updated_at": datetime.now(timezone.utc)}},
    )
    if result.matched_count == 0:
        return jsonify({"message": "Department not found"}), 404
    return jsonify({"types": types}), 200


@bp.route("/api/manager/my-employees", methods=["GET"])
@token_required
def manager_my_employees():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for u in users_col.find({"department": {"$in": _mgr_depts(request.user)}, "role": "employee"}, {"password": 0}):
        u["_id"] = str(u["_id"])
        rows.append(u)
    return jsonify(rows), 200


# ── Employee edits, promotions, deletions ─────────────────────────────────────

@bp.route("/api/admin/employees/<emp_id>", methods=["PUT"])
@token_required
def edit_employee(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    data   = request.json
    update = {}
    for k in ["name", "department", "position", "email", "phone", "manager_id", "shift", "doj", "employee_code"]:
        if k in data:
            update[k] = data[k]
    if "manager_id" in data and not data["manager_id"]:
        update["manager_id"] = None
    if "shift" in update and update["shift"] not in ("morning", "night", "general"):
        return jsonify({"message": "Invalid shift value. Must be 'morning', 'night', or 'general'."}), 400
    if update:
        users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": update})
    return jsonify({"message": "Employee profile updated successfully."}), 200


# ── Employee documents (personal file: resume, ID proof, certificates, etc.) ──
# Carried over automatically when someone is onboarded from the ATS pipeline
# (see routes/ats.py's ats_update_status), and admins can add/remove more here.

@bp.route("/api/admin/employees/<emp_id>/documents", methods=["POST"])
@token_required
def upload_employee_document(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(emp_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    if not users_col.find_one({"_id": obj}, {"_id": 1}):
        return jsonify({"message": "Employee not found"}), 404

    doc_name = (request.form.get("name") or "").strip()
    file     = request.files.get("file")
    if not doc_name or not file:
        return jsonify({"message": "name and file are required"}), 400

    file.seek(0, 2)
    if file.tell() > 15 * 1024 * 1024:
        return jsonify({"message": "File too large (max 15 MB)"}), 400
    file.seek(0)

    try:
        res = cloudinary.uploader.upload(
            file, resource_type="auto", folder=f"gdmr/employee_docs/{emp_id}",
            use_filename=True, unique_filename=True,
        )
        url = res.get("secure_url")
    except Exception as e:
        return jsonify({"message": f"Upload failed: {str(e)}"}), 500

    now = datetime.now(timezone.utc)
    doc = {
        "id":          secrets.token_hex(8),
        "name":        doc_name,
        "url":         url,
        "uploaded_at": now,
        "uploaded_by": str(request.user["_id"]),
        "source":      "manual",
    }
    users_col.update_one({"_id": obj}, {"$push": {"documents": doc}})
    doc["uploaded_at"] = doc["uploaded_at"].isoformat()
    return jsonify(doc), 201


@bp.route("/api/admin/employees/<emp_id>/documents/<doc_id>", methods=["DELETE"])
@token_required
def delete_employee_document(emp_id, doc_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(emp_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    users_col.update_one({"_id": obj}, {"$pull": {"documents": {"id": doc_id}}})
    return jsonify({"message": "Document removed."}), 200


@bp.route("/api/admin/employees/<emp_id>/promote", methods=["PUT"])
@token_required
def promote_to_manager(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "manager", write=True)):
        return jsonify({"message": "Unauthorized. Only admins can promote employees."}), 403
    emp = users_col.find_one({"_id": ObjectId(emp_id)})
    if not emp:
        return jsonify({"message": "Employee not found."}), 404
    if emp.get("role") == "manager":
        return jsonify({"message": "User is already a manager."}), 400
    dept = emp.get("department")
    users_col.update_one(
        {"_id": ObjectId(emp_id)},
        {"$set": {"role": "manager", "position": "Manager", "manager_id": None}}
    )
    if dept:
        users_col.update_many(
            {"department": dept, "role": "employee"},
            {"$set": {"manager_id": str(emp_id)}}
        )
    return jsonify({"message": f"Successfully promoted {emp.get('name')} to Manager of the {dept} department."}), 200


@bp.route("/api/admin/managers/<man_id>", methods=["PUT"])
@token_required
def edit_manager(man_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "manager", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    data   = request.json
    update = {}
    for k in ["name", "department", "email"]:
        if k in data:
            update[k] = data[k]
    if update:
        users_col.update_one({"_id": ObjectId(man_id)}, {"$set": update})
    return jsonify({"message": "Manager profile updated successfully."}), 200


@bp.route("/api/admin/employees/<emp_id>", methods=["DELETE"])
@token_required
def delete_employee(emp_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    users_col.delete_one({"_id": ObjectId(emp_id)})
    attendance_col.delete_many({"user_id": emp_id})
    leaves_col.delete_many({"user_id": emp_id})
    pms_reviews_col.delete_many({"user_id": emp_id})
    corrections_col.delete_many({"user_id": emp_id})
    access_grants_col.delete_many({"employee_id": emp_id})
    return jsonify({"message": "Employee completely removed from system."}), 200


@bp.route("/api/admin/managers/<man_id>", methods=["DELETE"])
@token_required
def delete_manager(man_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    users_col.delete_one({"_id": ObjectId(man_id)})
    users_col.update_many({"manager_id": man_id}, {"$set": {"manager_id": None}})
    return jsonify({"message": "Manager removed. Subordinates must be reassigned."}), 200


# ── Employment status helpers ─────────────────────────────────────────────────

def _get_emp_or_404(emp_id):
    try:
        emp = users_col.find_one({"_id": ObjectId(emp_id)}, {"password": 0})
    except Exception:
        return None, (jsonify({"message": "Invalid employee ID."}), 400)
    if not emp:
        return None, (jsonify({"message": "Employee not found."}), 404)
    return emp, None


def _status_payload(emp_id):
    emp = users_col.find_one({"_id": ObjectId(emp_id)}, {"extended_leaves": 1, "resignation": 1})
    _serialize_emp_status(emp)
    return {"extended_leaves": emp["extended_leaves"], "resignation": emp["resignation"]}


@bp.route("/api/admin/employees/<emp_id>/status", methods=["GET"])
@token_required
def get_employee_status(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees")):
        return jsonify({"message": "Unauthorized"}), 403
    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err
    _serialize_emp_status(emp)
    return jsonify({"extended_leaves": emp["extended_leaves"], "resignation": emp["resignation"]}), 200


@bp.route("/api/admin/employees/<emp_id>/extended-leave", methods=["POST"])
@token_required
def add_extended_leave(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err
    data          = request.json or {}
    leave_type    = str(data.get("type", "")).strip()
    from_date_raw = data.get("from_date")
    to_date_raw   = data.get("to_date")
    if not leave_type or not from_date_raw or not to_date_raw:
        return jsonify({"message": "type, from_date, and to_date are required."}), 400
    try:
        from_date = datetime.strptime(str(from_date_raw)[:10], "%Y-%m-%d")
        to_date   = datetime.strptime(str(to_date_raw)[:10],   "%Y-%m-%d")
    except ValueError:
        return jsonify({"message": "Invalid date format. Use YYYY-MM-DD."}), 400
    if to_date < from_date:
        return jsonify({"message": "to_date cannot be before from_date."}), 400
    entry = {
        "_id":         ObjectId(),
        "type":        leave_type,
        "from_date":   from_date,
        "to_date":     to_date,
        "notes":       str(data.get("notes", "")).strip(),
        "recorded_at": datetime.now(timezone.utc),
    }
    users_col.update_one({"_id": ObjectId(emp_id)}, {"$push": {"extended_leaves": entry}})
    return jsonify(_status_payload(emp_id)), 201


@bp.route("/api/admin/employees/<emp_id>/extended-leave/<leave_id>", methods=["DELETE"])
@token_required
def delete_extended_leave(emp_id, leave_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err
    try:
        users_col.update_one(
            {"_id": ObjectId(emp_id)},
            {"$pull": {"extended_leaves": {"_id": ObjectId(leave_id)}}},
        )
    except Exception:
        return jsonify({"message": "Invalid leave ID."}), 400
    return jsonify(_status_payload(emp_id)), 200


@bp.route("/api/admin/employees/<emp_id>/resignation", methods=["PUT"])
@token_required
def set_resignation(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err
    data = request.json or {}

    def _parse_date(raw):
        if not raw:
            return None
        try:
            return datetime.strptime(str(raw)[:10], "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"Invalid date '{raw}'. Use YYYY-MM-DD.")

    try:
        notice_date      = _parse_date(data.get("notice_date"))
        last_working_day = _parse_date(data.get("last_working_day"))
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    resignation = {
        "notice_date":      notice_date,
        "last_working_day": last_working_day,
        "reason":           str(data.get("reason", "")).strip(),
        "recorded_at":      datetime.now(timezone.utc),
    }
    users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": {"resignation": resignation}})
    return jsonify(_status_payload(emp_id)), 200


@bp.route("/api/admin/employees/<emp_id>/resignation", methods=["DELETE"])
@token_required
def clear_resignation(emp_id):
    if not (_is_admin(request.user) or _has_module_grant(request.user, "employees", write=True)):
        return jsonify({"message": "Unauthorized"}), 403
    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err
    users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": {"resignation": None}})
    return jsonify(_status_payload(emp_id)), 200
