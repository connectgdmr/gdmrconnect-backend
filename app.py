"""
===============================================================================
GDMR CONNECT - CORE BACKEND APPLICATION API (ENTERPRISE EDITION)
===============================================================================
This file contains all the core backend routes, database connections, and 
business logic for the GDMR Connect HRMS and Enterprise Management system.

Key Modules Included:
- JWT Authentication & Strict Role-based Access Control (RBAC)
- Employee & Manager Directory Management
- Daily Attendance & Camera/Photo Logging (with Cloudinary)
- Leave Management & Dual-Tier Approvals
- Temporary Delegated Admin Access (Auto-Expiring Grants)
- Performance Management System (PMS 2.0) Form Builder & Grading
- Asset & Hardware Management (Dual-Approval Workflow)
- Automated Background Tasks (APScheduler)
- Announcements & System Broadcasts (Create, Read, Update, Delete)
===============================================================================
"""

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import base64, os, re, csv, io, secrets, gzip
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from utils import send_email, generate_random_password
from bson import ObjectId
from datetime import datetime, timedelta, timezone, time
import pytz
from flask_bcrypt import Bcrypt
import threading
import cloudinary
import cloudinary.uploader
from apscheduler.schedulers.background import BackgroundScheduler

# =============================================================================
# 1. ENVIRONMENT & APP INITIALIZATION
# =============================================================================
load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

# =============================================================================
# 2. CLOUDINARY CONFIGURATION (For Image Uploads & Assets)
# =============================================================================
try:
    cloudinary.config(
        cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
        api_key = os.getenv('CLOUDINARY_API_KEY'),
        api_secret = os.getenv('CLOUDINARY_API_SECRET')
    )
    print("Cloudinary configured successfully for Asset Management.")
except Exception as e:
    print(f"Warning: Cloudinary configuration failed. Images may not upload. Error: {e}")

# =============================================================================
# 3. CORS CONFIGURATION (Cross-Origin Resource Sharing)
# =============================================================================
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://gdmrconnect.com",
            "https://www.gdmrconnect.com",
            "https://*.netlify.app",
            "http://localhost:5173",
            "http://127.0.0.1:5173"
        ],
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    }
})

# =============================================================================
# 4. DATABASE CONNECTION (MongoDB)
# =============================================================================
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "replace-this-secret-with-a-secure-key-in-production")
MONGO_URI = os.getenv("MONGO_URI")

try:
    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000,   # fail fast instead of hanging 30s
        connectTimeoutMS=10000,
        socketTimeoutMS=45000,
        retryWrites=True,
        maxPoolSize=50
    )
    client.admin.command("ping")         # verify connection is actually alive
    db = client["attendance_db"]
    print("MongoDB Connected Successfully to Database: attendance_db.")
except Exception as e:
    print(f"CRITICAL ERROR: Failed to connect to MongoDB. Error: {e}")
    db = None

# --- Core Collections ---
if db is None:
    raise RuntimeError("Cannot start: MongoDB connection failed. Check MONGO_URI and Atlas Network Access.")

users_col = db["users"]
attendance_col = db["attendance"]
leaves_col = db["leaves"]

# --- Extended Modules Collections ---
corrections_col = db["attendance_corrections"]
pip_records_col = db["pip_records"]
announcements_col = db["announcements"]
access_grants_col = db["access_grants"]
assets_col = db["assets"]

# --- Performance Management System (PMS) Collections ---
pms_templates_col = db["pms_templates"]
pms_reviews_col = db["pms_reviews"]

# --- Department Management ---
departments_col = db["departments"]

# --- Assessment Module ---
assessments_col   = db["assessments"]
candidates_col    = db["assessment_invites"]

# --- LMS Module ---
lms_courses_col   = db["lms_courses"]
lms_progress_col  = db["lms_progress"]

# --- Career Module ---
career_jobs_col   = db["career_jobs"]
referrals_col     = db["career_referrals"]

# --- Payroll Module ---
salary_structures_col = db["salary_structures"]
payslips_col          = db["payslips"]

# --- Work Plans Module ---
work_plans_col        = db["work_plans"]

# --- Clients ---
clients_col           = db["clients"]

# Local Upload Fallback Directory (Used if Cloudinary is unavailable)
UPLOAD_FOLDER = "uploads/attendance_photos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Application Timezone Context (Strict enforcement to avoid UTC drift)
IST = pytz.timezone('Asia/Kolkata')

# Company owners — always receive org-wide work plan summaries
OWNER_EMAILS = ["gina.gdmr@gmail.com", "githi@gdmrfoundation.com"]

# =============================================================================
# CREATE INDEXES (run once at startup; background=True means no lock)
# =============================================================================
try:
    users_col.create_index("email", background=True)
    users_col.create_index("role", background=True)
    users_col.create_index("department", background=True)
    attendance_col.create_index([("user_id", 1), ("date", 1), ("type", 1)], background=True)
    attendance_col.create_index([("date", 1), ("type", 1)], background=True)
    leaves_col.create_index([("user_id", 1), ("status", 1)], background=True)
    leaves_col.create_index([("from_date", 1), ("to_date", 1), ("status", 1)], background=True)
    corrections_col.create_index([("user_id", 1), ("month", 1)], background=True)
    pms_reviews_col.create_index([("user_id", 1), ("month", 1)], background=True)
    pms_reviews_col.create_index([("department", 1), ("month", 1)], background=True)
    access_grants_col.create_index([("employee_id", 1), ("is_active", 1)], background=True)
    assets_col.create_index("user_id", background=True)
    assets_col.create_index("department", background=True)
    announcements_col.create_index("created_at", background=True)
    departments_col.create_index("name", unique=True, background=True)
    candidates_col.create_index("assessment_id", background=True)
    candidates_col.create_index("email", background=True)
    lms_progress_col.create_index([("user_id", 1), ("course_id", 1)], unique=True, background=True)
    referrals_col.create_index([("referred_by", 1), ("job_id", 1)], background=True)
    referrals_col.create_index("status", background=True)
    salary_structures_col.create_index("employee_id", unique=True, background=True)
    payslips_col.create_index([("employee_id", 1), ("year", 1), ("month", 1)], unique=True, background=True)
    payslips_col.create_index([("year", 1), ("month", 1)], background=True)
    # Indexes backing common sorts on growing collections
    leaves_col.create_index([("applied_at", -1)], background=True)
    assets_col.create_index([("created_at", -1)], background=True)
    attendance_col.create_index([("user_id", 1), ("time", -1)], background=True)
    pms_reviews_col.create_index([("self_assessment_date", -1)], background=True)
    work_plans_col.create_index([("employee_id", 1), ("date", 1)], unique=True, background=True)
    work_plans_col.create_index([("date", 1), ("status", 1)], background=True)
    work_plans_col.create_index([("department", 1), ("date", 1)], background=True)
    clients_col.create_index("name", unique=True, background=True)
    print("MongoDB indexes ensured.")
except Exception as _idx_err:
    print(f"Warning: Could not create indexes: {_idx_err}")

# One-time migration: stamp "morning" on every employee that pre-dates the shift field
try:
    _migrated = users_col.update_many(
        {"shift": {"$exists": False}},
        {"$set": {"shift": "morning"}}
    ).modified_count
    if _migrated:
        print(f"Startup migration: set shift='morning' on {_migrated} existing employee(s).")
except Exception as _mig_err:
    print(f"Warning: shift migration failed: {_mig_err}")


# =============================================================================
# 5. UTILITY & HELPER FUNCTIONS
# =============================================================================

def utc_to_ist(utc_datetime):
    """
    Converts a standard UTC datetime object to Indian Standard Time (IST).
    Ensures the application operates consistently in the local time context.
    """
    if utc_datetime.tzinfo is None:
        utc_datetime = pytz.utc.localize(utc_datetime)
    return utc_datetime.astimezone(IST)

def format_datetime_ist(dt):
    """
    Formats a datetime object or ISO string into a standardized IST ISO string.
    Useful for JSON serialization to the frontend to ensure correct display times.
    """
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except Exception:
            dt = datetime.fromisoformat(dt)
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(IST).isoformat()

def is_strong_password(password):
    """
    Validates password strength to enforce enterprise security standards.
    Requires: Minimum 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character.
    """
    if len(password) < 8: return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"\d", password): return False
    if not re.search(r"[@$!%*?&#^_\-]", password): return False
    return True


def _serialize_emp_status(user_doc):
    """
    Converts extended_leaves and resignation BSON types (ObjectId, datetime)
    to JSON-safe strings in-place. Also ensures both keys are always present.
    """
    leaves = []
    for entry in user_doc.get("extended_leaves", []):
        e = dict(entry)
        if isinstance(e.get("_id"), ObjectId):
            e["_id"] = str(e["_id"])
        for f in ("from_date", "to_date", "recorded_at"):
            if isinstance(e.get(f), datetime):
                e[f] = e[f].strftime("%Y-%m-%d")
        leaves.append(e)
    user_doc["extended_leaves"] = leaves

    res = user_doc.get("resignation")
    if isinstance(res, dict):
        res = dict(res)
        for f in ("notice_date", "last_working_day", "recorded_at"):
            if isinstance(res.get(f), datetime):
                res[f] = res[f].strftime("%Y-%m-%d")
        user_doc["resignation"] = res
    else:
        user_doc["resignation"] = None


# =============================================================================
# 6. ROUTE: HEALTH CHECKS & STATIC FILES
# =============================================================================

@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Unhandled exception: {e}")
    return jsonify({"message": "A server error occurred. Please try again."}), 500


@app.after_request
def _gzip_response(response):
    """
    Transparently gzip JSON/text responses when the client supports it.
    Cuts transfer size ~80-90% on large list payloads (employees, leaves,
    attendance summaries) with no API contract change. Conservative guards
    skip streamed files, small bodies, errors, and already-encoded responses.
    """
    try:
        if "gzip" not in request.headers.get("Accept-Encoding", "").lower():
            return response
        if response.direct_passthrough or response.status_code != 200:
            return response
        if response.headers.get("Content-Encoding"):
            return response
        ctype = response.content_type or ""
        if not (ctype.startswith("application/json") or ctype.startswith("text/")):
            return response

        data = response.get_data()
        if len(data) < 1024:          # not worth compressing tiny payloads
            return response

        compressed = gzip.compress(data, compresslevel=6)
        response.set_data(compressed)
        response.headers["Content-Encoding"] = "gzip"
        response.headers["Content-Length"] = str(len(compressed))

        # Preserve any existing Vary (e.g. Origin from CORS) and add Accept-Encoding
        vary = response.headers.get("Vary")
        if vary:
            if "accept-encoding" not in vary.lower():
                response.headers["Vary"] = f"{vary}, Accept-Encoding"
        else:
            response.headers["Vary"] = "Accept-Encoding"
    except Exception as _gz_err:
        print(f"gzip skip: {_gz_err}")
    return response

@app.route("/")
def home():
    return "GDMR Connect Backend is running normally ✅", 200

@app.route("/api/health", methods=["GET"])
def health_check():
    try:
        client.admin.command("ping")
        return jsonify({"status": "ok", "db": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "error", "db": "disconnected", "detail": str(e)}), 503

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    """ Serves files from the local uploads directory if Cloudinary isn't used for storage. """
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    return send_from_directory(uploads_dir, filename)


# =============================================================================
# 7. AUTHENTICATION MIDDLEWARE
# =============================================================================

def token_required(f):
    """
    Decorator to protect routes using JWT authentication.
    Extracts the Bearer token from the Authorization header, decodes it, 
    and sets request.user with the full user document from the database.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({"message": "Authentication Token is missing! Please log in."}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data.get("user_id")
            current_user = users_col.find_one({"_id": ObjectId(user_id)})
            
            if not current_user:
                return jsonify({"message": "Invalid token. User not found in database."}), 401
                
            request.user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Session expired. Please log in again."}), 401
        except Exception as e:
            return jsonify({"message": "Token is invalid!", "error": str(e)}), 401
            
        return f(*args, **kwargs)
    return decorated


# =============================================================================
# 8. ACCOUNT MANAGEMENT & LOGIN ROUTES
# =============================================================================

@app.route("/api/login", methods=["POST"])
def login():
    """
    Authenticates a user against the database and returns a short-lived JWT token.
    Provides basic user payload so the frontend knows how to route the dashboard.
    """
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required."}), 400

    user = users_col.find_one({"email": email})
    
    if not user or not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid credentials. Please check your email and password."}), 401

    # Generate Token valid for 4 hours
    token = jwt.encode({
        "user_id": str(user["_id"]),
        "exp": datetime.now(timezone.utc) + timedelta(hours=4)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        "token": token,
        "role": user.get("role", "employee"),
        "password_changed": user.get("password_changed", False), 
        "user": {
            "name": user.get("name"),
            "email": user.get("email"),
            "department": user.get("department", "")
        }
    }), 200


@app.route("/api/my/set-password", methods=["POST"])
@token_required
def set_own_password():
    """
    Allows an authenticated user to update their password. 
    Enforces strong password rules and validates current password.
    """
    data = request.json
    old_password = data.get("oldPassword")
    new_password = data.get("password")
    
    if not old_password:
        return jsonify({"message": "Current password is required."}), 400
        
    if not bcrypt.check_password_hash(request.user["password"], old_password):
        return jsonify({"message": "Incorrect current password. Please try again."}), 400
    
    if not new_password or not is_strong_password(new_password):
        return jsonify({"message": "Password must be at least 8 characters and contain 1 uppercase, 1 lowercase, 1 number, and 1 special character."}), 400
        
    hashed = bcrypt.generate_password_hash(new_password).decode("utf-8")
    
    users_col.update_one(
        {"_id": request.user["_id"]}, 
        {"$set": {"password": hashed, "password_changed": True}}
    )
    
    return jsonify({"message": "Password updated successfully!"}), 200


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    """
    Generates a temporary secure password and emails it to the user.
    Flags the user account to require a password change on next login.
    """
    data = request.json
    email = data.get("email")

    user = users_col.find_one({"email": email})
    if not user:
        # Standard security practice: Don't reveal if email exists or not to prevent user enumeration
        return jsonify({"message": "If this email exists, a password reset has been sent."}), 200

    temp_password = generate_random_password()
    hashed = bcrypt.generate_password_hash(temp_password).decode("utf-8")
    
    # Flag the user to force them to change it on next login
    users_col.update_one({"_id": user["_id"]}, {"$set": {"password": hashed, "password_changed": False}})

    subject = "GDMR Connect - Password Reset Request"
    body = (
        f"Hello {user['name']},\n\n"
        "We received a request to reset your password.\n"
        f"Your new temporary password is: {temp_password}\n\n"
        "Please login and change your password immediately to secure your account."
    )

    # Send directly (not in a thread) so we can log the result clearly
    ok = send_email(email, subject, body)
    if ok:
        print(f"[forgot-password] Reset email sent successfully to {email}")
    else:
        print(f"[forgot-password] WARNING: Reset email FAILED for {email} — check BREVO_API_KEY in Railway env vars")

    return jsonify({"message": "If this email exists, a password reset has been sent."}), 200


# =============================================================================
# 9. USER REGISTRATION ROUTES (ADMIN ONLY)
# =============================================================================

@app.route("/api/register-admin", methods=["POST"])
def register_admin():
    """ Initial system setup route to create the master administrator. """
    data = request.json
    email = data.get("email")
    name = data.get("name", "Admin")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required."}), 400

    if not is_strong_password(password):
        return jsonify({"message": "Password must be at least 8 characters with uppercase, lowercase, number, and special character."}), 400

    if users_col.find_one({"email": email}):
        return jsonify({"message": "Admin with this email already exists"}), 400

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    user_doc = {
        "name": name,
        "email": email,
        "password": hashed,
        "password_changed": True, 
        "role": "admin",
        "department": "Administration",
        "position": "System Admin",
        "late_checkin_count_monthly": 0,
        "last_late_checkin_month": None,
    }
    res = users_col.insert_one(user_doc)
    return jsonify({"message": "Master Admin created successfully", "id": str(res.inserted_id)}), 201


@app.route("/api/register-manager", methods=["POST"])
@token_required
def register_manager():
    """ Registers a new manager profile. Requires Admin privileges. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized access."}), 403

    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    department = data.get("department", "Management") 

    if not name or not email or not password or not department:
        return jsonify({"message": "Name, Email, Password, and Department are required"}), 400

    if users_col.find_one({"email": email}):
        return jsonify({"message": "Email already registered in the system."}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    new_user = {
        "name": name,
        "email": email,
        "password": hashed_pw,
        "password_changed": False, 
        "role": "manager",
        "department": department,
        "position": "Manager",
        "created_at": datetime.now(timezone.utc),
        "late_checkin_count_monthly": 0, 
        "last_late_checkin_month": None,
    }

    users_col.insert_one(new_user)
    return jsonify({"message": "Manager created successfully!"}), 201


@app.route("/api/admin/employees", methods=["POST"])
@token_required
def add_employee():
    """ Registers a new employee profile. Requires Admin privileges. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized access."}), 403

    data = request.json
    name = data.get("name")
    email = data.get("email")
    department = data.get("department", "")
    position = data.get("position", "")
    manager_id = data.get("manager_id")

    if not name or not email:
        return jsonify({"message": "Name and Email are required."}), 400

    if users_col.find_one({"email": email}):
        return jsonify({"message": "User with this email already exists"}), 400

    # Auto-generate a secure temporary password
    password = generate_random_password()
    hashed = bcrypt.generate_password_hash(password).decode("utf-8")

    shift = data.get("shift", "morning")
    if shift not in ("morning", "night", "general"):
        shift = "morning"

    user_doc = {
        "name": name,
        "email": email,
        "password": hashed,
        "password_changed": False,
        "role": "employee",
        "department": department,
        "position": position,
        "created_at": datetime.now(timezone.utc),
        "manager_id": manager_id,
        "shift": shift,
        "late_checkin_count_monthly": 0,
        "last_late_checkin_month": None,
    }

    res = users_col.insert_one(user_doc)

    # Email the credentials to the new employee automatically
    subject = "Welcome to GDMR Connect: Your New Account Credentials"
    body = (
        f"Dear {name},\n\n"
        "Your new employee account for the GDMR Connect Attendance App has been successfully created.\n\n"
        "Please use the following credentials to log in:\n"
        f"Username (Email): {email}\n"
        f"Temporary Password: {password}\n\n"
        "We recommend logging in as soon as possible and updating your password to a strong format.\n\n"
        "Thank you,\n"
        "The GDMR Connect Team"
    )

    try:
        threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()
    except Exception as e:
        print("Failed to dispatch welcome email:", e)

    return jsonify({"message": "Employee created successfully", "id": str(res.inserted_id)}), 201


# =============================================================================
# 10. EMPLOYEE & MANAGER DIRECTORIES
# =============================================================================

@app.route("/api/admin/employees", methods=["GET"])
@token_required
def list_employees():
    """
    Returns a list of all employees and managers.
    Accessible by Admins or users with active delegated admin access.
    """
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    
    if role != "admin" and not has_delegated:
        return jsonify({"message": "Unauthorized access."}), 403

    # Single query — projection drops password on the DB side
    all_users = list(users_col.find({"role": {"$in": ["employee", "manager"]}}, {"password": 0}))
    managers = {str(u["_id"]): u["name"] for u in all_users if u.get("role") == "manager"}

    rows = []
    for u in all_users:
        u["_id"] = str(u["_id"])
        manager_id = u.get("manager_id")
        u["manager_name"] = managers.get(manager_id) if manager_id else None
        u.setdefault("shift", "morning")  # backfill for employees created before shift field existed
        _serialize_emp_status(u)
        rows.append(u)

    return jsonify(rows), 200


@app.route("/api/admin/managers", methods=["GET"])
@token_required
def list_managers():
    """ Fetches a list of all registered managers in the system. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    managers = []
    for m in users_col.find({"role": "manager"}, {"password": 0}):
        m["_id"] = str(m["_id"])
        managers.append(m)

    return jsonify(managers), 200


# =============================================================================
# DEPARTMENT MANAGEMENT (CRUD)
# =============================================================================

@app.route("/api/admin/departments", methods=["GET"])
@token_required
def list_departments():
    """ Returns all departments. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    depts = []
    for d in departments_col.find().sort("name", 1):
        d["_id"] = str(d["_id"])
        if d.get("head_id"):
            d["head_id"] = str(d["head_id"])
        depts.append(d)

    return jsonify(depts), 200


@app.route("/api/admin/departments", methods=["POST"])
@token_required
def create_department():
    """ Creates a new department. Name must be non-empty and unique. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json or {}
    name = str(data.get("name", "")).strip()

    if not name:
        return jsonify({"message": "Department name is required."}), 400

    if departments_col.find_one({"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}):
        return jsonify({"message": f"Department '{name}' already exists."}), 400

    head_id = data.get("head_id")
    doc = {
        "name": name,
        "description": str(data.get("description", "")).strip(),
        "head_id": ObjectId(head_id) if head_id else None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }

    res = departments_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    if doc.get("head_id"):
        doc["head_id"] = str(doc["head_id"])

    return jsonify(doc), 201


@app.route("/api/admin/departments/<dept_id>", methods=["PUT"])
@token_required
def update_department(dept_id):
    """ Updates name, description, and/or head_id of a department. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    try:
        dept = departments_col.find_one({"_id": ObjectId(dept_id)})
    except Exception:
        return jsonify({"message": "Invalid department ID."}), 400

    if not dept:
        return jsonify({"message": "Department not found."}), 404

    data = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}

    if "name" in data:
        new_name = str(data["name"]).strip()
        if not new_name:
            return jsonify({"message": "Department name cannot be empty."}), 400
        # Check uniqueness excluding the current document
        clash = departments_col.find_one({
            "name": {"$regex": f"^{re.escape(new_name)}$", "$options": "i"},
            "_id": {"$ne": ObjectId(dept_id)}
        })
        if clash:
            return jsonify({"message": f"Department '{new_name}' already exists."}), 400

        old_name = dept["name"]
        update["name"] = new_name

        # Keep employee department field in sync when the name changes
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
    updated = departments_col.find_one({"_id": ObjectId(dept_id)})
    updated["_id"] = str(updated["_id"])
    if updated.get("head_id"):
        updated["head_id"] = str(updated["head_id"])

    return jsonify(updated), 200


@app.route("/api/admin/departments/<dept_id>", methods=["DELETE"])
@token_required
def delete_department(dept_id):
    """ Deletes a department and clears it from all assigned employees. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    try:
        dept = departments_col.find_one({"_id": ObjectId(dept_id)})
    except Exception:
        return jsonify({"message": "Invalid department ID."}), 400

    if not dept:
        return jsonify({"message": "Department not found."}), 404

    departments_col.delete_one({"_id": ObjectId(dept_id)})

    return jsonify({"message": f"Department '{dept['name']}' metadata deleted."}), 200


@app.route("/api/manager/my-employees", methods=["GET"])
@token_required
def manager_my_employees():
    """ Returns a list of employees specific to a Manager's assigned department. """
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403

    rows = []
    for u in users_col.find({"department": request.user.get("department"), "role": "employee"}, {"password": 0}):
        u["_id"] = str(u["_id"])
        rows.append(u)

    return jsonify(rows), 200


# =============================================================================
# 11. USER UPDATES, PROMOTIONS & DELETIONS
# =============================================================================

@app.route("/api/admin/employees/<emp_id>", methods=["PUT"])
@token_required
def edit_employee(emp_id):
    """ Modifies an existing employee record. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    update = {}

    for k in ["name", "department", "position", "email", "manager_id", "shift"]:
        if k in data:
            update[k] = data[k]

    if "manager_id" in data and not data["manager_id"]:
        update["manager_id"] = None

    if "shift" in update and update["shift"] not in ("morning", "night", "general"):
        return jsonify({"message": "Invalid shift value. Must be 'morning', 'night', or 'general'."}), 400

    if update:
        users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": update})

    return jsonify({"message": "Employee profile updated successfully."}), 200


@app.route("/api/admin/employees/<emp_id>/promote", methods=["PUT"])
@token_required
def promote_to_manager(emp_id):
    """ 
    Promotes an employee to a manager role and automatically assigns them 
    as the manager for all other employees in their respective department.
    """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized. Only admins can promote employees."}), 403

    emp = users_col.find_one({"_id": ObjectId(emp_id)})
    if not emp:
        return jsonify({"message": "Employee not found."}), 404
        
    if emp.get("role") == "manager":
        return jsonify({"message": "User is already a manager."}), 400

    dept = emp.get("department")
    
    # 1. Upgrade the user's role to 'manager'
    users_col.update_one(
        {"_id": ObjectId(emp_id)},
        {"$set": {"role": "manager", "position": "Manager", "manager_id": None}}
    )
    
    # 2. Re-assign all employees in the same department to this new manager
    if dept:
        users_col.update_many(
            {"department": dept, "role": "employee"},
            {"$set": {"manager_id": str(emp_id)}}
        )

    return jsonify({"message": f"Successfully promoted {emp.get('name')} to Manager of the {dept} department."}), 200


@app.route("/api/admin/managers/<man_id>", methods=["PUT"])
@token_required
def edit_manager(man_id):
    """ Modifies an existing manager record. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    update = {}
    for k in ["name", "department", "email"]:
        if k in data:
            update[k] = data[k]

    if update:
        users_col.update_one({"_id": ObjectId(man_id)}, {"$set": update})

    return jsonify({"message": "Manager profile updated successfully."}), 200


@app.route("/api/admin/employees/<emp_id>", methods=["DELETE"])
@token_required
def delete_employee(emp_id):
    """ Hard deletes an employee and wipes all associated tracking data. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    # Clean up user and all associated records to prevent orphaned documents
    users_col.delete_one({"_id": ObjectId(emp_id)})
    attendance_col.delete_many({"user_id": emp_id})
    leaves_col.delete_many({"user_id": emp_id})
    pms_reviews_col.delete_many({"user_id": emp_id})
    corrections_col.delete_many({"user_id": emp_id})
    access_grants_col.delete_many({"employee_id": emp_id})

    return jsonify({"message": "Employee completely removed from system."}), 200


@app.route("/api/admin/managers/<man_id>", methods=["DELETE"])
@token_required
def delete_manager(man_id):
    """ Deletes a manager and unassigns them from their subordinates. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    users_col.delete_one({"_id": ObjectId(man_id)})
    # Unassign this manager from their subordinates
    users_col.update_many({"manager_id": man_id}, {"$set": {"manager_id": None}})
    
    return jsonify({"message": "Manager removed. Subordinates must be reassigned."}), 200


# =============================================================================
# EMPLOYMENT STATUS (extended leaves + resignation)
# =============================================================================

def _get_emp_or_404(emp_id):
    """Fetch employee by id string; returns (doc, error_response) tuple."""
    try:
        emp = users_col.find_one({"_id": ObjectId(emp_id)}, {"password": 0})
    except Exception:
        return None, (jsonify({"message": "Invalid employee ID."}), 400)
    if not emp:
        return None, (jsonify({"message": "Employee not found."}), 404)
    return emp, None


def _status_payload(emp_id):
    """Return the serialised status dict for a given employee ObjectId string."""
    emp = users_col.find_one({"_id": ObjectId(emp_id)}, {"extended_leaves": 1, "resignation": 1})
    _serialize_emp_status(emp)
    return {"extended_leaves": emp["extended_leaves"], "resignation": emp["resignation"]}


@app.route("/api/admin/employees/<emp_id>/status", methods=["GET"])
@token_required
def get_employee_status(emp_id):
    """ Returns extended_leaves and resignation for a single employee. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err

    _serialize_emp_status(emp)
    return jsonify({"extended_leaves": emp["extended_leaves"], "resignation": emp["resignation"]}), 200


@app.route("/api/admin/employees/<emp_id>/extended-leave", methods=["POST"])
@token_required
def add_extended_leave(emp_id):
    """ Appends an extended-leave entry to the employee's extended_leaves array. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err

    data = request.json or {}
    leave_type = str(data.get("type", "")).strip()
    from_date_raw = data.get("from_date")
    to_date_raw = data.get("to_date")

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
        "recorded_at": datetime.now(timezone.utc)
    }

    users_col.update_one({"_id": ObjectId(emp_id)}, {"$push": {"extended_leaves": entry}})
    return jsonify(_status_payload(emp_id)), 201


@app.route("/api/admin/employees/<emp_id>/extended-leave/<leave_id>", methods=["DELETE"])
@token_required
def delete_extended_leave(emp_id, leave_id):
    """ Removes a specific extended-leave entry by its _id. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err

    try:
        users_col.update_one(
            {"_id": ObjectId(emp_id)},
            {"$pull": {"extended_leaves": {"_id": ObjectId(leave_id)}}}
        )
    except Exception:
        return jsonify({"message": "Invalid leave ID."}), 400

    return jsonify(_status_payload(emp_id)), 200


@app.route("/api/admin/employees/<emp_id>/resignation", methods=["PUT"])
@token_required
def set_resignation(emp_id):
    """ Sets or replaces the resignation record on an employee. """
    if request.user.get("role") != "admin":
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
        "recorded_at":      datetime.now(timezone.utc)
    }

    users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": {"resignation": resignation}})
    return jsonify(_status_payload(emp_id)), 200


@app.route("/api/admin/employees/<emp_id>/resignation", methods=["DELETE"])
@token_required
def clear_resignation(emp_id):
    """ Clears the resignation record from an employee. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    emp, err = _get_emp_or_404(emp_id)
    if err:
        return err

    users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": {"resignation": None}})
    return jsonify(_status_payload(emp_id)), 200


# =============================================================================
# 12. DELEGATED ADMIN ACCESS (GRANT SYSTEM)
# =============================================================================

@app.route("/api/admin/grant-access", methods=["POST"])
@token_required
def grant_access():
    """ 
    Allows an Admin to grant temporary admin capabilities to a standard employee.
    Used for vacation coverages or temporary assignments.
    """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.json
    emp_id = data.get("employeeId")
    access_level = data.get("accessLevel", "view_only")
    scope = data.get("scope", "today")
    custom_date = data.get("customDate", "")
    expiry = data.get("expiry", "end_of_day")
    custom_expiry_time = data.get("customExpiryTime", "")

    if not emp_id:
        return jsonify({"message": "Employee ID is required"}), 400

    emp = users_col.find_one({"_id": ObjectId(emp_id)})
    if not emp or emp.get("role") == "admin":
        return jsonify({"message": "Invalid employee or employee is already an admin."}), 400

    module = data.get("module", "attendance")
    if module not in ("attendance", "lms"):
        module = "attendance"

    grant_record = {
        "employee_id": emp_id,
        "module": module,
        "access_level": access_level,
        "scope": scope,
        "custom_date": custom_date,
        "expiry": expiry,
        "custom_expiry_time": custom_expiry_time,
        "granted_by": str(request.user["_id"]),
        "granted_at": datetime.now(timezone.utc),
        "is_active": True
    }

    res = access_grants_col.insert_one(grant_record)
    return jsonify({"message": "Temporary access granted successfully", "id": str(res.inserted_id)}), 201


@app.route("/api/admin/active-grants", methods=["GET"])
@token_required
def get_active_grants():
    """ Returns a list of all currently active delegated access grants. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    
    raw_grants = list(access_grants_col.find({"is_active": True}).sort("granted_at", -1))
    emp_ids = []
    for g in raw_grants:
        try: emp_ids.append(ObjectId(g["employee_id"]))
        except Exception: pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": emp_ids}}, {"name": 1})}

    grants = []
    for g in raw_grants:
        g["_id"] = str(g["_id"])
        g["employee_name"] = emp_map.get(g.get("employee_id"), "Unknown Employee")
        grants.append(g)

    return jsonify(grants), 200


@app.route("/api/admin/revoke-access/<grant_id>", methods=["DELETE"])
@token_required
def revoke_access(grant_id):
    """ Manually revokes an active delegated access grant immediately. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    
    result = access_grants_col.update_one({"_id": ObjectId(grant_id)}, {"$set": {"is_active": False}})
    if result.modified_count > 0:
        return jsonify({"message": "Access revoked successfully"}), 200
    else:
        return jsonify({"message": "Access grant not found or already inactive."}), 404


@app.route("/api/my/delegated-access", methods=["GET"])
@token_required
def my_delegated_access():
    """ 
    Frontend utility to check if the currently logged-in user has active special permissions. 
    It evaluates the time restrictions live and deactivates them if expired.
    """
    uid = str(request.user["_id"])
    now = datetime.now(IST)
    active_grants = []
    
    grants = access_grants_col.find({"employee_id": uid, "is_active": True})

    for g in grants:
        expired = False
        if g.get("expiry") == "end_of_day":
            granted_at_ist = utc_to_ist(g["granted_at"])
            if now.date() > granted_at_ist.date():
                expired = True
                
        elif g.get("expiry") == "custom_time":
            custom_time_str = g.get("custom_expiry_time")
            if custom_time_str:
                try:
                    expiry_dt = datetime.strptime(custom_time_str, "%Y-%m-%dT%H:%M")
                    expiry_dt = IST.localize(expiry_dt)
                    if now >= expiry_dt:
                        expired = True
                except Exception as e:
                    print(f"Error parsing custom time: {e}")
        
        if expired:
            access_grants_col.update_one({"_id": g["_id"]}, {"$set": {"is_active": False}})
        else:
            g["_id"] = str(g["_id"])
            active_grants.append(g)

    return jsonify(active_grants), 200


# =============================================================================
# 13. PERFORMANCE MANAGEMENT SYSTEM (PMS 2.0)
# =============================================================================

@app.route("/api/admin/pms-template", methods=["POST"])
@token_required
def save_pms_template():
    """
    SAVES OR UPDATES A PMS TEMPLATE.
    Managers assign a template of questions to SPECIFIC EMPLOYEES using the 'assigned_to' array.
    """
    if request.user.get("role") not in ["admin", "manager"]: 
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.json 
    dept_to_update = data.get("department", "All")
    
    if request.user.get("role") == "manager":
        dept_to_update = request.user.get("department")

    assigned_to_list = data.get("assigned_to", [])
    if not assigned_to_list:
        return jsonify({"message": "You must assign the template to at least one employee."}), 400

    template_record = {
        "department": dept_to_update,
        "sessions": data.get("sessions", []),
        "assigned_to": assigned_to_list,
        "cycle_name": data.get("cycle_name", ""),
        "due_date": data.get("due_date", ""),
        "created_by": str(request.user["_id"]),
        "updated_at": datetime.now(timezone.utc)
    }

    # We update based on the department to maintain departmental templates, 
    # but the assigned_to list dictates who actually SEES it.
    pms_templates_col.update_one(
        {"department": dept_to_update},
        {"$set": template_record},
        upsert=True
    )
    
    return jsonify({"message": f"PMS Form Assigned to {len(assigned_to_list)} employees successfully!"}), 200


@app.route("/api/pms-template", methods=["GET"])
@token_required
def get_pms_template():
    """
    FETCHES THE PMS TEMPLATE FOR THE EMPLOYEE.
    Ensures the form is only sent to the user if their ID is in the 'assigned_to' array.
    """
    uid = str(request.user["_id"])
    
    # Strictly query the templates collection to find ANY template where this user's ID is assigned
    template = pms_templates_col.find_one({"assigned_to": uid}, {"_id": 0})
    
    if not template:
        # User is not targeted for any evaluations this cycle
        return jsonify({"sessions": [], "message": "No active evaluations assigned to you."}), 200
        
    return jsonify(template), 200


@app.route("/api/pms/submit", methods=["POST"])
@token_required
def submit_pms_review():
    """
    EMPLOYEE SUBMITS THEIR COMPLETED PMS FORM.
    Saves all details (session name, question, descriptive, scales, remarks).
    """
    uid = str(request.user["_id"])
    data = request.json
    month = datetime.now(IST).strftime("%Y-%m")

    if pms_reviews_col.find_one({"user_id": uid, "month": month}):
        return jsonify({"message": "You have already submitted your Self Assessment for this month."}), 400

    template = pms_templates_col.find_one({"assigned_to": uid}, {"cycle_name": 1})
    cycle_name = template.get("cycle_name", "") if template else ""

    submission = {
        "user_id": uid,
        "department": request.user.get("department"),
        "manager_id": request.user.get("manager_id"),
        "month": month,
        "cycle_name": cycle_name,
        "responses": data.get("responses", []),
        "status": "Pending Review",
        "self_assessment_date": datetime.now(timezone.utc),
        "manager_review_date": None,
        "manager_scores": [],
        "manager_feedback": "",
        "overall_rating": None,
        "development_plan": "",
        "manager_comments": [],
        "acknowledged_by_employee": False
    }

    pms_reviews_col.insert_one(submission)
    return jsonify({"message": "Self Assessment Submitted for Manager Review."}), 201


@app.route("/api/manager/pms", methods=["GET"])
@token_required
def get_manager_pms():
    """ Fetches all pending and completed PMS reviews for a manager's department. """
    if request.user.get("role") not in ["manager", "admin"]: return jsonify({"message": "Unauthorized"}), 403
    
    my_dept = request.user.get("department")
    query = {"department": my_dept} if request.user.get("role") == "manager" else {}
    
    reviews = list(pms_reviews_col.find(query).sort("self_assessment_date", -1))
    uids = []
    for r in reviews:
        try: uids.append(ObjectId(r["user_id"]))
        except Exception: pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": uids}}, {"name": 1})}

    rows = []
    for r in reviews:
        r["_id"] = str(r["_id"])
        r["employee_name"] = emp_map.get(r.get("user_id"), "Unknown")
        rows.append(r)
    return jsonify(rows), 200


@app.route("/api/manager/pms-calibration", methods=["GET"])
@token_required
def pms_calibration():
    """
    Returns a side-by-side self-avg vs manager-avg comparison for every team member
    for a given month. Used by the Calibration view in the manager dashboard.
    """
    if request.user.get("role") not in ["manager", "admin"]:
        return jsonify({"message": "Unauthorized"}), 403

    month = request.args.get("month", datetime.now(IST).strftime("%Y-%m"))

    if request.user.get("role") == "manager":
        query = {"month": month, "department": request.user.get("department")}
    else:
        query = {"month": month}

    reviews = list(pms_reviews_col.find(query))

    uids = []
    for r in reviews:
        try: uids.append(ObjectId(r["user_id"]))
        except Exception: pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": uids}}, {"name": 1})}

    def _to_num(v):
        try: return float(v)
        except (TypeError, ValueError): return None

    result = []
    for r in reviews:
        self_scores = [_to_num(res.get("self_score")) for res in r.get("responses", []) if _to_num(res.get("self_score")) is not None]
        mgr_scores  = [_to_num(ms.get("score"))      for ms  in r.get("manager_scores", []) if _to_num(ms.get("score")) is not None]

        result.append({
            "employee_name": emp_map.get(r.get("user_id"), "Unknown"),
            "self_avg":    round(sum(self_scores) / len(self_scores), 2) if self_scores else None,
            "manager_avg": round(sum(mgr_scores)  / len(mgr_scores),  2) if mgr_scores  else None,
            "overall_rating": r.get("overall_rating")
        })

    return jsonify(result), 200


@app.route("/api/manager/finalize-pms", methods=["POST"])
@token_required
def finalize_pms_review():
    """ 
    MANAGER SUBMITS THEIR GRADING.
    Locks the review and adds manager scores and summary feedback.
    """
    if request.user.get("role") not in ["manager", "admin"]: return jsonify({"message": "Unauthorized"}), 403
    data = request.json

    review_id = data.get("review_id")
    if not review_id:
        return jsonify({"message": "Review ID missing"}), 400

    overall_rating = data.get("overall_rating")
    VALID_RATINGS = {"Exceptional", "Exceeds Expectations", "Meets Expectations", "Needs Improvement", "Unsatisfactory"}
    if overall_rating and overall_rating not in VALID_RATINGS:
        return jsonify({"message": f"Invalid overall_rating. Allowed: {', '.join(sorted(VALID_RATINGS))}"}), 400

    try:
        pms_reviews_col.update_one(
            {"_id": ObjectId(review_id)},
            {"$set": {
                "manager_scores": data.get("manager_scores", []),
                "manager_feedback": data.get("manager_feedback", ""),
                "overall_rating": overall_rating,
                "development_plan": data.get("development_plan", ""),
                "manager_comments": data.get("manager_comments", []),
                "status": "Manager Review Completed",
                "manager_review_date": datetime.now(timezone.utc)
            }}
        )
    except Exception:
        return jsonify({"message": "Invalid review ID"}), 400

    return jsonify({"message": "PMS Evaluation Review Completed successfully!"}), 200


@app.route("/api/my/pms", methods=["GET"])
@token_required
def my_pms():
    """
    EMPLOYEE FETCHES THEIR PMS HISTORY.
    Returns the complete document, including all responses, manager scores, and manager feedback.
    """
    uid = str(request.user["_id"])
    rows = []
    for p in pms_reviews_col.find({"user_id": uid}).sort("month", -1):
        p["_id"] = str(p["_id"])
        rows.append(p)
    return jsonify(rows), 200


@app.route("/api/pms/acknowledge", methods=["POST"])
@token_required
def acknowledge_pms_review():
    """
    Employee acknowledges their completed PMS review.
    Only the owner of the review may acknowledge it, and only once the manager has finalised it.
    """
    uid = str(request.user["_id"])
    data = request.json
    review_id = data.get("review_id")

    if not review_id:
        return jsonify({"message": "review_id is required"}), 400

    try:
        review = pms_reviews_col.find_one({"_id": ObjectId(review_id)})
    except Exception:
        return jsonify({"message": "Invalid review ID"}), 400

    if not review:
        return jsonify({"message": "Review not found"}), 404

    if review.get("user_id") != uid:
        return jsonify({"message": "Unauthorized. You can only acknowledge your own review."}), 403

    if review.get("status") != "Manager Review Completed":
        return jsonify({"message": "Review has not been finalised by your manager yet."}), 400

    pms_reviews_col.update_one(
        {"_id": ObjectId(review_id)},
        {"$set": {"acknowledged_by_employee": True}}
    )
    return jsonify({"message": "Review acknowledged"}), 200


@app.route("/api/admin/pms-dashboard", methods=["GET"])
@token_required
def pms_dashboard():
    """ Dashboard analytics for PMS completion and scoring. """
    if request.user.get("role") not in ["admin", "manager"]: return jsonify({"message": "Unauthorized"}), 403
    
    month = request.args.get("month", datetime.now(IST).strftime("%Y-%m"))
    dashboard_data = {}
    
    if request.user.get("role") == "manager":
        departments = [request.user.get("department")]
    else:
        departments = users_col.distinct("department")
        
    for d in departments:
        if d:
            total_emps = users_col.count_documents({"department": d, "role": "employee"})
            dashboard_data[d] = {"total_employees": total_emps, "completed_pms": 0, "total_score": 0, "avg_score": 0}
            
    reviews = pms_reviews_col.find({"month": month, "status": "Manager Review Completed", "department": {"$in": departments}})
    
    for r in reviews:
        dept = r.get("department")
        if dept and dept in dashboard_data:
            dashboard_data[dept]["completed_pms"] += 1
            def _to_num(v):
                try: return float(v)
                except (TypeError, ValueError): return 0
            mgr_total = sum(_to_num(ms.get('score', 0)) for ms in r.get('manager_scores', []))
            dashboard_data[dept]["total_score"] += mgr_total

    final_output = []
    for dept, data in dashboard_data.items():
        if data["completed_pms"] > 0:
            data["avg_score"] = round(data["total_score"] / data["completed_pms"], 2)
        else:
            data["avg_score"] = 0
            
        final_output.append({
            "department": dept,
            "average_score": data["avg_score"],
            "total_employees": data["total_employees"],
            "completed_pms": data["completed_pms"]
        })
        
    return jsonify(final_output), 200


@app.route("/api/admin/export-pms", methods=["GET"])
@token_required
def export_pms():
    """ Generates a downloadable CSV report of the PMS data. """
    if request.user.get("role") not in ["admin", "manager"]: return jsonify({"message": "Unauthorized"}), 403
    
    month = request.args.get("month", datetime.now(IST).strftime("%Y-%m"))
    
    query = {"month": month}
    if request.user.get("role") == "manager":
        query["department"] = request.user.get("department")
    
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Employee Name", "Department", "Month", "Status", "Self Score Total", "Manager Score Total", "Manager Feedback"])
    
    reviews = list(pms_reviews_col.find(query).sort("department", 1))
    uids = []
    for r in reviews:
        try: uids.append(ObjectId(r["user_id"]))
        except Exception: pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": uids}}, {"name": 1})}

    def _to_num(v):
        try: return float(v)
        except (TypeError, ValueError): return 0

    for r in reviews:
        emp_name = emp_map.get(r.get("user_id"), "Unknown")
        self_total = sum(_to_num(res.get('self_score', 0)) for res in r.get('responses', []))
        mgr_total = sum(_to_num(ms.get('score', 0)) for ms in r.get('manager_scores', []))
        
        cw.writerow([
            emp_name, 
            r.get("department"), 
            r.get("month"), 
            r.get("status"), 
            self_total, 
            mgr_total, 
            r.get("manager_feedback", "")
        ])
    
    output = io.BytesIO(si.getvalue().encode('utf-8'))
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name=f'PMS_Report_{month}.csv')


# =============================================================================
# 14. ATTENDANCE & CAMERA LOGGING
# =============================================================================

@app.route("/api/attendance/checkin-photo", methods=["POST"])
@token_required
def checkin_photo():
    """ 
    Handles morning check-ins using a photo capture.
    Uploads photo to Cloudinary and logs time accurately based on cutoff windows.
    """
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    current_time = now_ist.time()
    employee_shift = request.user.get("shift", "morning")

    # Night-shift hours 0–3 AM belong to the previous calendar day's shift date
    if employee_shift == "night" and now_ist.hour < 4:
        today = (now_ist - timedelta(days=1)).date()
    else:
        today = now_ist.date()
    today_str = str(today)

    if leaves_col.find_one({"user_id": uid, "status": "Approved", "from_date": {"$lte": today_str}, "to_date": {"$gte": today_str}}):
        return jsonify({"message": "You have an approved leave for today. Attendance not required."}), 200

    if attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today_str}):
        return jsonify({"message": "Already checked in!"}), 400

    status_indicator = "Unknown"
    day_type = "full"

    if employee_shift == "morning":
        TIME_1000 = time(10, 0)
        TIME_1015 = time(10, 15)
        TIME_1300 = time(13, 0)
        TIME_1400 = time(14, 0)

        if current_time < TIME_1000:
            status_indicator = "Present (On-Time)"
            day_type = "full"
        elif TIME_1000 <= current_time < TIME_1015:
            status_indicator = "Present (Late)"
            day_type = "full"
        elif TIME_1015 <= current_time < TIME_1300:
            return jsonify({
                "message": "Check-in blocked. You missed the morning window (ended 10:15 AM). Please wait until 1:00 PM for Half Day check-in."
            }), 400
        elif TIME_1300 <= current_time < TIME_1400:
            status_indicator = "Half Day"
            day_type = "half-day"
        else:
            return jsonify({
                "message": "Check-in closed for the day. Marked as Absent (Full Day)."
            }), 400

    elif employee_shift == "general":  # general shift check-in: 8:00 AM – 10:00 AM
        TIME_0800 = time(8, 0)
        TIME_1000 = time(10, 0)
        if not (TIME_0800 <= current_time < TIME_1000):
            return jsonify({
                "message": "Check-in is allowed 8:00 AM – 10:00 AM for General Shift."
            }), 400
        status_indicator = "Present (On-Time)"
        day_type = "full"

    else:  # night shift check-in: 5:30 PM – 7:15 PM (late from 7:00 PM)
        TIME_1730 = time(17, 30)
        TIME_1900 = time(19, 0)
        TIME_1915 = time(19, 15)

        if current_time < TIME_1730:
            return jsonify({
                "message": "Check-in opens at 5:30 PM for Night Shift."
            }), 400
        elif current_time < TIME_1900:
            status_indicator = "Present (On-Time)"
        elif current_time <= TIME_1915:
            status_indicator = "Present (Late)"
        else:
            return jsonify({
                "message": "Check-in closed for Night Shift (window ended 7:15 PM)."
            }), 400
        day_type = "full"

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image data received from frontend."}), 400

    try:
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        photo_url = upload_result.get("secure_url")
    except Exception as e:
        print("Cloudinary Upload Error:", e)
        return jsonify({"message": "Image upload failed. Check connection."}), 500

    attendance_col.insert_one({
        "user_id": uid,
        "type": "checkin",
        "date": today_str,
        "day_type": day_type,
        "time": datetime.now(timezone.utc),
        "photo_url": photo_url, 
        "status_indicator": status_indicator 
    })

    return jsonify({"message": f"Checked in successfully ({status_indicator})"}), 200


@app.route("/api/attendance/checkout-photo", methods=["POST"])
@token_required
def checkout_photo():
    """ 
    Handles evening check-outs. Calculates final day type and flags early departures.
    """
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    current_time = now_ist.time()
    employee_shift = request.user.get("shift", "morning")

    # Night-shift hours up to 7 AM belong to the previous calendar day's shift date,
    # so a post-midnight checkout pairs with that night's check-in
    if employee_shift == "night" and now_ist.hour < 7:
        today = (now_ist - timedelta(days=1)).date()
    else:
        today = now_ist.date()

    checkin = attendance_col.find_one({"user_id": uid, "type": "checkin", "date": str(today)})
    if not checkin:
        return jsonify({"message": "You must Check-In first before Checking Out."}), 400

    if attendance_col.find_one({"user_id": uid, "type": "checkout", "date": str(today)}):
        return jsonify({"message": "Already checked out for today!"}), 400

    final_day_type = checkin.get("day_type", "full")
    status_indicator = "On Time"

    if employee_shift == "morning":
        HALF_DAY_OUT_START = time(13, 0)
        HALF_DAY_OUT_END = time(14, 0)
        FULL_DAY_OUT_START = time(18, 0)
        LATE_CHECKOUT_START = time(19, 30)

        checkin_dt = utc_to_ist(checkin["time"])
        checkin_time = checkin_dt.time()

        if checkin_time < time(13, 0) and (HALF_DAY_OUT_START <= current_time <= HALF_DAY_OUT_END):
            final_day_type = "half-day"
            attendance_col.update_one({"_id": checkin["_id"]}, {"$set": {"day_type": "half-day"}})

        if current_time > LATE_CHECKOUT_START:
            status_indicator = "Late Checkout"
        elif current_time < FULL_DAY_OUT_START:
            if final_day_type == "half-day" and (HALF_DAY_OUT_START <= current_time <= HALF_DAY_OUT_END):
                status_indicator = "On Time"
            else:
                status_indicator = "Early"
        else:
            status_indicator = "On Time"

    elif employee_shift == "general":  # general shift checkout: 5:00 PM – 7:00 PM
        if not (time(17, 0) <= current_time < time(19, 0)):
            return jsonify({
                "message": "Check-out is allowed 5:00 PM – 7:00 PM for General Shift."
            }), 400
        status_indicator = "On Time"

    else:  # night shift checkout: 7 PM – 7 AM
        hour = now_ist.hour
        if not (hour >= 19 or hour < 7):
            return jsonify({
                "message": "Check-out is not allowed outside your shift hours (Night Shift: 7 PM – 7 AM)"
            }), 400
        status_indicator = "On Time"

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image data provided"}), 400

    try:
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        photo_url = upload_result.get("secure_url")
    except Exception as e:
        print("Cloudinary Upload Error:", e)
        return jsonify({"message": "Image upload failed"}), 500

    attendance_col.insert_one({
        "user_id": uid,
        "type": "checkout",
        "date": str(today),
        "time": datetime.now(timezone.utc),
        "photo_url": photo_url,
        "day_type": final_day_type,
        "status_indicator": status_indicator
    })

    return jsonify({"message": f"Checked out successfully ({final_day_type}, {status_indicator})"}), 200


@app.route("/api/my/attendance", methods=["GET"])
@token_required
def my_attendance():
    """ Fetches attendance log for the logged-in user. """
    uid = str(request.user["_id"])
    rows = []

    for a in attendance_col.find({"user_id": uid}).sort("time", -1):
        a["_id"] = str(a["_id"])
        a["time"] = format_datetime_ist(a["time"])
        rows.append(a)

    return jsonify(rows), 200


@app.route("/api/admin/attendance/<emp_id>", methods=["GET"])
@token_required
def admin_employee_attendance(emp_id):
    """
    Fetches attendance for a specific employee. 
    Accessible by Admin, or users with delegated access.
    """
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    
    if role != "admin" and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    emp = users_col.find_one({"_id": ObjectId(emp_id)})
    if not emp:
        return jsonify({"message": "Employee not found"}), 404

    records = []
    for a in attendance_col.find({"user_id": emp_id}).sort("time", -1):
        a["_id"] = str(a["_id"])
        a["time"] = format_datetime_ist(a["time"])
        a["employee_name"] = emp.get("name")
        a["employee_email"] = emp.get("email")
        records.append(a)

    return jsonify(records), 200


# =============================================================================
# 15. LEAVE MANAGEMENT
# =============================================================================

@app.route("/api/leaves", methods=["POST"])
@token_required
def apply_leave():
    """
    Handles employee and manager leave applications. 
    Parses start/end dates and attempts to upload any attached medical files to Cloudinary.
    """
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    from_date = request.form.get("from_date")
    to_date = request.form.get("to_date")
    
    if not from_date and request.form.get("date"):
        from_date = request.form.get("date")
        to_date = request.form.get("date")

    leave_type = request.form.get("type", "full")
    period = request.form.get("period")
    reason = request.form.get("reason", "")

    if not from_date or not to_date:
        return jsonify({"message": "Start and End dates are required"}), 400

    try:
        f_date = datetime.strptime(from_date, "%Y-%m-%d").date()
        t_date = datetime.strptime(to_date, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"message": "Invalid date format."}), 400

    if t_date < f_date:
        return jsonify({"message": "End date cannot be before start date"}), 400

    now_ist_date = datetime.now(IST).date()
    max_past_date = now_ist_date - timedelta(days=7) 

    if f_date < max_past_date:
        return jsonify({"message": f"Leave application for past dates is limited to 7 days."}), 400

    attachment_url = None
    file = request.files.get("attachment")
    
    if file:
        try:
            upload_result = cloudinary.uploader.upload(file, folder="leave_attachments")
            attachment_url = upload_result.get("secure_url")
        except Exception:
            return jsonify({"message": "File upload failed"}), 500

    leave = {
        "user_id": str(request.user["_id"]),
        "from_date": from_date,
        "to_date": to_date,
        "date": from_date, 
        "type": leave_type,
        "period": period,
        "reason": reason,
        "status": "Pending",
        "manager_status": "Pending",
        "admin_status": "Pending",
        "applied_at": datetime.now(timezone.utc),
        "attachment_url": attachment_url
    }

    res = leaves_col.insert_one(leave)
    return jsonify({"message": "Applied", "id": str(res.inserted_id)}), 201


@app.route("/api/admin/leaves", methods=["GET"])
@token_required
def admin_view_leaves():
    """ 
    Returns leaves contextually based on user role and delegated grants. 
    Managers see their department; Admins/Delegated see everyone.
    """
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    
    if role not in ["admin", "manager"] and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    query = {}
    
    if role == "manager" and not has_delegated:
        my_dept = request.user.get("department")
        dept_users = [str(u["_id"]) for u in users_col.find({"department": my_dept}, {"_id": 1})]
        query = {"user_id": {"$in": dept_users}}

    rows = []
    # Only name + department are needed for enrichment — avoid pulling full docs
    employees = {str(e["_id"]): e for e in users_col.find({}, {"name": 1, "department": 1})}
    
    for l in leaves_col.find(query).sort("applied_at", -1):
        l["_id"] = str(l["_id"])
        user = employees.get(l.get("user_id"))
        
        if user:
            l["employee_name"] = user["name"]
            l["employee_department"] = user.get("department")
        else:
            l["employee_name"] = "Unknown"
            l["employee_department"] = ""
        
        l["applied_at_str"] = l["applied_at"].strftime("%Y-%m-%d") if l.get("applied_at") else l.get("date")
            
        rows.append(l)

    return jsonify(rows), 200


@app.route("/api/admin/leaves/<leave_id>", methods=["PUT"])
@token_required
def update_leave(leave_id):
    """
    Approve or reject leaves with role-based logic.
    A leave is only strictly "Approved" if BOTH manager and admin approve it.
    """
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    
    if role not in ["admin", "manager"] and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    action = data.get("status")

    if action not in ("Approved", "Rejected", "Pending"):
        return jsonify({"message": "Invalid status"}), 400

    update_fields = {}

    if role == "admin":
        update_fields["admin_status"] = action
    elif has_delegated:
        if has_delegated.get("access_level") == "view_only":
            return jsonify({"message": "Unauthorized: Your delegated access is View Only."}), 403
        update_fields["admin_status"] = action
    elif role == "manager":
        update_fields["manager_status"] = action

    leaves_col.update_one({"_id": ObjectId(leave_id)}, {"$set": update_fields})

    leave = leaves_col.find_one({"_id": ObjectId(leave_id)})
    ms = leave.get("manager_status", "Pending")
    as_ = leave.get("admin_status", "Pending")

    if ms == "Rejected" or as_ == "Rejected":
        final_status = "Rejected"
    elif ms == "Approved" and as_ == "Approved":
        final_status = "Approved"
    else:
        final_status = "Pending"

    leaves_col.update_one({"_id": ObjectId(leave_id)}, {"$set": {"status": final_status}})

    try:
        user = users_col.find_one({"_id": ObjectId(leave["user_id"])})
        if user:
            threading.Thread(target=send_email, args=(user["email"], "Leave Update", f"Your leave status is now: {final_status}"), daemon=True).start()
    except Exception as e:
        print("Email notification error:", e)

    return jsonify({"message": "Leave updated successfully"}), 200


@app.route("/api/my/leaves", methods=["GET"])
@token_required
def my_leaves():
    """ Fetches the authenticated user's leave history. """
    uid = str(request.user["_id"])
    rows = []
    for l in leaves_col.find({"user_id": uid}).sort("applied_at", -1):
        l["_id"] = str(l["_id"])
        rows.append(l)
    return jsonify(rows), 200


# =============================================================================
# 16. NEW: ASSET MANAGEMENT (DUAL-APPROVAL WORKFLOW)
# =============================================================================

@app.route("/api/assets/request", methods=["POST"])
@token_required
def request_asset():
    """
    EMPLOYEE ROUTE: Submits a request for new hardware, laptops, or equipment.
    The request is saved in the database with a dual-pending state.
    """
    uid = str(request.user["_id"])
    data = request.json
    
    asset_name = data.get("asset_name")
    reason = data.get("reason")
    
    if not asset_name or not reason:
        return jsonify({"message": "Asset name and reason are strictly required."}), 400
        
    asset_request = {
        "user_id": uid,
        "employee_name": request.user.get("name"),
        "department": request.user.get("department"),
        "asset_name": asset_name,
        "reason": reason,
        "manager_status": "Pending",
        "admin_status": "Pending",
        "status": "Pending", # Final overarching status combining the two above
        "created_at": datetime.now(timezone.utc)
    }
    
    res = assets_col.insert_one(asset_request)
    return jsonify({"message": "Asset requested successfully.", "id": str(res.inserted_id)}), 201


@app.route("/api/assets/my-requests", methods=["GET"])
@token_required
def get_my_assets():
    """
    EMPLOYEE ROUTE: Retrieves the logged-in employee's personal asset request history.
    Used to display tracking status on the Employee Dashboard.
    """
    uid = str(request.user["_id"])
    rows = []
    
    # Sort newest requests first
    for asset in assets_col.find({"user_id": uid}).sort("created_at", -1):
        asset["_id"] = str(asset["_id"])
        rows.append(asset)
        
    return jsonify(rows), 200


@app.route("/api/manager/assets", methods=["GET"])
@token_required
def manager_get_assets():
    """
    MANAGER ROUTE: Retrieves all asset requests strictly for employees within their specific department.
    """
    if request.user.get("role") not in ["manager", "admin"]:
        return jsonify({"message": "Unauthorized access to team assets."}), 403
        
    my_dept = request.user.get("department")
    # If the user is an admin acting as a manager, they can see all, otherwise restrict to dept
    query = {"department": my_dept} if request.user.get("role") == "manager" else {}
    
    rows = []
    for asset in assets_col.find(query).sort("created_at", -1):
        asset["_id"] = str(asset["_id"])
        rows.append(asset)
        
    return jsonify(rows), 200


@app.route("/api/manager/assets/<asset_id>", methods=["PUT"])
@token_required
def manager_update_asset(asset_id):
    """
    MANAGER ROUTE: Approves or rejects an asset request.
    This acts as the first gatekeeper. If rejected here, the final status is immediately marked Rejected.
    """
    if request.user.get("role") not in ["manager", "admin"]:
        return jsonify({"message": "Unauthorized action."}), 403
        
    data = request.json
    manager_status = data.get("manager_status")
    
    if manager_status not in ["Approved", "Rejected"]:
        return jsonify({"message": "Invalid manager status provided."}), 400
        
    asset = assets_col.find_one({"_id": ObjectId(asset_id)})
    if not asset:
        return jsonify({"message": "Asset request not found in database."}), 404
        
    update_data = {"manager_status": manager_status}
    
    # Immediate kill switch if the manager rejects the request
    if manager_status == "Rejected":
        update_data["status"] = "Rejected"
        
    assets_col.update_one({"_id": ObjectId(asset_id)}, {"$set": update_data})
    
    return jsonify({"message": f"Asset successfully marked as {manager_status} by Manager."}), 200


@app.route("/api/admin/assets", methods=["GET"])
@token_required
def admin_get_assets():
    """
    ADMIN ROUTE: Retrieves all organizational asset requests for final review and provisioning.
    """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized access. Admins only."}), 403
        
    rows = []
    for asset in assets_col.find().sort("created_at", -1):
        asset["_id"] = str(asset["_id"])
        rows.append(asset)
        
    return jsonify(rows), 200


@app.route("/api/admin/assets/<asset_id>", methods=["PUT"])
@token_required
def admin_update_asset(asset_id):
    """
    ADMIN ROUTE: Provides final approval or rejection for an asset request.
    This triggers the final 'status' change in the database.
    """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized action. Admins only."}), 403
        
    data = request.json
    admin_status = data.get("admin_status")
    
    if admin_status not in ["Approved", "Rejected"]:
        return jsonify({"message": "Invalid admin status provided."}), 400
        
    asset = assets_col.find_one({"_id": ObjectId(asset_id)})
    if not asset:
        return jsonify({"message": "Asset request not found in database."}), 404
        
    update_data = {"admin_status": admin_status}
    
    # Calculate the final overarching status combining both tiers
    mgr_status = asset.get("manager_status", "Pending")
    
    if admin_status == "Rejected" or mgr_status == "Rejected":
        update_data["status"] = "Rejected"
    elif admin_status == "Approved" and mgr_status == "Approved":
        update_data["status"] = "Approved"
    else:
        update_data["status"] = "Pending"
        
    assets_col.update_one({"_id": ObjectId(asset_id)}, {"$set": update_data})

    return jsonify({"message": f"Asset successfully marked as {admin_status} by Master Admin."}), 200


@app.route("/api/admin/assets/<asset_id>/assign", methods=["POST"])
@token_required
def assign_asset_to_office_admin(asset_id):
    """Send assignment notification emails to one or more office admins."""
    if request.user.get("role") != "admin":
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


# =============================================================================
# 17. ANNOUNCEMENTS, CORRECTIONS & NOTIFICATIONS
# =============================================================================

@app.route("/api/announcements", methods=["POST"])
@token_required
def create_announcement():
    """ Creates a new system-wide announcement. (Admin Only) """
    if request.user.get("role") != "admin": 
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.json
    announcements_col.insert_one({
        "title": data.get("title"),
        "message": data.get("message"),
        "created_at": datetime.now(timezone.utc)
    })
    return jsonify({"message": "Announcement broadcasted"}), 201


@app.route("/api/announcements", methods=["GET"])
@token_required
def get_announcements():
    """ Fetches all active announcements. Viewable by everyone. """
    rows = []
    for a in announcements_col.find().sort("created_at", -1):
        a["_id"] = str(a["_id"])
        rows.append(a)
    return jsonify(rows), 200


@app.route("/api/announcements/<ann_id>", methods=["PUT"])
@token_required
def update_announcement(ann_id):
    """ 
    Updates an existing announcement's title and message. (Admin Only) 
    Provides the backend logic for the frontend "Edit" feature.
    """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized access. Admins only."}), 403
        
    data = request.json
    title = data.get("title")
    message = data.get("message")
    
    if not title or not message:
        return jsonify({"message": "Title and message are required fields."}), 400
        
    result = announcements_col.update_one(
        {"_id": ObjectId(ann_id)},
        {"$set": {
            "title": title,
            "message": message,
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    
    if result.matched_count == 0:
        return jsonify({"message": "Announcement not found in the database."}), 404
        
    return jsonify({"message": "Announcement successfully updated."}), 200


@app.route("/api/announcements/<ann_id>", methods=["DELETE"])
@token_required
def delete_announcement(ann_id):
    """ 
    Deletes (recalls) an announcement from the system. (Admin Only) 
    Provides the backend logic for the frontend "Recall" feature.
    """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized access. Admins only."}), 403
        
    result = announcements_col.delete_one({"_id": ObjectId(ann_id)})
    
    if result.deleted_count == 0:
        return jsonify({"message": "Announcement not found or already deleted."}), 404
        
    return jsonify({"message": "Announcement recalled and deleted successfully."}), 200


@app.route("/api/attendance/request-correction", methods=["POST"])
@token_required
def request_correction():
    """ Allows an employee to request a fix for a missed or wrong punch. Limits to 3 per month. """
    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    month_str = now_ist.strftime("%Y-%m")
    
    usage_count = corrections_col.count_documents({"user_id": uid, "month": month_str})
    
    if usage_count >= 3:
        return jsonify({"message": "Monthly limit of 3 corrections reached"}), 400

    data = request.json
    correction = {
        "user_id": uid,
        "manager_id": request.user.get("manager_id"),
        "attendance_id": data.get("attendance_id"),
        "new_time": data.get("new_time"),
        "reason": data.get("reason"),
        "status": "Pending",
        "month": month_str,
        "created_at": datetime.now(timezone.utc)
    }
    corrections_col.insert_one(correction)
    return jsonify({"message": "Correction request dispatched"}), 201


@app.route("/api/manager/corrections", methods=["GET"])
@token_required
def manager_corrections():
    """ Fetches pending attendance correction requests for the manager's team. """
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    
    my_dept = request.user.get("department")
    dept_emp_list = list(users_col.find({"department": my_dept}, {"name": 1}))
    dept_users = [str(u["_id"]) for u in dept_emp_list]
    emp_map = {str(u["_id"]): u["name"] for u in dept_emp_list}

    query = {"$or": [{"manager_id": str(request.user["_id"])}, {"user_id": {"$in": dept_users}}]}

    rows = []
    for c in corrections_col.find(query).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        c["employee_name"] = emp_map.get(c.get("user_id"), "Unknown")
        rows.append(c)
    return jsonify(rows), 200


@app.route("/api/my/corrections", methods=["GET"])
@token_required
def my_corrections():
    """ Fetches the employee's own correction history. """
    uid = str(request.user["_id"])
    rows = []
    for c in corrections_col.find({"user_id": uid}).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows), 200


# =============================================================================
# USER PROFILE (birthday, phone, bio)
# =============================================================================

@app.route("/api/my/profile", methods=["GET"])
@token_required
def get_my_profile():
    """ Returns the current user's editable profile fields. """
    user = request.user
    birthday = user.get("birthday")
    return jsonify({
        "birthday": birthday.strftime("%Y-%m-%d") if isinstance(birthday, datetime) else birthday,
        "phone": user.get("phone"),
        "bio": user.get("bio")
    }), 200


@app.route("/api/my/profile", methods=["PUT"])
@token_required
def update_my_profile():
    """ Updates birthday, phone, and/or bio on the current user document. """
    data = request.json or {}
    update = {}

    if "birthday" in data:
        raw = data["birthday"]
        if raw:
            try:
                # Store as midnight datetime so MongoDB $month/$dayOfMonth work
                update["birthday"] = datetime.strptime(str(raw)[:10], "%Y-%m-%d")
            except ValueError:
                return jsonify({"message": "Invalid birthday format. Use YYYY-MM-DD."}), 400
        else:
            update["birthday"] = None

    if "phone" in data:
        update["phone"] = str(data["phone"]).strip() if data["phone"] else None

    if "bio" in data:
        update["bio"] = str(data["bio"]).strip() if data["bio"] else None

    if update:
        users_col.update_one({"_id": request.user["_id"]}, {"$set": update})

    return jsonify({"success": True}), 200


@app.route("/api/manager/approve-correction", methods=["POST"])
@token_required
def approve_correction():
    """
    Manager approves/rejects an attendance fix.
    If approved, it injects a new synthetic attendance record into the database.
    """
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    cid = data.get("id")
    action = data.get("action")
    
    correction = corrections_col.find_one({"_id": ObjectId(cid)})
    if not correction: return jsonify({"message": "Not found"}), 404
    
    corrections_col.update_one({"_id": ObjectId(cid)}, {"$set": {"status": action}})
    
    if action == "Approved":
        try:
            new_time_str = correction["new_time"]
            if "T" in new_time_str and not new_time_str.endswith("Z") and "+" not in new_time_str:
                new_dt = datetime.fromisoformat(new_time_str)
            else:
                new_dt = datetime.fromisoformat(new_time_str.replace("Z", "+00:00"))

            # Determine the original record type (checkin/checkout) from the attendance reference
            original_record = attendance_col.find_one({"_id": ObjectId(correction["attendance_id"])}) if correction.get("attendance_id") else None
            record_type = original_record.get("type", "checkin") if original_record else "checkin"

            attendance_col.insert_one({
                "user_id": correction["user_id"],
                "type": record_type,
                "date": str(new_dt.date()),
                "time": new_dt,
                "photo_url": None,
                "status_indicator": "Corrected",
                "correction_ref": cid
            })
        except Exception as e:
            print("Error updating attendance log:", e)
    
    return jsonify({"message": f"Correction {action}"}), 200


@app.route("/api/notifications/counts", methods=["GET"])
@token_required
def get_notification_counts():
    """ Fetch dynamic badge counts for the dashboard sidebar/quick-launch items. """
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    counts = {
        "leaves": 0,
        "pms": 0,
        "corrections": 0,
        "assets": 0,
        "announcements": 0,
    }

    if role == "manager":
        my_dept = request.user.get("department")
        dept_users = [str(u["_id"]) for u in users_col.find({"department": my_dept}, {"_id": 1})]

        counts["leaves"] = leaves_col.count_documents({
            "user_id": {"$in": dept_users},
            "status": "Pending",
            "manager_status": "Pending"
        })

        counts["pms"] = pms_reviews_col.count_documents({
            "user_id": {"$in": dept_users},
            "status": "Pending Review"
        })

        counts["corrections"] = corrections_col.count_documents({
            "user_id": {"$in": dept_users},
            "status": "Pending"
        })

        counts["assets"] = assets_col.count_documents({
            "department": my_dept,
            "manager_status": "Pending"
        })

    elif role == "admin" or has_delegated:
        # Leaves still awaiting the admin's approval (not yet finalised/rejected)
        counts["leaves"] = leaves_col.count_documents({
            "status": "Pending",
            "admin_status": "Pending"
        })

        # Asset requests awaiting final admin approval
        counts["assets"] = assets_col.count_documents({
            "status": "Pending",
            "admin_status": "Pending"
        })
        # announcements stays 0 — no unseen-announcement tracking yet, so the
        # badge hides rather than showing the static total.

    return jsonify(counts), 200


@app.route("/api/notifications/birthdays", methods=["GET"])
@token_required
def birthday_notifications():
    """
    Returns users whose birthday (month + day) matches today.
    Scoped by role: employees see their department, managers see their
    department, admins see everyone. Always returns [] on any error.
    """
    try:
        today = datetime.now(IST)
        uid = str(request.user["_id"])
        role = request.user.get("role")
        dept = request.user.get("department")

        # Match BSON Date fields only, then filter by month+day via aggregation
        base_filter = {
            "birthday": {"$type": "date"},
            "$expr": {
                "$and": [
                    {"$eq": [{"$month": "$birthday"}, today.month]},
                    {"$eq": [{"$dayOfMonth": "$birthday"}, today.day]}
                ]
            }
        }

        if role in ("employee", "manager"):
            base_filter["department"] = dept

        celebrants = list(users_col.find(base_filter, {"name": 1}))

        return jsonify([
            {"name": u["name"], "is_self": str(u["_id"]) == uid}
            for u in celebrants
        ]), 200

    except Exception as e:
        print(f"Birthday notification error: {e}")
        return jsonify([]), 200


# =============================================================================
# 18. STATS & ANALYTICS DASHBOARDS
# =============================================================================

@app.route("/api/admin/today-stats", methods=["GET"])
@token_required
def today_stats():
    """ Aggregates raw counts for the top dashboard widgets. """
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    
    if role != "admin" and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    today = str(datetime.now(IST).date())
    today_dt = datetime.strptime(today, "%Y-%m-%d")

    # Active employees — exclude anyone who has tendered resignation
    # resignation.notice_date: None matches null, missing field, or parent null
    active_ids = {
        str(e["_id"]) for e in users_col.find(
            {"role": {"$in": ["employee", "manager"]}, "resignation.notice_date": None},
            {"_id": 1}
        )
    }

    # Employees who checked in today
    present_ids = {
        r["user_id"] for r in attendance_col.find(
            {"date": today, "type": "checkin"}, {"user_id": 1}
        )
    }

    # All leaves covering today that are not rejected (Pending counts — employees
    # apply and go on leave before approval; Rejected means they didn't take it)
    std_leave_ids = {
        l["user_id"] for l in leaves_col.find(
            {"from_date": {"$lte": today}, "to_date": {"$gte": today},
             "status": {"$nin": ["Rejected"]}},
            {"user_id": 1}
        )
    }

    # Extended leaves stored on the employee document (dates are datetime objects)
    ext_leave_ids = {
        str(e["_id"]) for e in users_col.find(
            {"role": {"$in": ["employee", "manager"]},
             "extended_leaves": {"$elemMatch": {
                 "from_date": {"$lte": today_dt},
                 "to_date":   {"$gte": today_dt}
             }}},
            {"_id": 1}
        )
    }

    all_leave_ids = std_leave_ids | ext_leave_ids

    # Scope everything to active employees only
    present_count   = len(present_ids & active_ids)
    # Leave: on leave AND active AND did not check in (check-in takes priority)
    leave_count     = len((all_leave_ids - present_ids) & active_ids)
    not_in_count    = len(active_ids - present_ids - all_leave_ids)

    return jsonify({
        "present":       present_count,
        "leave":         leave_count,
        "not_checked_in": not_in_count
    }), 200


@app.route("/api/admin/attendance-summary", methods=["GET"])
@token_required
def attendance_summary():
    """Monthly attendance breakdown — every employee classified into exactly one
    bucket per day: present | leave | not_checked_in (today only) | absent."""
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    if role != "admin" and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    month_param = request.args.get("month")
    if not month_param:
        return jsonify({"message": "month required"}), 400

    year, month_num = map(int, month_param.split("-"))
    start = IST.localize(datetime(year, month_num, 1))
    end   = IST.localize(datetime(year + (month_num // 12), (month_num % 12) + 1, 1))
    start_str = start.date().isoformat()
    end_str   = (end - timedelta(days=1)).date().isoformat()
    today_str = str(datetime.now(IST).date())

    # ── 1. Employee roster (fetch only fields we need) ────────────────────
    employees = list(users_col.find(
        {"role": {"$in": ["employee", "manager"]}},
        {"name": 1, "joined_at": 1, "resignation": 1, "extended_leaves": 1}
    ))
    emp_names = {str(e["_id"]): e.get("name", "") for e in employees}

    def _date_str(val):
        """Coerce datetime / date / ISO-string to YYYY-MM-DD string, or None."""
        if val is None:
            return None
        if hasattr(val, "date"):        # datetime object
            return val.date().isoformat()
        return str(val)[:10]

    # ── 2. Pre-index check-ins by date → set of user_ids ─────────────────
    all_recs = attendance_col.find({"date": {"$regex": f"^{month_param}"}, "type": "checkin"})
    checkins_by_date: dict[str, set] = {}
    for rec in all_recs:
        checkins_by_date.setdefault(rec["date"], set()).add(rec["user_id"])

    # ── 3. Pre-index standard leaves by user_id ───────────────────────────
    all_leaves = list(leaves_col.find({
        "from_date": {"$lte": end_str},
        "to_date":   {"$gte": start_str},
        "status":    {"$nin": ["Rejected"]},
    }))
    leaves_by_uid: dict[str, list] = {}
    for lv in all_leaves:
        leaves_by_uid.setdefault(lv["user_id"], []).append(lv)

    # ── 4. Day loop ───────────────────────────────────────────────────────
    summary: dict = {"total_employees": len(employees), "days": {}}

    curr = start
    while curr < end:
        day_str    = curr.date().isoformat()
        curr      += timedelta(days=1)          # advance early so we can `continue` safely

        if day_str > today_str:                 # skip future dates entirely
            continue

        is_weekend = datetime.strptime(day_str, "%Y-%m-%d").weekday() >= 5
        is_today   = day_str == today_str
        day_checkins = checkins_by_date.get(day_str, set())

        present_ids, leave_ids, absent_ids, nci_ids = [], [], [], []

        for emp in employees:
            uid = str(emp["_id"])

            # Gate — employee hadn't joined yet on this day
            joined = _date_str(emp.get("joined_at"))
            if joined and day_str < joined:
                continue

            # Gate — employee already off-boarded before this day
            resignation = emp.get("resignation") or {}
            lwd = _date_str(resignation.get("last_working_day"))
            if lwd and day_str > lwd:
                continue

            # ── Bucket classification (strict priority order) ────────────
            # 1) Present — checked in
            if uid in day_checkins:
                present_ids.append(uid)
                continue

            # 2) Leave — approved standard leave OR active extended leave
            on_leave = any(
                lv.get("from_date", "") <= day_str <= lv.get("to_date", "")
                for lv in leaves_by_uid.get(uid, [])
            )
            if not on_leave:
                for el in (emp.get("extended_leaves") or []):
                    el_from = _date_str(el.get("from_date"))
                    el_to   = _date_str(el.get("to_date"))
                    if el_from and el_to and el_from <= day_str <= el_to:
                        on_leave = True
                        break
            if on_leave:
                leave_ids.append(uid)
                continue

            # 3) Not-checked-in (today still in progress) or Absent (past weekday)
            if is_today:
                nci_ids.append(uid)
            elif not is_weekend:
                absent_ids.append(uid)
            # weekend with no check-in and no leave → no bucket (not expected to work)

        def _names(ids):
            return [emp_names[uid] for uid in ids if emp_names.get(uid)]

        summary["days"][day_str] = {
            "present":            present_ids,   "present_count":        len(present_ids),  "present_names":        _names(present_ids),
            "leave":              leave_ids,     "leave_count":          len(leave_ids),    "leave_names":          _names(leave_ids),
            "absent":             absent_ids,    "absent_count":         len(absent_ids),   "absent_names":         _names(absent_ids),
            "not_checked_in":     nci_ids,       "not_checked_in_count": len(nci_ids),      "not_checked_in_names": _names(nci_ids),
            "is_weekend":         is_weekend,
        }

    return jsonify(summary), 200


@app.route("/api/attendance/auto-absent", methods=["POST"])
def auto_mark_absent():
    """
    Script endpoint to auto-flag users who didn't punch in.
    Called internally via cron or external trigger at night.
    Requires CRON_SECRET header to prevent unauthorized invocation.
    """
    cron_secret = os.getenv("CRON_SECRET")
    if cron_secret:
        provided = request.headers.get("X-Cron-Secret", "")
        if provided != cron_secret:
            return jsonify({"message": "Unauthorized"}), 401

    today = datetime.now(IST).date()
    today_str = str(today)
    all_users = users_col.find({"role": {"$in": ["employee", "manager"]}})

    for emp in all_users:
        uid = str(emp["_id"])
        
        if not attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today_str}):
            if not leaves_col.find_one({"user_id": uid, "status": "Approved", "from_date": {"$lte": today_str}, "to_date": {"$gte": today_str}}):
                
                if not attendance_col.find_one({"user_id": uid, "type": "absent", "date": today_str}):
                    attendance_col.insert_one({
                        "user_id": uid, "type": "absent", "date": today_str, "time": datetime.now(timezone.utc)
                    })
                
                if not leaves_col.find_one({"user_id": uid, "type": "System Absent", "date": today_str}):
                    leaves_col.insert_one({
                        "user_id": uid, 
                        "from_date": today_str, "to_date": today_str, "date": today_str,
                        "type": "System Absent", 
                        "reason": "Not checked in by cutoff time", 
                        "status": "Absent", 
                        "applied_at": datetime.now(timezone.utc)
                    })

    return jsonify({"message": "Absent auto-marking completed"}), 200


# =============================================================================
# 19. AUTOMATED SCHEDULED JOBS (APScheduler)
# =============================================================================

def send_pms_reminders():
    """
    Automated job that fires every day at 10 AM IST. 
    Checks if it is past the 28th of the month. If so, emails managers 
    reminding them to complete any pending PMS reviews for their staff.
    """
    print("Running Automated PMS Reminder Job...")
    now = datetime.now(IST)
    
    if now.day >= 28:
        pending_reviews = pms_reviews_col.find({"status": "Pending Review"})
        for rev in pending_reviews:
            if not rev.get("manager_id"):
                continue
            try:
                manager = users_col.find_one({"_id": ObjectId(rev["manager_id"])})
                emp = users_col.find_one({"_id": ObjectId(rev["user_id"])})
            except Exception:
                continue
            if manager and emp:
                subject = f"Action Required: Pending PMS Review for {emp['name']}"
                body = (
                    f"Hello {manager['name']},\n\n"
                    f"This is an automated reminder that you have a pending PMS review for {emp['name']} "
                    f"in the {emp['department']} department for the month of {rev['month']}.\n\n"
                    f"Please log in to the HRMS portal to complete the evaluation.\n\n"
                    f"Thank you,\n"
                    f"GDMR Connect Automated System"
                )
                try:
                    threading.Thread(target=send_email, args=(manager["email"], subject, body), daemon=True).start()
                except Exception as e:
                    print(f"Reminder email failed: {e}")

def auto_expire_grants():
    """
    Automated job running every 30 minutes. 
    Scans the 'access_grants' collection and deactivates any grants
    that have passed their expiration deadline (custom or end-of-day).
    """
    print("Running Auto-Expire Access Grants Job...")
    now = datetime.now(IST)
    active_grants = access_grants_col.find({"is_active": True})
    
    for g in active_grants:
        expired = False
        if g.get("expiry") == "end_of_day":
            granted_at_ist = utc_to_ist(g["granted_at"])
            if now.date() > granted_at_ist.date():
                expired = True
                
        elif g.get("expiry") == "custom_time":
            custom_time_str = g.get("custom_expiry_time")
            if custom_time_str:
                try:
                    expiry_dt = datetime.strptime(custom_time_str, "%Y-%m-%dT%H:%M")
                    expiry_dt = IST.localize(expiry_dt)
                    if now >= expiry_dt:
                        expired = True
                except Exception as e:
                    print(f"Error parsing custom time for grant {g['_id']}: {e}")
        
        if expired:
            access_grants_col.update_one({"_id": g["_id"]}, {"$set": {"is_active": False}})
            print(f"Automatically expired access grant for employee {g['employee_id']}.")


# =============================================================================
# ASSESSMENT MODULE
# =============================================================================

@app.route("/api/admin/assessments", methods=["GET"])
@token_required
def list_assessments():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for a in assessments_col.find().sort("created_at", -1):
        a["_id"] = str(a["_id"])
        rows.append(a)
    return jsonify(rows), 200


@app.route("/api/admin/assessments", methods=["POST"])
@token_required
def create_assessment():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    data = request.json or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"message": "title is required"}), 400
    doc = {
        "title":            title,
        "description":      str(data.get("description", "")).strip(),
        "questions":        data.get("questions", []),
        "duration_minutes": int(data.get("duration_minutes", 0)),
        "created_by":       str(request.user["_id"]),
        "created_at":       datetime.now(timezone.utc),
    }
    res = assessments_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@app.route("/api/admin/assessments/<assessment_id>", methods=["PUT"])
@token_required
def update_assessment(assessment_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(assessment_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}
    for k in ["title", "description", "questions", "duration_minutes"]:
        if k in data:
            update[k] = data[k]
    result = assessments_col.update_one({"_id": obj}, {"$set": update})
    if result.matched_count == 0:
        return jsonify({"message": "Assessment not found"}), 404
    return jsonify({"message": "Assessment updated"}), 200


@app.route("/api/admin/assessments/<assessment_id>", methods=["DELETE"])
@token_required
def delete_assessment(assessment_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(assessment_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    result = assessments_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Assessment not found"}), 404
    candidates_col.delete_many({"assessment_id": assessment_id})
    return jsonify({"message": "Assessment deleted"}), 200


@app.route("/api/admin/assessments/invite", methods=["POST"])
@token_required
def invite_candidate():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    data = request.json or {}
    name          = str(data.get("name", "")).strip()
    email         = str(data.get("email", "")).strip()
    phone         = str(data.get("phone", "")).strip()
    assessment_id = str(data.get("assessmentId", "")).strip()
    if not name or not email or not assessment_id:
        return jsonify({"message": "name, email, and assessmentId are required"}), 400
    assessment = assessments_col.find_one({"_id": ObjectId(assessment_id)})
    if not assessment:
        return jsonify({"message": "Assessment not found"}), 404

    token = secrets.token_urlsafe(32)
    doc = {
        "assessment_id": assessment_id,
        "name":          name,
        "email":         email,
        "phone":         phone,
        "token":         token,
        "status":        "pending",
        "invited_at":    datetime.now(timezone.utc),
    }
    res = candidates_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)

    assessment_link = f"https://www.gdmrconnect.com/assessment/{token}"
    duration = assessment.get("duration", assessment.get("duration_minutes", 30))
    subject = f"You've Been Invited to Take an Assessment — GDMR Connect"
    body = (
        f"Hello {name},\n\n"
        f"You have been invited to complete an assessment: \"{assessment.get('title', '')}\".\n\n"
        f"Click the link below to begin:\n{assessment_link}\n\n"
        + (f"Duration: {duration} minutes\n\n" if duration else "")
        + "This link is unique to you — please do not share it.\n\n"
        "Best regards,\nGDMR Connect Team"
    )
    threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()

    return jsonify(doc), 201


@app.route("/api/admin/assessments/candidates", methods=["GET"])
@token_required
def list_candidates():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    assessment_id = request.args.get("assessmentId")
    query = {"assessment_id": assessment_id} if assessment_id else {}
    rows = []
    for c in candidates_col.find(query).sort("invited_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows), 200


@app.route("/api/admin/assessments/candidates/<candidate_id>/result", methods=["GET"])
@token_required
def candidate_result(candidate_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        invite = candidates_col.find_one({"_id": ObjectId(candidate_id)})
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    if not invite:
        return jsonify({"message": "Candidate not found"}), 404

    invite["_id"] = str(invite["_id"])

    # Enrich answers with question text and correctness when the assessment exists
    try:
        assessment = assessments_col.find_one({"_id": ObjectId(invite.get("assessment_id", ""))})
    except Exception:
        assessment = None

    if assessment and invite.get("answers"):
        questions = assessment.get("questions", [])
        answers_enriched = []
        for ans in invite["answers"]:
            qi          = ans.get("question_index", 0)
            q           = questions[qi] if qi < len(questions) else {}
            given       = str(ans.get("answer", ""))
            correct_idx = str(q.get("correctIndex", ""))
            is_correct  = (given == correct_idx) if q.get("type") == "mcq" else None

            options = q.get("options", [])
            given_text   = options[int(given)]   if q.get("type") == "mcq" and given.isdigit()       and int(given)       < len(options) else given
            correct_text = options[int(correct_idx)] if q.get("type") == "mcq" and correct_idx.isdigit() and int(correct_idx) < len(options) else None

            answers_enriched.append({
                "question_index": qi,
                "question":       q.get("text", f"Question {qi + 1}"),
                "given_answer":   given_text,
                "correct_answer": correct_text,
                "correct":        is_correct,
            })
        invite["answers"] = answers_enriched

    return jsonify(invite), 200


# =============================================================================
# ASSESSMENT — PUBLIC (token-based, no auth header required)
# =============================================================================

@app.route("/api/assessment/<token>", methods=["GET"])
def get_assessment_by_token(token):
    """Candidate fetches their assessment using the unique link token."""
    invite = candidates_col.find_one({"token": token})
    if not invite or invite.get("status") == "completed":
        return jsonify({"message": "Link is invalid or has already been used."}), 404

    try:
        assessment = assessments_col.find_one({"_id": ObjectId(invite["assessment_id"])})
    except Exception:
        assessment = None
    if not assessment:
        return jsonify({"message": "Assessment not found."}), 404

    # Mark as started so we can track who opened the link
    candidates_col.update_one({"token": token}, {"$set": {"status": "started"}})

    # Strip answer keys — never send correctIndex or correct_answer to the client
    questions = []
    for q in assessment.get("questions", []):
        q_clean = {"type": q.get("type"), "text": q.get("text")}
        if q.get("type") == "mcq":
            q_clean["options"] = q.get("options", [])
        questions.append(q_clean)

    return jsonify({
        "title":         assessment.get("title"),
        "description":   assessment.get("description", ""),
        "duration":      assessment.get("duration", assessment.get("duration_minutes", 30)),
        "passing_score": assessment.get("passing_score", 60),
        "questions":     questions,
    }), 200


@app.route("/api/assessment/submit", methods=["POST"])
def submit_assessment():
    """Grade answers, mark invite completed, return exactly {score, passed}."""
    data      = request.json or {}
    token     = data.get("token", "")
    answers   = data.get("answers", [])
    forced    = bool(data.get("forced", False))
    timed_out = bool(data.get("timed_out", False))

    if not token:
        return jsonify({"message": "token is required"}), 400

    invite = candidates_col.find_one({"token": token})
    if not invite:
        return jsonify({"message": "Invalid submission token."}), 400
    if invite.get("status") == "completed":
        return jsonify({"message": "This assessment has already been submitted."}), 400

    try:
        assessment = assessments_col.find_one({"_id": ObjectId(invite["assessment_id"])})
    except Exception:
        assessment = None
    if not assessment:
        return jsonify({"message": "Assessment not found."}), 404

    questions     = assessment.get("questions", [])
    passing_score = int(assessment.get("passing_score", 60))

    # Grade MCQ questions using correctIndex (integer index into options[])
    total_mcq = sum(1 for q in questions if q.get("type") == "mcq")
    correct   = 0

    for ans in answers:
        qi = ans.get("question_index")
        if qi is None or qi >= len(questions):
            continue
        q = questions[qi]
        if q.get("type") == "mcq":
            try:
                if str(ans.get("answer")) == str(q.get("correctIndex")):
                    correct += 1
            except Exception:
                pass

    score  = round((correct / total_mcq) * 100) if total_mcq > 0 else 0
    passed = score >= passing_score

    candidates_col.update_one(
        {"token": token},
        {"$set": {
            "status":       "completed",
            "score":        score,
            "passed":       passed,
            "answers":      answers,
            "submitted_at": datetime.now(timezone.utc),
            "forced":       forced,
            "timed_out":    timed_out,
        }}
    )

    return jsonify({"score": score, "passed": passed}), 200


# =============================================================================
# LMS MODULE
# =============================================================================

def _get_lms_grant(user):
    """Return active LMS grant for this user, or None."""
    return access_grants_col.find_one({
        "employee_id": str(user["_id"]),
        "is_active": True,
        "module": "lms",
    })


def _require_lms(user, write=False):
    """
    Check LMS access for non-admin users.
    Returns (grant, error_response) — error_response is None if access is allowed.
    write=True requires access_level="view_edit"; write=False allows view_only too.
    """
    if user.get("role") == "admin":
        return None, None
    grant = _get_lms_grant(user)
    if not grant:
        return None, (jsonify({"message": "Unauthorized"}), 403)
    if write and grant.get("access_level") != "view_edit":
        return None, (jsonify({"message": "Read-only LMS access — cannot modify"}), 403)
    return grant, None


@app.route("/api/admin/lms/courses", methods=["GET"])
@token_required
def list_courses():
    _, err = _require_lms(request.user)
    if err: return err
    rows = []
    for c in lms_courses_col.find().sort("created_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows), 200


def _normalize_modules(modules):
    """Ensure every lesson has a stable string _id so progress tracking works."""
    if not isinstance(modules, list):
        return []
    for m in modules:
        for l in m.get("lessons", []):
            # Assign an id only when missing; keep existing ones stable across edits
            if not l.get("_id") and not l.get("id"):
                l["_id"] = str(ObjectId())
            elif l.get("_id"):
                l["_id"] = str(l["_id"])
    return modules


@app.route("/api/admin/lms/courses", methods=["POST"])
@token_required
def create_course():
    _, err = _require_lms(request.user, write=True)
    if err: return err
    data = request.json or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"message": "title is required"}), 400
    expiry_raw = data.get("expiry_date")
    doc = {
        "title":         title,
        "description":   str(data.get("description", "")).strip(),
        "category":      str(data.get("category", "Technical")).strip(),
        "thumbnail_url": str(data.get("thumbnail_url", "")).strip(),
        "content_url":   str(data.get("content_url", "")).strip(),
        "tags":          data.get("tags", []),
        "modules":       _normalize_modules(data.get("modules", [])),
        "expiry_date":   str(expiry_raw)[:10] if expiry_raw else None,
        "created_by":    str(request.user["_id"]),
        "created_at":    datetime.now(timezone.utc),
    }
    res = lms_courses_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@app.route("/api/admin/lms/courses/<course_id>", methods=["PUT"])
@token_required
def update_course(course_id):
    _, err = _require_lms(request.user, write=True)
    if err: return err
    try:
        obj = ObjectId(course_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}
    for k in ["title", "description", "category", "thumbnail_url", "content_url", "tags"]:
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


@app.route("/api/admin/lms/courses/<course_id>", methods=["DELETE"])
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


@app.route("/api/admin/lms/courses/<course_id>/assign", methods=["POST"])
@token_required
def assign_course(course_id):
    _, err = _require_lms(request.user, write=True)
    if err: return err
    try:
        course_obj = ObjectId(course_id)
    except Exception:
        return jsonify({"message": "Invalid course ID"}), 400
    if not lms_courses_col.find_one({"_id": course_obj}):
        return jsonify({"message": "Course not found"}), 404

    data         = request.json or {}
    employee_ids = list(data.get("employee_ids") or [])
    scheduled_at_raw = data.get("scheduled_at")  # ISO string or None

    # Normalise scheduled_at → UTC datetime (store None if missing/invalid)
    scheduled_at = None
    if scheduled_at_raw:
        try:
            scheduled_at = IST.localize(
                datetime.strptime(scheduled_at_raw[:16], "%Y-%m-%dT%H:%M")
            ).astimezone(timezone.utc)
        except Exception:
            pass

    # ── Department mode ───────────────────────────────────────────────────
    # Accept both "departments" (array) and "department" (single string)
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
        # Merge with any explicitly supplied employee_ids
        employee_ids = list({*employee_ids, *dept_emp_ids})

        # Record which departments this course is assigned to so that
        # GET /my/lms/courses can surface it without a progress record.
        # Also store scheduled_at at course level so ghost records (employees
        # who join after the assignment) can inherit the schedule.
        dept_update: dict = {"$addToSet": {"assigned_departments": {"$each": departments}}}
        if scheduled_at:
            dept_update["$set"] = {"dept_scheduled_at": scheduled_at}
        lms_courses_col.update_one({"_id": course_obj}, dept_update)

    if not employee_ids:
        return jsonify({"message": "No employees to assign"}), 400

    now = datetime.now(timezone.utc)
    assigned = skipped = 0
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
            else:
                skipped += 1   # already assigned — don't overwrite progress
        except Exception:
            pass

    msg = f"Course assigned to {assigned} employee(s)"
    if skipped:
        msg += f" ({skipped} already assigned, skipped)"
    return jsonify({"message": msg, "assigned": assigned, "skipped": skipped}), 200


@app.route("/api/admin/lms/progress", methods=["GET"])
@token_required
def lms_progress():
    _, err = _require_lms(request.user)
    if err: return err
    course_id = request.args.get("course_id")
    query = {"course_id": course_id} if course_id else {}
    rows = list(lms_progress_col.find(query))

    # Employee name + department lookup
    uids = []
    for r in rows:
        try: uids.append(ObjectId(r["user_id"]))
        except Exception: pass
    emp_map = {str(e["_id"]): e for e in users_col.find({"_id": {"$in": uids}}, {"name": 1, "department": 1})}

    # Full course docs (need modules to count lessons, not just the title)
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

        # Count using the SAME dual-key matching as the employee endpoint so the
        # admin view and the employee view always report identical progress
        completed_set = set(r.get("completed_lessons", []))
        total = 0
        done  = 0
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
            "employee_name":     emp.get("name") if emp else "Unknown",
            "department":        emp.get("department") if emp else None,
            "course_id":         r.get("course_id"),
            "course_title":      course.get("title") if course else "Unknown",
            "total_lessons":     total,
            "completed_lessons": done,
            "percent_complete":  pct,
            "status":            r.get("status", "Assigned"),
            "last_activity":     r.get("last_activity"),
            "assigned_at":       r.get("assigned_at"),
            "completed_at":      r.get("completed_at"),
        })
    return jsonify(result), 200


# =============================================================================
# CAREER MODULE
# =============================================================================

def _normalize_requirements(raw):
    """Always return a list of trimmed, non-empty requirement strings.
    Accepts a list, or a comma/newline-separated string (legacy), or None."""
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        items = re.split(r"[,\n]", raw)
    else:
        items = []
    return [str(item).strip() for item in items if str(item).strip()]


@app.route("/api/admin/career/jobs", methods=["GET"])
@token_required
def list_jobs():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for j in career_jobs_col.find().sort("created_at", -1):
        j["_id"] = str(j["_id"])
        j["requirements"] = _normalize_requirements(j.get("requirements"))
        rows.append(j)
    return jsonify(rows), 200


@app.route("/api/admin/career/jobs", methods=["POST"])
@token_required
def create_job():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    data = request.json or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"message": "title is required"}), 400
    doc = {
        "title":        title,
        "department":   str(data.get("department", "")).strip(),
        "description":  str(data.get("description", "")).strip(),
        "requirements": _normalize_requirements(data.get("requirements")),
        "type":         data.get("type", "Full-time"),
        "status":       "Open",
        "created_by":   str(request.user["_id"]),
        "created_at":   datetime.now(timezone.utc),
    }
    res = career_jobs_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return jsonify(doc), 201


@app.route("/api/admin/career/jobs/<job_id>", methods=["PUT"])
@token_required
def update_job(job_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(job_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data = request.json or {}
    update = {"updated_at": datetime.now(timezone.utc)}
    for k in ["title", "department", "description", "type", "status"]:
        if k in data:
            update[k] = data[k]
    if "requirements" in data:
        update["requirements"] = _normalize_requirements(data.get("requirements"))
    if "status" in update and update["status"] not in ("Open", "Closed"):
        return jsonify({"message": "status must be 'Open' or 'Closed'"}), 400
    result = career_jobs_col.update_one({"_id": obj}, {"$set": update})
    if result.matched_count == 0:
        return jsonify({"message": "Job not found"}), 404
    return jsonify({"message": "Job updated"}), 200


@app.route("/api/admin/career/jobs/<job_id>", methods=["DELETE"])
@token_required
def delete_job(job_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(job_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    result = career_jobs_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Job not found"}), 404
    return jsonify({"message": "Job deleted"}), 200


@app.route("/api/admin/career/referrals", methods=["GET"])
@token_required
def admin_list_referrals():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    job_id = request.args.get("job_id")
    query = {"job_id": job_id} if job_id else {}
    rows = []
    for r in referrals_col.find(query).sort("submitted_at", -1):
        r["_id"] = str(r["_id"])
        rows.append(r)
    return jsonify(rows), 200


@app.route("/api/admin/career/referrals/<referral_id>", methods=["PUT"])
@token_required
def update_referral(referral_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(referral_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    data = request.json or {}
    status = data.get("status")
    valid_statuses = {"Pending", "Reviewed", "Shortlisted", "Rejected", "Hired"}
    if not status or status not in valid_statuses:
        return jsonify({"message": f"status must be one of: {', '.join(sorted(valid_statuses))}"}), 400
    result = referrals_col.update_one({"_id": obj}, {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}})
    if result.matched_count == 0:
        return jsonify({"message": "Referral not found"}), 404
    return jsonify({"message": "Referral status updated"}), 200


@app.route("/api/career/referrals", methods=["POST"])
@token_required
def submit_referral():
    """
    Employee submits a candidate referral for an open job.
    Accepts multipart/form-data so an optional resume file can be uploaded.
    Falls back to JSON body if no form data is present.
    """
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    # Read from form (multipart) with a JSON fallback for older clients
    src = request.form if request.form else (request.json or {})
    job_id          = str(src.get("job_id", "")).strip()
    candidate_name  = str(src.get("candidate_name", "")).strip()
    candidate_email = str(src.get("candidate_email", "")).strip()
    candidate_phone = str(src.get("candidate_phone", "")).strip()
    resume_link     = str(src.get("resume_url", "")).strip() or None
    notes           = str(src.get("notes", "")).strip() or None

    if not job_id or not candidate_name or not candidate_email:
        return jsonify({"message": "job_id, candidate_name, and candidate_email are required"}), 400

    try:
        job = career_jobs_col.find_one({"_id": ObjectId(job_id), "status": "Open"})
    except Exception:
        return jsonify({"message": "Invalid job ID"}), 400
    if not job:
        return jsonify({"message": "Job not found or no longer open"}), 404

    # Optional resume file → Cloudinary, with strict server-side validation.
    # Frontend checks are UX only; re-validate everything here since a client
    # can POST anything directly to the API.
    resume_file_url = None
    f = request.files.get("resume")
    if f and f.filename:
        # 1. Extension check
        if not f.filename.lower().endswith(".pdf"):
            return jsonify({"message": "Only PDF files are allowed."}), 400

        # 2. MIME check
        if f.mimetype != "application/pdf":
            return jsonify({"message": "Invalid file type."}), 400

        # 3. Magic-byte check — first 5 bytes must be %PDF-
        head = f.stream.read(5)
        f.stream.seek(0)                       # rewind so the upload reads the full file
        if head != b"%PDF-":
            return jsonify({"message": "File is not a valid PDF."}), 400

        # 4. Size cap (5 MB)
        f.stream.seek(0, 2)
        size = f.stream.tell()
        f.stream.seek(0)
        if size > 5 * 1024 * 1024:
            return jsonify({"message": "File too large (max 5 MB)."}), 400

        # 5. Upload as raw, force .pdf so the delivered file is always a real PDF
        try:
            res = cloudinary.uploader.upload(
                f,
                resource_type="raw",
                folder="gdmr/referral_resumes",
                format="pdf",
                use_filename=True, unique_filename=True,
            )
            resume_file_url = res.get("secure_url")
        except Exception as e:
            print("Resume upload error:", e)
            return jsonify({"message": "Resume upload failed. Please try again."}), 500

    doc = {
        "job_id":          job_id,
        "job_title":       job.get("title", ""),
        "referred_by":     str(request.user["_id"]),
        "referrer_name":   request.user.get("name", ""),
        "candidate_name":  candidate_name,
        "candidate_email": candidate_email,
        "candidate_phone": candidate_phone,
        "resume_url":      resume_link,        # LinkedIn / portfolio link
        "resume_file_url": resume_file_url,    # uploaded Cloudinary file
        "notes":           notes,
        "status":          "Pending",
        "submitted_at":    datetime.now(timezone.utc),
    }
    res = referrals_col.insert_one(doc)
    doc["_id"] = str(res.inserted_id)

    # Notify the referring employee's manager, if they have one
    manager_id = request.user.get("manager_id")
    if manager_id:
        try:
            manager = users_col.find_one({"_id": ObjectId(manager_id)})
        except Exception:
            manager = None
        if manager and manager.get("email"):
            subject = f"New Referral from {doc['referrer_name']}"
            body = (
                f"{doc['referrer_name']} has submitted a referral.\n\n"
                f"Candidate : {candidate_name}\n"
                f"Email     : {candidate_email}\n"
                f"Phone     : {candidate_phone or '—'}\n"
                f"Position  : {doc['job_title']}\n"
                f"Resume    : {resume_file_url or resume_link or 'Not provided'}\n"
                f"Notes     : {notes or '—'}\n\n"
                f"Please review in the GDMR Connect admin panel."
            )
            threading.Thread(target=send_email, args=(manager["email"], subject, body), daemon=True).start()

    return jsonify(doc), 201


# =============================================================================
# CAREER — PUBLIC & EMPLOYEE ROUTES
# =============================================================================

@app.route("/api/career/jobs", methods=["GET"])
def public_career_jobs():
    """Open job listings — no authentication required."""
    rows = []
    for j in career_jobs_col.find({"status": "Open"}).sort("created_at", -1):
        j["_id"] = str(j["_id"])
        j["requirements"] = _normalize_requirements(j.get("requirements"))
        rows.append(j)
    return jsonify(rows), 200


@app.route("/api/my/referrals", methods=["GET"])
@token_required
def my_referrals():
    """Returns all referrals submitted by the logged-in employee."""
    uid = str(request.user["_id"])
    rows = []
    for r in referrals_col.find({"referred_by": uid}).sort("submitted_at", -1):
        r["_id"] = str(r["_id"])
        rows.append(r)
    return jsonify(rows), 200


# =============================================================================
# LMS — EMPLOYEE ROUTES
# =============================================================================

@app.route("/api/my/lms/courses", methods=["GET"])
@token_required
def my_lms_courses():
    """Returns courses assigned to the logged-in employee with per-lesson completion state.
    Courses with a future scheduled_at are hidden until that time arrives."""
    uid  = str(request.user["_id"])
    dept = request.user.get("department")
    now_utc   = datetime.now(timezone.utc)
    today_iso = _today_ist().isoformat()
    not_expired = {"$or": [
        {"expiry_date": None},
        {"expiry_date": {"$exists": False}},
        {"expiry_date": {"$gte": today_iso}},
    ]}

    # Collect all progress records for this employee (covers both direct and dept assignments)
    progress_records = list(lms_progress_col.find({"user_id": uid}))

    def _is_available(sched):
        """Return True if the schedule time has passed (or there is no schedule)."""
        if not sched:
            return True
        # MongoDB returns naive UTC datetimes; make them aware before comparing
        if sched.tzinfo is None:
            sched = sched.replace(tzinfo=timezone.utc)
        return sched <= now_utc

    # Filter out records that are scheduled for the future
    progress_records = [r for r in progress_records if _is_available(r.get("scheduled_at"))]

    # Also surface any courses assigned to this employee's department that have no
    # progress record yet (assigned but never opened). Check dept_scheduled_at on
    # the course doc to honour schedules for ghost records.
    assigned_course_ids = {r["course_id"] for r in progress_records}
    if dept:
        dept_courses = lms_courses_col.find(
            {"assigned_departments": dept, **not_expired},
            {"_id": 1, "dept_scheduled_at": 1}
        )
        for c in dept_courses:
            cid = str(c["_id"])
            if cid in assigned_course_ids:
                continue
            dept_sched = c.get("dept_scheduled_at")
            if not _is_available(dept_sched):
                continue  # not yet time to show this course
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

    courses = {
        str(c["_id"]): c
        for c in lms_courses_col.find({"_id": {"$in": course_ids}, **not_expired})
    }

    result = []
    for prog in progress_records:
        course = courses.get(prog.get("course_id"))
        if not course:
            continue

        completed_set = set(prog.get("completed_lessons", []))
        modules       = []
        total_lessons = 0
        completed_count = 0

        for m_idx, mod in enumerate(course.get("modules", [])):
            lessons = []
            for l_idx, ls in enumerate(mod.get("lessons", [])):
                # Normalise lesson id — may be ObjectId, string "_id", or plain "id"
                ls_id      = str(ls.get("_id", ls.get("id", "")))
                key_byidx  = f"{m_idx}_{l_idx}"
                # Match whichever key form was stored (real _id or positional)
                done = (ls_id and ls_id in completed_set) or (key_byidx in completed_set)
                if done:
                    completed_count += 1
                total_lessons += 1
                lessons.append({
                    "_id":       ls_id,
                    "title":     ls.get("title", ""),
                    "type":      ls.get("type", "Video"),
                    "url":       ls.get("url", ""),
                    "content":   ls.get("content", ""),
                    "completed": done,
                })
            modules.append({"title": mod.get("title", ""), "lessons": lessons})

        pct = round(completed_count / total_lessons * 100) if total_lessons > 0 else 0

        result.append({
            "_id":               str(course["_id"]),
            "title":             course.get("title"),
            "description":       course.get("description", ""),
            "category":          course.get("category", ""),
            "thumbnail_url":     course.get("thumbnail_url", ""),
            "content_url":       course.get("content_url", ""),
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


@app.route("/api/my/lms/lessons/<lesson_id>/complete", methods=["POST"])
@token_required
def complete_lesson(lesson_id):
    """Mark a lesson as done and recalculate percent_complete for the course."""
    uid  = str(request.user["_id"])
    data = request.json or {}

    # Prefer course_id from body; fall back to finding the course by lesson _id
    course_id = str(data.get("course_id", "")).strip()
    course = None

    if course_id:
        try:
            course = lms_courses_col.find_one({"_id": ObjectId(course_id)})
        except Exception:
            pass

    if not course:
        # Try ObjectId lookup first, then string _id / id
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

    # Build a stable key for this lesson. The frontend sends the real _id when one
    # exists, otherwise "by-index" plus positional indices — store whichever applies.
    module_index = data.get("module_index")
    lesson_index = data.get("lesson_index")
    lesson_key = lesson_id if lesson_id and lesson_id != "by-index" else f"{module_index}_{lesson_index}"

    # Upsert: works for both pre-assigned and department-assigned courses
    lms_progress_col.update_one(
        {"course_id": course_id, "user_id": uid},
        {"$addToSet": {"completed_lessons": lesson_key},
         "$set":      {"status": "In Progress", "last_activity": now},
         "$setOnInsert": {
             "course_id":   course_id,
             "user_id":     uid,
             "assigned_at": now,
             "completed_at": None,
             "progress_pct": 0,
         }},
        upsert=True
    )

    # Recalculate progress using the same dual-key matching as the read endpoint,
    # so the count never exceeds the real lesson total or double-counts a lesson.
    prog          = lms_progress_col.find_one({"course_id": course_id, "user_id": uid})
    completed_set = set(prog.get("completed_lessons", []))
    total = 0
    done  = 0
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


# =============================================================================
# PAYROLL MODULE
# =============================================================================

# Salary component field groups
SALARY_EARNINGS   = ["basic", "hra", "conveyance", "medical", "special", "other_earnings"]
SALARY_DEDUCTIONS = ["pf", "professional_tax", "tds", "other_deductions"]


def _payroll_allowed(user):
    """Payroll access: admins, or anyone in the Accounts department."""
    if user.get("role") == "admin":
        return True
    dept = (user.get("department") or "").strip().lower()
    return dept.startswith("accounts")


def _to_money(v):
    """Coerce any input to a non-negative rounded float; bad input → 0.0."""
    try:
        return round(max(0.0, float(v)), 2)
    except (TypeError, ValueError):
        return 0.0


@app.route("/api/admin/payroll/salaries", methods=["GET"])
@token_required
def list_salaries():
    if not _payroll_allowed(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    employees = list(users_col.find({"role": {"$in": ["employee", "manager"]}}, {"name": 1, "department": 1}))
    struct_map = {s["employee_id"]: s for s in salary_structures_col.find()}

    rows = []
    for e in employees:
        eid = str(e["_id"])
        s = struct_map.get(eid)
        salary = None
        if s:
            salary = {f: s.get(f, 0) for f in SALARY_EARNINGS + SALARY_DEDUCTIONS}
        rows.append({
            "employee_id":   eid,
            "employee_name": e.get("name", ""),
            "department":    e.get("department", ""),
            "salary":        salary,
        })
    return jsonify(rows), 200


@app.route("/api/admin/payroll/salaries/<employee_id>", methods=["PUT"])
@token_required
def upsert_salary(employee_id):
    if not _payroll_allowed(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        emp = users_col.find_one({"_id": ObjectId(employee_id)})
    except Exception:
        return jsonify({"message": "Invalid employee ID"}), 400
    if not emp:
        return jsonify({"message": "Employee not found"}), 404

    data = request.json or {}
    struct = {f: _to_money(data.get(f, 0)) for f in SALARY_EARNINGS + SALARY_DEDUCTIONS}
    struct["employee_id"] = employee_id
    struct["updated_at"]  = datetime.now(timezone.utc)

    salary_structures_col.update_one({"employee_id": employee_id}, {"$set": struct}, upsert=True)
    return jsonify({"message": "Salary structure saved", "salary": {f: struct[f] for f in SALARY_EARNINGS + SALARY_DEDUCTIONS}}), 200


@app.route("/api/admin/payroll/run", methods=["POST"])
@token_required
def run_payroll():
    if not _payroll_allowed(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json or {}
    try:
        month = int(data.get("month"))
        year  = int(data.get("year"))
    except (TypeError, ValueError):
        return jsonify({"message": "month (1-12) and year are required"}), 400
    if not (1 <= month <= 12) or year < 2000:
        return jsonify({"message": "Invalid month or year"}), 400

    period = datetime(year, month, 1).strftime("%B %Y")
    now = datetime.now(timezone.utc)

    created = 0
    skipped = 0
    for s in salary_structures_col.find():
        eid = s.get("employee_id")
        if not eid:
            continue

        # No duplicate payslip for the same employee + period
        if payslips_col.find_one({"employee_id": eid, "month": month, "year": year}):
            skipped += 1
            continue

        try:
            emp = users_col.find_one({"_id": ObjectId(eid)})
        except Exception:
            emp = None
        if not emp:
            continue  # salary structure left behind by a deleted employee

        # Snapshot the numbers at generation time — never a live reference
        earnings   = {f: _to_money(s.get(f, 0)) for f in SALARY_EARNINGS}
        deductions = {f: _to_money(s.get(f, 0)) for f in SALARY_DEDUCTIONS}
        gross            = round(sum(earnings.values()), 2)
        total_deductions = round(sum(deductions.values()), 2)
        net              = round(gross - total_deductions, 2)

        payslip = {
            "employee_id":      eid,
            "employee_name":    emp.get("name", ""),
            "department":       emp.get("department", ""),
            "month":            month,
            "year":             year,
            "period":           period,
            **earnings,
            **deductions,
            "gross":            gross,
            "total_deductions": total_deductions,
            "net":              net,
            "status":           "Pending",
            "created_at":       now,
        }
        try:
            payslips_col.insert_one(payslip)
            created += 1
        except Exception:
            # Unique index race — treat as already generated
            skipped += 1

    return jsonify({
        "message": f"Payroll run complete for {period}.",
        "period":  period,
        "created": created,
        "skipped": skipped,
    }), 200


@app.route("/api/admin/payroll/payslips", methods=["GET"])
@token_required
def list_payslips():
    if not _payroll_allowed(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    query = {}
    month = request.args.get("month")
    year  = request.args.get("year")
    if month:
        try: query["month"] = int(month)
        except ValueError: return jsonify({"message": "Invalid month"}), 400
    if year:
        try: query["year"] = int(year)
        except ValueError: return jsonify({"message": "Invalid year"}), 400

    rows = []
    for p in payslips_col.find(query).sort([("year", -1), ("month", -1), ("employee_name", 1)]):
        p["_id"] = str(p["_id"])
        rows.append(p)
    return jsonify(rows), 200


@app.route("/api/admin/payroll/payslips/<payslip_id>/status", methods=["PUT"])
@token_required
def update_payslip_status(payslip_id):
    if not _payroll_allowed(request.user):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        obj = ObjectId(payslip_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400

    data = request.json or {}
    status = data.get("status")
    if status not in ("Pending", "Paid"):
        return jsonify({"message": "status must be 'Pending' or 'Paid'"}), 400

    update = {"status": status, "updated_at": datetime.now(timezone.utc)}
    if status == "Paid":
        update["paid_at"] = datetime.now(timezone.utc)

    result = payslips_col.update_one({"_id": obj}, {"$set": update})
    if result.matched_count == 0:
        return jsonify({"message": "Payslip not found"}), 404
    return jsonify({"message": f"Payslip marked {status}"}), 200


@app.route("/api/my/payslips", methods=["GET"])
@token_required
def my_payslips():
    """Payslips for the logged-in employee, newest first."""
    uid = str(request.user["_id"])
    rows = []
    for p in payslips_col.find({"employee_id": uid}).sort([("year", -1), ("month", -1)]):
        p["_id"] = str(p["_id"])
        rows.append(p)
    return jsonify(rows), 200


# =============================================================================
# WORK PLANS MODULE (daily task plans + analytics + scheduled summaries)
# =============================================================================

def _today_ist():
    return datetime.now(IST).date()


def _is_task_done(t):
    return str(t.get("status", "")).strip().lower() in ("completed", "done")


def _checkin_time_for(uid, date_str):
    rec = attendance_col.find_one(
        {"user_id": uid, "type": "checkin", "date": date_str}, {"time": 1}
    )
    if rec and rec.get("time"):
        return format_datetime_ist(rec["time"])
    return None


def _checkin_map(uids, date_str):
    recs = attendance_col.find(
        {"user_id": {"$in": uids}, "type": "checkin", "date": date_str},
        {"user_id": 1, "time": 1}
    )
    return {r["user_id"]: format_datetime_ist(r["time"]) for r in recs if r.get("time")}


def _serialize_plan(doc, checkin=None):
    doc["_id"] = str(doc["_id"])
    doc.setdefault("tasks", [])
    doc.setdefault("manager_comment", None)
    doc["check_in_time"] = checkin if checkin is not None else _checkin_time_for(doc.get("employee_id", ""), doc.get("date", ""))
    return doc


def _range_start(range_key, today_date):
    if range_key == "today":
        return today_date
    if range_key == "month":
        return today_date - timedelta(days=29)
    return today_date - timedelta(days=6)   # "week" / default


def _build_analytics(plans, start_date, today_date):
    """Aggregate a list of submitted-eligible work plans into trend/analytics."""
    tasks_submitted = 0
    tasks_completed = 0
    active_days = set()
    projects = {}
    per_day = {}     # "YYYY-MM-DD" -> task count

    for p in plans:
        if p.get("status") != "submitted":
            continue
        d = p.get("date", "")
        active_days.add(d)
        tlist = p.get("tasks", [])
        tasks_submitted += len(tlist)
        per_day[d] = per_day.get(d, 0) + len(tlist)
        for t in tlist:
            if _is_task_done(t):
                tasks_completed += 1
            proj = (t.get("project") or "Unassigned").strip() or "Unassigned"
            projects[proj] = projects.get(proj, 0) + 1

    # Daily trend across the requested window
    daily_trend = []
    cur = start_date
    while cur <= today_date:
        ds = cur.isoformat()
        daily_trend.append({"label": cur.strftime("%a %d"), "value": per_day.get(ds, 0)})
        cur += timedelta(days=1)

    # Weekly trend — group the same window by ISO week
    weekly = {}
    for ds, cnt in per_day.items():
        try:
            dt = datetime.strptime(ds, "%Y-%m-%d").date()
        except ValueError:
            continue
        iso = dt.isocalendar()
        key = (iso[0], iso[1])
        weekly[key] = weekly.get(key, 0) + cnt
    weekly_trend = [
        {"label": f"W{wk}", "value": val}
        for (yr, wk), val in sorted(weekly.items())
    ]

    projects_list = sorted(
        [{"name": n, "count": c} for n, c in projects.items()],
        key=lambda x: x["count"], reverse=True
    )

    return {
        "tasks_submitted": tasks_submitted,
        "tasks_completed": tasks_completed,
        "active_days":     len(active_days),
        "daily_trend":     daily_trend,
        "weekly_trend":    weekly_trend,
        "projects":        projects_list,
    }


# ── Employee routes ──────────────────────────────────────────────────────────

@app.route("/api/my/work-plan", methods=["GET"])
@token_required
def get_my_work_plan():
    uid = str(request.user["_id"])
    date_str = request.args.get("date") or _today_ist().isoformat()
    plan = work_plans_col.find_one({"employee_id": uid, "date": date_str})
    if not plan:
        return jsonify(None), 200
    return jsonify(_serialize_plan(plan)), 200


@app.route("/api/my/work-plan", methods=["POST"])
@token_required
def upsert_my_work_plan():
    uid = str(request.user["_id"])
    data = request.json or {}
    date_str = str(data.get("date") or _today_ist().isoformat())[:10]
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"message": "Invalid date. Use YYYY-MM-DD."}), 400

    status = data.get("status", "draft")
    if status not in ("draft", "submitted"):
        return jsonify({"message": "status must be 'draft' or 'submitted'"}), 400

    tasks = data.get("tasks", [])
    if not isinstance(tasks, list):
        return jsonify({"message": "tasks must be a list"}), 400

    now = datetime.now(timezone.utc)
    set_fields = {
        "employee_id":   uid,
        "employee_name": request.user.get("name", ""),
        "department":    request.user.get("department", ""),
        "date":          date_str,
        "tasks":         tasks,
        "status":        status,
        "updated_at":    now,
    }
    if status == "submitted":
        set_fields["submitted_at"] = now

    work_plans_col.update_one(
        {"employee_id": uid, "date": date_str},
        {"$set": set_fields, "$setOnInsert": {"created_at": now, "manager_comment": None}},
        upsert=True
    )

    # On submit the plan becomes eligible for the manager's 11 AM consolidated
    # email — the scheduled job picks up all submitted plans for the day.
    plan = work_plans_col.find_one({"employee_id": uid, "date": date_str})
    return jsonify(_serialize_plan(plan)), 200


TASK_STATUSES = ("Pending", "Started", "In Progress", "Completed")

@app.route("/api/my/work-plan/<plan_id>/task/<task_id>", methods=["PUT"])
@token_required
def update_my_task(plan_id, task_id):
    uid = str(request.user["_id"])
    try:
        obj = ObjectId(plan_id)
    except Exception:
        return jsonify({"message": "Invalid plan ID"}), 400

    status = (request.json or {}).get("status")
    if not status:
        return jsonify({"message": "status is required"}), 400
    if status not in TASK_STATUSES:
        return jsonify({"message": f"status must be one of: {', '.join(TASK_STATUSES)}"}), 400

    now = datetime.now(timezone.utc)
    update_doc = {"$set": {"tasks.$[t].status": status, "updated_at": now}}

    # Tasks may store their id as "id" or "_id" — try both
    result = work_plans_col.update_one(
        {"_id": obj, "employee_id": uid},
        update_doc,
        array_filters=[{"t.id": task_id}]
    )
    if result.matched_count == 0:
        return jsonify({"message": "Plan not found or not yours"}), 404
    if result.modified_count == 0:
        # Plan exists but t.id didn't match — try t._id
        work_plans_col.update_one(
            {"_id": obj, "employee_id": uid},
            update_doc,
            array_filters=[{"t._id": task_id}]
        )

    plan = work_plans_col.find_one({"_id": obj})
    return jsonify(_serialize_plan(plan)), 200


# =============================================================================
# CLIENTS
# =============================================================================

@app.route("/api/clients", methods=["GET"])
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


@app.route("/api/admin/clients", methods=["POST"])
@token_required
def create_client():
    role = request.user.get("role")
    if role not in ("admin", "manager"):
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


@app.route("/api/admin/clients/<client_id>", methods=["DELETE"])
@token_required
def delete_client(client_id):
    role = request.user.get("role")
    if role not in ("admin", "manager"):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        obj = ObjectId(client_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    result = clients_col.delete_one({"_id": obj})
    if result.deleted_count == 0:
        return jsonify({"message": "Client not found"}), 404
    return jsonify({"message": "Client deleted"}), 200


@app.route("/api/my/work-plans", methods=["GET"])
@token_required
def my_work_plans_history():
    """Work history for the logged-in employee. range=week|month|all (default: week)."""
    uid       = str(request.user["_id"])
    range_key = request.args.get("range", "week")
    today     = _today_ist()

    query: dict = {"employee_id": uid}
    if range_key == "week":
        query["date"] = {"$gte": (today - timedelta(days=6)).isoformat(), "$lte": today.isoformat()}
    elif range_key == "month":
        query["date"] = {"$gte": (today - timedelta(days=29)).isoformat(), "$lte": today.isoformat()}
    # range_key == "all" → no date filter

    plans = work_plans_col.find(query, {
        "_id": 1, "date": 1, "status": 1, "tasks": 1
    }).sort("date", -1)

    result = []
    for p in plans:
        result.append({
            "_id":    str(p["_id"]),
            "date":   p.get("date"),
            "status": p.get("status"),
            "tasks":  [
                {
                    "id":       t.get("id") or t.get("_id", ""),
                    "title":    t.get("title", ""),
                    "priority": t.get("priority", ""),
                    "project":  t.get("project", ""),
                    "client":   t.get("client", ""),
                    "est_time": t.get("est_time", ""),
                    "status":   t.get("status", "Pending"),
                }
                for t in (p.get("tasks") or [])
            ],
        })
    return jsonify(result), 200


@app.route("/api/my/work-analytics", methods=["GET"])
@token_required
def my_work_analytics():
    uid = str(request.user["_id"])
    range_key = request.args.get("range", "week")
    today_date = _today_ist()
    start_date = _range_start(range_key, today_date)

    plans = list(work_plans_col.find({
        "employee_id": uid,
        "date": {"$gte": start_date.isoformat(), "$lte": today_date.isoformat()}
    }))
    return jsonify(_build_analytics(plans, start_date, today_date)), 200


# ── Admin / Manager routes ───────────────────────────────────────────────────

@app.route("/api/admin/work-plans", methods=["GET"])
@token_required
def admin_work_plans():
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    if role not in ("admin", "manager") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    date_str = request.args.get("date") or _today_ist().isoformat()
    query = {"date": date_str}
    # Managers (without delegated admin) see only their department
    if role == "manager" and not has_delegated:
        query["department"] = request.user.get("department")

    plans = list(work_plans_col.find(query).sort("employee_name", 1))
    checkins = _checkin_map([p["employee_id"] for p in plans], date_str)
    rows = [_serialize_plan(p, checkin=checkins.get(p["employee_id"])) for p in plans]
    return jsonify(rows), 200


@app.route("/api/admin/work-analytics", methods=["GET"])
@token_required
def admin_work_analytics():
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    if role not in ("admin", "manager") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    range_key = request.args.get("range", "week")
    today_date = _today_ist()
    start_date = _range_start(range_key, today_date)

    query = {"date": {"$gte": start_date.isoformat(), "$lte": today_date.isoformat()}}
    if role == "manager" and not has_delegated:
        query["department"] = request.user.get("department")

    plans = list(work_plans_col.find(query))
    return jsonify(_build_analytics(plans, start_date, today_date)), 200


@app.route("/api/admin/work-plans/<plan_id>/comment", methods=["POST"])
@token_required
def comment_work_plan(plan_id):
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    if role not in ("admin", "manager") and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    try:
        obj = ObjectId(plan_id)
    except Exception:
        return jsonify({"message": "Invalid plan ID"}), 400

    plan = work_plans_col.find_one({"_id": obj})
    if not plan:
        return jsonify({"message": "Plan not found"}), 404
    # Managers may only comment on their own department's plans
    if role == "manager" and not has_delegated and plan.get("department") != request.user.get("department"):
        return jsonify({"message": "Unauthorized"}), 403

    comment = str((request.json or {}).get("comment", "")).strip()
    work_plans_col.update_one({"_id": obj}, {"$set": {"manager_comment": comment, "updated_at": datetime.now(timezone.utc)}})
    return jsonify({"message": "Comment saved"}), 200


# ── Scheduled email automation ───────────────────────────────────────────────

def send_daily_work_summaries():
    """11 AM IST — email each manager their team's submitted work plans for today."""
    print("Running Daily Work-Plan Summary Job...")
    today_str = _today_ist().isoformat()

    all_today_plans = list(work_plans_col.find({"date": today_str, "status": "submitted"}).sort([("department", 1), ("employee_name", 1)]))

    for m in users_col.find({"role": "manager"}, {"name": 1, "email": 1, "department": 1}):
        dept = m.get("department")
        if not dept or not m.get("email"):
            continue

        plans = [p for p in all_today_plans if p.get("department") == dept]
        if not plans:
            continue

        checkins = _checkin_map([p["employee_id"] for p in plans], today_str)
        lines = [
            f"Daily Work Plan Summary — {today_str}",
            f"Department: {dept}",
            f"Submitted plans: {len(plans)}",
            "",
        ]
        for p in plans:
            ci = checkins.get(p["employee_id"]) or "—"
            lines.append(f"• {p.get('employee_name', '')}  (check-in: {ci})")
            for t in p.get("tasks", []):
                done = "✓" if _is_task_done(t) else " "
                lines.append(
                    f"    [{done}] {t.get('title', '')}"
                    f"  | priority: {t.get('priority', '-')}"
                    f"  | est: {t.get('est_time', '-')}"
                    f"  | project: {t.get('project', '-')}"
                )
            if p.get("manager_comment"):
                lines.append(f"    ↳ comment: {p['manager_comment']}")
            lines.append("")

        body = "\n".join(lines)
        try:
            threading.Thread(target=send_email, args=(m["email"], f"Team Work Plans — {today_str}", body), daemon=True).start()
        except Exception as e:
            print(f"Daily summary email failed for {m.get('email')}: {e}")


def send_owner_daily_digest():
    """11:30 AM IST — HTML digest to company owners: every submitted plan grouped by department."""
    print("Running Owner Daily Digest Job...")
    today_str = _today_ist().isoformat()

    plans = list(work_plans_col.find(
        {"date": today_str, "status": "submitted"}
    ).sort([("department", 1), ("employee_name", 1)]))

    if not plans:
        print("Owner digest: no submitted plans today, skipping.")
        return

    # Build role map so we can show Employee / Manager next to each name
    all_uids = [p["employee_id"] for p in plans]
    role_map = {
        str(u["_id"]): u.get("role", "employee").capitalize()
        for u in users_col.find({"_id": {"$in": [ObjectId(uid) for uid in all_uids if uid]}}, {"role": 1})
    }
    checkins = _checkin_map(all_uids, today_str)

    # Group plans by department
    by_dept: dict = {}
    for p in plans:
        dept = (p.get("department") or "—").strip()
        by_dept.setdefault(dept, []).append(p)

    # ── Build plain-text fallback ──────────────────────────────────────────
    txt_lines = [f"Daily Work Updates — {today_str}", f"Total plans: {len(plans)}", ""]
    for dept, dept_plans in by_dept.items():
        txt_lines.append(f"=== {dept.upper()} ===")
        for p in dept_plans:
            uid = p["employee_id"]
            role = role_map.get(uid, "Employee")
            ci = checkins.get(uid) or "not checked in"
            txt_lines.append(f"  {p.get('employee_name', '')} ({role}) · check-in: {ci}")
            for t in p.get("tasks", []):
                done = "✓" if _is_task_done(t) else "○"
                pri = t.get("priority", "")
                txt_lines.append(f"    {done} {t.get('title', '')}{'  [' + pri + ']' if pri else ''}")
            if p.get("manager_comment"):
                txt_lines.append(f"    ↳ {p['manager_comment']}")
            txt_lines.append("")
        txt_lines.append("")
    plain_body = "\n".join(txt_lines)

    # ── Build HTML body ────────────────────────────────────────────────────
    PRIORITY_COLOR = {"High": "#e53e3e", "Medium": "#d97706", "Low": "#16a34a"}

    dept_html_parts = []
    for dept, dept_plans in by_dept.items():
        rows = []
        for p in dept_plans:
            uid = p["employee_id"]
            role = role_map.get(uid, "Employee")
            ci = checkins.get(uid) or "not checked in"
            task_items = []
            for t in p.get("tasks", []):
                done = _is_task_done(t)
                pri = (t.get("priority") or "").strip()
                color = PRIORITY_COLOR.get(pri, "#6b7280")
                badge = f'<span style="background:{color};color:#fff;font-size:10px;padding:1px 6px;border-radius:10px;margin-left:6px;">{pri}</span>' if pri else ""
                check = "✓" if done else "○"
                style = "color:#16a34a;font-weight:600;" if done else "color:#374151;"
                est = f'<span style="color:#9ca3af;font-size:11px;"> · {t["est_time"]}</span>' if t.get("est_time") else ""
                proj = f'<span style="color:#9ca3af;font-size:11px;"> · {t["project"]}</span>' if t.get("project") else ""
                task_items.append(
                    f'<li style="margin:3px 0;{style}">{check} {t.get("title","")}{badge}{est}{proj}</li>'
                )
            tasks_html = f'<ul style="margin:6px 0 6px 16px;padding:0;list-style:none;">{"".join(task_items)}</ul>' if task_items else ""
            comment_html = (
                f'<div style="margin:4px 0 0 16px;color:#6b7280;font-size:12px;font-style:italic;">↳ {p["manager_comment"]}</div>'
                if p.get("manager_comment") else ""
            )
            rows.append(f"""
            <div style="border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;margin-bottom:10px;background:#fff;">
              <div style="font-weight:600;color:#111827;">{p.get("employee_name","")}</div>
              <div style="font-size:12px;color:#6b7280;margin-bottom:6px;">{role} · checked in: {ci}</div>
              {tasks_html}{comment_html}
            </div>""")

        dept_html_parts.append(f"""
        <div style="margin-bottom:28px;">
          <h3 style="margin:0 0 10px;font-size:13px;font-weight:700;letter-spacing:.08em;
                     color:#fff;background:#1f2937;padding:6px 14px;border-radius:6px;
                     text-transform:uppercase;">{dept}</h3>
          {"".join(rows)}
        </div>""")

    html_body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
             background:#f3f4f6;margin:0;padding:20px;">
  <div style="max-width:640px;margin:0 auto;">
    <div style="background:#1f2937;color:#fff;padding:20px 24px;border-radius:10px 10px 0 0;">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.1em;opacity:.7;">GDMR Foundation</div>
      <h1 style="margin:4px 0 0;font-size:20px;">Daily Work Updates</h1>
      <div style="font-size:13px;opacity:.8;margin-top:4px;">{today_str} &nbsp;·&nbsp; {len(plans)} plans submitted</div>
    </div>
    <div style="background:#f9fafb;padding:20px 24px;border-radius:0 0 10px 10px;border:1px solid #e5e7eb;border-top:none;">
      {"".join(dept_html_parts)}
    </div>
    <div style="text-align:center;font-size:11px;color:#9ca3af;margin-top:12px;">
      GDMR Connect HRMS &nbsp;·&nbsp; Automated daily digest
    </div>
  </div>
</body></html>"""

    for email in OWNER_EMAILS:
        try:
            threading.Thread(
                target=send_email,
                args=(email, f"Daily Work Updates — {today_str}", plain_body),
                kwargs={"html_body": html_body},
                daemon=True
            ).start()
        except Exception as e:
            print(f"Owner daily digest failed for {email}: {e}")


def send_weekly_work_reports():
    """Monday 9 AM IST — weekly productivity report (per-dept to managers, org-wide to admins)."""
    print("Running Weekly Work-Plan Report Job...")
    today_date = _today_ist()
    start_date = today_date - timedelta(days=6)
    start_str, today_str = start_date.isoformat(), today_date.isoformat()

    all_plans = list(work_plans_col.find({
        "status": "submitted",
        "date": {"$gte": start_str, "$lte": today_str}
    }))

    def _report_body(plans, scope_label):
        submitted = sum(len(p.get("tasks", [])) for p in plans)
        completed = sum(1 for p in plans for t in p.get("tasks", []) if _is_task_done(t))

        by_dept, by_emp, by_proj, by_day = {}, {}, {}, {}
        for p in plans:
            d = p.get("department", "—")
            by_dept[d] = by_dept.get(d, 0) + len(p.get("tasks", []))
            name = p.get("employee_name", "—")
            by_emp[name] = by_emp.get(name, 0) + len(p.get("tasks", []))
            by_day[p.get("date", "")] = by_day.get(p.get("date", ""), 0) + len(p.get("tasks", []))
            for t in p.get("tasks", []):
                proj = (t.get("project") or "Unassigned").strip() or "Unassigned"
                by_proj[proj] = by_proj.get(proj, 0) + 1

        rate = round(completed / submitted * 100) if submitted else 0
        top_emps = sorted(by_emp.items(), key=lambda x: x[1], reverse=True)[:5]

        lines = [
            f"Weekly Work Report ({scope_label}) — {start_str} to {today_str}",
            "",
            f"Tasks submitted: {submitted}",
            f"Tasks completed: {completed}  ({rate}%)",
            "",
            "Department activity:",
        ]
        for d, c in sorted(by_dept.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"   {d}: {c} tasks")
        lines += ["", "Most active employees:"]
        for name, c in top_emps:
            lines.append(f"   {name}: {c} tasks")
        lines += ["", "Project allocation:"]
        for proj, c in sorted(by_proj.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"   {proj}: {c} tasks")
        lines += ["", "Daily trend:"]
        cur = start_date
        while cur <= today_date:
            lines.append(f"   {cur.strftime('%a %d')}: {by_day.get(cur.isoformat(), 0)}")
            cur += timedelta(days=1)
        return "\n".join(lines)

    # Org-wide to every admin and to company owners
    if all_plans:
        org_body = _report_body(all_plans, "Organisation")
        recipients = [a["email"] for a in users_col.find({"role": "admin"}, {"email": 1}) if a.get("email")]
        # Add owners, deduplicating in case an owner is also an admin user
        for email in OWNER_EMAILS:
            if email not in recipients:
                recipients.append(email)
        for email in recipients:
            try:
                threading.Thread(target=send_email, args=(email, f"Weekly Work Report — {today_str}", org_body), daemon=True).start()
            except Exception as e:
                print(f"Weekly org report failed for {email}: {e}")

    # Per-department to each manager
    for m in users_col.find({"role": "manager"}, {"email": 1, "department": 1}):
        dept = m.get("department")
        if not dept or not m.get("email"):
            continue
        dept_plans = [p for p in all_plans if p.get("department") == dept]
        if not dept_plans:
            continue
        body = _report_body(dept_plans, dept)
        try:
            threading.Thread(target=send_email, args=(m["email"], f"Weekly Work Report — {dept} — {today_str}", body), daemon=True).start()
        except Exception as e:
            print(f"Weekly manager report failed for {m.get('email')}: {e}")


# Initialize the background scheduler
try:
    scheduler = BackgroundScheduler(timezone=IST)
    scheduler.add_job(func=send_pms_reminders, trigger="cron", hour=10, minute=0)
    scheduler.add_job(func=auto_expire_grants, trigger="interval", minutes=30)
    scheduler.add_job(func=send_daily_work_summaries, trigger="cron", hour=11, minute=0)
    scheduler.add_job(func=send_owner_daily_digest,   trigger="cron", hour=11, minute=30)
    scheduler.add_job(func=send_weekly_work_reports,  trigger="cron", day_of_week="mon", hour=9, minute=0)
    scheduler.start()
    print("Background Job Scheduler initialized successfully.")
except Exception as e:
    print(f"Warning: Failed to start background scheduler. Error: {e}")



# =============================================================================
# RUN SERVER
# =============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)