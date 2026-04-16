"""
===============================================================================
GDMR CONNECT - CORE BACKEND APPLICATION API
===============================================================================
This file contains all the core backend routes, database connections, and 
business logic for the GDMR Connect HRMS and Attendance system.

Key Modules:
- JWT Authentication & Role-based Access Control
- Employee & Manager Management
- Daily Attendance & Camera/Photo Logging
- Leave Management & Approvals
- Temporary Delegated Admin Access
- Performance Management System (PMS 2.0)
- Automated Background Tasks (APScheduler)
===============================================================================
"""

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import base64, os, re, csv, io
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
# 2. CLOUDINARY CONFIGURATION (For Image Uploads)
# =============================================================================
try:
    cloudinary.config(
        cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
        api_key = os.getenv('CLOUDINARY_API_KEY'),
        api_secret = os.getenv('CLOUDINARY_API_SECRET')
    )
    print("Cloudinary configured successfully.")
except Exception as e:
    print(f"Warning: Cloudinary configuration failed. Images may not upload. Error: {e}")

# =============================================================================
# 3. CORS CONFIGURATION
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
    client = MongoClient(MONGO_URI)
    db = client["attendance_db"]
    print("MongoDB Connected Successfully.")
except Exception as e:
    print(f"CRITICAL ERROR: Failed to connect to MongoDB. Error: {e}")

# --- Core Collections ---
users_col = db["users"]
attendance_col = db["attendance"]
leaves_col = db["leaves"]

# --- Extended Modules Collections ---
corrections_col = db["attendance_corrections"]
pip_records_col = db["pip_records"]
announcements_col = db["announcements"]
access_grants_col = db["access_grants"] # Stores temporary admin access for employees

# --- Performance Management System (PMS) Collections ---
pms_templates_col = db["pms_templates"] # Stores Admin/Manager Sessions & Questions
pms_reviews_col = db["pms_reviews"] # Stores actual employee responses and manager evaluations

# Local Upload Fallback
UPLOAD_FOLDER = "uploads/attendance_photos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Application Timezone
IST = pytz.timezone('Asia/Kolkata')


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
    Useful for JSON serialization to the frontend.
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
    Validates password strength to enforce security standards.
    Requires: 8+ chars, 1 uppercase, 1 lowercase, 1 number, 1 special char.
    """
    if len(password) < 8: return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"\d", password): return False
    if not re.search(r"[@$!%*?&#^_\-]", password): return False
    return True


# =============================================================================
# 6. ROUTE: HEALTH CHECKS & STATIC FILES
# =============================================================================

@app.route("/")
def home():
    """ Health check route to ensure the backend is active. """
    return "GDMR Connect Backend is running normally ✅", 200

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    """ Serves files from the local uploads directory if Cloudinary isn't used. """
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    return send_from_directory(uploads_dir, filename)


# =============================================================================
# 7. AUTHENTICATION MIDDLEWARE
# =============================================================================

def token_required(f):
    """
    Decorator to protect routes using JWT authentication.
    Extracts the token from the Authorization header, decodes it, 
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
    Authenticates a user and returns a JWT token along with user details.
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
    Allows a user to update their password. Enforces strong password rules.
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
    Generates a temporary password and emails it to the user.
    """
    data = request.json
    email = data.get("email")

    user = users_col.find_one({"email": email})
    if not user:
        # Standard security practice: Don't reveal if email exists or not
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

    try:
        threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()
    except Exception as e:
        print(f"Failed to start email thread: {e}")

    return jsonify({"message": "Password reset email processed."}), 200


# =============================================================================
# 9. USER REGISTRATION ROUTES (ADMIN ONLY)
# =============================================================================

@app.route("/api/register-admin", methods=["POST"])
def register_admin():
    """ Initial setup route to create the master admin. """
    data = request.json
    email = data.get("email")
    name = data.get("name", "Admin")
    password = data.get("password", "admin123")

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
    """ Registers a new manager. Requires Admin privileges. """
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
    """ Registers a new employee. Requires Admin privileges. """
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized access."}), 403

    data = request.json
    name = data.get("name")
    email = data.get("email")
    department = data.get("department", "")
    position = data.get("position", "")
    manager_id = data.get("manager_id") 

    if users_col.find_one({"email": email}):
        return jsonify({"message": "User with this email already exists"}), 400

    # Auto-generate a secure temporary password
    password = generate_random_password()
    hashed = bcrypt.generate_password_hash(password).decode("utf-8")

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
        "late_checkin_count_monthly": 0, 
        "last_late_checkin_month": None,
    }

    res = users_col.insert_one(user_doc)

    # Email the credentials to the new employee
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

    # Map manager IDs to their names for easy reference on the frontend
    managers = {str(m["_id"]): m["name"] for m in users_col.find({"role": "manager"})}

    rows = []
    for u in users_col.find({"role": {"$in": ["employee", "manager"]}}):
        u["_id"] = str(u["_id"])
        if "password" in u:
            del u["password"]
        
        manager_id = u.get("manager_id")
        u["manager_name"] = managers.get(manager_id) if manager_id else None

        rows.append(u)

    return jsonify(rows), 200


@app.route("/api/admin/managers", methods=["GET"])
@token_required
def list_managers():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    managers = []
    for m in users_col.find({"role": "manager"}):
        m["_id"] = str(m["_id"])
        if "password" in m:
            del m["password"]
        managers.append(m)

    return jsonify(managers), 200


@app.route("/api/manager/my-employees", methods=["GET"])
@token_required
def manager_my_employees():
    """ Returns a list of employees specific to a Manager's department. """
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403

    rows = []
    for u in users_col.find({"department": request.user.get("department"), "role": "employee"}):
        u["_id"] = str(u["_id"])
        if "password" in u: del u["password"]
        rows.append(u)

    return jsonify(rows), 200


# =============================================================================
# 11. USER UPDATES & DELETIONS
# =============================================================================

@app.route("/api/admin/employees/<emp_id>", methods=["PUT"])
@token_required
def edit_employee(emp_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    update = {}

    for k in ["name", "department", "position", "email", "manager_id"]:
        if k in data:
            update[k] = data[k]
    
    if "manager_id" in data and not data["manager_id"]:
         update["manager_id"] = None
         
    if update:
        users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": update})
    
    return jsonify({"message": "Employee profile updated successfully."}), 200


@app.route("/api/admin/managers/<man_id>", methods=["PUT"])
@token_required
def edit_manager(man_id):
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
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    # Clean up user and all associated records
    users_col.delete_one({"_id": ObjectId(emp_id)})
    attendance_col.delete_many({"user_id": emp_id})
    leaves_col.delete_many({"user_id": emp_id})
    pms_reviews_col.delete_many({"user_id": emp_id})

    return jsonify({"message": "Employee completely removed from system."}), 200


@app.route("/api/admin/managers/<man_id>", methods=["DELETE"])
@token_required
def delete_manager(man_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    users_col.delete_one({"_id": ObjectId(man_id)})
    # Unassign this manager from their subordinates
    users_col.update_many({"manager_id": man_id}, {"$set": {"manager_id": None}})
    
    return jsonify({"message": "Manager removed. Subordinates must be reassigned."}), 200


# =============================================================================
# 12. DELEGATED ADMIN ACCESS (GRANT SYSTEM)
# =============================================================================

@app.route("/api/admin/grant-access", methods=["POST"])
@token_required
def grant_access():
    """ 
    Allows an Admin to grant temporary admin capabilities to a standard employee.
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

    grant_record = {
        "employee_id": emp_id,
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
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    
    grants = []
    for g in access_grants_col.find({"is_active": True}).sort("granted_at", -1):
        g["_id"] = str(g["_id"])
        emp = users_col.find_one({"_id": ObjectId(g["employee_id"])})
        g["employee_name"] = emp["name"] if emp else "Unknown Employee"
        grants.append(g)
        
    return jsonify(grants), 200


@app.route("/api/admin/revoke-access/<grant_id>", methods=["DELETE"])
@token_required
def revoke_access(grant_id):
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
    """ Frontend utility to check if the current user has active special permissions. """
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

    # Save the template strictly containing the specific assigned employee IDs
    template_record = {
        "department": dept_to_update,
        "sessions": data.get("sessions", []),
        "assigned_to": assigned_to_list,
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
    FIXED: Ensures the form is only sent to the user if their ID is in the 'assigned_to' array.
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

    # Prevent double submissions
    if pms_reviews_col.find_one({"user_id": uid, "month": month}):
        return jsonify({"message": "You have already submitted your Self Assessment for this month."}), 400

    submission = {
        "user_id": uid,
        "department": request.user.get("department"),
        "manager_id": request.user.get("manager_id"),
        "month": month,
        "responses": data.get("responses", []), 
        "status": "Pending Review", 
        "self_assessment_date": datetime.now(timezone.utc),
        "manager_review_date": None,
        "manager_scores": [],
        "manager_feedback": ""
    }
    
    pms_reviews_col.insert_one(submission)
    
    # OPTIONAL: You could remove the user from the `assigned_to` list here so they 
    # don't see the form anymore, but relying on the "Already Submitted" block is safer for records.
    
    return jsonify({"message": "Self Assessment Submitted for Manager Review."}), 201


@app.route("/api/manager/pms", methods=["GET"])
@token_required
def get_manager_pms():
    """ Fetches all pending and completed PMS reviews for a manager's department. """
    if request.user.get("role") not in ["manager", "admin"]: return jsonify({"message": "Unauthorized"}), 403
    
    my_dept = request.user.get("department")
    query = {"department": my_dept} if request.user.get("role") == "manager" else {}
    
    rows = []
    for r in pms_reviews_col.find(query).sort("self_assessment_date", -1):
        r["_id"] = str(r["_id"])
        emp = users_col.find_one({"_id": ObjectId(r["user_id"])})
        r["employee_name"] = emp["name"] if emp else "Unknown"
        rows.append(r)
    return jsonify(rows), 200


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
        
    pms_reviews_col.update_one(
        {"_id": ObjectId(review_id)},
        {"$set": {
            "manager_scores": data.get("manager_scores", []), 
            "manager_feedback": data.get("manager_feedback", ""),
            "status": "Manager Review Completed",
            "manager_review_date": datetime.now(timezone.utc)
        }}
    )
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
            mgr_total = sum([int(ms.get('score', 0)) for ms in r.get('manager_scores', []) if str(ms.get('score')).isdigit()])
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
    
    for r in pms_reviews_col.find(query).sort("department", 1):
        emp = users_col.find_one({"_id": ObjectId(r["user_id"])})
        emp_name = emp["name"] if emp else "Unknown"
        
        self_total = sum([int(res.get('self_score', 0)) for res in r.get('responses', []) if str(res.get('self_score')).isdigit()])
        mgr_total = sum([int(ms.get('score', 0)) for ms in r.get('manager_scores', []) if str(ms.get('score')).isdigit()])
        
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
    today = now_ist.date()
    today_str = str(today)

    if leaves_col.find_one({"user_id": uid, "status": "Approved", "date": today_str}):
        return jsonify({"message": "You have an approved leave for today. Attendance not required."}), 200

    if attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today_str}):
        return jsonify({"message": "Already checked in!"}), 400

    TIME_0900 = time(9, 0)
    TIME_1000 = time(10, 0)
    TIME_1015 = time(10, 15)
    TIME_1300 = time(13, 0)
    TIME_1400 = time(14, 0)

    status_indicator = "Unknown"
    day_type = "full"
    
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
    today = now_ist.date()

    checkin = attendance_col.find_one({"user_id": uid, "type": "checkin", "date": str(today)})
    if not checkin:
        return jsonify({"message": "You must Check-In first before Checking Out."}), 400

    if attendance_col.find_one({"user_id": uid, "type": "checkout", "date": str(today)}):
        return jsonify({"message": "Already checked out for today!"}), 400

    HALF_DAY_OUT_START = time(13, 0)
    HALF_DAY_OUT_END = time(14, 0)
    FULL_DAY_OUT_START = time(18, 0)
    LATE_CHECKOUT_START = time(19, 30)

    checkin_dt = utc_to_ist(checkin["time"])
    checkin_time = checkin_dt.time()

    final_day_type = checkin.get("day_type", "full")
    status_indicator = "On Time"

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
        except Exception as e:
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
    """ Returns leaves contextually based on user role and delegated grants. """
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    
    if role not in ["admin", "manager"] and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    query = {}
    
    if role == "manager" and not has_delegated:
        my_dept = request.user.get("department")
        dept_users = [str(u["_id"]) for u in users_col.find({"department": my_dept})]
        query = {"user_id": {"$in": dept_users}}

    rows = []
    employees = {str(e["_id"]): e for e in users_col.find()}
    
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
    uid = str(request.user["_id"])
    rows = []
    for l in leaves_col.find({"user_id": uid}).sort("applied_at", -1):
        l["_id"] = str(l["_id"])
        rows.append(l)
    return jsonify(rows), 200


# =============================================================================
# 16. ANNOUNCEMENTS, CORRECTIONS & NOTIFICATIONS
# =============================================================================

@app.route("/api/announcements", methods=["POST"])
@token_required
def create_announcement():
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
    rows = []
    for a in announcements_col.find().sort("created_at", -1):
        a["_id"] = str(a["_id"])
        rows.append(a)
    return jsonify(rows), 200


@app.route("/api/attendance/request-correction", methods=["POST"])
@token_required
def request_correction():
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
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    
    my_dept = request.user.get("department")
    dept_users = [str(u["_id"]) for u in users_col.find({"department": my_dept})]
    
    query = {"$or": [{"manager_id": str(request.user["_id"])}, {"user_id": {"$in": dept_users}}]}
    
    rows = []
    for c in corrections_col.find(query).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        u = users_col.find_one({"_id": ObjectId(c["user_id"])})
        c["employee_name"] = u["name"] if u else "Unknown"
        rows.append(c)
    return jsonify(rows), 200


@app.route("/api/my/corrections", methods=["GET"])
@token_required
def my_corrections():
    uid = str(request.user["_id"])
    rows = []
    for c in corrections_col.find({"user_id": uid}).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows), 200


@app.route("/api/manager/approve-correction", methods=["POST"])
@token_required
def approve_correction():
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
            
            attendance_col.insert_one({
                "user_id": correction["user_id"],
                "type": "checkin", 
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
    counts = {"leaves": 0, "pms": 0, "corrections": 0, "announcements": announcements_col.count_documents({})}
    
    if role == "manager":
        my_dept = request.user.get("department")
        dept_users = [str(u["_id"]) for u in users_col.find({"department": my_dept})]
        
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
        
    return jsonify(counts), 200


# =============================================================================
# 17. STATS & ANALYTICS DASHBOARDS
# =============================================================================

@app.route("/api/admin/today-stats", methods=["GET"])
@token_required
def today_stats():
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    
    if role != "admin" and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    today = str(datetime.now(IST).date())
    present = attendance_col.count_documents({"date": today, "type": "checkin"})
    leaves = leaves_col.count_documents({"date": today, "status": {"$in": ["Approved", "Absent"]}})
    total = users_col.count_documents({"role": {"$in": ["employee", "manager"]}})
    not_in = total - present - leaves

    return jsonify({"present": present, "leave": leaves, "not_checked_in": not_in}), 200


@app.route("/api/admin/attendance-summary", methods=["GET"])
@token_required
def attendance_summary():
    role = request.user.get("role")
    has_delegated = access_grants_col.find_one({"employee_id": str(request.user["_id"]), "is_active": True})
    
    if role != "admin" and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    month_param = request.args.get("month")
    if not month_param: return jsonify({"message": "month required"}), 400

    year, month = map(int, month_param.split("-"))
    start = datetime(year, month, 1, tzinfo=IST)
    end = (start + timedelta(days=32)).replace(day=1)

    employees = list(users_col.find({"role": {"$in": ["employee", "manager"]}}))
    emp_ids = [str(e["_id"]) for e in employees]

    summary = {"total_employees": len(employees), "days": {}}

    curr = start
    while curr < end:
        day_str = curr.date().isoformat()
        recs = list(attendance_col.find({"date": day_str}))
        present = {r["user_id"] for r in recs if r["type"] == "checkin"}
        
        leaves_today_docs = list(leaves_col.find({"date": day_str, "status": {"$in": ["Approved", "Absent"]}}))
        
        leave_names = []
        leave_ids = set()
        for l in leaves_today_docs:
            leave_ids.add(l["user_id"])
            u = users_col.find_one({"_id": ObjectId(l["user_id"])})
            if u: leave_names.append(u["name"])

        not_checked_in = set(emp_ids) - present - leave_ids

        summary["days"][day_str] = {
            "present": list(present), 
            "absent": [], 
            "leave": list(leave_ids), 
            "leave_names": leave_names, 
            "not_checked_in": list(not_checked_in),
        }
        curr += timedelta(days=1)

    return jsonify(summary), 200


@app.route("/api/attendance/auto-absent", methods=["POST"])
def auto_mark_absent():
    """ 
    Script endpoint to auto-flag users who didn't punch in.
    Usually called internally via cron or external trigger.
    """
    today = datetime.now(IST).date()
    today_str = str(today)
    all_users = users_col.find({"role": {"$in": ["employee", "manager"]}})

    for emp in all_users:
        uid = str(emp["_id"])
        
        if not attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today_str}):
            if not leaves_col.find_one({"user_id": uid, "status": "Approved", "date": today_str}):
                
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
# 18. AUTOMATED SCHEDULED JOBS (APScheduler)
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
            manager = users_col.find_one({"_id": ObjectId(rev["manager_id"])})
            emp = users_col.find_one({"_id": ObjectId(rev["user_id"])})
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


# Initialize the background scheduler
try:
    scheduler = BackgroundScheduler(timezone=IST)
    scheduler.add_job(func=send_pms_reminders, trigger="cron", hour=10, minute=0)
    scheduler.add_job(func=auto_expire_grants, trigger="interval", minutes=30)
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