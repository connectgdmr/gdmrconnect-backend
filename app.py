from flask import Flask, request, jsonify
from flask_cors import CORS
import base64, os
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from utils import send_email, generate_random_password
from bson import ObjectId
from datetime import datetime, timedelta, timezone, time
from flask import send_from_directory
import pytz
from flask_bcrypt import Bcrypt
import threading
import cloudinary
import cloudinary.uploader

load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

# --- CLOUDINARY CONFIG ---
cloudinary.config(
    cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key = os.getenv('CLOUDINARY_API_KEY'),
    api_secret = os.getenv('CLOUDINARY_API_SECRET')
)

# --- CORS CONFIG ---
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

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "replace-this-secret")
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["attendance_db"]

# --- COLLECTIONS ---
users_col = db["users"]
attendance_col = db["attendance"]
leaves_col = db["leaves"]

# --- PHASE 2 & 3 COLLECTIONS ---
pms_submissions_col = db["pms_submissions"]
pms_assignments_col = db["pms_assignments"] 
corrections_col = db["attendance_corrections"]
pip_records_col = db["pip_records"]
announcements_col = db["announcements"] 

UPLOAD_FOLDER = "uploads/attendance_photos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

IST = pytz.timezone('Asia/Kolkata')

# --- HELPERS ---
def utc_to_ist(utc_datetime):
    if utc_datetime.tzinfo is None:
        utc_datetime = pytz.utc.localize(utc_datetime)
    return utc_datetime.astimezone(IST)

def format_datetime_ist(dt):
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except:
            dt = datetime.fromisoformat(dt)
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(IST).isoformat()

@app.route("/")
def home():
    return "Backend running ✅", 200

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    return send_from_directory(uploads_dir, filename)

# -------------------------------------------------------------
# AUTH MIDDLEWARE
# -------------------------------------------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data.get("user_id")
            current_user = users_col.find_one({"_id": ObjectId(user_id)})
            if not current_user:
                return jsonify({"message": "User not found"}), 401
            request.user = current_user
        except Exception as e:
            return jsonify({"message": "Token is invalid!", "error": str(e)}), 401
        return f(*args, **kwargs)
    return decorated


# -------------------------------------------------------------
# FORGOT PASSWORD
# -------------------------------------------------------------
@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email")

    user = users_col.find_one({"email": email})
    if not user:
        return jsonify({"message": "If this email exists, a password reset has been sent."}), 200

    temp_password = generate_random_password()
    hashed = bcrypt.generate_password_hash(temp_password).decode("utf-8")
    
    users_col.update_one({"_id": user["_id"]}, {"$set": {"password": hashed}})

    subject = "Password Reset Request"
    body = (
        f"Hello {user['name']},\n\n"
        "We received a request to reset your password.\n"
        f"Your new temporary password is: {temp_password}\n\n"
        "Please login and change your password immediately."
    )
    
    threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()

    return jsonify({"message": "Password reset email sent."}), 200


# -------------------------------------------------------------
# ADMIN REGISTER
# -------------------------------------------------------------
@app.route("/api/register-admin", methods=["POST"])
def register_admin():
    data = request.json
    email = data.get("email")
    name = data.get("name", "Admin")
    password = data.get("password", "admin123")

    if users_col.find_one({"email": email}):
        return jsonify({"message": "Admin already exists"}), 400

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    user_doc = {
        "name": name,
        "email": email,
        "password": hashed,
        "role": "admin",
        "department": "",
        "position": "",
        "late_checkin_count_monthly": 0,
        "last_late_checkin_month": None,
    }
    res = users_col.insert_one(user_doc)
    return jsonify({"message": "Admin created", "id": str(res.inserted_id)}), 201


# -------------------------------------------------------------
# MANAGER REGISTER
# -------------------------------------------------------------
@app.route("/api/register-manager", methods=["POST"])
@token_required
def register_manager():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    department = data.get("department", "Management") 

    if not name or not email or not password or not department:
        return jsonify({"message": "Name, Email, Password, and Department are required"}), 400

    if users_col.find_one({"email": email}):
        return jsonify({"message": "Email already exists"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    new_user = {
        "name": name,
        "email": email,
        "password": hashed_pw,
        "role": "manager",
        "department": department,
        "position": "Manager",
        "created_at": datetime.now(timezone.utc),
        "late_checkin_count_monthly": 0, 
        "last_late_checkin_month": None,
    }

    users_col.insert_one(new_user)
    return jsonify({"message": "Manager created successfully!"}), 201


# -------------------------------------------------------------
# LOGIN
# -------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = users_col.find_one({"email": email})
    if not user or not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid credentials"}), 401

    token = jwt.encode({
        "user_id": str(user["_id"]),
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        "token": token,
        "role": user.get("role", "employee"),
        "user": {
            "name": user.get("name"),
            "email": user.get("email"),
            "department": user.get("department", "")
        }
    })


# -------------------------------------------------------------
# ADMIN: ADD EMPLOYEE
# -------------------------------------------------------------
@app.route("/api/admin/employees", methods=["POST"])
@token_required
def add_employee():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    name = data.get("name")
    email = data.get("email")
    department = data.get("department", "")
    position = data.get("position", "")
    manager_id = data.get("manager_id") 

    if users_col.find_one({"email": email}):
        return jsonify({"message": "User with this email already exists"}), 400

    password = generate_random_password()
    hashed = bcrypt.generate_password_hash(password).decode("utf-8")

    user_doc = {
        "name": name,
        "email": email,
        "password": hashed,
        "role": "employee",
        "department": department,
        "position": position,
        "created_at": datetime.now(timezone.utc),
        "manager_id": manager_id,
        "late_checkin_count_monthly": 0, 
        "last_late_checkin_month": None,
    }

    res = users_col.insert_one(user_doc)

    subject = "Welcome to GDMR Connect: Your New Account Credentials"
    body = (
        f"Dear {name},\n\n"
        "Your new employee account for the GDMR Connect Attendance App has been successfully created.\n\n"
        "Please use the following credentials to log in:\n"
        f"Username (Email): {email}\n"
        f"Temporary Password: {password}\n\n"
        "We recommend logging in as soon as possible and updating your password.\n\n"
        "Thank you,\n"
        "The GDMR Connect Team"
    )

    threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()

    return jsonify({"message": "Employee created", "id": str(res.inserted_id)}), 201


# -------------------------------------------------------------
# ADMIN: LIST EMPLOYEES
# -------------------------------------------------------------
@app.route("/api/admin/employees", methods=["GET"])
@token_required
def list_employees():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    managers = {str(m["_id"]): m["name"] for m in users_col.find({"role": "manager"})}

    rows = []
    for u in users_col.find({"role": {"$in": ["employee", "manager"]}}):
        u["_id"] = str(u["_id"])
        if "password" in u:
            del u["password"]
        
        manager_id = u.get("manager_id")
        u["manager_name"] = managers.get(manager_id) if manager_id else None

        rows.append(u)

    return jsonify(rows)


# -------------------------------------------------------------
# ADMIN: LIST MANAGERS
# -------------------------------------------------------------
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

    return jsonify(managers)


# -------------------------------------------------------------
# EDIT EMPLOYEE
# -------------------------------------------------------------
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
    
    return jsonify({"message": "Updated"})

# -------------------------------------------------------------
# EDIT MANAGER
# -------------------------------------------------------------
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

    return jsonify({"message": "Manager Updated"})


# -------------------------------------------------------------
# DELETE EMPLOYEE
# -------------------------------------------------------------
@app.route("/api/admin/employees/<emp_id>", methods=["DELETE"])
@token_required
def delete_employee(emp_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    users_col.delete_one({"_id": ObjectId(emp_id)})
    attendance_col.delete_many({"user_id": emp_id})
    leaves_col.delete_many({"user_id": emp_id})

    return jsonify({"message": "Deleted"})

# -------------------------------------------------------------
# DELETE MANAGER
# -------------------------------------------------------------
@app.route("/api/admin/managers/<man_id>", methods=["DELETE"])
@token_required
def delete_manager(man_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    users_col.delete_one({"_id": ObjectId(man_id)})
    users_col.update_many({"manager_id": man_id}, {"$set": {"manager_id": None}})
    
    return jsonify({"message": "Deleted"})


# -------------------------------------------------------------
# PHASE 3: ANNOUNCEMENTS
# -------------------------------------------------------------
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
    return jsonify({"message": "Announcement created"}), 201

@app.route("/api/announcements", methods=["GET"])
@token_required
def get_announcements():
    rows = []
    for a in announcements_col.find().sort("created_at", -1):
        a["_id"] = str(a["_id"])
        rows.append(a)
    return jsonify(rows)


# -------------------------------------------------------------
# PHASE 3: NOTIFICATIONS (COUNTS) - UPDATED
# -------------------------------------------------------------
@app.route("/api/notifications/counts", methods=["GET"])
@token_required
def get_notification_counts():
    uid = str(request.user["_id"])
    role = request.user.get("role")
    
    counts = {"leaves": 0, "pms": 0, "corrections": 0}
    
    if role == "manager":
        my_dept = request.user.get("department")
        dept_users = [str(u["_id"]) for u in users_col.find({"department": my_dept})]
        
        counts["leaves"] = leaves_col.count_documents({
            "user_id": {"$in": dept_users},
            "status": "Pending",
            "manager_status": "Pending" 
        })
        
        counts["pms"] = pms_submissions_col.count_documents({
            "user_id": {"$in": dept_users},
            "status": "Submitted_by_Employee"
        })
        
        counts["corrections"] = corrections_col.count_documents({
            "user_id": {"$in": dept_users},
            "status": "Pending"
        })
        
    elif role == "employee":
        # Check for PMS Assignment vs Submission
        month = datetime.now(IST).strftime("%Y-%m")
        # Has manager assigned questions?
        has_assignment = pms_assignments_col.find_one({"employee_id": uid, "month": month})
        # Has employee submitted?
        has_submission = pms_submissions_col.find_one({"user_id": uid, "month": month})
        
        # If Assigned BUT NOT Submitted -> 1 Notification
        if has_assignment and not has_submission:
            counts["pms"] = 1
        
    return jsonify(counts)


# -------------------------------------------------------------
# PHASE 2: ATTENDANCE CORRECTIONS
# -------------------------------------------------------------
@app.route("/api/attendance/request-correction", methods=["POST"])
@token_required
def request_correction():
    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    month_str = now_ist.strftime("%Y-%m")
    
    usage_count = corrections_col.count_documents({
        "user_id": uid, 
        "month": month_str
    })
    
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
    return jsonify({"message": "Correction request sent to manager"}), 201

@app.route("/api/my/corrections", methods=["GET"])
@token_required
def my_corrections():
    uid = str(request.user["_id"])
    rows = []
    for c in corrections_col.find({"user_id": uid}).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        rows.append(c)
    return jsonify(rows)

@app.route("/api/manager/corrections", methods=["GET"])
@token_required
def manager_corrections():
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    
    my_dept = request.user.get("department")
    dept_users = [str(u["_id"]) for u in users_col.find({"department": my_dept})]
    
    query = {"$or": [
        {"manager_id": str(request.user["_id"])},
        {"user_id": {"$in": dept_users}}
    ]}
    
    rows = []
    for c in corrections_col.find(query).sort("created_at", -1):
        c["_id"] = str(c["_id"])
        u = users_col.find_one({"_id": ObjectId(c["user_id"])})
        c["employee_name"] = u["name"] if u else "Unknown"
        rows.append(c)
    return jsonify(rows)

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


# ==============================================================================
#  PHASE 2: DYNAMIC PMS
# ==============================================================================

@app.route("/api/manager/assign-pms", methods=["POST"])
@token_required
def assign_pms():
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    employee_id = data.get("employee_id")
    questions = data.get("questions") 
    month = data.get("month")
    
    pms_assignments_col.update_one(
        {"employee_id": employee_id, "month": month},
        {"$set": {
            "manager_id": str(request.user["_id"]),
            "questions": questions,
            "created_at": datetime.now(timezone.utc)
        }},
        upsert=True
    )
    return jsonify({"message": "PMS Questions Assigned"}), 200

@app.route("/api/employee/pms-assignment", methods=["GET"])
@token_required
def get_pms_assignment():
    uid = str(request.user["_id"])
    month = datetime.now(IST).strftime("%Y-%m")
    
    assignment = pms_assignments_col.find_one({"employee_id": uid, "month": month})
    
    questions = assignment.get("questions", []) if assignment else []
    return jsonify({"questions": questions}), 200

@app.route("/api/pms/submit", methods=["POST"])
@token_required
def submit_pms():
    uid = str(request.user["_id"])
    data = request.json
    month = data.get("month")

    if pms_submissions_col.find_one({"user_id": uid, "month": month}):
        return jsonify({"message": "Evaluation already submitted for this month"}), 400

    submission_data = data.get("responses") or data.get("evaluation")

    submission = {
        "user_id": uid,
        "manager_id": request.user.get("manager_id"),
        "month": month,
        "responses": submission_data,
        "status": "Submitted_by_Employee",
        "submitted_at": datetime.now(timezone.utc)
    }
    pms_submissions_col.insert_one(submission)
    return jsonify({"message": "PMS Evaluation Submitted"}), 201

@app.route("/api/manager/pms", methods=["GET"])
@token_required
def manager_pms():
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    
    my_dept = request.user.get("department")
    dept_users = [str(u["_id"]) for u in users_col.find({"department": my_dept})]
    
    query = {"$or": [
        {"manager_id": str(request.user["_id"])},
        {"user_id": {"$in": dept_users}}
    ]}
    
    rows = []
    for p in pms_submissions_col.find(query).sort("submitted_at", -1):
        p["_id"] = str(p["_id"])
        u = users_col.find_one({"_id": ObjectId(p["user_id"])})
        p["employee_name"] = u["name"] if u else "Unknown"
        rows.append(p)
    return jsonify(rows)

@app.route("/api/manager/finalize-pms", methods=["POST"])
@token_required
def finalize_pms():
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    pid = data.get("id")
    score = data.get("manager_score")
    
    pms_submissions_col.update_one(
        {"_id": ObjectId(pid)}, 
        {"$set": {"manager_score": score, "status": "Approved"}}
    )
    return jsonify({"message": "PMS Finalized"}), 200

@app.route("/api/my/pms", methods=["GET"])
@token_required
def my_pms():
    uid = str(request.user["_id"])
    rows = []
    for p in pms_submissions_col.find({"user_id": uid}).sort("month", -1):
        p["_id"] = str(p["_id"])
        rows.append(p)
    return jsonify(rows)


# -------------------------------------------------------------
# PHASE 2: PIP
# -------------------------------------------------------------
@app.route("/api/pip/initiate", methods=["POST"])
@token_required
def initiate_pip():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    pip_record = {
        "employee_id": data.get("employee_id"),
        "manager_id": str(request.user["_id"]),
        "start_date": data.get("start_date"),
        "end_date": data.get("end_date"),
        "reason": data.get("reason"),
        "status": "Active",
        "weekly_updates": []
    }
    pip_records_col.insert_one(pip_record)
    
    emp = users_col.find_one({"_id": ObjectId(data.get("employee_id"))})
    if emp:
        subject = "Performance Improvement Plan Initiated"
        body = f"Hello {emp['name']},\nA PIP has been initiated. Please check your dashboard."
        threading.Thread(target=send_email, args=(emp["email"], subject, body), daemon=True).start()

    return jsonify({"message": "PIP Initiated"}), 201


# -------------------------------------------------------------
# CHECK-IN WITH PHOTO - UPDATED (FIX 1)
# -------------------------------------------------------------
@app.route("/api/attendance/checkin-photo", methods=["POST"])
@token_required
def checkin_photo():
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

    # Define Time Boundaries
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
        
    # Rule: Blocked Check-In Window (10:15 AM - 1:00 PM)
    elif TIME_1015 <= current_time < TIME_1300:
        # FIX: Explicitly mark as Absent (Half Day) in DB
        if not attendance_col.find_one({"user_id": uid, "date": today_str, "type": "absent"}):
             attendance_col.insert_one({
                "user_id": uid, "type": "absent", "date": today_str, 
                "time": datetime.now(timezone.utc), "status_indicator": "Absent (Half Day)"
             })
             if not leaves_col.find_one({"user_id": uid, "date": today_str, "type": "System Absent"}):
                 leaves_col.insert_one({
                    "user_id": uid, "from_date": today_str, "to_date": today_str, "date": today_str,
                    "type": "System Absent", "reason": "Late: Missed Morning Window", "status": "Absent", "applied_at": datetime.now(timezone.utc)
                 })
                 
        return jsonify({
            "message": "Check-in blocked (10:15 AM - 1:00 PM). Marked as Absent (Half Day)."
        }), 400

    elif TIME_1300 <= current_time < TIME_1400:
        status_indicator = "Half Day"
        day_type = "half-day"
        
    # Rule: Full-Day Absent Conversion (After 2:00 PM)
    else: 
        # current_time >= 14:00
        # FIX: Explicitly mark as Absent (Full Day) in DB
        if not attendance_col.find_one({"user_id": uid, "date": today_str, "type": "absent"}):
             attendance_col.insert_one({
                "user_id": uid, "type": "absent", "date": today_str, 
                "time": datetime.now(timezone.utc), "status_indicator": "Absent (Full Day)"
             })
             if not leaves_col.find_one({"user_id": uid, "date": today_str, "type": "System Absent"}):
                 leaves_col.insert_one({
                    "user_id": uid, "from_date": today_str, "to_date": today_str, "date": today_str,
                    "type": "System Absent", "reason": "Absent: Missed Check-in", "status": "Absent", "applied_at": datetime.now(timezone.utc)
                 })

        return jsonify({
            "message": "Check-in closed. Marked as Absent (Full Day)."
        }), 400

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image"}), 400

    try:
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        photo_url = upload_result.get("secure_url")
    except Exception as e:
        print("Cloudinary Upload Error:", e)
        return jsonify({"message": "Image upload failed"}), 500

    attendance_col.insert_one({
        "user_id": uid,
        "type": "checkin",
        "date": today_str,
        "day_type": day_type,
        "time": datetime.now(timezone.utc),
        "photo_url": photo_url, 
        "status_indicator": status_indicator 
    })

    return jsonify({"message": f"Checked in ({status_indicator})"}), 200


# -------------------------------------------------------------
# CHECK-OUT PHOTO
# -------------------------------------------------------------
@app.route("/api/attendance/checkout-photo", methods=["POST"])
@token_required
def checkout_photo():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    current_time = now_ist.time()
    today = now_ist.date()

    checkin = attendance_col.find_one({"user_id": uid, "type": "checkin", "date": str(today)})
    if not checkin:
        return jsonify({"message": "Check in first!"}), 400

    if attendance_col.find_one({"user_id": uid, "type": "checkout", "date": str(today)}):
        return jsonify({"message": "Already checked out!"}), 400

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
        return jsonify({"message": "No image"}), 400

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

    return jsonify({"message": f"Checked out ({final_day_type}, {status_indicator})"}), 200


@app.route("/attendance_photos/<path:filename>")
def serve_attendance_photo(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# -------------------------------------------------------------
# APPLY LEAVE
# -------------------------------------------------------------
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


# -------------------------------------------------------------
# ADMIN VIEW LEAVES
# -------------------------------------------------------------
@app.route("/api/admin/leaves", methods=["GET"])
@token_required
def admin_view_leaves():
    if request.user.get("role") not in ["admin", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    query = {}
    
    if request.user.get("role") == "manager":
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


# -------------------------------------------------------------
# UPDATE LEAVE STATUS
# -------------------------------------------------------------
@app.route("/api/admin/leaves/<leave_id>", methods=["PUT"])
@token_required
def update_leave(leave_id):
    role = request.user.get("role")
    if role not in ["admin", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    action = data.get("status")

    if action not in ("Approved", "Rejected", "Pending"):
        return jsonify({"message": "Invalid status"}), 400

    update_fields = {}

    if role == "manager":
        update_fields["manager_status"] = action
    elif role == "admin":
        update_fields["admin_status"] = action

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

    leaves_col.update_one({"_id": ObjectId(leave_id)}, {
        "$set": {"status": final_status}
    })

    try:
        user = users_col.find_one({"_id": ObjectId(leave["user_id"])})
        if user:
            threading.Thread(target=send_email, args=(user["email"], "Leave Update", f"Status: {final_status}"), daemon=True).start()
    except Exception as e:
        print("Email error:", e)

    return jsonify({"message": "Updated"})


# -------------------------------------------------------------
# MANAGER: LIST MY EMPLOYEES
# -------------------------------------------------------------
@app.route("/api/manager/my-employees", methods=["GET"])
@token_required
def manager_my_employees():
    if request.user.get("role") != "manager":
        return jsonify({"message": "Unauthorized"}), 403

    rows = []
    for u in users_col.find({"department": request.user.get("department"), "role": "employee"}):
        u["_id"] = str(u["_id"])
        if "password" in u: del u["password"]
        rows.append(u)

    return jsonify(rows)


# -------------------------------------------------------------
# MY ATTENDANCE
# -------------------------------------------------------------
@app.route("/api/my/attendance", methods=["GET"])
@token_required
def my_attendance():
    uid = str(request.user["_id"])
    rows = []

    for a in attendance_col.find({"user_id": uid}).sort("time", -1):
        a["_id"] = str(a["_id"])
        a["time"] = format_datetime_ist(a["time"])
        rows.append(a)

    return jsonify(rows)


# -------------------------------------------------------------
# MY LEAVES
# -------------------------------------------------------------
@app.route("/api/my/leaves", methods=["GET"])
@token_required
def my_leaves():
    uid = str(request.user["_id"])
    rows = []

    for l in leaves_col.find({"user_id": uid}).sort("applied_at", -1):
        l["_id"] = str(l["_id"])
        rows.append(l)

    return jsonify(rows)


# -------------------------------------------------------------
# ADMIN: EMPLOYEE ATTENDANCE
# -------------------------------------------------------------
@app.route("/api/admin/attendance/<emp_id>", methods=["GET"])
@token_required
def admin_employee_attendance(emp_id):
    if request.user.get("role") != "admin":
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

    return jsonify(records)


# -------------------------------------------------------------
# AUTO ABSENT
# -------------------------------------------------------------
@app.route("/api/attendance/auto-absent", methods=["POST"])
def auto_mark_absent():
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


# -------------------------------------------------------------
# ADMIN MONTHLY SUMMARY
# -------------------------------------------------------------
@app.route("/api/admin/attendance-summary", methods=["GET"])
@token_required
def attendance_summary():
    if request.user.get("role") != "admin":
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


# -------------------------------------------------------------
# TODAY STATS
# -------------------------------------------------------------
@app.route("/api/admin/today-stats", methods=["GET"])
@token_required
def today_stats():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    today = str(datetime.now(IST).date())
    present = attendance_col.count_documents({"date": today, "type": "checkin"})
    leaves = leaves_col.count_documents({"date": today, "status": {"$in": ["Approved", "Absent"]}})
    total = users_col.count_documents({"role": {"$in": ["employee", "manager"]}})
    not_in = total - present - leaves

    return jsonify({
        "present": present, "leave": leaves, "not_checked_in": not_in,
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)