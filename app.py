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
pms_assignments_col = db["pms_assignments"] # NEW: Stores Manager Questions
corrections_col = db["attendance_corrections"]
pip_records_col = db["pip_records"]
announcements_col = db["announcements"] # NEW: Admin Announcements

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
# AUTH & USER MANAGEMENT ROUTES
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
    body = f"Hello {user['name']},\n\nYour new temporary password is: {temp_password}\n\nPlease login immediately."
    threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()
    return jsonify({"message": "Password reset email sent."}), 200

@app.route("/api/register-admin", methods=["POST"])
def register_admin():
    data = request.json
    email = data.get("email")
    if users_col.find_one({"email": email}):
        return jsonify({"message": "Admin already exists"}), 400

    hashed = bcrypt.generate_password_hash(data.get("password", "admin123")).decode("utf-8")
    users_col.insert_one({
        "name": data.get("name", "Admin"), "email": email, "password": hashed, "role": "admin", "department": "", "late_checkin_count_monthly": 0
    })
    return jsonify({"message": "Admin created"}), 201

@app.route("/api/register-manager", methods=["POST"])
@token_required
def register_manager():
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    data = request.get_json()
    if users_col.find_one({"email": data.get("email")}): return jsonify({"message": "Email already exists"}), 400

    hashed = bcrypt.generate_password_hash(data.get("password")).decode("utf-8")
    users_col.insert_one({
        "name": data.get("name"), "email": data.get("email"), "password": hashed, "role": "manager",
        "department": data.get("department", "Management"), "position": "Manager",
        "created_at": datetime.now(timezone.utc), "late_checkin_count_monthly": 0
    })
    return jsonify({"message": "Manager created successfully!"}), 201

@app.route("/api/admin/employees", methods=["POST"])
@token_required
def add_employee():
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    if users_col.find_one({"email": data.get("email")}): return jsonify({"message": "User exists"}), 400

    password = generate_random_password()
    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    res = users_col.insert_one({
        "name": data.get("name"), "email": data.get("email"), "password": hashed, "role": "employee",
        "department": data.get("department"), "position": data.get("position"), "manager_id": data.get("manager_id"),
        "created_at": datetime.now(timezone.utc), "late_checkin_count_monthly": 0
    })
    
    subject = "Welcome to GDMR Connect"
    body = f"Dear {data.get('name')},\n\nUsername: {data.get('email')}\nPassword: {password}\n\nLogin immediately."
    threading.Thread(target=send_email, args=(data.get("email"), subject, body), daemon=True).start()
    return jsonify({"message": "Employee created", "id": str(res.inserted_id)}), 201

@app.route("/api/admin/employees", methods=["GET"])
@token_required
def list_employees():
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    managers = {str(m["_id"]): m["name"] for m in users_col.find({"role": "manager"})}
    rows = []
    for u in users_col.find({"role": {"$in": ["employee", "manager"]}}):
        u["_id"] = str(u["_id"])
        if "password" in u: del u["password"]
        u["manager_name"] = managers.get(u.get("manager_id")) if u.get("manager_id") else None
        rows.append(u)
    return jsonify(rows)

@app.route("/api/admin/managers", methods=["GET"])
@token_required
def list_managers():
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for m in users_col.find({"role": "manager"}):
        m["_id"] = str(m["_id"])
        del m["password"]
        rows.append(m)
    return jsonify(rows)

@app.route("/api/admin/employees/<emp_id>", methods=["PUT"])
@token_required
def edit_employee(emp_id):
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    update = {k: data[k] for k in ["name", "department", "position", "email", "manager_id"] if k in data}
    if "manager_id" in data and not data["manager_id"]: update["manager_id"] = None
    if update: users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": update})
    return jsonify({"message": "Updated"})

@app.route("/api/admin/managers/<man_id>", methods=["PUT"])
@token_required
def edit_manager(man_id):
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    update = {k: data[k] for k in ["name", "department", "email"] if k in data}
    if update: users_col.update_one({"_id": ObjectId(man_id)}, {"$set": update})
    return jsonify({"message": "Updated"})

@app.route("/api/admin/employees/<emp_id>", methods=["DELETE"])
@token_required
def delete_employee(emp_id):
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    users_col.delete_one({"_id": ObjectId(emp_id)})
    attendance_col.delete_many({"user_id": emp_id})
    leaves_col.delete_many({"user_id": emp_id})
    return jsonify({"message": "Deleted"})

@app.route("/api/admin/managers/<man_id>", methods=["DELETE"])
@token_required
def delete_manager(man_id):
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    users_col.delete_one({"_id": ObjectId(man_id)})
    users_col.update_many({"manager_id": man_id}, {"$set": {"manager_id": None}})
    return jsonify({"message": "Deleted"})


# -------------------------------------------------------------
# PHASE 3: ANNOUNCEMENTS (NEW)
# -------------------------------------------------------------
@app.route("/api/announcements", methods=["POST"])
@token_required
def create_announcement():
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
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
# PHASE 3: NOTIFICATIONS (COUNTS)
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
        
        # Count pending items for manager's department
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
        # Optionally count employee specific notifications here if needed
        pass
        
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
    
    if corrections_col.count_documents({"user_id": uid, "month": month_str}) >= 3:
        return jsonify({"message": "Monthly limit of 3 corrections reached"}), 400
    
    data = request.json
    corrections_col.insert_one({
        "user_id": uid, "manager_id": request.user.get("manager_id"),
        "attendance_id": data.get("attendance_id"),
        "new_time": data.get("new_time"), "reason": data.get("reason"),
        "status": "Pending", "month": month_str, "created_at": datetime.now(timezone.utc)
    })
    return jsonify({"message": "Correction request sent"}), 201

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
                "user_id": correction["user_id"], "type": "checkin", 
                "date": str(new_dt.date()), "time": new_dt, 
                "photo_url": None, "status_indicator": "Corrected", "correction_ref": cid
            })
        except Exception as e:
            print("Error updating attendance log:", e)
    
    return jsonify({"message": f"Correction {action}"}), 200


# ==============================================================================
#  PHASE 2: DYNAMIC PMS
# ==============================================================================
# 1. Manager Assigns Questions
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
            "manager_id": str(request.user["_id"]), "questions": questions, "created_at": datetime.now(timezone.utc)
        }},
        upsert=True
    )
    return jsonify({"message": "PMS Questions Assigned"}), 200

# 2. Employee Fetches Questions
@app.route("/api/employee/pms-assignment", methods=["GET"])
@token_required
def get_pms_assignment():
    uid = str(request.user["_id"])
    month = datetime.now(IST).strftime("%Y-%m")
    assignment = pms_assignments_col.find_one({"employee_id": uid, "month": month})
    return jsonify({"questions": assignment.get("questions", []) if assignment else []}), 200

# 3. Employee Submits Responses
@app.route("/api/pms/submit", methods=["POST"])
@token_required
def submit_pms():
    uid = str(request.user["_id"])
    data = request.json
    month = data.get("month")
    
    if pms_submissions_col.find_one({"user_id": uid, "month": month}):
        return jsonify({"message": "Already submitted"}), 400

    submission = {
        "user_id": uid, "manager_id": request.user.get("manager_id"),
        "month": month, "responses": data.get("responses"), 
        "status": "Submitted_by_Employee", "submitted_at": datetime.now(timezone.utc)
    }
    pms_submissions_col.insert_one(submission)
    return jsonify({"message": "PMS Evaluation Submitted"}), 201

# 4. Manager Reviews
@app.route("/api/manager/pms", methods=["GET"])
@token_required
def manager_pms():
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    dept_users = [str(u["_id"]) for u in users_col.find({"department": request.user.get("department")})]
    query = {"$or": [{"manager_id": str(request.user["_id"])}, {"user_id": {"$in": dept_users}}]}
    rows = []
    for p in pms_submissions_col.find(query).sort("submitted_at", -1):
        p["_id"] = str(p["_id"])
        u = users_col.find_one({"_id": ObjectId(p["user_id"])})
        p["employee_name"] = u["name"] if u else "Unknown"
        rows.append(p)
    return jsonify(rows)

# 5. Manager Finalizes
@app.route("/api/manager/finalize-pms", methods=["POST"])
@token_required
def finalize_pms():
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    pms_submissions_col.update_one(
        {"_id": ObjectId(data.get("id"))}, 
        {"$set": {"manager_score": data.get("manager_score"), "status": "Approved"}}
    )
    return jsonify({"message": "PMS Finalized"}), 200

# 6. History
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
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    pip_records_col.insert_one({
        "employee_id": data.get("employee_id"), "manager_id": str(request.user["_id"]),
        "start_date": data.get("start_date"), "end_date": data.get("end_date"),
        "reason": data.get("reason"), "status": "Active", "weekly_updates": []
    })
    return jsonify({"message": "PIP Initiated"}), 201


# -------------------------------------------------------------
# ATTENDANCE (CHECK-IN)
# -------------------------------------------------------------
@app.route("/api/attendance/checkin-photo", methods=["POST"])
@token_required
def checkin_photo():
    if request.user.get("role") not in ["employee", "manager"]: return jsonify({"message": "Unauthorized"}), 403
    
    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    current_time = now_ist.time()
    today = now_ist.date()

    # Define Times
    MORNING_LATE_CUTOFF = time(10, 15)
    AFTERNOON_START_THRESHOLD = time(13, 0)
    AFTERNOON_LATE_CUTOFF = time(14, 0)

    if attendance_col.find_one({"user_id": uid, "type": "checkin", "date": str(today)}):
        return jsonify({"message": "Already checked in!"}), 400

    checkin_type = "full"
    status_indicator = "On Time"

    if current_time < AFTERNOON_START_THRESHOLD:
        checkin_type = "full"
        if current_time > MORNING_LATE_CUTOFF: status_indicator = "Late"
    else:
        checkin_type = "half-day"
        if current_time > AFTERNOON_LATE_CUTOFF: status_indicator = "Late"

    data = request.get_json()
    try:
        photo_url = cloudinary.uploader.upload(data.get("image"), folder="attendance_photos").get("secure_url")
    except: return jsonify({"message": "Image upload failed"}), 500

    attendance_col.insert_one({
        "user_id": uid, "type": "checkin", "date": str(today), "day_type": checkin_type,
        "time": datetime.now(timezone.utc), "photo_url": photo_url, "status_indicator": status_indicator 
    })
    return jsonify({"message": f"Checked in ({status_indicator})"}), 200

# -------------------------------------------------------------
# ATTENDANCE (CHECK-OUT)
# -------------------------------------------------------------
@app.route("/api/attendance/checkout-photo", methods=["POST"])
@token_required
def checkout_photo():
    if request.user.get("role") not in ["employee", "manager"]: return jsonify({"message": "Unauthorized"}), 403

    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    current_time = now_ist.time()
    today = now_ist.date()

    checkin = attendance_col.find_one({"user_id": uid, "type": "checkin", "date": str(today)})
    if not checkin: return jsonify({"message": "Check in first!"}), 400
    if attendance_col.find_one({"user_id": uid, "type": "checkout", "date": str(today)}): return jsonify({"message": "Already checked out!"}), 400

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
    
    if current_time > LATE_CHECKOUT_START: status_indicator = "Late Checkout"
    elif current_time < FULL_DAY_OUT_START:
        if final_day_type == "half-day" and (HALF_DAY_OUT_START <= current_time <= HALF_DAY_OUT_END):
             status_indicator = "On Time"
        else:
             status_indicator = "Early"

    data = request.get_json()
    try:
        photo_url = cloudinary.uploader.upload(data.get("image"), folder="attendance_photos").get("secure_url")
    except: return jsonify({"message": "Image upload failed"}), 500

    attendance_col.insert_one({
        "user_id": uid, "type": "checkout", "date": str(today), "time": datetime.now(timezone.utc),
        "photo_url": photo_url, "day_type": final_day_type, "status_indicator": status_indicator
    })
    return jsonify({"message": f"Checked out ({final_day_type}, {status_indicator})"}), 200

@app.route("/attendance_photos/<path:filename>")
def serve_attendance_photo(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# -------------------------------------------------------------
# LEAVE MANAGEMENT (Fix: Half Day Period)
# -------------------------------------------------------------
@app.route("/api/leaves", methods=["POST"])
@token_required
def apply_leave():
    if request.user.get("role") not in ["employee", "manager"]: return jsonify({"message": "Unauthorized"}), 403

    from_date = request.form.get("from_date")
    to_date = request.form.get("to_date")
    
    if not from_date and request.form.get("date"):
        from_date = request.form.get("date")
        to_date = request.form.get("date")

    leave_type = request.form.get("type", "full")
    period = request.form.get("period") # NEW: "First Half", "Second Half"
    reason = request.form.get("reason", "")

    if not from_date or not to_date: return jsonify({"message": "Start and End dates are required"}), 400

    try:
        f_date = datetime.strptime(from_date, "%Y-%m-%d").date()
        t_date = datetime.strptime(to_date, "%Y-%m-%d").date()
    except ValueError: return jsonify({"message": "Invalid date format."}), 400

    if t_date < f_date: return jsonify({"message": "End date cannot be before start date"}), 400

    # 7-day past limit check
    now_ist_date = datetime.now(IST).date()
    max_past_date = now_ist_date - timedelta(days=7) 
    if f_date < max_past_date: return jsonify({"message": f"Leave application for past dates is limited to 7 days."}), 400

    attachment_url = None
    if request.files.get("attachment"):
        try: attachment_url = cloudinary.uploader.upload(request.files.get("attachment"), folder="leave_attachments").get("secure_url")
        except: return jsonify({"message": "File upload failed"}), 500

    leaves_col.insert_one({
        "user_id": str(request.user["_id"]), "from_date": from_date, "to_date": to_date, "date": from_date,
        "type": leave_type, "period": period, # Saved Here
        "reason": reason, "status": "Pending", "manager_status": "Pending", "admin_status": "Pending",
        "applied_at": datetime.now(timezone.utc), "attachment_url": attachment_url
    })
    return jsonify({"message": "Applied"}), 201


# -------------------------------------------------------------
# ADMIN VIEW LEAVES (Fix: Applied Date + Dept Filter)
# -------------------------------------------------------------
@app.route("/api/admin/leaves", methods=["GET"])
@token_required
def admin_view_leaves():
    if request.user.get("role") not in ["admin", "manager"]: return jsonify({"message": "Unauthorized"}), 403
    
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
            
        # FIX: Send Applied Date
        l["applied_at_str"] = l["applied_at"].strftime("%Y-%m-%d") if l.get("applied_at") else l.get("date")
        rows.append(l)

    return jsonify(rows), 200

@app.route("/api/admin/leaves/<leave_id>", methods=["PUT"])
@token_required
def update_leave(leave_id):
    role = request.user.get("role")
    if role not in ["admin", "manager"]: return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    status = data.get("status")
    update_fields = {}

    if role == "manager": update_fields["manager_status"] = status
    elif role == "admin": update_fields["admin_status"] = status

    leaves_col.update_one({"_id": ObjectId(leave_id)}, {"$set": update_fields})
    leave = leaves_col.find_one({"_id": ObjectId(leave_id)})
    
    ms, as_ = leave.get("manager_status", "Pending"), leave.get("admin_status", "Pending")
    final = "Pending"
    if ms == "Rejected" or as_ == "Rejected": final = "Rejected"
    elif ms == "Approved" and as_ == "Approved": final = "Approved"
    
    leaves_col.update_one({"_id": ObjectId(leave_id)}, {"$set": {"status": final}})

    user = users_col.find_one({"_id": ObjectId(leave["user_id"])})
    if user: threading.Thread(target=send_email, args=(user["email"], "Leave Update", f"Status: {final}"), daemon=True).start()
    return jsonify({"message": "Updated"})


# -------------------------------------------------------------
# MY ATTENDANCE / LEAVES / TEAM
# -------------------------------------------------------------
@app.route("/api/manager/my-employees", methods=["GET"])
@token_required
def manager_my_employees():
    if request.user.get("role") != "manager": return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for u in users_col.find({"department": request.user.get("department"), "role": "employee"}):
        u["_id"] = str(u["_id"])
        del u["password"]
        rows.append(u)
    return jsonify(rows)

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

@app.route("/api/my/leaves", methods=["GET"])
@token_required
def my_leaves():
    uid = str(request.user["_id"])
    rows = []
    for l in leaves_col.find({"user_id": uid}).sort("applied_at", -1):
        l["_id"] = str(l["_id"])
        rows.append(l)
    return jsonify(rows)

@app.route("/api/admin/attendance/<emp_id>", methods=["GET"])
@token_required
def admin_employee_attendance(emp_id):
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    records = []
    for a in attendance_col.find({"user_id": emp_id}).sort("time", -1):
        a["_id"] = str(a["_id"])
        a["time"] = format_datetime_ist(a["time"])
        records.append(a)
    return jsonify(records)


# -------------------------------------------------------------
# AUTO ABSENT (Fix: Reflect in My Leaves)
# -------------------------------------------------------------
@app.route("/api/attendance/auto-absent", methods=["POST"])
def auto_mark_absent():
    today = str(datetime.now(IST).date())
    all_users = users_col.find({"role": {"$in": ["employee", "manager"]}})

    for emp in all_users:
        uid = str(emp["_id"])
        # If not checked in
        if not attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today}):
            # And no approved leave exists
            if not leaves_col.find_one({"user_id": uid, "status": "Approved", "date": today}):
                
                # 1. Log Attendance
                if not attendance_col.find_one({"user_id": uid, "type": "absent", "date": today}):
                    attendance_col.insert_one({"user_id": uid, "type": "absent", "date": today, "time": datetime.now(timezone.utc)})
                
                # 2. Log in Leaves (Fix #6)
                if not leaves_col.find_one({"user_id": uid, "type": "System Absent", "date": today}):
                    leaves_col.insert_one({
                        "user_id": uid, "from_date": today, "to_date": today, "date": today,
                        "type": "System Absent", "reason": "Not checked in", "status": "Absent", 
                        "applied_at": datetime.now(timezone.utc)
                    })

    return jsonify({"message": "Auto-absent checked"}), 200


# -------------------------------------------------------------
# ADMIN REPORTS
# -------------------------------------------------------------
@app.route("/api/admin/attendance-summary", methods=["GET"])
@token_required
def attendance_summary():
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    month_param = request.args.get("month")
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
        
        # Include Approved and System Absent leaves
        leaves_today_docs = list(leaves_col.find({"date": day_str, "status": {"$in": ["Approved", "Absent"]}}))
        leave_ids = {l["user_id"] for l in leaves_today_docs}
        leave_names = []
        for l in leaves_today_docs:
            u = users_col.find_one({"_id": ObjectId(l["user_id"])})
            if u: leave_names.append(u["name"])

        not_checked_in = set(emp_ids) - present - leave_ids

        summary["days"][day_str] = {
            "present": list(present), "absent": [], "leave": list(leave_ids), "leave_names": leave_names,
            "not_checked_in": list(not_checked_in)
        }
        curr += timedelta(days=1)
    return jsonify(summary), 200

@app.route("/api/admin/today-stats", methods=["GET"])
@token_required
def today_stats():
    if request.user.get("role") != "admin": return jsonify({"message": "Unauthorized"}), 403
    today = str(datetime.now(IST).date())
    present = attendance_col.count_documents({"date": today, "type": "checkin"})
    leaves = leaves_col.count_documents({"date": today, "status": {"$in": ["Approved", "Absent"]}})
    total = users_col.count_documents({"role": {"$in": ["employee", "manager"]}})
    return jsonify({"present": present, "leave": leaves, "not_checked_in": total - present - leaves})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))