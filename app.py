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

users_col = db["users"]
attendance_col = db["attendance"]
leaves_col = db["leaves"]

# UPLOAD_FOLDER is no longer strictly needed for persistent storage if using Cloudinary
UPLOAD_FOLDER = "uploads/attendance_photos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

IST = pytz.timezone('Asia/Kolkata')

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

# Keep this for backward compatibility if old files still exist locally
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
            "email": user.get("email")
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
    
    # Allow clearing manager
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
# DELETE MANAGER (Existing endpoint updated to be specific)
# -------------------------------------------------------------
@app.route("/api/admin/managers/<man_id>", methods=["DELETE"])
@token_required
def delete_manager(man_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    users_col.delete_one({"_id": ObjectId(man_id)})
    # Also unassign this manager from any employees
    users_col.update_many({"manager_id": man_id}, {"$set": {"manager_id": None}})
    
    return jsonify({"message": "Deleted"})


# -------------------------------------------------------------
# CHECK-IN WITH PHOTO (UPDATED RULES + CLOUDINARY)
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

    # Define Times
    MORNING_LATE_CUTOFF = time(10, 15)
    AFTERNOON_START_THRESHOLD = time(13, 0)
    AFTERNOON_LATE_CUTOFF = time(14, 0)

    # Check for existing checkin
    if attendance_col.find_one({"user_id": uid, "type": "checkin", "date": str(today)}):
        return jsonify({"message": "Already checked in!"}), 400

    # Determine Day Type and Status
    checkin_type = "full"
    status_indicator = "On Time"

    if current_time < AFTERNOON_START_THRESHOLD:
        # Morning Session
        checkin_type = "full"
        if current_time > MORNING_LATE_CUTOFF:
            status_indicator = "Late" # Frontend shows "Late Check-in"
    else:
        # Afternoon Session
        checkin_type = "half-day"
        if current_time > AFTERNOON_LATE_CUTOFF:
             status_indicator = "Late"

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image"}), 400

    # --- CLOUDINARY UPLOAD START ---
    # img_data comes as "data:image/jpeg;base64,....." which Cloudinary supports directly
    try:
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        photo_url = upload_result.get("secure_url")
    except Exception as e:
        print("Cloudinary Upload Error:", e)
        return jsonify({"message": "Image upload failed"}), 500
    # --- CLOUDINARY UPLOAD END ---

    attendance_col.insert_one({
        "user_id": uid,
        "type": "checkin",
        "date": str(today),
        "day_type": checkin_type,
        "time": datetime.now(timezone.utc),
        "photo_url": photo_url, # Now storing Cloudinary URL
        "status_indicator": status_indicator 
    })

    return jsonify({"message": f"Checked in ({checkin_type}, {status_indicator})"}), 200


# -------------------------------------------------------------
# CHECK-OUT PHOTO (UPDATED RULES + CLOUDINARY)
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

    # Define Times
    HALF_DAY_OUT_START = time(13, 0)
    HALF_DAY_OUT_END = time(14, 0)
    FULL_DAY_OUT_START = time(18, 0)
    LATE_CHECKOUT_START = time(19, 30)

    # Convert checkin time to IST to compare
    checkin_dt = utc_to_ist(checkin["time"])
    checkin_time = checkin_dt.time()

    final_day_type = checkin.get("day_type", "full")
    status_indicator = "On Time"

    # --- Day Type Logic ---
    # If checked in morning (< 1 PM) AND checking out between 1 PM and 2 PM -> Half Day
    if checkin_time < time(13, 0) and (HALF_DAY_OUT_START <= current_time <= HALF_DAY_OUT_END):
        final_day_type = "half-day"
        attendance_col.update_one({"_id": checkin["_id"]}, {"$set": {"day_type": "half-day"}})
    
    # --- Status Logic ---
    # "if checkout late show late checkout" -> > 7:30 PM
    if current_time > LATE_CHECKOUT_START:
        status_indicator = "Late Checkout" # or just "Late"
    elif current_time < FULL_DAY_OUT_START:
        # Check if it is a valid Half Day checkout time (1-2 PM)
        if final_day_type == "half-day" and (HALF_DAY_OUT_START <= current_time <= HALF_DAY_OUT_END):
             status_indicator = "On Time"
        else:
             status_indicator = "Early" # Frontend shows "Early Checkout"
    else:
        status_indicator = "On Time"

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image"}), 400

    # --- CLOUDINARY UPLOAD START ---
    try:
        upload_result = cloudinary.uploader.upload(img_data, folder="attendance_photos")
        photo_url = upload_result.get("secure_url")
    except Exception as e:
        print("Cloudinary Upload Error:", e)
        return jsonify({"message": "Image upload failed"}), 500
    # --- CLOUDINARY UPLOAD END ---

    attendance_col.insert_one({
        "user_id": uid,
        "type": "checkout",
        "date": str(today),
        "time": datetime.now(timezone.utc),
        "photo_url": photo_url, # Now storing Cloudinary URL
        "day_type": final_day_type,
        "status_indicator": status_indicator
    })

    return jsonify({"message": f"Checked out ({final_day_type}, {status_indicator})"}), 200


@app.route("/attendance_photos/<path:filename>")
def serve_attendance_photo(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# -------------------------------------------------------------
# APPLY LEAVE (UPDATED FOR MULTIPLE DAYS)
# -------------------------------------------------------------
@app.route("/api/leaves", methods=["POST"])
@token_required
def apply_leave():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    # New fields: from_date, to_date. Fallback to 'date' for old single day logic support if needed
    from_date = request.form.get("from_date")
    to_date = request.form.get("to_date")
    
    # Backward compatibility or Single Day
    if not from_date and request.form.get("date"):
        from_date = request.form.get("date")
        to_date = request.form.get("date")

    leave_type = request.form.get("type", "full")
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

    # 7-day past limit check
    now_ist_date = datetime.now(IST).date()
    max_past_date = now_ist_date - timedelta(days=7) 

    if f_date < max_past_date:
        return jsonify({
            "message": f"Leave application for past dates is limited to 7 days."
        }), 400

    attachment_url = None
    file = request.files.get("attachment")
    
    # --- CLOUDINARY UPLOAD CHANGE ---
    if file:
        try:
            upload_result = cloudinary.uploader.upload(file, folder="leave_attachments")
            attachment_url = upload_result.get("secure_url")
        except Exception as e:
            print("Cloudinary Upload Error:", e)
            return jsonify({"message": "File upload failed"}), 500
    # --------------------------------

    leave = {
        "user_id": str(request.user["_id"]),
        "from_date": from_date,
        "to_date": to_date,
        "date": from_date, # Keep for sorting/simple view fallback
        "type": leave_type,
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

    rows = []
    employees = {str(e["_id"]): e for e in users_col.find({"role": {"$in": ["employee", "manager"]}})}
    
    for l in leaves_col.find():
        l["_id"] = str(l["_id"])
        user_id = l.get("user_id")
        user = employees.get(user_id)
        
        if user:
            l["employee_name"] = user["name"]
            l["employee_department"] = user.get("department")
        else:
            l["employee_name"] = "Unknown"
            l["employee_department"] = ""
            
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
            subject = "Leave Update"
            date_info = f"{leave.get('from_date')} to {leave.get('to_date')}" if leave.get('from_date') != leave.get('to_date') else leave.get('date')
            body = (
                f"Your leave request for {date_info} has been updated.\n"
                f"Manager: {ms}\nHR: {as_}\nFinal Status: {final_status}"
            )
            threading.Thread(target=send_email, args=(user["email"], subject, body), daemon=True).start()
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

    manager_id = str(request.user["_id"])
    rows = []
    for u in users_col.find({"manager_id": manager_id, "role": "employee"}):
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
    all_users = users_col.find({"role": {"$in": ["employee", "manager"]}})

    for emp in all_users:
        uid = str(emp["_id"])
        checked_in = attendance_col.find_one({
            "user_id": uid, "type": "checkin", "date": str(today)
        })
        if checked_in: continue

        if not attendance_col.find_one({"user_id": uid, "type": "absent", "date": str(today)}):
            attendance_col.insert_one({
                "user_id": uid, "type": "absent", "date": str(today), "time": datetime.now(timezone.utc)
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
    start_date = datetime(year, month, 1, tzinfo=IST)

    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1
    end_date = datetime(next_year, next_month, 1, tzinfo=IST)

    employees = list(users_col.find({"role": {"$in": ["employee", "manager"]}}))
    emp_ids = [str(e["_id"]) for e in employees]

    summary = {"total_employees": len(employees), "days": {}}

    current = start_date
    while current < end_date:
        day_str = current.date().isoformat()
        day_records = list(attendance_col.find({
            "time": {
                "$gte": datetime.combine(current.date(), datetime.min.time(), tzinfo=IST),
                "$lt": datetime.combine(current.date(), datetime.max.time(), tzinfo=IST),
            }
        }))

        present = {rec["user_id"] for rec in day_records if rec["type"] == "checkin"}
        absent = {rec["user_id"] for rec in day_records if rec["type"] == "absent"}
        leaves_today = {l["user_id"] for l in leaves_col.find({"date": day_str, "status": "Approved"})}
        not_checked_in = set(emp_ids) - present - leaves_today - absent

        summary["days"][day_str] = {
            "present": list(present), "absent": list(absent),
            "leave": list(leaves_today), "not_checked_in": list(not_checked_in),
        }
        current += timedelta(days=1)

    return jsonify(summary), 200


# -------------------------------------------------------------
# TODAY STATS
# -------------------------------------------------------------
@app.route("/api/admin/today-stats", methods=["GET"])
@token_required
def today_stats():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    today = datetime.now(IST).date()
    employees = list(users_col.find({"role": {"$in": ["employee", "manager"]}}))
    emp_ids = [str(e["_id"]) for e in employees]

    day_records = list(attendance_col.find({
        "time": {
            "$gte": datetime.combine(today, datetime.min.time(), tzinfo=IST),
            "$lt": datetime.combine(today, datetime.max.time(), tzinfo=IST),
        }
    }))

    present = {rec["user_id"] for rec in day_records if rec["type"] == "checkin"}
    absent = {rec["user_id"] for rec in day_records if rec["type"] == "absent"}
    leaves_today = {l["user_id"] for l in leaves_col.find({"date": str(today), "status": "Approved"})}
    not_checked_in = set(emp_ids) - present - leaves_today - absent

    return jsonify({
        "present": len(present), "absent": len(absent),
        "leave": len(leaves_today), "not_checked_in": len(not_checked_in),
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)