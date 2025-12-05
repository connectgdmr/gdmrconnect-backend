# backend/app.py
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
from datetime import datetime, timedelta, timezone
from flask import send_from_directory
import pytz
from flask_bcrypt import Bcrypt

load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

CORS(app, resources={
    r"/*": {
        "origins": [
            "https://gdmrconnect.com",       # Your custom domain
            "https://www.gdmrconnect.com",   # Also allow www
            "https://*.netlify.app",         # Any Netlify preview URL
            "http://localhost:5173",         # Local testing
            "http://127.0.0.1:5173"
        ],
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    }
})

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "replace-this-secret")
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://jinugdmr_db_user:jHVhucjfLIN1Q9Jz@cluster0.lwly6jg.mongodb.net/?appName=Cluster0")
# MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["attendance_db"]

users_col = db["users"]
attendance_col = db["attendance"]
leaves_col = db["leaves"]

UPLOAD_FOLDER = "uploads/attendance_photos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# IST timezone
IST = pytz.timezone('Asia/Kolkata')

def utc_to_ist(utc_datetime):
    if utc_datetime.tzinfo is None:
        utc_datetime = pytz.utc.localize(utc_datetime)
    ist_datetime = utc_datetime.astimezone(IST)
    return ist_datetime

def format_datetime_ist(dt):
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except:
            dt = datetime.fromisoformat(dt)
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    ist_dt = dt.astimezone(IST)
    return ist_dt.isoformat()

@app.route("/")
def home():
    return "Backend running ✅", 200

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    import os
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    return send_from_directory(uploads_dir, filename)

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
        "position": ""
    }
    res = users_col.insert_one(user_doc)
    return jsonify({"message": "Admin created", "id": str(res.inserted_id)}), 201

@app.route("/api/register-manager", methods=["POST"])
@token_required
def register_manager():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    existing = users_col.find_one({"email": email})
    if existing:
        return jsonify({"message": "Email already exists"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    new_user = {
        "name": name,
        "email": email,
        "password": hashed_pw,
        "role": "manager",
        "department": "Management", # Default for managers
        "position": "Manager",
        "created_at": datetime.now(timezone.utc)
    }

    users_col.insert_one(new_user)
    return jsonify({"message": "Manager created successfully!"}), 201

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

# Admin: add employee
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
    
    # Check if email exists in any role
    if users_col.find_one({"email": email}):
        return jsonify({"message": "User with this email already exists"}), 400

    password = generate_random_password()
    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    now = datetime.now(timezone.utc)
    user_doc = {
        "name": name,
        "email": email,
        "password": hashed,
        "role": "employee",
        "department": department,
        "position": position,
        "created_at": now
    }
    res = users_col.insert_one(user_doc)
    try:
        send_email(
            to_email=email,
            subject="Your account created - Attendance App",
            body=f"Hello {name},\n\nYour GDMR employee account has been created Successfully.\nEmail: {email}\nPassword: {password}\n\nPlease login."
        )
    except Exception as e:
        print("Email send failed:", e)
    return jsonify({"message": "Employee created", "id": str(res.inserted_id)}), 201

# Admin get employees (NOW INCLUDES MANAGERS)
@app.route("/api/admin/employees", methods=["GET"])
@token_required
def list_employees():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    # Fetch both employees and managers
    for u in users_col.find({"role": {"$in": ["employee", "manager"]}}):
        u["_id"] = str(u["_id"])
        del u["password"]
        rows.append(u)
    return jsonify(rows)

@app.route("/api/admin/employees/<emp_id>", methods=["PUT"])
@token_required
def edit_employee(emp_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    update = {}
    for k in ["name", "department", "position", "email"]:
        if data.get(k):
            update[k] = data[k]
    users_col.update_one({"_id": ObjectId(emp_id)}, {"$set": update})
    return jsonify({"message": "Updated"})

@app.route("/api/admin/employees/<emp_id>", methods=["DELETE"])
@token_required
def delete_employee(emp_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    users_col.delete_one({"_id": ObjectId(emp_id)})
    attendance_col.delete_many({"user_id": emp_id})
    leaves_col.delete_many({"user_id": emp_id})
    return jsonify({"message": "Deleted"})


# ---- Check-in with photo (UPDATED to allow Managers) ----
@app.route("/api/attendance/checkin-photo", methods=["POST"])
@token_required
def checkin_photo():
    # Allow Managers to check in too
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    today = now_ist.date()

    start_time = now_ist.replace(hour=9, minute=0, second=0, microsecond=0)
    end_time = now_ist.replace(hour=11, minute=30, second=0, microsecond=0)
    half_day_start = now_ist.replace(hour=13, minute=0, second=0, microsecond=0)
    half_day_end = now_ist.replace(hour=14, minute=0, second=0, microsecond=0)

    existing_checkin = attendance_col.find_one({
        "user_id": uid,
        "type": "checkin",
        "date": str(today)
    })
    if existing_checkin:
        return jsonify({"message": "You already checked in today!"}), 400

    if now_ist < start_time:
        return jsonify({"message": "Check-in allowed only after 9:00 AM"}), 400

    if start_time <= now_ist <= end_time:
        checkin_type = "full"
    elif half_day_start <= now_ist <= half_day_end:
        checkin_type = "half-day"
    else:
        existing_absent = attendance_col.find_one({
            "user_id": uid,
            "type": "absent",
            "date": str(today)
        })
        if not existing_absent:
            attendance_col.insert_one({
                "user_id": uid,
                "type": "absent",
                "date": str(today),
                "time": datetime.now(timezone.utc)
            })
        return jsonify({"message": "Check-in window closed. Marked as Absent."}), 400

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image received"}), 400

    header, encoded = img_data.split(",", 1)
    image_bytes = base64.b64decode(encoded)
    filename = f"{uid}_checkin_{int(datetime.now(timezone.utc).timestamp())}.jpg"
    path = os.path.join(UPLOAD_FOLDER, filename)

    with open(path, "wb") as f:
        f.write(image_bytes)

    now_utc = datetime.now(timezone.utc)
    attendance_col.insert_one({
        "user_id": uid,
        "type": "checkin",
        "date": str(today),
        "day_type": checkin_type,
        "time": now_utc,
        "photo_url": f"/attendance_photos/{filename}",
    })

    return jsonify({"message": f"Check-in successful ({checkin_type})", "day_type": checkin_type}), 200


# ---- Check-out with photo (UPDATED to allow Managers) ----
@app.route("/api/attendance/checkout-photo", methods=["POST"])
@token_required
def checkout_photo():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    uid = str(request.user["_id"])
    now_ist = datetime.now(IST)
    today_date = now_ist.date()

    existing_checkin = attendance_col.find_one({"user_id": uid, "type": "checkin", "date": str(today_date)})
    if not existing_checkin:
        return jsonify({"message": "You must check in before checking out!"}), 400

    existing_checkout = attendance_col.find_one({"user_id": uid, "type": "checkout", "date": str(today_date)})
    if existing_checkout:
        return jsonify({"message": "You already checked out today!"}), 400

    half_day_start = now_ist.replace(hour=13, minute=0, second=0, microsecond=0)
    half_day_end = now_ist.replace(hour=14, minute=0, second=0, microsecond=0)
    day_type = existing_checkin.get("day_type", "full")

    if half_day_start <= now_ist <= half_day_end:
        day_type = "half-day"
        attendance_col.update_one({"_id": existing_checkin["_id"]}, {"$set": {"day_type": "half-day"}})

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image received"}), 400

    header, encoded = img_data.split(",", 1)
    image_bytes = base64.b64decode(encoded)
    filename = f"{uid}_checkout_{int(datetime.now(timezone.utc).timestamp())}.jpg"
    path = os.path.join(UPLOAD_FOLDER, filename)

    with open(path, "wb") as f:
        f.write(image_bytes)

    now_utc = datetime.now(timezone.utc)
    attendance_col.insert_one({
        "user_id": uid,
        "type": "checkout",
        "date": str(today_date),
        "time": now_utc,
        "photo_url": f"/attendance_photos/{filename}",
        "day_type": day_type
    })

    cleanup_old_attendance_photos()
    return jsonify({"message": f"Checked out successfully ({day_type})", "day_type": day_type}), 200

@app.route("/attendance_photos/<path:filename>")
def serve_attendance_photo(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# Apply leave (UPDATED: Managers can apply + Split Statuses)
@app.route("/api/leaves", methods=["POST"])
@token_required
def apply_leave():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    date = request.form.get("date")
    leave_type = request.form.get("type", "full")
    reason = request.form.get("reason", "")

    if not date:
        return jsonify({"message": "Date is required"}), 400

    attachment_url = None
    file = request.files.get("attachment")
    if file:
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        os.makedirs("uploads", exist_ok=True)
        file_path = os.path.join("uploads", filename)
        file.save(file_path)
        attachment_url = f"/uploads/{filename}"

    leave = {
        "user_id": str(request.user["_id"]),
        "date": date,
        "type": leave_type,
        "reason": reason,
        "status": "Pending",          # Overall Status
        "manager_status": "Pending",  # New Field
        "admin_status": "Pending",    # New Field
        "applied_at": datetime.now(timezone.utc),
        "attachment_url": attachment_url
    }
    res = leaves_col.insert_one(leave)
    return jsonify({"message": "Applied", "id": str(res.inserted_id)}), 201

# Admin: view leaves
@app.route("/api/admin/leaves", methods=["GET"])
@token_required
def admin_view_leaves():
    if request.user.get("role") not in ["admin", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    rows = []
    for l in leaves_col.find():
        l["_id"] = str(l["_id"])
        user_id = l.get("user_id")
        try:
            user = users_col.find_one({"_id": ObjectId(user_id)})
            l["employee_name"] = user["name"] if user else "Unknown"
        except:
            l["employee_name"] = "Unknown"
        rows.append(l)

    return jsonify(rows), 200

# Update leave status (UPDATED: Logic for Admin vs Manager)
@app.route("/api/admin/leaves/<leave_id>", methods=["PUT"])
@token_required
def update_leave(leave_id):
    role = request.user.get("role")
    if role not in ["admin", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    action = data.get("status") # "Approved" or "Rejected"
    if action not in ("Approved", "Rejected", "Pending"):
        return jsonify({"message": "Invalid status"}), 400

    update_fields = {}

    # 1. Update specific approval field based on role
    if role == "manager":
        update_fields["manager_status"] = action
    elif role == "admin":
        update_fields["admin_status"] = action

    # Apply the specific update first
    leaves_col.update_one({"_id": ObjectId(leave_id)}, {"$set": update_fields})

    # 2. Calculate Final Overall Status
    leave = leaves_col.find_one({"_id": ObjectId(leave_id)})
    
    ms = leave.get("manager_status", "Pending")
    as_ = leave.get("admin_status", "Pending")

    final_status = "Pending"
    
    # Logic: If ANYONE rejects -> Rejected. If BOTH approve -> Approved.
    if ms == "Rejected" or as_ == "Rejected":
        final_status = "Rejected"
    elif ms == "Approved" and as_ == "Approved":
        final_status = "Approved"
    
    # Update final status
    leaves_col.update_one({"_id": ObjectId(leave_id)}, {"$set": {"status": final_status}})

    # Email notification (simplified)
    try:
        user = users_col.find_one({"_id": ObjectId(leave["user_id"])})
        if user:
            send_email(
                user["email"], 
                "Leave Update", 
                f"Your leave request for {leave.get('date')} has been updated.\nManager: {ms}\nHR: {as_}\nFinal Status: {final_status}"
            )
    except Exception as e:
        print("email fail", e)

    return jsonify({"message": "Updated"})

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

def cleanup_old_attendance_photos():
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    old_records = attendance_col.find({"time": {"$lt": seven_days_ago}})
    for record in old_records:
        photo_url = record.get("photo_url")
        if photo_url:
            file_path = os.path.join("uploads/attendance_photos", photo_url.split("/")[-1])
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                print("File deletion error:", e)
        attendance_col.delete_one({"_id": record["_id"]})

@app.route("/api/admin/managers", methods=["GET"])
@token_required
def list_managers():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for m in users_col.find({"role": "manager"}):
        m["_id"] = str(m["_id"])
        del m["password"]
        rows.append(m)
    return jsonify(rows)

@app.route("/api/admin/managers/<manager_id>", methods=["DELETE"])
@token_required
def delete_manager(manager_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    users_col.delete_one({"_id": ObjectId(manager_id)})
    leaves_col.update_many({"approved_by": manager_id}, {"$set": {"approved_by": None}})
    return jsonify({"message": "Manager deleted"})

@app.route("/api/attendance/auto-absent", methods=["POST"])
def auto_mark_absent():
    today = datetime.now(IST).date()
    # Check employees AND managers
    all_users = users_col.find({"role": {"$in": ["employee", "manager"]}})

    for emp in all_users:
        uid = str(emp["_id"])
        checked_in = attendance_col.find_one({
            "user_id": uid,
            "type": "checkin",
            "time": {
                "$gte": datetime.combine(today, datetime.min.time()),
                "$lt": datetime.combine(today, datetime.max.time())
            }
        })
        if checked_in: continue

        already_absent = attendance_col.find_one({"user_id": uid, "type": "absent", "date": str(today)})
        if not already_absent:
            attendance_col.insert_one({
                "user_id": uid,
                "type": "absent",
                "date": str(today),
                "time": datetime.now(timezone.utc)
            })
    return jsonify({"message": "Absent auto-marking completed"}), 200

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
    next_month_year = year if month < 12 else year + 1
    end_date = datetime(next_month_year, next_month, 1, tzinfo=IST)

    employees = list(users_col.find({"role": {"$in": ["employee", "manager"]}}))
    emp_ids = [str(e["_id"]) for e in employees]

    summary = { "total_employees": len(employees), "days": {} }
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
            "present": list(present),
            "absent": list(absent),
            "leave": list(leaves_today),
            "not_checked_in": list(not_checked_in),
        }
        current += timedelta(days=1)
    return jsonify(summary), 200

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
    response = {
        "present": len(present),
        "absent": len(absent),
        "leave": len(leaves_today),
        "not_checked_in": len(not_checked_in),
    }
    return jsonify(response), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)