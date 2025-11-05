# backend/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import base64, os
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from utils import send_email, generate_random_password
from bson import ObjectId
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from flask import send_from_directory

load_dotenv()
app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "replace-this-secret")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["attendance_db"]

users_col = db["users"]
attendance_col = db["attendance"]
leaves_col = db["leaves"]


UPLOAD_FOLDER = "uploads/attendance_photos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    import os
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    return send_from_directory(uploads_dir, filename)

# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#         if 'Authorization' in request.headers:
#             token = request.headers['Authorization'].split(" ")[1]
#         if not token:
#             return jsonify({"message": "Token is missing!"}), 401
#         try:
#             data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#             current_user = users_col.find_one({"_id": data["user_id"]})
#             if not current_user:
#                 return jsonify({"message": "User not found"}), 401
#             request.user = current_user
#         except Exception as e:
#             return jsonify({"message": "Token is invalid!", "error": str(e)}), 401
#         return f(*args, **kwargs)
#     return decorated

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
            # convert string ID back to ObjectId before querying
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
    # One-time endpoint to create an admin
    data = request.json
    email = data.get("email")
    name = data.get("name", "Admin")
    password = data.get("password", "admin123")
    if users_col.find_one({"email": email}):
        return jsonify({"message": "Admin already exists"}), 400
    hashed = generate_password_hash(password)
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

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    print("Dataaaaa>>>>>>>>>",data)
    email = data.get("email")
    password = data.get("password")
    user = users_col.find_one({"email": email})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid credentials"}), 401
    token = jwt.encode({
        "user_id": str(user["_id"]),
        # "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    print("Token>>>>>>>>>>>>",token)
    print("USER id>>>>>>>>>>>>",user.get("role", "employee"))
    return jsonify({"token": token, "role": user.get("role", "employee"), "user": {"name": user.get("name"), "email": user.get("email")}})

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
    if users_col.find_one({"email": email}):
        return jsonify({"message": "Employee with email exists"}), 400
    password = generate_random_password()
    print("pasword>>>>>>>>>>>",password)
    hashed = generate_password_hash(password)
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
    # send password email
    try:
        send_email(
            to_email=email,
            subject="Your account created - Attendance App",
            body=f"Hello {name},\n\nYour GDMR employee account has been created Successfully.\nEmail: {email}\nPassword: {password}\n\nPlease login."
        )
    except Exception as e:
        print("Email send failed:", e)
    return jsonify({"message": "Employee created", "id": str(res.inserted_id)}), 201

# Admin get employees
@app.route("/api/admin/employees", methods=["GET"])
@token_required
def list_employees():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    rows = []
    for u in users_col.find({"role": "employee"}):
        u["_id"] = str(u["_id"])
        del u["password"]
        rows.append(u)
    print('Users list>>>>>>>>>>>>', rows)
    return jsonify(rows)

# Admin edit employee
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
    users_col.update_one({"_id": __import__("bson").ObjectId(emp_id)}, {"$set": update})
    return jsonify({"message": "Updated"})

# Admin delete
@app.route("/api/admin/employees/<emp_id>", methods=["DELETE"])
@token_required
def delete_employee(emp_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    users_col.delete_one({"_id": __import__("bson").ObjectId(emp_id)})
    attendance_col.delete_many({"user_id": emp_id})
    leaves_col.delete_many({"user_id": emp_id})
    return jsonify({"message": "Deleted"})

# Employee: check-in / check-out
# @app.route("/api/attendance/checkin", methods=["POST"])
# @token_required
# def checkin():
#     if request.user.get("role") != "employee":
#         return jsonify({"message": "Only employees can check in"}), 403
#     now = datetime.now(timezone.utc)
#     rec = {
#         "user_id": str(request.user["_id"]),
#         "type": "checkin",
#         "time": now
#     }
#     attendance_col.insert_one(rec)
#     return jsonify({"message": "Checked in", "time": now.isoformat()})

# @app.route("/api/attendance/checkout", methods=["POST"])
# @token_required
# def checkout():
#     if request.user.get("role") != "employee":
#         return jsonify({"message": "Only employees can check out"}), 403
#     now = datetime.now(timezone.utc)
#     rec = {
#         "user_id": str(request.user["_id"]),
#         "type": "checkout",
#         "time": now
#     }
#     attendance_col.insert_one(rec)
#     return jsonify({"message": "Checked out", "time": now.isoformat()})

# ---- Check-in with photo ----
@app.route("/api/attendance/checkin-photo", methods=["POST"])
@token_required
def checkin_photo():
    if request.user.get("role") != "employee":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image received"}), 400

    # decode base64 string
    header, encoded = img_data.split(",", 1)
    image_bytes = base64.b64decode(encoded)
    filename = f"{request.user['_id']}_checkin_{int(datetime.utcnow().timestamp())}.jpg"
    path = os.path.join(UPLOAD_FOLDER, filename)

    with open(path, "wb") as f:
        f.write(image_bytes)

    record = {
        "user_id": str(request.user["_id"]),
        "type": "checkin",
        "time": datetime.utcnow(),
        "photo_url": f"/attendance_photos/{filename}",
    }
    attendance_col.insert_one(record)
    cleanup_old_attendance_photos()
    return jsonify({"message": "Checked in with photo"})

# ---- Check-out with photo ----
@app.route("/api/attendance/checkout-photo", methods=["POST"])
@token_required
def checkout_photo():
    if request.user.get("role") != "employee":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    img_data = data.get("image")
    if not img_data:
        return jsonify({"message": "No image received"}), 400

    header, encoded = img_data.split(",", 1)
    image_bytes = base64.b64decode(encoded)
    filename = f"{request.user['_id']}_checkout_{int(datetime.utcnow().timestamp())}.jpg"
    path = os.path.join(UPLOAD_FOLDER, filename)

    with open(path, "wb") as f:
        f.write(image_bytes)

    record = {
        "user_id": str(request.user["_id"]),
        "type": "checkout",
        "time": datetime.utcnow(),
        "photo_url": f"/attendance_photos/{filename}",
    }
    attendance_col.insert_one(record)
    cleanup_old_attendance_photos()
    return jsonify({"message": "Checked out with photo"})

# serve photos
@app.route("/attendance_photos/<path:filename>")
def serve_attendance_photo(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# Employee: apply leave
# @app.route("/api/leaves", methods=["POST"])
# @token_required
# def apply_leave():
#     data = request.json
#     if request.user.get("role") != "employee":
#         return jsonify({"message": "Only employees can apply leave"}), 403
#     leave = {
#         "user_id": str(request.user["_id"]),
#         "date": data.get("date"),
#         "type": data.get("type", "full"),  # half or full
#         "reason": data.get("reason", ""),
#         "status": "pending",
#         "applied_at": datetime.now(timezone.utc)
#     }
#     res = leaves_col.insert_one(leave)
#     # Optionally notify admin via email (not implemented)
#     return jsonify({"message": "Applied", "id": str(res.inserted_id)}), 201

# Employee: apply leave (with optional attachment)
@app.route("/api/leaves", methods=["POST"])
@token_required
def apply_leave():
    if request.user.get("role") != "employee":
        return jsonify({"message": "Only employees can apply leave"}), 403

    # Use form data instead of JSON for file upload
    date = request.form.get("date")
    leave_type = request.form.get("type", "full")
    reason = request.form.get("reason", "")

    if not date:
        return jsonify({"message": "Date is required"}), 400

    attachment_url = None
    file = request.files.get("attachment")
    if file:
        # Secure filename and save file
        from werkzeug.utils import secure_filename
        import os
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
        "status": "Pending",
        "applied_at": datetime.now(timezone.utc),
        "attachment_url": attachment_url
    }
    res = leaves_col.insert_one(leave)
    return jsonify({"message": "Applied", "id": str(res.inserted_id)}), 201


# Admin: view leaves
@app.route("/api/admin/leaves", methods=["GET"])
@token_required
def admin_view_leaves():
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    rows = []
    for l in leaves_col.find():
        # Convert IDs and timestamps to readable format
        l["_id"] = str(l["_id"])
        user_id = l.get("user_id")

        # Ensure user_id is always converted to ObjectId
        try:
            user = users_col.find_one({"_id": ObjectId(user_id)})
            l["employee_name"] = user["name"] if user else "Unknown"
        except:
            l["employee_name"] = "Unknown"

        rows.append(l)

    return jsonify(rows), 200

# Admin: update leave status
@app.route("/api/admin/leaves/<leave_id>", methods=["PUT"])
@token_required
def update_leave(leave_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403
    data = request.json
    status = data.get("status")
    if status not in ("Approved", "Rejected", "Pending"):
        return jsonify({"message": "Invalid status"}), 400
    leaves_col.update_one({"_id": __import__("bson").ObjectId(leave_id)}, {"$set": {"status": status}})
    # Optionally email employee
    leave = leaves_col.find_one({"_id": __import__("bson").ObjectId(leave_id)})
    try:
        user = users_col.find_one({"_id": __import__("bson").ObjectId(leave["user_id"])})
        if user:
            send_email(user["email"], "Leave status updated", f"Your leave on {leave.get('date')} is {status}.")
    except Exception as e:
        print("email fail", e)
    return jsonify({"message": "Updated"})

# Employee: view attendance & leaves
@app.route("/api/my/attendance", methods=["GET"])
@token_required
def my_attendance():
    uid = str(request.user["_id"])
    rows = []
    for a in attendance_col.find({"user_id": uid}).sort("time", -1):
        a["_id"] = str(a["_id"])
        a["time"] = a["time"].isoformat()
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




# Admin: view attendance for a specific employee
@app.route("/api/admin/attendance/<emp_id>", methods=["GET"])
@token_required
def admin_employee_attendance(emp_id):
    if request.user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 403

    from bson import ObjectId

    emp = users_col.find_one({"_id": ObjectId(emp_id)})
    if not emp:
        return jsonify({"message": "Employee not found"}), 404

    records = []
    for a in attendance_col.find({"user_id": emp_id}).sort("time", -1):
        a["_id"] = str(a["_id"])
        a["time"] = a["time"].isoformat()
        a["employee_name"] = emp.get("name")
        a["employee_email"] = emp.get("email")
        records.append(a)

    return jsonify(records)


def cleanup_old_attendance_photos():
    """Delete attendance photos and DB records older than 7 days"""
    seven_days_ago = datetime.utcnow() - timedelta(days=7)

    old_records = attendance_col.find({
        "time": {"$lt": seven_days_ago}
    })

    for record in old_records:
        photo_url = record.get("photo_url")
        if photo_url:
            file_path = os.path.join("uploads/attendance_photos", photo_url.split("/")[-1])
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print("Deleted file:", file_path)
            except Exception as e:
                print("File deletion error:", e)

        attendance_col.delete_one({"_id": record["_id"]})
        print("Deleted DB record:", record["_id"])


if __name__ == "__main__":
    app.run(debug=True, port=int(os.getenv("PORT", 5000)))


