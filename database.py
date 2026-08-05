"""
database.py — GDMR Connect
===========================
MongoDB connection, all collection references, index creation,
and one-time startup migrations.  Import collections from here.
"""
from pymongo import MongoClient
from config import MONGO_URI

# ── Connection ────────────────────────────────────────────────────────────────
try:
    _client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=10000,
        socketTimeoutMS=45000,
        retryWrites=True,
        maxPoolSize=50,
    )
    _client.admin.command("ping")
    db = _client["attendance_db"]
    print("MongoDB Connected Successfully to Database: attendance_db.")
except Exception as _e:
    print(f"CRITICAL ERROR: Failed to connect to MongoDB. Error: {_e}")
    db = None

if db is None:
    raise RuntimeError(
        "Cannot start: MongoDB connection failed. "
        "Check MONGO_URI and Atlas Network Access."
    )

# Expose the underlying MongoClient so health-check can ping it
mongo_client = _client

# ── Core collections ──────────────────────────────────────────────────────────
users_col       = db["users"]
attendance_col  = db["attendance"]
leaves_col      = db["leaves"]

# ── Extended modules ──────────────────────────────────────────────────────────
corrections_col  = db["attendance_corrections"]
pip_records_col  = db["pip_records"]
announcements_col = db["announcements"]
access_grants_col = db["access_grants"]
assets_col        = db["assets"]

# ── PMS ───────────────────────────────────────────────────────────────────────
pms_templates_col = db["pms_templates"]
pms_reviews_col   = db["pms_reviews"]

# ── Departments ───────────────────────────────────────────────────────────────
departments_col = db["departments"]

# ── Assessment ────────────────────────────────────────────────────────────────
assessments_col = db["assessments"]
candidates_col  = db["assessment_invites"]

# ── LMS ───────────────────────────────────────────────────────────────────────
lms_courses_col  = db["lms_courses"]
lms_progress_col = db["lms_progress"]

# ── Career ────────────────────────────────────────────────────────────────────
career_jobs_col = db["career_jobs"]
referrals_col   = db["career_referrals"]

# ── Payroll ───────────────────────────────────────────────────────────────────
salary_structures_col = db["salary_structures"]
payslips_col          = db["payslips"]
payroll_loans_col     = db["payroll_loans"]

# ── Work Plans ────────────────────────────────────────────────────────────────
work_plans_col = db["work_plans"]

# ── Clients ───────────────────────────────────────────────────────────────────
clients_col = db["clients"]

# ── ATS ───────────────────────────────────────────────────────────────────────
ats_candidates_col = db["ats_candidates"]

# ── Team Chat ─────────────────────────────────────────────────────────────────
conversations_col = db["conversations"]
messages_col      = db["messages"]

# ── Achievements ──────────────────────────────────────────────────────────────
achievements_col = db["achievements"]

# ── Indexes (background=True — no write-lock) ─────────────────────────────────
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
    leaves_col.create_index([("applied_at", -1)], background=True)
    assets_col.create_index([("created_at", -1)], background=True)
    attendance_col.create_index([("user_id", 1), ("time", -1)], background=True)
    pms_reviews_col.create_index([("self_assessment_date", -1)], background=True)
    work_plans_col.create_index([("employee_id", 1), ("date", 1)], unique=True, background=True)
    work_plans_col.create_index([("date", 1), ("status", 1)], background=True)
    work_plans_col.create_index([("department", 1), ("date", 1)], background=True)
    clients_col.create_index("name", unique=True, background=True)
    ats_candidates_col.create_index("email", background=True)
    ats_candidates_col.create_index("status", background=True)
    ats_candidates_col.create_index("department", background=True)
    ats_candidates_col.create_index("doc_token", background=True)
    ats_candidates_col.create_index([("applied_at", -1)], background=True)
    payroll_loans_col.create_index([("employee_id", 1), ("status", 1)], background=True)
    payroll_loans_col.create_index([("status", 1), ("created_at", -1)], background=True)
    conversations_col.create_index("members", background=True)
    conversations_col.create_index([("last_at", -1)], background=True)
    conversations_col.create_index([("type", 1), ("members", 1)], background=True)
    messages_col.create_index([("conversation_id", 1), ("created_at", 1)], background=True)
    messages_col.create_index([("conversation_id", 1), ("read_by", 1)], background=True)
    print("MongoDB indexes ensured.")
except Exception as _idx_err:
    print(f"Warning: Could not create indexes: {_idx_err}")

# ── One-time startup migrations ───────────────────────────────────────────────
try:
    _migrated = users_col.update_many(
        {"shift": {"$exists": False}},
        {"$set": {"shift": "morning"}},
    ).modified_count
    if _migrated:
        print(f"Startup migration: set shift='morning' on {_migrated} existing employee(s).")
except Exception as _mig_err:
    print(f"Warning: shift migration failed: {_mig_err}")

try:
    _lk_count = users_col.update_many(
        {"failed_login_attempts": {"$exists": False}},
        {"$set": {"failed_login_attempts": 0, "locked_until": None}},
    ).modified_count
    if _lk_count:
        print(f"Startup migration: added lockout fields to {_lk_count} user(s).")
except Exception as _lk_err:
    print(f"Warning: lockout migration failed: {_lk_err}")
