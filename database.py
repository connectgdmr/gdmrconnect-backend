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
comp_off_col    = db["comp_off_ledger"]  # manager-granted comp-off credits / debits

# ── Extended modules ──────────────────────────────────────────────────────────
corrections_col  = db["attendance_corrections"]
pip_records_col  = db["pip_records"]
announcements_col = db["announcements"]
access_grants_col = db["access_grants"]
assets_col        = db["assets"]

# ── PMS ───────────────────────────────────────────────────────────────────────
pms_templates_col = db["pms_templates"]
pms_reviews_col   = db["pms_reviews"]

# ── PMS Compliance & Attendance Blocking (pms_compliance.py) ──────────────────
# One doc per (manager_id, month): review-completion status for that manager's
# team + whether their team's attendance check-in is currently blocked for it.
pms_compliance_col       = db["pms_compliance"]
# Append-only history of every reminder/block/unblock/override/extension.
pms_compliance_audit_col = db["pms_compliance_audit"]
# Single "singleton" doc: the master on/off switch + configurable exceptions
# (FRD §14) — never hard-coded.
pms_compliance_settings_col = db["pms_compliance_settings"]

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
clients_col       = db["clients"]
# Unified folders+files for a client's "Drive" — one collection so "list this
# folder's contents" is a single query. type: "folder" | "file"; parent_id is
# None for items at the client's root.
client_drive_col   = db["client_drive"]
# Manual "Post an Update" log on a client, separate from the auto-pulled Daily
# Work Plan timeline (which reads work_plans_col directly, no storage of its own).
client_updates_col = db["client_updates"]

# ── ATS ───────────────────────────────────────────────────────────────────────
ats_candidates_col = db["ats_candidates"]

# ── Sequence counters (atomic auto-increment IDs, e.g. applicant codes) ───────
counters_col = db["counters"]

# ── Team Chat ─────────────────────────────────────────────────────────────────
conversations_col = db["conversations"]
messages_col      = db["messages"]

# ── Achievements ──────────────────────────────────────────────────────────────
achievements_col = db["achievements"]

# ── Company Holidays ────────────────────────────────────────────────────────
# {date: "YYYY-MM-DD", day: "Thursday", name: "New Year"} — admin-managed via
# routes/calendar.py (GET/POST/DELETE /api/holidays), the single source of
# truth for the Holiday Calendar tab, the Attendance Calendar's grey-out
# overlay, and payroll's LOP auto-fill (all three read/derive from this
# collection so none of them can drift out of sync with each other again).
holidays_col = db["holidays"]

# ── One-time cleanup: duplicate attendance punches ─────────────────────────────
# A check-then-insert race in checkin_photo()/checkout_photo() (routes/
# attendance.py) — the "already checked in/out today?" existence check and
# the actual insert are two separate steps with the slow (1-3s) Cloudinary
# photo upload sitting between them, leaving a window for a second
# near-simultaneous request (a double-tap on a laggy touchscreen, most
# often) to pass the same check before the first request has written its
# row — could leave two check-in or two check-out rows for the same
# user/date. Must run before the unique index below is created: Mongo
# refuses to build a unique index over data that already violates it, which
# would otherwise silently skip creating this index forever on any database
# that already has duplicates — and because index creation below is one big
# try/except, that failure would also abort every index listed after it.
try:
    _dupe_groups = list(attendance_col.aggregate([
        {"$group": {
            "_id":     {"user_id": "$user_id", "date": "$date", "type": "$type"},
            "docs":    {"$push": {"_id": "$_id", "status_indicator": "$status_indicator"}},
            "count":   {"$sum": 1},
        }},
        {"$match": {"count": {"$gt": 1}}},
    ]))
    _removed = 0
    for _g in _dupe_groups:
        docs = sorted(_g["docs"], key=lambda d: d["_id"])  # ObjectId sorts chronologically
        corrected = [d for d in docs if d.get("status_indicator") == "Corrected"]
        if corrected:
            # A deliberate, admin-approved correction (routes/announcements.py's
            # _apply_correction_attendance) beats an accidental duplicate —
            # keep its latest, drop everything else in the group.
            keep_id = corrected[-1]["_id"]
        else:
            # Otherwise this is the double-tap race (routes/attendance.py's
            # checkin_photo/checkout_photo) — keep the earliest (the real
            # punch), drop the rest.
            keep_id = docs[0]["_id"]
        for d in docs:
            if d["_id"] != keep_id:
                attendance_col.delete_one({"_id": d["_id"]})
                _removed += 1
    if _removed:
        print(f"Startup migration: removed {_removed} duplicate attendance punch(es).")
except Exception as _att_dupe_err:
    print(f"Warning: attendance dedupe migration failed: {_att_dupe_err}")

# ── Indexes (background=True — no write-lock) ─────────────────────────────────
try:
    users_col.create_index("email", background=True)
    users_col.create_index("role", background=True)
    users_col.create_index("department", background=True)
    # unique: the real fix for the duplicate-punch race above — the
    # check-then-insert gap in checkin_photo()/checkout_photo() can no
    # longer let two rows through no matter how the two requests interleave,
    # since Mongo now rejects the second insert outright (caught there and
    # turned back into the same friendly "Already checked in/out" message).
    attendance_col.create_index([("user_id", 1), ("date", 1), ("type", 1)], unique=True, background=True)
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
    clients_col.create_index("departments", background=True)
    client_drive_col.create_index([("client_id", 1), ("parent_id", 1)], background=True)
    client_updates_col.create_index([("client_id", 1), ("posted_at", -1)], background=True)
    ats_candidates_col.create_index("email", background=True)
    ats_candidates_col.create_index("phone", background=True)
    ats_candidates_col.create_index("applicant_code", unique=True, sparse=True, background=True)
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
    holidays_col.create_index("date", unique=True, background=True)
    pms_compliance_col.create_index([("manager_id", 1), ("month", 1)], unique=True, background=True)
    pms_compliance_audit_col.create_index([("manager_id", 1), ("month", 1), ("at", -1)], background=True)
    pms_compliance_audit_col.create_index([("at", -1)], background=True)
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

try:
    # One-time: holidays used to be a hardcoded list (helpers.py / the
    # frontend's src/data/holidays.js) with no admin UI at all — seed the
    # real collection with that same 2026 list so nothing is lost the first
    # time this runs against an empty holidays_col. Never overwrites once
    # any holiday exists (including if an admin has since deleted all of
    # them on purpose — count stays 0 either way, so this would reseed;
    # acceptable since "delete everything" isn't a realistic real-world state
    # for a company holiday calendar, unlike "haven't been touched yet").
    if holidays_col.count_documents({}) == 0:
        _seed_holidays = [
            {"date": "2026-01-01", "day": "Thursday",  "name": "New Year"},
            {"date": "2026-01-26", "day": "Monday",    "name": "Republic Day"},
            {"date": "2026-02-15", "day": "Sunday",    "name": "Shivaratri"},
            {"date": "2026-03-04", "day": "Wednesday", "name": "Holi"},
            {"date": "2026-03-21", "day": "Saturday",  "name": "Eid-ul-Fitr"},
            {"date": "2026-04-03", "day": "Friday",    "name": "Good Friday"},
            {"date": "2026-04-05", "day": "Sunday",    "name": "Easter"},
            {"date": "2026-05-01", "day": "Friday",    "name": "Labour Day"},
            {"date": "2026-05-27", "day": "Wednesday", "name": "Bakrid"},
            {"date": "2026-06-26", "day": "Friday",    "name": "Muharram"},
            {"date": "2026-08-15", "day": "Saturday",  "name": "Independence Day"},
            {"date": "2026-08-26", "day": "Wednesday", "name": "Thiruvonam"},
            {"date": "2026-09-04", "day": "Friday",    "name": "Janmashtami"},
            {"date": "2026-10-02", "day": "Friday",    "name": "Gandhi Jayanti"},
            {"date": "2026-10-20", "day": "Tuesday",   "name": "Vijayadashami"},
            {"date": "2026-11-08", "day": "Sunday",    "name": "Diwali"},
            {"date": "2026-12-25", "day": "Friday",    "name": "Christmas"},
        ]
        holidays_col.insert_many(_seed_holidays)
        print(f"Startup migration: seeded {len(_seed_holidays)} company holiday(s).")
except Exception as _hol_err:
    print(f"Warning: holiday seed migration failed: {_hol_err}")

try:
    # A manager's own leave now goes to the owner alone — one approval, no
    # manager-approval stage (routes/leaves.py). Backfill applicant_role on
    # leaves filed before that field existed, and unblock any manager leave an
    # owner had already approved but the old "manager AND admin" rule left
    # stuck at Pending.
    _mgr_ids = [str(u["_id"]) for u in users_col.find({"role": "manager"}, {"_id": 1})]
    if _mgr_ids:
        _br = leaves_col.update_many(
            {"user_id": {"$in": _mgr_ids}, "applicant_role": {"$exists": False}},
            {"$set": {"applicant_role": "manager"}},
        ).modified_count
        _fx = leaves_col.update_many(
            {"applicant_role": "manager", "admin_status": "Approved",
             "manager_status": {"$ne": "Rejected"}, "status": "Pending"},
            {"$set": {"status": "Approved", "manager_status": "N/A"}},
        ).modified_count
        if _br or _fx:
            print(f"Startup migration: tagged {_br} manager leave(s), unblocked {_fx} owner-approved one(s).")
except Exception as _lv_err:
    print(f"Warning: manager-leave migration failed: {_lv_err}")

try:
    # A department head is a manager of that department by definition —
    # routes/employees.py now promotes to role="manager" the moment someone
    # is newly picked as a head, but that only fires on the next Add/Edit
    # Department save. Backfill it once here for every head already set
    # before this rule existed, so they show correctly in the department
    # drawer's Management section and get manager-level access everywhere
    # else immediately, not just on the next unrelated department edit.
    _head_ids = set()
    for _d in departments_col.find({}, {"head_ids": 1, "head_id": 1}):
        _head_ids.update(_d.get("head_ids") or [])
        if _d.get("head_id"):
            _head_ids.add(_d["head_id"])
    if _head_ids:
        _promoted = users_col.update_many(
            {"_id": {"$in": list(_head_ids)}, "role": "employee"},
            {"$set": {"role": "manager"}},
        ).modified_count
        if _promoted:
            print(f"Startup migration: promoted {_promoted} existing department head(s) to role='manager'.")
except Exception as _head_err:
    print(f"Warning: department-head-promotion migration failed: {_head_err}")

try:
    # The reverse gap: a department with an existing manager but no head on
    # record at all (shows "Department Head: Not assigned" even though
    # someone is clearly running it) — routes/employees.py's
    # register_manager now fills this in the moment a NEW manager is
    # registered for an empty-headed department; this backfills it once for
    # departments that already had a manager before that existed. Picks one
    # deterministically (alphabetically first by name) rather than guessing
    # — an admin can always add/change heads afterward.
    for _d in departments_col.find({}, {"name": 1, "head_ids": 1, "head_id": 1}):
        if _d.get("head_ids") or _d.get("head_id"):
            continue  # already has a head
        _cands = list(users_col.find(
            {"role": "manager", "department": _d["name"]}, {"name": 1}
        ).sort("name", 1).limit(1))
        if _cands:
            departments_col.update_one(
                {"_id": _d["_id"]},
                {"$set": {"head_ids": [_cands[0]["_id"]], "head_id": _cands[0]["_id"],
                         "updated_at": datetime.now(timezone.utc)}},
            )
            print(f"Startup migration: set '{_cands[0]['name']}' as head of headless department '{_d['name']}'.")
except Exception as _headless_err:
    print(f"Warning: headless-department migration failed: {_headless_err}")

try:
    # PMS Compliance & Attendance Blocking — seed the singleton settings doc
    # once so every reader can assume it exists. blocking_enabled defaults to
    # False: status tracking, the dashboard and every notification run for
    # real from the day this ships, but nobody's check-in is actually
    # rejected until HR/Admin turns it on from the Compliance tab.
    if pms_compliance_settings_col.count_documents({"_id": "singleton"}) == 0:
        pms_compliance_settings_col.insert_one({
            "_id":                    "singleton",
            "blocking_enabled":       False,
            "exempt_employee_ids":    [],
            "exempt_department_names": [],
            "new_joiner_grace_days":  30,
            "updated_at":             datetime.now(timezone.utc),
            "updated_by":             None,
        })
        print("Startup migration: seeded PMS compliance settings (blocking disabled by default).")
except Exception as _pmscomp_err:
    print(f"Warning: PMS compliance settings seed failed: {_pmscomp_err}")
