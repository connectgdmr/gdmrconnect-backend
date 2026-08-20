"""
helpers.py — GDMR Connect
===========================
Pure utility / helper functions shared across route modules.
No Flask application context required; safe to import at module level.
"""
import re
from datetime import datetime, timedelta
from bson import ObjectId
from config import IST
from database import attendance_col, users_col, access_grants_col


# ── Timezone helpers ──────────────────────────────────────────────────────────

def utc_to_ist(utc_datetime):
    """Convert a UTC datetime to IST. Naive datetimes are assumed UTC."""
    import pytz
    if utc_datetime.tzinfo is None:
        utc_datetime = pytz.utc.localize(utc_datetime)
    return utc_datetime.astimezone(IST)


def format_datetime_ist(dt):
    """Return an IST ISO string from a datetime or ISO string."""
    import pytz
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.fromisoformat(dt)
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(IST).isoformat()


def _today_ist():
    """Return today's date in IST."""
    return datetime.now(IST).date()


# ── Validation helpers ────────────────────────────────────────────────────────

def is_strong_password(password):
    """Enforce enterprise password rules (8+ chars, mixed case, digit, special)."""
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[@$!%*?&#^_\-]", password):
        return False
    return True


# C0 control chars except \t (0x09) \n (0x0a) \r (0x0d)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize(value, max_len=500):
    """Strip control characters and enforce a length cap. Returns '' for non-strings."""
    if not isinstance(value, str):
        return ""
    return _CTRL_RE.sub("", value).strip()[:max_len]


def _valid_email(email):
    return bool(re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email))


# ── Employee status serialiser ────────────────────────────────────────────────

def _serialize_emp_status(user_doc):
    """
    Converts extended_leaves and resignation BSON types to JSON-safe strings
    in-place. Ensures both keys are always present on the document.
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


# ── Employment status checks ────────────────────────────────────────────────

def is_offboarded(user_doc):
    """
    True once an employee's resignation notice + last working day have both
    been recorded and the last working day has already passed (IST "today").
    Mirrors the same rule used across stats.py, assistant.py, employees.py,
    and the frontend isOffboarded() helpers — kept here as the single
    canonical backend implementation.
    """
    resignation = (user_doc or {}).get("resignation") or {}
    notice_date = resignation.get("notice_date")
    lwd = resignation.get("last_working_day")
    if not notice_date or not lwd:
        return False
    if isinstance(lwd, datetime):
        lwd_date = lwd.date()
    else:
        lwd_date = datetime.strptime(str(lwd)[:10], "%Y-%m-%d").date()
    return lwd_date < _today_ist()


# ── Company holidays ─────────────────────────────────────────────────────────
# Single source of truth for the company holiday calendar — the frontend's
# Holiday Calendar tab and Attendance Calendar both fetch GET /api/holidays
# (routes/calendar.py) instead of each hardcoding their own copy, and
# classify_attendance_day() below treats a holiday exactly like a weekend
# (excluded from "absent"/LOP) so payroll's auto-LOP fill
# (routes/payroll.py's payroll_lop_preview -> _month_calendar_for_employee)
# stops silently deducting pay for days nobody was expected to work.
# 2026 only — matches the single-year limitation this system already had
# everywhere holidays showed up (the frontend's old src/data/holidays.js,
# "Holiday Calendar 2026" heading) before this became the backend source
# of truth; extending to future years is a separate, larger feature.
COMPANY_HOLIDAYS = [
    {"id": 1,  "date": "2026-01-01", "day": "Thursday",  "name": "New Year"},
    {"id": 2,  "date": "2026-01-26", "day": "Monday",    "name": "Republic Day"},
    {"id": 3,  "date": "2026-02-15", "day": "Sunday",    "name": "Shivaratri"},
    {"id": 4,  "date": "2026-03-04", "day": "Wednesday", "name": "Holi"},
    {"id": 5,  "date": "2026-03-21", "day": "Saturday",  "name": "Eid-ul-Fitr"},
    {"id": 6,  "date": "2026-04-03", "day": "Friday",    "name": "Good Friday"},
    {"id": 7,  "date": "2026-04-05", "day": "Sunday",    "name": "Easter"},
    {"id": 8,  "date": "2026-05-01", "day": "Friday",    "name": "Labour Day"},
    {"id": 9,  "date": "2026-05-27", "day": "Wednesday", "name": "Bakrid"},
    {"id": 10, "date": "2026-06-26", "day": "Friday",    "name": "Muharram"},
    {"id": 11, "date": "2026-08-15", "day": "Saturday",  "name": "Independence Day"},
    {"id": 12, "date": "2026-08-26", "day": "Wednesday", "name": "Thiruvonam"},
    {"id": 13, "date": "2026-09-04", "day": "Friday",    "name": "Janmashtami"},
    {"id": 14, "date": "2026-10-02", "day": "Friday",    "name": "Gandhi Jayanti"},
    {"id": 15, "date": "2026-10-20", "day": "Tuesday",   "name": "Vijayadashami"},
    {"id": 16, "date": "2026-11-08", "day": "Sunday",    "name": "Diwali"},
    {"id": 17, "date": "2026-12-25", "day": "Friday",    "name": "Christmas"},
]
COMPANY_HOLIDAY_DATES = {h["date"] for h in COMPANY_HOLIDAYS}


# ── Attendance day classification ───────────────────────────────────────────

def _date_str(val):
    """Normalize a Mongo date value (datetime or already-a-string) to 'YYYY-MM-DD', or None."""
    if val is None:
        return None
    if hasattr(val, "date"):
        return val.date().isoformat()
    return str(val)[:10]


def classify_attendance_day(emp, day_str, day_checkins, leaves_by_uid, is_weekend, is_today):
    """
    Single source of truth for "what was this employee's status on this day" —
    extracted verbatim from routes/stats.py's attendance_summary() so it and
    the monthly attendance calendar (routes/calendar.py) share one
    implementation and can never drift apart.

    Returns "present" | "leave" | "absent" | "not_checked_in" | None.
    None means this employee doesn't belong in any bucket for this day: not
    yet joined, already offboarded, or a weekend/day off with nothing recorded.

    Args:
        emp:            employee doc with at least _id, doj, resignation,
                        extended_leaves.
        day_str:        the day being classified, "YYYY-MM-DD".
        day_checkins:   set of user_id strings who checked in on this day.
        leaves_by_uid:  {user_id: [leave_doc, ...]} — standard (leaves_col)
                        leave requests overlapping the period, already
                        pre-filtered to non-Rejected/Cancelled by the caller.
        is_weekend:     whether day_str falls on Sat/Sun.
        is_today:       whether day_str is "today" in IST — a missing
                        check-in today reads as "not_checked_in" (still
                        pending), not "absent", until the day has passed.
    """
    uid    = str(emp["_id"])
    joined = _date_str(emp.get("doj"))
    if joined and day_str < joined:
        return None
    resignation = emp.get("resignation") or {}
    lwd = _date_str(resignation.get("last_working_day"))
    if lwd and day_str > lwd:
        return None

    if uid in day_checkins:
        return "present"

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
        return "leave"

    if is_today:
        return "not_checked_in"
    if not is_weekend:
        return "absent"
    return None


# ── Employment type helpers ─────────────────────────────────────────────────

def parse_employment_type(data):
    """
    Validates the Employment Type / Contract Duration fields shared by the
    Add Employee form and ATS auto-onboarding.

    Returns (employment_type, contract_months, error_message) —
    error_message is None on success. Only Permanent employees get portal
    login credentials; Contract employees are stored as records only
    (no password / no welcome email).
    """
    employment_type = data.get("employment_type") or "Permanent"
    if employment_type not in ("Permanent", "Contract"):
        return None, None, "employment_type must be 'Permanent' or 'Contract'."

    contract_months = None
    if employment_type == "Contract":
        try:
            contract_months = int(data.get("contract_months"))
        except (TypeError, ValueError):
            contract_months = None
        if not contract_months or contract_months < 1:
            return None, None, "Contract Duration (months) is required for Contract employees."

    return employment_type, contract_months, None


# ── Role helpers ──────────────────────────────────────────────────────────────

def _is_admin(user):
    """Return True for 'admin' and 'owner' roles — owners have full admin privileges."""
    return user.get("role") in ("admin", "owner")


def _mgr_depts(user):
    """Return a manager's departments as a flat non-empty list.
    Handles both string and list department field values."""
    d = user.get("department")
    if isinstance(d, list):
        return [x for x in d if x]
    return [d] if d else []


# ── Delegated (Grant Access) module permissions ─────────────────────────────
# Canonical set of admin features that "Grant Access" can delegate, keyed the
# same as the sidebar's view name so frontend/backend stay in sync. Excludes
# things that must always stay admin-only regardless of delegation: creating
# other admin accounts, and Grant Access itself (both would be privilege-
# escalation loopholes — a delegated user could otherwise grant themselves
# permanent admin).
GRANTABLE_MODULES = {
    "employees":     "Employees",
    "leaves":        "Leave Requests",
    "attendance":    "Attendance",
    "departments":   "Departments",
    "manager":       "Managers",
    "summary":       "Reports",
    "pms":           "PMS",
    "announcements": "Announcements",
    "assets":        "Manage Assets",
    "work-by-team":  "Work by Team",
    "clients":       "Clients",
    "assessment":    "Assessments",
    "lms":           "LMS",
    "career":        "Jobs",
    "ats":           "Recruitment",
    "payroll":       "Payroll",
}


def _has_module_grant(user, module, write=False):
    """
    True if this user holds an active delegated-access grant (see
    routes/access.py) covering `module`. write=True additionally requires
    the grant's access_level to be 'view_edit' rather than 'view_only'.

    An employee can hold more than one active grant at once (routes/access.py
    ::grant_access() doesn't deactivate a prior grant when a new one is made —
    my_delegated_access() and the frontend's delegatedGrants already treat
    them as a set, checking every active grant with `.some()`). This must do
    the same: scanning only the first grant find_one() happens to return
    would miss a module that's only covered by a *different* active grant
    (e.g. an earlier "employees" grant plus a separate later "manager"
    grant — find_one() could hand back the "employees" one and make a valid
    "manager" grant look like it doesn't exist).
    """
    grants = access_grants_col.find({"employee_id": str(user["_id"]), "is_active": True})
    for grant in grants:
        modules = grant.get("modules")
        if not modules:
            legacy = grant.get("module")  # older grants stored a single "module" string
            modules = [legacy] if legacy else []
        if module not in modules:
            continue
        if write and grant.get("access_level") != "view_edit":
            continue  # this grant covers the module but not for writing — another active grant might
        return True
    return False


# ── Payroll helpers ───────────────────────────────────────────────────────────

def _to_money(v):
    """Coerce any input to a non-negative rounded float; bad input → 0.0."""
    try:
        return round(max(0.0, float(v)), 2)
    except (TypeError, ValueError):
        return 0.0


def _payroll_allowed(user):
    """Payroll access: admins/owners, or anyone in the Accounts department."""
    if _is_admin(user):
        return True
    dept = (user.get("department") or "").strip().lower()
    return dept.startswith("accounts")


# ── Work-plan helpers ─────────────────────────────────────────────────────────

def _is_task_done(t):
    return str(t.get("status", "")).strip().lower() in ("completed", "done")


def _checkin_time_for(uid, date_str):
    """Return the IST check-in timestamp string for a single user on a date, or None."""
    rec = attendance_col.find_one(
        {"user_id": uid, "type": "checkin", "date": date_str}, {"time": 1}
    )
    if rec and rec.get("time"):
        return format_datetime_ist(rec["time"])
    return None


def _checkin_map(uids, date_str):
    """Return {user_id: ist_timestamp_str} for all given user IDs on a date."""
    recs = attendance_col.find(
        {"user_id": {"$in": uids}, "type": "checkin", "date": date_str},
        {"user_id": 1, "time": 1},
    )
    return {r["user_id"]: format_datetime_ist(r["time"]) for r in recs if r.get("time")}


def _serialize_plan(doc, checkin=None):
    doc["_id"] = str(doc["_id"])
    doc.setdefault("tasks", [])
    doc.setdefault("manager_comment", None)
    doc["check_in_time"] = (
        checkin if checkin is not None
        else _checkin_time_for(doc.get("employee_id", ""), doc.get("date", ""))
    )
    return doc


def _range_start(range_key, today_date):
    if range_key == "today":
        return today_date
    if range_key == "month":
        return today_date - timedelta(days=29)
    return today_date - timedelta(days=6)   # "week" / default


def _build_analytics(plans, start_date, today_date):
    """Aggregate a list of submitted work plans into trend/analytics dict."""
    tasks_submitted = 0
    tasks_completed = 0
    active_days = set()
    projects    = {}
    per_day     = {}

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

    daily_trend = []
    cur = start_date
    while cur <= today_date:
        ds = cur.isoformat()
        daily_trend.append({"label": cur.strftime("%a %d"), "value": per_day.get(ds, 0)})
        cur += timedelta(days=1)

    weekly: dict = {}
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
        key=lambda x: x["count"], reverse=True,
    )

    return {
        "tasks_submitted": tasks_submitted,
        "tasks_completed": tasks_completed,
        "active_days":     len(active_days),
        "daily_trend":     daily_trend,
        "weekly_trend":    weekly_trend,
        "projects":        projects_list,
    }
