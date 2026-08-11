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

    Callers should check _is_admin(user) separately (usually
    `_is_admin(user) or _has_module_grant(user, "x")`) — this only covers
    delegated, non-admin access. Mirrors the pattern routes/lms.py already
    used for LMS-specific grants, generalized to every grantable module.
    """
    grant = access_grants_col.find_one({"employee_id": str(user["_id"]), "is_active": True})
    if not grant:
        return False
    modules = grant.get("modules")
    if not modules:
        legacy = grant.get("module")  # older grants stored a single "module" string
        modules = [legacy] if legacy else []
    if module not in modules:
        return False
    if write and grant.get("access_level") != "view_edit":
        return False
    return True


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
