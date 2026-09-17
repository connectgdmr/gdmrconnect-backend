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
from database import attendance_col, users_col, access_grants_col, holidays_col, departments_col


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


ACTIVE_STAFF_ROLES = ["employee", "manager"]


def active_staff(projection=None, extra_query=None, roles=None):
    """All non-off-boarded employee/manager docs — the single source of truth
    for "the current active roster". Wraps the users_col.find + is_offboarded
    filter that was otherwise re-written (and occasionally forgotten) in every
    route that needs a headcount or a roster.

    projection / extra_query / roles are optional passthroughs to the
    underlying find(); off-boarding can't be expressed as a plain Mongo query
    (it's a date comparison against IST "today" over a mixed string/datetime
    field) so the is_offboarded() filter is always applied in Python here.
    """
    q = {"role": {"$in": list(roles or ACTIVE_STAFF_ROLES)}}
    if extra_query:
        q.update(extra_query)
    # A caller-supplied inclusion projection must still bring back `resignation`
    # (and `role`, used by some callers to split employee/manager) or the
    # is_offboarded() filter below silently sees nothing and never excludes.
    if projection and all(v for v in projection.values()):
        projection = {**projection, "resignation": 1, "role": 1}
    return [u for u in users_col.find(q, projection) if not is_offboarded(u)]


# ── Company holidays ─────────────────────────────────────────────────────────
# Single source of truth for the company holiday calendar — holidays_col
# (database.py), managed via GET/POST/DELETE /api/holidays (routes/
# calendar.py). The Holiday Calendar tab, the Attendance Calendar's
# grey-out overlay, and classify_attendance_day() below (which treats a
# holiday exactly like a weekend — excluded from "absent"/LOP, so
# payroll's auto-LOP fill via routes/payroll.py's payroll_lop_preview ->
# _month_calendar_for_employee stops silently deducting pay for a holiday)
# all read from the same collection, so none of them can drift out of
# sync with each other or with what an admin actually added/removed.
def get_company_holiday_dates():
    """{"YYYY-MM-DD", ...} for every stored holiday — call once per request
    (not per day in a loop) and reuse the returned set."""
    return {h["date"] for h in holidays_col.find({}, {"date": 1}) if h.get("date")}


# ── Attendance day classification ───────────────────────────────────────────

def is_weekend_day(day_str, holiday_dates):
    """
    Single source of truth for "is this day a non-working day" — a company
    holiday, any Sunday, or a Saturday EXCEPT the LAST Saturday of its
    month (company policy: the last Saturday is a regular working day,
    every other Saturday is not). Used by both routes/calendar.py and
    routes/stats.py so the two can't classify the same Saturday
    differently from each other.
    """
    if day_str in holiday_dates:
        return True
    d  = datetime.strptime(day_str, "%Y-%m-%d")
    wd = d.weekday()  # Monday=0 ... Saturday=5, Sunday=6
    if wd == 6:
        return True
    if wd == 5:
        # Last Saturday of the month: adding 7 days rolls into next month.
        return (d + timedelta(days=7)).month == d.month
    return False


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
    error_message is None on success. Only Contract is stored as a record
    only (no password / no welcome email) — Permanent and Internship both
    get full portal login credentials.
    """
    employment_type = data.get("employment_type") or "Permanent"
    if employment_type not in ("Permanent", "Contract", "Internship"):
        return None, None, "employment_type must be 'Permanent', 'Contract' or 'Internship'."

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


def _dept_list(val):
    """Normalize a raw department field value (plain string, OR a list for
    a manager who heads more than one department) into a flat, non-empty
    list of stripped/lowercased names — the one shape every department
    comparison should use. Calling .strip() directly on a department field
    that turns out to be a list (any multi-department manager) throws
    AttributeError outright; this replaces several call sites that each
    used to risk exactly that."""
    d = [val] if not isinstance(val, list) else val
    return [str(x).strip().lower() for x in d if x]


def _mgr_depts(user):
    """Return a manager's departments as a flat non-empty list (original
    case, not lowercased — most callers display these). Handles both
    string and list department field values."""
    d = user.get("department")
    if isinstance(d, list):
        return [x for x in d if x]
    return [d] if d else []


def _managed_employee_ids(manager_user):
    """All employee _ids (as strings) a manager can act on — department
    overlap OR a direct manager_id assignment (routes/employees.py sets
    this on every employee and keeps it current through promotions/
    reassignments, so it's the authoritative "who reports to whom" field).
    Department-string equality alone is fragile: a review/leave/etc. can
    carry a department value snapshotted at submission time that later
    drifts out of sync with a rename, or an employee can simply be managed
    cross-department. Matching on either catches both cases instead of
    silently hiding a manager's own team. Doesn't cover department heads
    who aren't also a manager_id/department match — see
    _team_ids_incl_dept_head() below for that."""
    depts  = _mgr_depts(manager_user)
    mgr_id = str(manager_user["_id"])
    return {str(u["_id"]) for u in users_col.find(
        {"$or": [{"department": {"$in": depts}}, {"manager_id": mgr_id}]}, {"_id": 1}
    )}


def _dept_head_dept_names(user_id):
    """Names of departments this user heads (departments_col.head_ids array,
    or the legacy single head_id). A department head is treated as a manager
    of that department everywhere "who can act as this employee's manager"
    matters — comp-off, leave/asset approval, notification badges."""
    try:
        oid = ObjectId(user_id)
    except Exception:
        return []
    names = []
    for d in departments_col.find(
        {"$or": [{"head_ids": oid}, {"head_id": oid}]}, {"name": 1}
    ):
        if d.get("name"):
            names.append(d["name"])
    return names


def _team_ids_incl_dept_head(user):
    """Employee _ids (strings) this user has "manager" authority over: their
    department(s) + direct reports (manager_id) + any department(s) they
    head. The single source of truth for manager-side scoping — leave/asset
    approval authorization, the Leave Requests / notification-badge counts,
    comp-off grants — so a second manager in the same department, or a
    department head who isn't literally anyone's manager_id, still counts.
    (Was _comp_off_team_ids in routes/leaves.py; generalized here since the
    same "who can act as this employee's manager" question applies well
    beyond comp-off.)"""
    ids = set(_managed_employee_ids(user))
    head_depts = _dept_head_dept_names(str(user["_id"]))
    if head_depts:
        ids |= {str(u["_id"]) for u in users_col.find(
            {"department": {"$in": head_depts}}, {"_id": 1}
        )}
    ids.discard(str(user["_id"]))  # not oneself
    return ids


# ── Notification recipients ──────────────────────────────────────────────────
# Shared "who to email" resolution so every activity-submitted notification
# (leave, asset request, referral, ...) reaches the same people the same way,
# instead of each route hand-rolling its own manager lookup.

def resolve_employee_manager_emails(employee):
    """Every manager-tier person eligible to approve / be notified about this
    employee's requests — the exact reverse of _team_ids_incl_dept_head():
    their direct manager (manager_id), any other manager in their
    department, and anyone heading their department. A department with two
    managers (or a department head who isn't set as anyone's manager_id)
    means everyone here gets the same notification, and any ONE of them
    approving is enough (see routes/leaves.py's update_leave). De-duplicated
    by email, original list order kept; empty list if none resolve."""
    emp_depts = _mgr_depts(employee)  # original case; works for any user doc, not just managers
    seen, emails = set(), []

    def _add(u):
        e = u.get("email") if u else None
        if e and e.lower() not in seen:
            seen.add(e.lower())
            emails.append(e)

    # Direct manager first (whatever their role — matches the pre-existing
    # single-recipient lookup this replaces, which never role-checked it).
    if employee.get("manager_id"):
        try:
            _add(users_col.find_one({"_id": ObjectId(str(employee["manager_id"]))}, {"email": 1}))
        except Exception:
            pass
    # Then every other role:"manager" person sharing a department — role-
    # scoped here so this doesn't sweep in ordinary department colleagues.
    if emp_depts:
        for u in users_col.find({"role": "manager", "department": {"$in": emp_depts}}, {"email": 1}):
            _add(u)

    # Department head(s) may not carry role "manager" in the data, so
    # resolved separately rather than folded into the role-scoped query above.
    if emp_depts:
        head_ids = []
        for d in departments_col.find({"name": {"$in": emp_depts}}, {"head_ids": 1, "head_id": 1}):
            head_ids.extend(d.get("head_ids") or ([d["head_id"]] if d.get("head_id") else []))
        for hid in head_ids:
            _add(users_col.find_one({"_id": hid}, {"email": 1}))

    return emails


def all_owner_emails():
    """Email addresses of every 'owner' role user (Business Owners)."""
    return [o["email"] for o in users_col.find({"role": "owner"}, {"email": 1}) if o.get("email")]


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
