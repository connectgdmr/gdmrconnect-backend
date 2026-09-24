"""
pms_compliance.py — GDMR Connect
===================================
Performance Review Compliance & Department Attendance Blocking.

A Manager must finalize ("Manager Review Completed") every PMS self-assessment
their active team actually submitted for a month by that month's own last
working day. Miss it, and their team's attendance check-in gets blocked until
they catch up or HR/Admin overrides it. See the FRD ("Performance Review
Compliance & Department Attendance Blocking") this module implements.

Deliberately reuses the app's existing primitives instead of re-deriving them:
- _team_ids_incl_dept_head() / is_offboarded() (helpers.py) for "who's
  actually on this manager's active team" — the same rule leave/asset/PMS
  approval scoping already uses everywhere else.
- is_weekend_day() + get_company_holiday_dates() (helpers.py) for "what's a
  working day" — the same calendar the Attendance Calendar and payroll LOP
  already share, so "last working day of the month" can't drift from what
  the rest of the app considers a working day.
- pms_reviews_col's existing lifecycle (routes/pms.py): status "Pending
  Review" -> "Manager Review Completed" is the one and only signal for
  whether a review is done — no new review workflow, just reading this one.

blocking_enabled (pms_compliance_settings_col) defaults to False — everything
below (status computation, the dashboard, every notification) runs for real
regardless, so HR/Admin can watch a full cycle before the one thing that's
actually gated on the toggle — check-in enforcement — can lock anyone out.
"""
import calendar
import threading
from datetime import datetime, timedelta, timezone, date
from bson import ObjectId

from database import (
    users_col, leaves_col, pms_reviews_col,
    pms_compliance_col, pms_compliance_audit_col, pms_compliance_settings_col,
)
from helpers import (
    is_offboarded, _team_ids_incl_dept_head, is_weekend_day,
    get_company_holiday_dates, _date_str, all_owner_emails,
)
from config import IST, HR_EMAIL
from utils import send_email

_SETTINGS_DEFAULTS = {
    "_id":                     "singleton",
    "blocking_enabled":        False,
    "exempt_employee_ids":     [],
    "exempt_department_names": [],
    "new_joiner_grace_days":   30,
}


# ── Settings ─────────────────────────────────────────────────────────────────

def get_settings():
    """The one settings doc, seeded with defaults if somehow missing (the
    database.py startup migration already seeds it on first boot)."""
    doc = pms_compliance_settings_col.find_one({"_id": "singleton"})
    return doc if doc else dict(_SETTINGS_DEFAULTS)


def update_settings(fields, actor=None):
    fields = dict(fields)
    fields["updated_at"] = datetime.now(timezone.utc)
    fields["updated_by"] = str(actor["_id"]) if actor else None
    pms_compliance_settings_col.update_one(
        {"_id": "singleton"}, {"$set": fields}, upsert=True
    )
    return get_settings()


# ── Calendar ─────────────────────────────────────────────────────────────────

def _last_working_day_of_month(year, month, holiday_dates):
    """The actual last working day of (year, month) — walk back from the
    last calendar day past any holiday/weekend (is_weekend_day already knows
    the company's "last Saturday of the month is a working day" rule)."""
    last_num = calendar.monthrange(year, month)[1]
    d = date(year, month, last_num)
    while is_weekend_day(str(d), holiday_dates):
        d -= timedelta(days=1)
    return d


def is_last_working_day(d, holiday_dates):
    """True if date `d` is the last working day of its own month."""
    return d == _last_working_day_of_month(d.year, d.month, holiday_dates)


# ── Team resolution (with the configurable FRD §14 exceptions applied) ───────

def _dept_label(user):
    d = user.get("department")
    if isinstance(d, list):
        return ", ".join(x for x in d if x)
    return d or ""


def active_managers():
    """Every non-offboarded manager — the population this whole module
    tracks compliance for."""
    return [u for u in users_col.find({"role": "manager"}) if not is_offboarded(u)]


def team_for_manager(manager, settings=None):
    """This manager's active team (department overlap, direct reports, or a
    department they head — _team_ids_incl_dept_head), minus offboarded staff,
    minus anyone HR/Admin has explicitly exempted (by id or by department),
    minus anyone still within their new-joiner grace period. Returns a set of
    user-id strings."""
    settings = settings if settings is not None else get_settings()
    ids = _team_ids_incl_dept_head(manager)
    if not ids:
        return set()

    try:
        oids = [ObjectId(i) for i in ids]
    except Exception:
        oids = []
    docs = {
        str(u["_id"]): u
        for u in users_col.find({"_id": {"$in": oids}}, {"department": 1, "doj": 1, "resignation": 1})
    }

    exempt_emp   = set(settings.get("exempt_employee_ids") or [])
    exempt_depts = {str(d).strip().lower() for d in (settings.get("exempt_department_names") or [])}
    grace_days   = settings.get("new_joiner_grace_days") or 0
    today        = datetime.now(IST).date()

    out = set()
    for uid in ids:
        if uid in exempt_emp:
            continue
        u = docs.get(uid)
        if not u or is_offboarded(u):
            continue
        if exempt_depts:
            dept_val  = u.get("department")
            dept_list = dept_val if isinstance(dept_val, list) else ([dept_val] if dept_val else [])
            if any((d or "").strip().lower() in exempt_depts for d in dept_list):
                continue
        if grace_days:
            doj = _date_str(u.get("doj"))
            if doj:
                try:
                    joined = datetime.strptime(doj, "%Y-%m-%d").date()
                    if (today - joined).days < grace_days:
                        continue
                except Exception:
                    pass
        out.add(uid)
    return out


def is_manager_on_leave(manager):
    """FRD §14 — a Manager on approved leave is exempt from that month's
    deadline/block. Covers both a standard approved leave and an extended
    leave, same two sources classify_attendance_day() already checks."""
    uid   = str(manager["_id"])
    today = str(datetime.now(IST).date())
    if leaves_col.find_one({
        "user_id": uid, "status": "Approved",
        "from_date": {"$lte": today}, "to_date": {"$gte": today},
    }):
        return True
    for el in manager.get("extended_leaves") or []:
        f, t = _date_str(el.get("from_date")), _date_str(el.get("to_date"))
        if f and t and f <= today <= t:
            return True
    return False


# ── Review completion ─────────────────────────────────────────────────────────

def manager_month_status(manager, month, settings=None):
    """(status, reviews_completed, reviews_pending, team_size) for this
    manager's month. Only reviews that were actually *submitted* by the team
    count — a team member nobody assigned a PMS form to this month isn't
    held against the manager (confirmed policy: compliance = finalize
    whatever exists, not force-assign 100% of the team)."""
    settings = settings if settings is not None else get_settings()
    team = team_for_manager(manager, settings)
    if not team:
        return "Completed", 0, 0, 0

    reviews = list(pms_reviews_col.find(
        {"user_id": {"$in": list(team)}, "month": month}, {"status": 1}
    ))
    completed = sum(1 for r in reviews if r.get("status") == "Manager Review Completed")
    pending   = len(reviews) - completed

    if pending == 0:
        status = "Completed"
    elif completed == 0:
        status = "Pending"
    else:
        status = "In Progress"
    return status, completed, pending, len(team)


# ── State transitions (each upserts the record + writes the audit trail) ────

def write_audit(action, manager, month, actor=None, reason=None, details=None):
    pms_compliance_audit_col.insert_one({
        "action":      action,
        "manager_id":  str(manager["_id"]),
        "manager_name": manager.get("name", ""),
        "month":       month,
        "actor_id":    str(actor["_id"]) if actor else None,
        "actor_name":  actor.get("name") if actor else "System",
        "reason":      reason,
        "details":     details or {},
        "at":          datetime.now(timezone.utc),
    })


def set_status(manager, month, settings=None):
    """Recompute and persist this manager's status for `month`. If they're
    currently blocked and still have pending reviews, the status is pinned
    to "Overdue" regardless of the raw Pending/In Progress split — that
    split only matters before the deadline; once blocked, "Overdue" is the
    one thing the dashboard needs to say."""
    settings = settings if settings is not None else get_settings()
    status, completed, pending, team_size = manager_month_status(manager, month, settings)
    manager_id = str(manager["_id"])
    existing   = pms_compliance_col.find_one({"manager_id": manager_id, "month": month})
    if existing and existing.get("blocked") and pending > 0:
        status = "Overdue"

    pms_compliance_col.update_one(
        {"manager_id": manager_id, "month": month},
        {
            "$set": {
                "manager_id":        manager_id,
                "manager_name":      manager.get("name", ""),
                "department":        _dept_label(manager),
                "month":             month,
                "status":            status,
                "team_size":         team_size,
                "reviews_completed": completed,
                "reviews_pending":   pending,
                "updated_at":        datetime.now(timezone.utc),
            },
            "$setOnInsert": {
                "blocked": False, "blocked_at": None,
                "first_warning_sent_at": None, "overdue_notice_sent_at": None,
                "restored_at": None, "override": None, "deadline_override": None,
            },
        },
        upsert=True,
    )
    return status, completed, pending, team_size


def send_warning(manager, month):
    """FRD §6/§3 — the prior-alert notification, sent once on the last
    working day to every manager who isn't Completed yet."""
    write_audit("reminder_sent", manager, month)
    pms_compliance_col.update_one(
        {"manager_id": str(manager["_id"]), "month": month},
        {"$set": {"first_warning_sent_at": datetime.now(timezone.utc)}},
    )
    if not manager.get("email"):
        return
    subject = "Action Required – Monthly Performance Review Pending"
    body = (
        f"Dear {manager.get('name', 'Manager')},\n\n"
        f"The monthly Performance Review for your team is pending completion. Please "
        f"ensure that all required reviews are completed within the prescribed timeline.\n\n"
        f"Please note that failure to complete the Performance Review may result in the "
        f"attendance Check-in facility being blocked for your entire department/team.\n\n"
        f"Kindly complete the pending reviews at the earliest."
    )
    threading.Thread(target=send_email, args=(manager["email"], subject, body), daemon=True).start()


def send_overdue_and_block(manager, month):
    """FRD §5/§6 — the deadline has passed and reviews are still pending:
    mark Overdue + blocked, and notify the manager (and HR/owners, so
    someone with override authority actually sees it happen)."""
    manager_id = str(manager["_id"])
    now = datetime.now(timezone.utc)
    pms_compliance_col.update_one(
        {"manager_id": manager_id, "month": month},
        {"$set": {
            "status": "Overdue", "blocked": True,
            "blocked_at": now, "overdue_notice_sent_at": now,
        }},
    )
    write_audit("blocked", manager, month)

    recipients = {}
    if manager.get("email"):
        recipients[manager["email"].lower()] = manager["email"]
    if HR_EMAIL:
        recipients[HR_EMAIL.lower()] = HR_EMAIL
    for email in all_owner_emails():
        recipients[email.lower()] = email

    subject = "Attendance Restricted — Monthly Performance Review Overdue"
    body = (
        f"Dear {manager.get('name', 'Manager')},\n\n"
        f"The monthly Performance Review for your team was not completed within the "
        f"prescribed timeline. As a result, the attendance Check-in facility for your "
        f"department/team has been blocked.\n\n"
        f"Please complete the pending review(s) to restore Check-in access for your team."
    )
    for email in recipients.values():
        threading.Thread(target=send_email, args=(email, subject, body), daemon=True).start()


def auto_unblock_if_complete(manager, month, settings=None):
    """Call after any manager action that could have finished off their
    last pending review (finalize_pms_review). No-op unless they were
    actually blocked and are now genuinely Completed."""
    manager_id = str(manager["_id"])
    rec = pms_compliance_col.find_one({"manager_id": manager_id, "month": month})
    if not rec or not rec.get("blocked"):
        return
    status, completed, pending, team_size = set_status(manager, month, settings)
    if status != "Completed":
        return

    now = datetime.now(timezone.utc)
    pms_compliance_col.update_one(
        {"manager_id": manager_id, "month": month},
        {"$set": {"blocked": False, "restored_at": now, "override": None}},
    )
    write_audit("unblocked_auto", manager, month)
    if manager.get("email"):
        subject = "Performance Review Completed – Attendance Restored"
        body = (
            f"Dear {manager.get('name', 'Manager')},\n\n"
            f"The pending monthly Performance Review has been completed successfully. "
            f"The attendance Check-in facility for your team has been restored."
        )
        threading.Thread(target=send_email, args=(manager["email"], subject, body), daemon=True).start()


def override_unblock(manager, month, actor, reason=None, until=None):
    """HR/Admin manually restoring access without the underlying reviews
    actually being finished — `blocked` (the compliance engine's own view)
    is left as-is on purpose; the dashboard's "Attendance Status" reads
    Active because of the override, while "Override Status" stays visibly
    Yes so it's clear this manager is still technically non-compliant."""
    pms_compliance_col.update_one(
        {"manager_id": str(manager["_id"]), "month": month},
        {"$set": {"override": {
            "active": True, "by": str(actor["_id"]), "by_name": actor.get("name", ""),
            "reason": reason or "", "until": until, "at": datetime.now(timezone.utc),
        }}},
    )
    write_audit("unblocked_override", manager, month, actor=actor, reason=reason, details={"until": until})
    if manager.get("email"):
        subject = "Attendance Check-in Restored by HR/Admin"
        body = (
            f"Dear {manager.get('name', 'Manager')},\n\n"
            f"HR/Admin has restored the attendance Check-in facility for your team."
            + (f"\n\nReason: {reason}" if reason else "")
            + ("\n\nNote: your monthly Performance Review is still pending — please "
               "complete it at the earliest." )
        )
        threading.Thread(target=send_email, args=(manager["email"], subject, body), daemon=True).start()


def extend_deadline(manager, month, until, actor, reason=None):
    """HR/Admin pushes this manager's deadline for `month` out to `until`
    ("YYYY-MM-DD") — the scheduler's overdue check skips them until then."""
    pms_compliance_col.update_one(
        {"manager_id": str(manager["_id"]), "month": month},
        {"$set": {"deadline_override": until}},
        upsert=True,
    )
    write_audit("deadline_extended", manager, month, actor=actor, reason=reason, details={"until": until})


# ── Attendance-side check (routes/attendance.py) ─────────────────────────────

def _has_active_block(manager_id, month):
    rec = pms_compliance_col.find_one({"manager_id": manager_id, "month": month})
    if not rec or not rec.get("blocked"):
        return False
    override = rec.get("override") or {}
    if override.get("active"):
        until = override.get("until")
        if not until or str(until) >= str(datetime.now(IST).date()):
            return False  # override still in effect
    return True


def is_employee_blocked(employee, settings=None):
    """(blocked: bool, manager_doc | None) for this employee right now.
    Checks the employee's own record if they're a manager (FRD §5 — "the
    Manager's own attendance Check-in should also be blocked"), then every
    other manager whose team currently includes them."""
    settings = settings if settings is not None else get_settings()
    if not settings.get("blocking_enabled"):
        return False, None

    month  = datetime.now(IST).strftime("%Y-%m")
    emp_id = str(employee["_id"])

    if employee.get("role") == "manager" and _has_active_block(emp_id, month):
        return True, employee

    for m in active_managers():
        mid = str(m["_id"])
        if mid == emp_id:
            continue
        if emp_id in team_for_manager(m, settings) and _has_active_block(mid, month):
            return True, m

    return False, None


BLOCKED_MESSAGE = (
    "Attendance Check-in Blocked. The attendance Check-in facility for your department "
    "has been temporarily blocked due to the pending monthly Performance Review. "
    "Please contact your Reporting Manager for further clarification."
)
