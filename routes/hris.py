"""
routes/hris.py - aieque HRIS (UAE) extensions.

DEMO DEPLOYMENT ONLY: app_new.py registers this blueprint only when DEMO_MODE is on, so the production GDMR Connect
server never exposes any of these routes. Everything here is additive: it reads/writes its own collections
(hris_profiles, hris_drafts, hris_audit, hris_settings, hris_docs) and creates ordinary `users` rows so the rest of the
app (login, attendance, leave, payroll) keeps working unchanged.
"""
import io
import re
import secrets
import calendar as _cal
from datetime import datetime, timezone, timedelta, date

import cloudinary.uploader
from bson import ObjectId
from flask import Blueprint, request, jsonify, Response

from database import db, users_col, salary_structures_col, assets_col, attendance_col, leaves_col, holidays_col
from decorators import token_required
from helpers import _is_admin, _today_ist, is_offboarded
from config import IST

bp = Blueprint("hris", __name__)

profiles_col = db["hris_profiles"]
drafts_col   = db["hris_drafts"]
audit_col    = db["hris_audit"]
settings_col = db["hris_settings"]
docs_col     = db["hris_docs"]

EMPLOYMENT_TYPES = ["Permanent", "Fixed-term", "Probation", "Part-time", "Intern/Trainee", "Consultant"]
STATUSES         = ["On Probation", "Active", "Serving Notice", "Exited"]
GENDERS          = ["Male", "Female"]
MARITAL          = ["Single", "Married", "Divorced", "Widowed"]
PAY_MODES        = ["Bank", "Cash", "Card"]
CURRENCIES       = ["AED", "USD", "EUR", "GBP", "SAR", "INR"]
VISA_TYPES       = ["Employment", "Investor / Partner", "Dependant", "Golden", "Green", "Other"]
HIRED_VIA        = ["Direct", "Referral", "Agency", "Job portal", "Walk-in", "Transfer"]
DOC_KINDS        = ["passport", "visa", "emirates_id", "offer_letter", "contract", "nda", "non_solicit", "education",
                    "experience", "noc", "other"]
DEFAULT_OFFICES  = [{"name": "Dubai Head Office", "country": "UAE", "city": "Dubai"},
                    {"name": "Abu Dhabi Office", "country": "UAE", "city": "Abu Dhabi"},
                    {"name": "Sharjah Office", "country": "UAE", "city": "Sharjah"}]
DEFAULT_SETTINGS = {
    "_id": "main",
    "working_week": [0, 1, 2, 3, 4],                 # Monday=0 ... Sunday=6
    "offices": DEFAULT_OFFICES,
    "probation_max_months": 6,
    "expiry_alert_days": [90, 60, 30],
    "leave_policies": ["UAE Labour Law - Standard"],
    "carry_forward_max_days": 5,
    "company_docs": [{"name": "Trade licence", "expiry": ""}],
    "employer_id": "", "employer_bank_routing": "",  # for the WPS (SIF) file
}
ONBOARDING  = [("laptop", "Laptop and other items issued"), ("email", "Email and system access created"),
               ("induction", "Induction completed"), ("contract_signed", "Contract and NDA signed"),
               ("bank_wps", "Bank / WPS details collected")]
OFFBOARDING = [("items_returned", "Items returned (laptop, access card, phone)"), ("access_removed", "Email and system access removed"),
               ("final_payment", "Final payment and gratuity settled"), ("clearance", "Clearance form signed"),
               ("exit_interview", "Exit interview done")]

# ── small helpers ────────────────────────────────────────────────────────────

def _now():
    return datetime.now(timezone.utc)


def _hr(user):                      # Admin / Owner = "Admin and HR" in the client's wording
    return _is_admin(user)


def _forbid():
    return jsonify({"message": "Only Admin / HR can do this."}), 403


def _s(v, n=200):
    return str(v or "").strip()[:n]


def _num(v):
    try:
        x = float(str(v).replace(",", "").strip() or 0)
    except (TypeError, ValueError):
        return 0.0
    return round(x, 2)


def _d(v):
    """'YYYY-MM-DD' (or datetime/date) -> date, else None."""
    if not v:
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    s = str(v).strip()[:10]
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    return None


def _iso(v):
    d = _d(v)
    return d.isoformat() if d else ""


def _add_months(d, m):
    y, mo = divmod(d.month - 1 + int(m), 12)
    y += d.year
    mo += 1
    return date(y, mo, min(d.day, _cal.monthrange(y, mo)[1]))


def settings():
    row = settings_col.find_one({"_id": "main"}) or {}
    out = {**DEFAULT_SETTINGS, **{k: v for k, v in row.items() if k != "_id"}}
    out.pop("_id", None)
    return out


def audit(actor, emp, field, before, after):
    if str(before or "") == str(after or ""):
        return
    audit_col.insert_one({"at": _now(), "by": str(actor.get("_id", "")), "by_name": actor.get("name", ""),
                          "employee_id": str(emp.get("_id", "")), "employee": emp.get("name", ""),
                          "field": field, "before": str(before if before is not None else ""), "after": str(after if after is not None else "")})


# ── validators ───────────────────────────────────────────────────────────────

def norm_eid(v):
    digits = re.sub(r"\D", "", str(v or ""))
    return digits


def fmt_eid(v):
    d = norm_eid(v)
    return f"{d[:3]}-{d[3:7]}-{d[7:14]}-{d[14:]}" if len(d) == 15 else str(v or "").strip()


def norm_iban(v):
    return re.sub(r"\s+", "", str(v or "")).upper()


def iban_checksum_ok(iban):
    s = iban[4:] + iban[:4]
    try:
        return int("".join(str(int(c, 36)) for c in s)) % 97 == 1
    except ValueError:
        return False


def _flat_dup_keys(profile):
    j, dd, sal = profile.get("job") or {}, profile.get("docs") or {}, profile.get("salary") or {}
    return {
        "job.work_email": _s(j.get("work_email")).lower(),
        "docs.eid.number": norm_eid((dd.get("eid") or {}).get("number")),
        "docs.passport.number": _s((dd.get("passport") or {}).get("number")).upper().replace(" ", ""),
        "salary.bank.iban": norm_iban((sal.get("bank") or {}).get("iban")),
    }


def validate_profile(p, *, creating, exclude_id=None, extra_seen=None):
    """-> (errors, warnings), both {dotted.field: message}. `extra_seen` = values already used by earlier rows of the same upload."""
    st = settings()
    err, warn = {}, {}
    per, job = p.get("personal") or {}, p.get("job") or {}
    docs, sal, lv = p.get("docs") or {}, p.get("salary") or {}, p.get("leave") or {}
    today = _today_ist()

    def req(path, val, label):
        if not _s(val):
            err[path] = f"{label} is required."

    if creating:
        req("job.full_name", job.get("full_name"), "Full name")
        req("job.work_email", job.get("work_email"), "Work email")
        req("job.department", job.get("department"), "Department")
        req("job.job_title", job.get("job_title"), "Job title")
        req("job.office", job.get("office"), "Office")
        req("job.doj", job.get("doj"), "Date of joining")
        req("personal.dob", per.get("dob"), "Date of birth")
        req("personal.gender", per.get("gender"), "Gender")
        req("personal.nationality", per.get("nationality"), "Nationality")
        req("personal.marital_status", per.get("marital_status"), "Marital status")
        em = per.get("emergency") or {}
        req("personal.emergency.name", em.get("name"), "Emergency contact name")
        req("personal.emergency.relationship", em.get("relationship"), "Relationship")
        req("personal.emergency.phone", em.get("phone"), "Emergency contact phone")
        req("job.notice_days", job.get("notice_days"), "Notice period")
        req("job.status", job.get("status"), "Current status")
        req("job.attendance_id", job.get("attendance_id"), "Attendance machine ID")
    email = _s(job.get("work_email")).lower()
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        err["job.work_email"] = "Enter a valid email address."
    pe = _s(per.get("personal_email")).lower()
    if pe and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", pe):
        err["personal.personal_email"] = "Enter a valid email address."
    if job.get("employment_type") and job["employment_type"] not in EMPLOYMENT_TYPES:
        err["job.employment_type"] = "Choose a valid employment type."
    if creating:
        req("job.employment_type", job.get("employment_type"), "Employment type")
    # manager: compulsory for everyone except the Managing Director
    is_md = bool(job.get("is_md")) or "managing director" in _s(job.get("job_title")).lower()
    if not job.get("manager_id") and not is_md and (creating or "manager_id" in job):
        err["job.manager_id"] = "Manager is required (leave and attendance approvals depend on it). Only the Managing Director can be without one."
    if job.get("manager_id"):
        try:
            if not users_col.find_one({"_id": ObjectId(str(job["manager_id"]))}):
                err["job.manager_id"] = "That manager no longer exists."
        except Exception:
            err["job.manager_id"] = "Choose a manager from the list."
    # probation + dates
    doj = _d(job.get("doj"))
    if job.get("doj") and not doj:
        err["job.doj"] = "Enter a valid date (dd/mm/yyyy)."
    pm = job.get("probation_months")
    if _s(pm) != "":
        try:
            pmi = int(float(pm))
            if pmi < 0:
                raise ValueError
            if pmi > st["probation_max_months"]:
                err["job.probation_months"] = f"Probation cannot be more than {st['probation_max_months']} months (UAE limit)."
        except (TypeError, ValueError):
            err["job.probation_months"] = "Enter the probation period as a whole number of months."
    cs, ce = _d(job.get("contract_start")), _d(job.get("contract_end"))
    if (job.get("employment_type") == "Fixed-term") and not ce:
        err["job.contract_end"] = "A fixed-term contract needs an end date."
    if cs and ce and ce < cs:
        err["job.contract_end"] = "The contract end date is before the start date."
    conf = _d(job.get("confirmation_date"))
    if conf and doj and conf < doj:
        err["job.confirmation_date"] = "The confirmation date is before the joining date."
    if job.get("status") and job["status"] not in STATUSES:
        err["job.status"] = "Choose a valid status."
    if job.get("notice_days") not in (None, "") and not re.match(r"^\d{1,3}$", str(job.get("notice_days")).strip()):
        err["job.notice_days"] = "Enter the notice period in days (0-999)."
    if job.get("office") and job["office"] not in [o["name"] for o in st["offices"]]:
        err["job.office"] = "Choose an office from the list."
    # personal
    dob = _d(per.get("dob"))
    if per.get("dob") and (not dob or dob >= today):
        err["personal.dob"] = "Enter a valid date of birth in the past."
    elif dob and today.year - dob.year < 15:
        err["personal.dob"] = "The employee must be at least 15 years old."
    if per.get("gender") and per["gender"] not in GENDERS:
        err["personal.gender"] = "Choose a gender."
    if per.get("marital_status") and per["marital_status"] not in MARITAL:
        err["personal.marital_status"] = "Choose a marital status."
    ph = re.sub(r"\D", "", _s(per.get("phone")))
    if ph and not (6 <= len(ph) <= 12):
        err["personal.phone"] = "Enter a valid phone number (digits only, without the country code)."
    ep = re.sub(r"\D", "", _s((per.get("emergency") or {}).get("phone")))
    if ep and not (6 <= len(ep) <= 12):
        err["personal.emergency.phone"] = "Enter a valid phone number."
    # documents: format + expiry rules
    def expiry(path, val, label, required=False):
        e = _d(val)
        if not _s(val):
            if required:
                err[path] = f"{label} expiry date is required."
            return
        if not e:
            err[path] = "Enter a valid date (dd/mm/yyyy)."
        elif e < today:
            err[path] = f"{label} has already expired ({e.strftime('%d/%m/%Y')})."
        elif (e - today).days <= 90:
            warn[path] = f"{label} expires in {(e - today).days} days."
    pp = docs.get("passport") or {}
    if pp.get("number") and not re.match(r"^[A-Za-z0-9]{6,12}$", _s(pp["number"]).replace(" ", "")):
        err["docs.passport.number"] = "Passport numbers are 6-12 letters/digits."
    if pp.get("issue") and pp.get("expiry") and _d(pp["issue"]) and _d(pp["expiry"]) and _d(pp["expiry"]) <= _d(pp["issue"]):
        err["docs.passport.expiry"] = "The expiry date is before the issue date."
    expiry("docs.passport.expiry", pp.get("expiry"), "Passport")
    visa = docs.get("visa") or {}
    expiry("docs.visa.expiry", visa.get("expiry"), "Residence visa")
    if visa.get("type") and visa["type"] not in VISA_TYPES:
        err["docs.visa.type"] = "Choose a visa type."
    eid = docs.get("eid") or {}
    if eid.get("number"):
        d15 = norm_eid(eid["number"])
        if len(d15) != 15 or not d15.startswith("784"):
            err["docs.eid.number"] = "Emirates ID must be 15 digits starting with 784 (784-YYYY-NNNNNNN-N)."
    expiry("docs.eid.expiry", eid.get("expiry"), "Emirates ID")
    expiry("docs.mohre.labour_card_expiry", (docs.get("mohre") or {}).get("labour_card_expiry"), "Labour card")
    expiry("docs.insurance.expiry", (docs.get("insurance") or {}).get("expiry"), "Health insurance")
    iloe = docs.get("iloe") or {}
    if iloe.get("enrolled"):
        expiry("docs.iloe.expiry", iloe.get("expiry"), "ILOE")
    # salary
    if sal:
        parts = [_num(sal.get(k)) for k in ("basic", "housing", "transport", "other")]
        if any(x < 0 for x in parts):
            err["salary.basic"] = "Salary amounts cannot be negative."
        claimed = sal.get("total_claimed")
        if claimed is not None and abs(sum(parts) - float(claimed)) > 0.009:
            err["salary.total"] = f"The parts add up to {sum(parts):,.2f}, not {float(claimed):,.2f}."
        bank = sal.get("bank") or {}
        ib = norm_iban(bank.get("iban"))
        if ib:
            if len(ib) != 23 or not ib.startswith("AE") or not re.match(r"^AE\d{21}$", ib):
                err["salary.bank.iban"] = "A UAE IBAN has 23 characters: AE followed by 21 digits."
            elif not iban_checksum_ok(ib):
                warn["salary.bank.iban"] = "This IBAN's check digits don't match - please re-check it."
        if bank.get("routing") and not re.match(r"^\d{9}$", _s(bank["routing"])):
            err["salary.bank.routing"] = "The routing code is 9 digits."
        if sal.get("pay_mode") and sal["pay_mode"] not in PAY_MODES:
            err["salary.pay_mode"] = "Choose how the salary is paid."
    # duplicates
    keys = _flat_dup_keys({"job": job, "docs": docs, "salary": sal})
    labels = {"job.work_email": "work email", "docs.eid.number": "Emirates ID number", "docs.passport.number": "passport number", "salary.bank.iban": "IBAN"}
    for path, val in keys.items():
        if not val or path in err:
            continue
        if extra_seen is not None:
            if val in extra_seen.setdefault(path, set()):
                err[path] = f"This {labels[path]} appears twice in the file."
                continue
            extra_seen[path].add(val)
        for other in _dup_candidates(path, val, exclude_id):
            err[path] = f"This {labels[path]} is already used by {other}."
            break
    return err, warn


def _dup_candidates(path, val, exclude_id):
    out = []
    if path == "job.work_email":
        for u in users_col.find({"email": val}, {"name": 1}):
            if str(u["_id"]) != str(exclude_id):
                out.append(u.get("name", "another employee"))
    for pr in profiles_col.find({}, {"user_id": 1, "job": 1, "docs": 1, "salary": 1}):
        if str(pr.get("user_id")) == str(exclude_id):
            continue
        if _flat_dup_keys(pr).get(path) == val:
            u = users_col.find_one({"_id": ObjectId(pr["user_id"])}, {"name": 1}) if ObjectId.is_valid(str(pr.get("user_id"))) else None
            out.append((u or {}).get("name", "another employee"))
    return out


# ── normalisation / persistence ──────────────────────────────────────────────

def _clean_profile(p, is_hr=True):
    """Whitelist + trim everything that comes from the browser."""
    p = p or {}
    per, job, docs, sal, lv = (p.get(k) or {} for k in ("personal", "job", "docs", "salary", "leave"))
    em = per.get("emergency") or {}
    out = {
        "personal": {
            "dob": _iso(per.get("dob")), "gender": _s(per.get("gender")), "nationality": _s(per.get("nationality")),
            "marital_status": _s(per.get("marital_status")), "religion": _s(per.get("religion")), "personal_email": _s(per.get("personal_email")).lower(),
            "phone_cc": _s(per.get("phone_cc") or "+971", 6), "phone": re.sub(r"\D", "", _s(per.get("phone"), 20)),
            "address_uae": _s(per.get("address_uae"), 300), "address_home": _s(per.get("address_home"), 300), "blood_group": _s(per.get("blood_group"), 5),
            "emergency": {"name": _s(em.get("name")), "relationship": _s(em.get("relationship")), "phone_cc": _s(em.get("phone_cc") or "+971", 6),
                          "phone": re.sub(r"\D", "", _s(em.get("phone"), 20))},
            "dependants": [{"name": _s(x.get("name")), "relationship": _s(x.get("relationship")), "dob": _iso(x.get("dob"))}
                           for x in (per.get("dependants") or [])[:15] if isinstance(x, dict) and _s(x.get("name"))],
        },
        "job": {
            "full_name": _s(job.get("full_name")), "work_email": _s(job.get("work_email")).lower(), "attendance_id": _s(job.get("attendance_id"), 30),
            "department": _s(job.get("department")), "job_title": _s(job.get("job_title")), "grade": _s(job.get("grade"), 30),
            "employment_type": _s(job.get("employment_type")), "probation_months": _s(job.get("probation_months"), 3),
            "doj": _iso(job.get("doj")), "confirmation_date": _iso(job.get("confirmation_date")),
            "contract_start": _iso(job.get("contract_start")), "contract_end": _iso(job.get("contract_end")),
            "notice_days": _s(job.get("notice_days"), 3), "status": _s(job.get("status")), "manager_id": _s(job.get("manager_id"), 40),
            "is_md": bool(job.get("is_md")), "office": _s(job.get("office")), "shift": _s(job.get("shift") or "general"),
            "role": "manager" if _s(job.get("role")) == "manager" else "employee",
            "hired_via": _s(job.get("hired_via")), "referral_ref": _s(job.get("referral_ref")), "prev_employer": _s(job.get("prev_employer")),
            "experience_years": _s(job.get("experience_years"), 4), "education": _s(job.get("education"), 300),
        },
        "docs": {
            "passport": {k: (_iso(v) if k in ("issue", "expiry") else _s(v)) for k, v in (docs.get("passport") or {}).items() if k in ("number", "issue", "expiry")},
            "visa": {k: (_iso(v) if k in ("issue", "expiry") else _s(v)) for k, v in (docs.get("visa") or {}).items() if k in ("type", "file_no", "uid_no", "issue", "expiry")},
            "eid": {"number": fmt_eid((docs.get("eid") or {}).get("number")) if (docs.get("eid") or {}).get("number") else "", "expiry": _iso((docs.get("eid") or {}).get("expiry"))},
            "mohre": {k: (_iso(v) if k == "labour_card_expiry" else _s(v)) for k, v in (docs.get("mohre") or {}).items() if k in ("labour_card", "person_code", "contract_no", "labour_card_expiry")},
            "insurance": {k: (_iso(v) if k == "expiry" else _s(v)) for k, v in (docs.get("insurance") or {}).items() if k in ("company", "policy_no", "category", "expiry")},
            "iloe": {"enrolled": bool((docs.get("iloe") or {}).get("enrolled")), "expiry": _iso((docs.get("iloe") or {}).get("expiry"))},
        },
        "leave": {"policy": _s(lv.get("policy")), "opening_annual": _num(lv.get("opening_annual")), "opening_sick": _num(lv.get("opening_sick")),
                  "opening_other": _num(lv.get("opening_other")), "opening_as_of": _iso(lv.get("opening_as_of"))},
    }
    if is_hr and sal:
        bank = sal.get("bank") or {}
        tot = sum(_num(sal.get(k)) for k in ("basic", "housing", "transport", "other"))
        out["salary"] = {
            "basic": _num(sal.get("basic")), "housing": _num(sal.get("housing")), "transport": _num(sal.get("transport")), "other": _num(sal.get("other")),
            "total": round(tot, 2), "total_claimed": _num(sal.get("total")) if sal.get("total") not in (None, "") else None, "pay_mode": _s(sal.get("pay_mode") or "Bank"), "currency": _s(sal.get("currency") or "AED", 3).upper(),
            "gratuity_start": _iso(sal.get("gratuity_start")), "overtime_eligible": bool(sal.get("overtime_eligible")), "commission": _s(sal.get("commission"), 200),
            "air_ticket": {"amount": _s((sal.get("air_ticket") or {}).get("amount"), 30), "class": _s((sal.get("air_ticket") or {}).get("class"), 30),
                           "frequency": _s((sal.get("air_ticket") or {}).get("frequency"), 30)},
            "bank": {"name": _s(bank.get("name")), "iban": norm_iban(bank.get("iban")), "routing": _s(bank.get("routing"), 9), "wps_person_id": _s(bank.get("wps_person_id"), 20)},
        }
    return out


def _derive(prof, st):
    """Fill in computed job fields: confirmation date from probation months; country from the office; default status."""
    job = prof["job"]
    doj, pm = _d(job.get("doj")), job.get("probation_months")
    if doj and _s(pm) != "":
        try:
            if int(float(pm)) > 0:
                job["confirmation_date"] = _add_months(doj, int(float(pm))).isoformat()
            else:
                job["confirmation_date"] = doj.isoformat()
        except (TypeError, ValueError):
            pass
    office = next((o for o in st["offices"] if o["name"] == job.get("office")), None)
    job["country"] = (office or {}).get("country", "")
    if not job.get("status"):
        c = _d(job.get("confirmation_date"))
        job["status"] = "On Probation" if c and c > _today_ist() else "Active"
    return prof


def _users_fields(prof):
    """The fields the rest of the app reads off the `users` document."""
    j, per = prof["job"], prof["personal"]
    et = j.get("employment_type") or "Permanent"
    legacy_et = {"Intern/Trainee": "Internship", "Consultant": "Consultant"}.get(et, "Permanent")
    return {
        "name": j.get("full_name"), "email": j.get("work_email"), "department": j.get("department"), "position": j.get("job_title"),
        "location": j.get("office"), "doj": j.get("doj"), "confirmation_date": j.get("confirmation_date"), "shift": j.get("shift") or "general",
        "manager_id": j.get("manager_id") or None, "employment_type": legacy_et, "phone": f"{per.get('phone_cc', '')}{per.get('phone', '')}",
    }


def _next_code():
    hi = 0
    for u in users_col.find({"employee_code": {"$regex": r"^AIQ-\d+$"}}, {"employee_code": 1}):
        hi = max(hi, int(u["employee_code"].split("-")[1]))
    return f"AIQ-{hi + 1:03d}"


def _sync_payroll(emp_id, sal, actor):
    """Keep the Payroll module's salary structure in step with the HRIS salary section."""
    if not sal:
        return
    now = _now()
    fields = {"basic": sal["basic"], "da": 0.0, "hra": sal["housing"], "travel_allowance": sal["transport"], "other_allowance": sal["other"]}
    salary_structures_col.update_one({"employee_id": emp_id}, {"$set": {**fields, "employee_id": emp_id, "updated_at": now, "transaction_detail": "Complete"},
                                                              "$setOnInsert": {"salary_history": []}}, upsert=True)


def create_employee(payload, actor, st=None):
    """Validated payload -> users row + profile. Returns (user_id, temp_password)."""
    import bcrypt
    st = st or settings()
    prof = _derive(_clean_profile(payload, True), st)
    prof["promotions"], prof["created_at"] = [], _now()
    password = secrets.token_urlsafe(9)
    fields = _users_fields(prof)
    user = {**fields, "role": prof["job"]["role"], "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt(10)).decode(), "password_changed": False,
            "created_at": _now(), "late_checkin_count_monthly": 0, "last_late_checkin_month": None, "contract_months": None,
            "failed_login_attempts": 0, "locked_until": None, "token_version": 0}
    for _ in range(5):
        user["employee_code"] = _next_code()
        try:
            res = users_col.insert_one(user)
            break
        except Exception:
            continue
    else:
        raise RuntimeError("Could not allocate an employee ID")
    uid = str(res.inserted_id)
    prof["user_id"] = uid
    prof["employee_code"] = user["employee_code"]
    profiles_col.insert_one(prof)
    _sync_payroll(uid, prof.get("salary"), actor)
    audit(actor, {"_id": uid, "name": fields["name"]}, "employee", "", "created")
    return uid, password


# ── settings / reference lists ───────────────────────────────────────────────

@bp.route("/api/hris/meta", methods=["GET"])
@token_required
def meta():
    st = settings()
    return jsonify({"offices": st["offices"], "leave_policies": st["leave_policies"], "probation_max_months": st["probation_max_months"],
                    "employment_types": EMPLOYMENT_TYPES, "statuses": STATUSES, "genders": GENDERS, "marital": MARITAL, "pay_modes": PAY_MODES,
                    "currencies": CURRENCIES, "visa_types": VISA_TYPES, "hired_via": HIRED_VIA, "working_week": st["working_week"],
                    "can_see_salary": _hr(request.user)}), 200


@bp.route("/api/hris/settings", methods=["GET", "PUT"])
@token_required
def settings_api():
    if not _hr(request.user):
        return _forbid()
    if request.method == "GET":
        return jsonify(settings()), 200
    data = request.get_json(silent=True) or {}
    upd = {}
    if "working_week" in data:
        ww = sorted({int(x) for x in data["working_week"] if str(x).isdigit() and 0 <= int(x) <= 6})
        if not ww:
            return jsonify({"message": "Choose at least one working day."}), 400
        upd["working_week"] = ww
    if "offices" in data:
        offices = [{"name": _s(o.get("name")), "country": _s(o.get("country") or "UAE"), "city": _s(o.get("city"))} for o in data["offices"] if isinstance(o, dict) and _s(o.get("name"))]
        if not offices:
            return jsonify({"message": "Keep at least one office."}), 400
        if len({o["name"].lower() for o in offices}) != len(offices):
            return jsonify({"message": "Two offices have the same name."}), 400
        upd["offices"] = offices
    if "leave_policies" in data:
        lp = [_s(x) for x in data["leave_policies"] if _s(x)]
        if lp:
            upd["leave_policies"] = lp
    if "company_docs" in data:
        upd["company_docs"] = [{"name": _s(x.get("name")), "expiry": _iso(x.get("expiry"))} for x in data["company_docs"] if isinstance(x, dict) and _s(x.get("name"))]
    for k in ("employer_id", "employer_bank_routing"):
        if k in data:
            upd[k] = _s(data[k], 20)
    if "carry_forward_max_days" in data:
        upd["carry_forward_max_days"] = max(0, min(60, int(_num(data["carry_forward_max_days"]))))
    settings_col.update_one({"_id": "main"}, {"$set": upd}, upsert=True)
    import helpers
    if hasattr(helpers, "_hris_cache"):
        helpers._hris_cache["at"] = 0
    audit(request.user, {"_id": "", "name": "Company settings"}, "settings", "", ", ".join(upd.keys()))
    return jsonify(settings()), 200


# ── employees: list / read / create / update ─────────────────────────────────

def _strip_for(user, prof, own):
    """Salary is for Admin/HR only. Managers see job + leave of their team; employees see their own non-salary profile."""
    if not _hr(user):
        prof.pop("salary", None)
    return prof


def _may_view(user, emp):
    if _hr(user) or str(emp["_id"]) == str(user["_id"]):
        return True
    return user.get("role") == "manager" and str(emp.get("manager_id") or "") == str(user["_id"])


def _ser(prof):
    prof = dict(prof)
    prof["_id"] = str(prof.pop("_id"))
    for k in ("created_at", "updated_at"):
        if isinstance(prof.get(k), datetime):
            prof[k] = prof[k].isoformat()
    return prof


@bp.route("/api/hris/employees", methods=["GET"])
@token_required
def list_people():
    user = request.user
    rows = []
    q = {} if _hr(user) else {"manager_id": str(user["_id"])} if user.get("role") == "manager" else {"_id": user["_id"]}
    profs = {p["user_id"]: p for p in profiles_col.find({})}
    mgr_names = {str(u["_id"]): u.get("name", "") for u in users_col.find({}, {"name": 1})}
    for u in users_col.find({**q, "role": {"$in": ["employee", "manager"]}}).sort("name", 1):
        pr = profs.get(str(u["_id"])) or {}
        j = pr.get("job") or {}
        rows.append({"_id": str(u["_id"]), "code": u.get("employee_code", ""), "name": u.get("name", ""), "email": u.get("email", ""),
                     "department": u.get("department", ""), "job_title": u.get("position", ""), "office": j.get("office") or u.get("location", ""),
                     "status": j.get("status") or ("Exited" if is_offboarded(u) else "Active"), "employment_type": j.get("employment_type") or u.get("employment_type", ""),
                     "doj": j.get("doj") or u.get("doj", ""), "manager": mgr_names.get(str(u.get("manager_id") or ""), ""), "has_profile": bool(pr)})
    return jsonify(rows), 200


@bp.route("/api/hris/managers", methods=["GET"])
@token_required
def managers():
    if not _hr(request.user):
        return _forbid()
    return jsonify([{"_id": str(u["_id"]), "name": u.get("name", ""), "department": u.get("department", ""), "role": u.get("role")}
                    for u in users_col.find({"role": {"$in": ["manager", "admin", "owner"]}}).sort("name", 1)]), 200


@bp.route("/api/hris/employees/<emp_id>", methods=["GET"])
@token_required
def get_person(emp_id):
    try:
        emp = users_col.find_one({"_id": ObjectId(emp_id)})
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    if not emp:
        return jsonify({"message": "Employee not found"}), 404
    if not _may_view(request.user, emp):
        return jsonify({"message": "Unauthorized"}), 403
    pr = profiles_col.find_one({"user_id": emp_id})
    if not pr:                                            # employee created elsewhere (e.g. by the demo's seed): build a minimal profile
        pr = {"user_id": emp_id, "employee_code": emp.get("employee_code", ""), "personal": {}, "docs": {}, "leave": {}, "promotions": [],
              "job": {"full_name": emp.get("name", ""), "work_email": emp.get("email", ""), "department": emp.get("department", ""), "job_title": emp.get("position", ""),
                      "office": emp.get("location", ""), "doj": emp.get("doj", ""), "manager_id": emp.get("manager_id") or "", "shift": emp.get("shift", "general"),
                      "employment_type": "Permanent", "role": emp.get("role", "employee"), "status": "Active"}}
        if _hr(request.user):
            sal = salary_structures_col.find_one({"employee_id": emp_id})
            if sal:
                pr["salary"] = {"basic": sal.get("basic", 0), "housing": sal.get("hra", 0), "transport": sal.get("travel_allowance", 0), "other": sal.get("other_allowance", 0),
                                "total": sum(sal.get(k, 0) for k in ("basic", "hra", "travel_allowance", "other_allowance")), "currency": "AED", "pay_mode": "Bank"}
        pr["_id"] = ObjectId()
    out = _strip_for(request.user, _ser(pr), str(emp["_id"]) == str(request.user["_id"]))
    out["employee"] = {"_id": emp_id, "name": emp.get("name"), "code": emp.get("employee_code"), "role": emp.get("role")}
    return jsonify(out), 200


@bp.route("/api/hris/validate", methods=["POST"])
@token_required
def validate_api():
    if not _hr(request.user):
        return _forbid()
    data = request.get_json(silent=True) or {}
    creating = not data.get("employee_id")
    clean = _clean_profile(data.get("profile"), True)
    if creating:
        clean = _derive(clean, settings())
    errors, warnings = validate_profile(clean if creating else {**clean}, creating=creating, exclude_id=data.get("employee_id"))
    return jsonify({"errors": errors, "warnings": warnings, "derived": {"confirmation_date": clean["job"].get("confirmation_date"), "country": clean["job"].get("country")}}), 200


@bp.route("/api/hris/employees", methods=["POST"])
@token_required
def create_api():
    if not _hr(request.user):
        return _forbid()
    data = request.get_json(silent=True) or {}
    st = settings()
    clean = _derive(_clean_profile(data.get("profile"), True), st)
    errors, warnings = validate_profile(clean, creating=True)
    if errors:
        return jsonify({"message": "Please fix the highlighted fields.", "errors": errors, "warnings": warnings}), 422
    uid, pw = create_employee(data.get("profile"), request.user, st)
    if data.get("draft_id"):
        try:
            drafts_col.delete_one({"_id": ObjectId(data["draft_id"])})
        except Exception:
            pass
    return jsonify({"message": "Employee added.", "id": uid, "temp_password": pw, "login": clean["job"]["work_email"], "warnings": warnings,
                    "email_note": "This demo cannot send emails - give the employee this temporary password yourself."}), 201


@bp.route("/api/hris/employees/<emp_id>", methods=["PUT"])
@token_required
def update_person(emp_id):
    if not _hr(request.user):
        return _forbid()
    try:
        emp = users_col.find_one({"_id": ObjectId(emp_id)})
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    if not emp:
        return jsonify({"message": "Employee not found"}), 404
    st = settings()
    data = (request.get_json(silent=True) or {}).get("profile") or {}
    pr = profiles_col.find_one({"user_id": emp_id})
    if not pr:                                            # first time this (seeded) person gets an HRIS profile
        pr = {"user_id": emp_id, "employee_code": emp.get("employee_code", ""), "promotions": [], "created_at": _now(),
              "personal": {}, "docs": {}, "leave": {}, "salary": {},
              "job": {"full_name": emp.get("name", ""), "work_email": emp.get("email", ""), "department": emp.get("department", ""), "job_title": emp.get("position", ""),
                      "office": emp.get("location", ""), "doj": emp.get("doj", ""), "manager_id": emp.get("manager_id") or "", "shift": emp.get("shift", "general"),
                      "employment_type": "Permanent", "role": emp.get("role", "employee"), "status": "Active"}}
        pr["_id"] = profiles_col.insert_one(dict(pr)).inserted_id
    new = _clean_profile({**{k: (data.get(k) if k in data else pr.get(k)) for k in ("personal", "job", "docs", "salary", "leave")}}, True)
    if "salary" not in data:                              # untouched sections keep what is stored
        new.pop("salary", None)
        if pr.get("salary"):
            new["salary"] = pr["salary"]
    for k in ("personal", "job", "docs", "leave"):
        if k not in data:
            new[k] = pr.get(k) or new[k]
    new["job"]["role"] = pr.get("job", {}).get("role") or new["job"]["role"]
    new = _derive(new, st)
    errors, warnings = validate_profile(new, creating=False, exclude_id=emp_id)
    if errors:
        return jsonify({"message": "Please fix the highlighted fields.", "errors": errors, "warnings": warnings}), 422
    # who-changed-what for the sensitive fields
    old_j, new_j = pr.get("job") or {}, new["job"]
    for f, label in (("job_title", "Job title"), ("manager_id", "Manager"), ("status", "Status"), ("department", "Department"), ("office", "Office"), ("employment_type", "Employment type")):
        b, a = old_j.get(f), new_j.get(f)
        if f == "manager_id":
            nm = {str(u["_id"]): u.get("name", "") for u in users_col.find({"_id": {"$in": [ObjectId(x) for x in (b, a) if x and ObjectId.is_valid(str(x))]}}, {"name": 1})}
            b, a = nm.get(str(b), b), nm.get(str(a), a)
        audit(request.user, emp, label, b, a)
    old_s, new_s = pr.get("salary") or {}, new.get("salary") or {}
    for f in ("basic", "housing", "transport", "other", "total", "pay_mode", "currency"):
        audit(request.user, emp, f"Salary - {f}", old_s.get(f), new_s.get(f))
    audit(request.user, emp, "Bank IBAN", (old_s.get("bank") or {}).get("iban"), (new_s.get("bank") or {}).get("iban"))
    audit(request.user, emp, "Leave - opening annual", (pr.get("leave") or {}).get("opening_annual"), new["leave"].get("opening_annual"))
    audit(request.user, emp, "Leave - policy", (pr.get("leave") or {}).get("policy"), new["leave"].get("policy"))
    new["updated_at"] = _now()
    keep = {k: pr[k] for k in ("promotions", "onboarding", "offboarding", "created_at", "employee_code", "user_id") if k in pr}
    profiles_col.update_one({"_id": pr["_id"]}, {"$set": {**new, **keep}})
    users_col.update_one({"_id": emp["_id"]}, {"$set": {k: v for k, v in _users_fields(new).items() if v is not None}})
    _sync_payroll(emp_id, new.get("salary"), request.user)
    return jsonify({"message": "Saved.", "warnings": warnings, "derived": {"confirmation_date": new["job"].get("confirmation_date"), "country": new["job"].get("country")}}), 200


@bp.route("/api/hris/employees/<emp_id>/promotions", methods=["POST"])
@token_required
def add_promotion(emp_id):
    if not _hr(request.user):
        return _forbid()
    try:
        emp = users_col.find_one({"_id": ObjectId(emp_id)})
    except Exception:
        emp = None
    if not emp:
        return jsonify({"message": "Employee not found"}), 404
    data = request.get_json(silent=True) or {}
    when, new_title = _d(data.get("date")), _s(data.get("new_title"))
    if not when:
        return jsonify({"message": "Promotion date is required (dd/mm/yyyy)."}), 400
    if when > _today_ist() + timedelta(days=366):
        return jsonify({"message": "That date is too far in the future."}), 400
    if not new_title:
        return jsonify({"message": "New job title is required."}), 400
    old_title = emp.get("position", "")
    entry = {"date": when.isoformat(), "old_title": old_title, "new_title": new_title, "new_salary": _num(data.get("new_salary")) or None,
             "by": request.user.get("name", ""), "recorded_at": _now()}
    pr = profiles_col.find_one({"user_id": emp_id})
    if not pr:
        profiles_col.insert_one({"user_id": emp_id, "employee_code": emp.get("employee_code", ""), "personal": {}, "docs": {}, "leave": {}, "promotions": [],
                                 "job": {"full_name": emp.get("name"), "work_email": emp.get("email"), "department": emp.get("department"), "job_title": old_title,
                                         "office": emp.get("location", ""), "doj": emp.get("doj", ""), "manager_id": emp.get("manager_id") or "", "role": emp.get("role", "employee")}})
    profiles_col.update_one({"user_id": emp_id}, {"$push": {"promotions": entry}, "$set": {"job.job_title": new_title}})
    users_col.update_one({"_id": emp["_id"]}, {"$set": {"position": new_title}})
    audit(request.user, emp, "Job title (promotion)", old_title, new_title)
    return jsonify({"message": "Promotion recorded.", "promotion": {**entry, "recorded_at": None}}), 201


# ── drafts ───────────────────────────────────────────────────────────────────

@bp.route("/api/hris/drafts", methods=["GET", "POST"])
@token_required
def drafts():
    if not _hr(request.user):
        return _forbid()
    me = str(request.user["_id"])
    if request.method == "GET":
        return jsonify([{"_id": str(d["_id"]), "title": d.get("title", ""), "updated_at": d["updated_at"].isoformat(), "profile": d.get("profile", {})}
                        for d in drafts_col.find({"owner": me}).sort("updated_at", -1).limit(30)]), 200
    data = request.get_json(silent=True) or {}
    prof = data.get("profile") or {}
    title = _s((prof.get("job") or {}).get("full_name")) or "Untitled draft"
    doc = {"owner": me, "title": title, "profile": prof, "updated_at": _now()}
    if data.get("draft_id"):
        try:
            if drafts_col.update_one({"_id": ObjectId(data["draft_id"]), "owner": me}, {"$set": doc}).matched_count:
                return jsonify({"message": "Draft saved.", "draft_id": data["draft_id"]}), 200
        except Exception:
            pass
    res = drafts_col.insert_one(doc)
    return jsonify({"message": "Draft saved.", "draft_id": str(res.inserted_id)}), 201


@bp.route("/api/hris/drafts/<draft_id>", methods=["DELETE"])
@token_required
def delete_draft(draft_id):
    if not _hr(request.user):
        return _forbid()
    try:
        drafts_col.delete_one({"_id": ObjectId(draft_id), "owner": str(request.user["_id"])})
    except Exception:
        pass
    return jsonify({"message": "Draft deleted."}), 200


# ── bulk upload (Excel) ──────────────────────────────────────────────────────

IMPORT_COLS = [
    ("full_name", "Full name *"), ("work_email", "Work email *"), ("department", "Department *"), ("job_title", "Job title *"), ("office", "Office *"),
    ("manager_email", "Manager's work email *"), ("employment_type", "Employment type *"), ("doj", "Date of joining * (dd/mm/yyyy)"),
    ("probation_months", "Probation (months)"), ("contract_end", "Contract end (dd/mm/yyyy)"), ("notice_days", "Notice period (days) *"),
    ("attendance_id", "Attendance machine ID *"), ("dob", "Date of birth * (dd/mm/yyyy)"), ("gender", "Gender *"), ("nationality", "Nationality *"),
    ("marital_status", "Marital status *"), ("phone", "Phone (without +971)"), ("emergency_name", "Emergency contact name *"),
    ("emergency_relationship", "Emergency relationship *"), ("emergency_phone", "Emergency phone *"), ("eid_number", "Emirates ID"),
    ("eid_expiry", "Emirates ID expiry (dd/mm/yyyy)"), ("passport_number", "Passport number"), ("passport_expiry", "Passport expiry (dd/mm/yyyy)"),
    ("visa_expiry", "Visa expiry (dd/mm/yyyy)"), ("basic", "Basic salary"), ("housing", "Housing allowance"), ("transport", "Transport allowance"),
    ("other", "Other allowances"), ("bank_name", "Bank name"), ("iban", "IBAN"), ("is_md", "Managing Director? (Yes/No)"),
]


@bp.route("/api/hris/import/template", methods=["GET"])
@token_required
def import_template():
    if not _hr(request.user):
        return _forbid()
    import openpyxl
    from openpyxl.styles import Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation
    st = settings()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Employees"
    ws.append([c[1] for c in IMPORT_COLS])
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="1F7A8C" if "*" in str(cell.value) else "64748B")
    for i in range(1, len(IMPORT_COLS) + 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = 24
    ws.append(["Aisha Khan", "aisha.khan@example.com", "Operations", "Accountant", st["offices"][0]["name"], "manager@aieque.com", "Permanent", "01/03/2026", 6, "", 30,
               "1001", "14/05/1992", "Female", "Pakistani", "Married", "501234567", "Omar Khan", "Spouse", "507654321", "784-1992-1234567-1", "31/12/2028",
               "P1234567", "30/06/2030", "15/09/2027", 8000, 3000, 1000, 500, "Emirates NBD", "AE070331234567890123456", "No"])
    ws.freeze_panes = "A2"
    lists = wb.create_sheet("Lists")
    for i, (title, vals) in enumerate((("Employment type", EMPLOYMENT_TYPES), ("Gender", GENDERS), ("Marital status", MARITAL), ("Office", [o["name"] for o in st["offices"]])), start=1):
        lists.cell(row=1, column=i, value=title).font = Font(bold=True)
        for r, v in enumerate(vals, start=2):
            lists.cell(row=r, column=i, value=v)
    def dv(col, listcol, n):
        letter = openpyxl.utils.get_column_letter(listcol)
        v = DataValidation(type="list", formula1=f"=Lists!${letter}$2:${letter}${n + 1}", allow_blank=True)
        ws.add_data_validation(v)
        v.add(f"{col}2:{col}1000")
    keys = [c[0] for c in IMPORT_COLS]
    dv(openpyxl.utils.get_column_letter(keys.index("employment_type") + 1), 1, len(EMPLOYMENT_TYPES))
    dv(openpyxl.utils.get_column_letter(keys.index("gender") + 1), 2, len(GENDERS))
    dv(openpyxl.utils.get_column_letter(keys.index("marital_status") + 1), 3, len(MARITAL))
    dv(openpyxl.utils.get_column_letter(keys.index("office") + 1), 4, len(st["offices"]))
    info = wb.create_sheet("Read me", 0)
    for line in ("How to add all your staff at once", "",
                 "1. Fill one row per employee on the 'Employees' sheet (the first row is an example - delete or overwrite it).",
                 "2. Columns marked * are compulsory. Dates are dd/mm/yyyy. Choose Office, Employment type, Gender and Marital status from the drop-down lists.",
                 "3. The manager is identified by his or her WORK EMAIL, who must already be in the system (or earlier in this same file). Only the Managing Director may leave it empty.",
                 "4. Upload the file on the 'Bulk upload' page. You will see every row that has a mistake and why. Nothing is saved until you press Import.",
                 "5. The same work email, Emirates ID, passport number or IBAN cannot be used twice - such rows are rejected."):
        info.append([line])
    info.column_dimensions["A"].width = 130
    info["A1"].font = Font(bold=True, size=14)
    buf = io.BytesIO()
    wb.save(buf)
    return Response(buf.getvalue(), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment; filename=aieque-employee-import-template.xlsx"})


def _row_to_profile(r, mgr_lookup):
    def g(k):
        v = r.get(k)
        return "" if v is None else (v.strftime("%d/%m/%Y") if hasattr(v, "strftime") else str(v).strip())
    mgr_email = g("manager_email").lower()
    return {
        "personal": {"dob": g("dob"), "gender": g("gender"), "nationality": g("nationality"), "marital_status": g("marital_status"),
                     "phone": g("phone"), "phone_cc": "+971", "emergency": {"name": g("emergency_name"), "relationship": g("emergency_relationship"), "phone": g("emergency_phone")}},
        "job": {"full_name": g("full_name"), "work_email": g("work_email"), "department": g("department"), "job_title": g("job_title"), "office": g("office"),
                "manager_id": mgr_lookup.get(mgr_email, "") if mgr_email else "", "employment_type": g("employment_type"), "doj": g("doj"),
                "probation_months": g("probation_months").replace(".0", ""), "contract_end": g("contract_end"), "notice_days": g("notice_days").replace(".0", ""),
                "attendance_id": g("attendance_id").replace(".0", ""), "is_md": g("is_md").lower() in ("yes", "y", "true", "1"), "status": ""},
        "docs": {"eid": {"number": g("eid_number"), "expiry": g("eid_expiry")}, "passport": {"number": g("passport_number"), "expiry": g("passport_expiry")},
                 "visa": {"expiry": g("visa_expiry")}},
        "salary": {"basic": g("basic"), "housing": g("housing"), "transport": g("transport"), "other": g("other"), "currency": "AED", "pay_mode": "Bank",
                   "bank": {"name": g("bank_name"), "iban": g("iban")}},
        "leave": {"policy": settings()["leave_policies"][0]},
        "_mgr_email": mgr_email,
    }


@bp.route("/api/hris/import", methods=["POST"])
@token_required
def import_employees():
    if not _hr(request.user):
        return _forbid()
    import openpyxl
    f = request.files.get("file")
    commit = request.form.get("commit") == "1"
    if not f:
        return jsonify({"message": "Choose the filled-in Excel file first."}), 400
    if not (f.filename or "").lower().endswith(".xlsx"):
        return jsonify({"message": "Please upload the .xlsx template (not CSV or .xls)."}), 400
    try:
        wb = openpyxl.load_workbook(io.BytesIO(f.read()), data_only=True)
        ws = wb["Employees"] if "Employees" in wb.sheetnames else wb.worksheets[0]
    except Exception:
        return jsonify({"message": "That file could not be read. Download the template again and fill it in."}), 400
    rows = [list(r) for r in ws.iter_rows(min_row=2, values_only=True)]
    rows = [r for r in rows if any(c not in (None, "") for c in r)]
    if not rows:
        return jsonify({"message": "The file has no employee rows."}), 400
    if len(rows) > 500:
        return jsonify({"message": "Please upload at most 500 employees at a time."}), 400
    keys = [c[0] for c in IMPORT_COLS]
    st = settings()
    mgr_lookup = {u["email"].lower(): str(u["_id"]) for u in users_col.find({}, {"email": 1}) if u.get("email")}
    seen, results, created = {}, [], 0
    for i, raw in enumerate(rows, start=2):
        r = dict(zip(keys, list(raw) + [None] * (len(keys) - len(raw))))
        prof = _row_to_profile(r, mgr_lookup)
        mgr_email = prof.pop("_mgr_email")
        clean = _derive(_clean_profile(prof, True), st)
        errors, warns = validate_profile(clean, creating=True, extra_seen=seen)
        if mgr_email and not prof["job"]["manager_id"]:
            errors["job.manager_id"] = f"No employee with the email {mgr_email} (add that manager first)."
        item = {"row": i, "name": clean["job"]["full_name"] or "(no name)", "email": clean["job"]["work_email"], "errors": errors, "warnings": warns, "status": "error" if errors else "ok"}
        if commit and not errors:
            uid, pw = create_employee(prof, request.user, st)
            mgr_lookup[clean["job"]["work_email"]] = uid
            item.update({"status": "imported", "temp_password": pw})
            created += 1
        results.append(item)
    bad = sum(1 for x in results if x["errors"])
    return jsonify({"committed": commit, "total": len(results), "ok": len(results) - bad, "bad": bad, "imported": created, "rows": results}), 200


# ── expiries / alerts ────────────────────────────────────────────────────────

DOC_LABELS = {"passport": "Passport", "visa": "Residence visa", "eid": "Emirates ID", "labour": "Labour card", "insurance": "Health insurance", "iloe": "ILOE"}


def _bucket(days):
    return "expired" if days < 0 else "30" if days <= 30 else "60" if days <= 60 else "90" if days <= 90 else "later"


def collect_expiries(within=90):
    today, st, out = _today_ist(), settings(), []
    users = {str(u["_id"]): u for u in users_col.find({"role": {"$in": ["employee", "manager"]}}, {"name": 1, "department": 1, "resignation": 1, "manager_id": 1})}
    def add(kind, label, who, when, uid=None, dept="", extra=""):
        e = _d(when)
        if not e:
            return
        days = (e - today).days
        if days <= within:
            out.append({"kind": kind, "label": label, "employee": who, "employee_id": uid, "department": dept, "date": e.isoformat(), "days": days, "bucket": _bucket(days), "note": extra})
    for pr in profiles_col.find({}):
        u = users.get(pr["user_id"])
        if not u or is_offboarded(u):
            continue
        name, dept, d = u.get("name", ""), u.get("department", ""), pr.get("docs") or {}
        for key, path in (("passport", (d.get("passport") or {}).get("expiry")), ("visa", (d.get("visa") or {}).get("expiry")), ("eid", (d.get("eid") or {}).get("expiry")),
                          ("labour", (d.get("mohre") or {}).get("labour_card_expiry")), ("insurance", (d.get("insurance") or {}).get("expiry")),
                          ("iloe", (d.get("iloe") or {}).get("expiry") if (d.get("iloe") or {}).get("enrolled") else "")):
            add("document", DOC_LABELS[key], name, path, pr["user_id"], dept)
        j = pr.get("job") or {}
        if j.get("status") == "On Probation" or (_d(j.get("confirmation_date")) and _d(j["confirmation_date"]) >= today and j.get("status") != "Active"):
            add("probation", "Probation ends", name, j.get("confirmation_date"), pr["user_id"], dept, "Confirm or extend the employee")
        if j.get("employment_type") == "Fixed-term" or j.get("contract_end"):
            add("contract", "Contract ends", name, j.get("contract_end"), pr["user_id"], dept, "Renew or let the contract end")
    for cd in st.get("company_docs", []):
        add("company", cd.get("name", "Company document"), "Company", cd.get("expiry"), None, "")
    out.sort(key=lambda x: x["days"])
    return out


@bp.route("/api/hris/expiries", methods=["GET"])
@token_required
def expiries():
    if not _hr(request.user):
        return _forbid()
    within = min(max(int(request.args.get("within", 90)), 1), 365)
    items = collect_expiries(within)
    counts = {"expired": 0, "30": 0, "60": 0, "90": 0}
    for it in items:
        if it["bucket"] in counts:
            counts[it["bucket"]] += 1
    return jsonify({"items": items, "counts": counts, "alert_days": settings()["expiry_alert_days"]}), 200


@bp.route("/api/hris/attention", methods=["GET"])
@token_required
def attention():
    """Extra rows for the dashboard's 'Needs your attention' box: document expiries, probation ends, contracts due."""
    if not _hr(request.user):
        return jsonify({"documents": 0, "probation": 0, "contracts": 0, "expired": 0, "top": []}), 200
    items = collect_expiries(90)
    return jsonify({"documents": sum(1 for i in items if i["kind"] in ("document", "company") and i["days"] >= 0),
                    "expired": sum(1 for i in items if i["kind"] in ("document", "company") and i["days"] < 0),
                    "probation": sum(1 for i in items if i["kind"] == "probation" and i["days"] <= 30),
                    "contracts": sum(1 for i in items if i["kind"] == "contract"), "top": items[:6]}), 200


@bp.route("/api/hris/dashboard-extras", methods=["GET"])
@token_required
def dashboard_extras():
    today = _today_ist()
    horizon, bdays, annis = 30, [], []
    for pr in profiles_col.find({}, {"user_id": 1, "personal.dob": 1, "job.doj": 1}):
        try:
            u = users_col.find_one({"_id": ObjectId(pr["user_id"])}, {"name": 1, "resignation": 1})
        except Exception:
            continue
        if not u or is_offboarded(u):
            continue
        for src, bucket in (((pr.get("personal") or {}).get("dob"), bdays), ((pr.get("job") or {}).get("doj"), annis)):
            dd = _d(src)
            if not dd:
                continue
            try:
                nxt = dd.replace(year=today.year)
            except ValueError:
                nxt = dd.replace(year=today.year, day=28)
            if nxt < today:
                nxt = nxt.replace(year=today.year + 1)
            if (nxt - today).days <= horizon:
                bucket.append({"name": u.get("name", ""), "date": nxt.isoformat(), "days": (nxt - today).days, "years": nxt.year - dd.year})
    return jsonify({"birthdays": sorted(bdays, key=lambda x: x["days"]), "anniversaries": sorted([a for a in annis if a["years"] > 0], key=lambda x: x["days"])}), 200


@bp.route("/api/hris/orgchart", methods=["GET"])
@token_required
def orgchart():
    people = [u for u in users_col.find({"role": {"$in": ["employee", "manager", "admin", "owner"]}}, {"name": 1, "position": 1, "department": 1, "manager_id": 1, "resignation": 1, "role": 1}) if not is_offboarded(u)]
    ids = {str(u["_id"]) for u in people}
    return jsonify([{"_id": str(u["_id"]), "name": u.get("name", ""), "title": u.get("position", ""), "department": u.get("department", ""),
                     "manager_id": str(u["manager_id"]) if u.get("manager_id") and str(u["manager_id"]) in ids else None} for u in people]), 200


# ── audit ────────────────────────────────────────────────────────────────────

@bp.route("/api/hris/audit", methods=["GET"])
@token_required
def audit_list():
    if not _hr(request.user):
        return _forbid()
    q = {}
    if request.args.get("employee_id"):
        q["employee_id"] = request.args["employee_id"]
    rows = audit_col.find(q).sort("at", -1).limit(min(int(request.args.get("limit", 200)), 1000))
    return jsonify([{**{k: v for k, v in r.items() if k != "_id"}, "_id": str(r["_id"]), "at": r["at"].isoformat()} for r in rows]), 200


# ── checklists ───────────────────────────────────────────────────────────────

def _checklist_payload(emp_id, kind):
    items = ONBOARDING if kind == "onboarding" else OFFBOARDING
    pr = profiles_col.find_one({"user_id": emp_id}) or {}
    state = (pr.get(kind) or {})
    out = {"items": [{"key": k, "label": l, "done": bool((state.get(k) or {}).get("done")), "at": (state.get(k) or {}).get("at"), "by": (state.get(k) or {}).get("by")} for k, l in items]}
    out["assets"] = [{"name": a.get("asset_name") or a.get("name") or "Asset", "status": a.get("status", ""), "type": a.get("request_type", "")}
                     for a in assets_col.find({"user_id": emp_id, "status": {"$in": ["Approved", "Assigned", "Issued"]}})]
    return out


@bp.route("/api/hris/employees/<emp_id>/checklist/<kind>", methods=["GET", "PUT"])
@token_required
def checklist(emp_id, kind):
    if kind not in ("onboarding", "offboarding"):
        return jsonify({"message": "Unknown checklist"}), 404
    if not _hr(request.user):
        return _forbid()
    try:
        emp = users_col.find_one({"_id": ObjectId(emp_id)})
    except Exception:
        emp = None
    if not emp:
        return jsonify({"message": "Employee not found"}), 404
    if request.method == "PUT":
        data = request.get_json(silent=True) or {}
        valid = {k for k, _ in (ONBOARDING if kind == "onboarding" else OFFBOARDING)}
        if data.get("key") not in valid:
            return jsonify({"message": "Unknown checklist item"}), 400
        done = bool(data.get("done"))
        profiles_col.update_one({"user_id": emp_id}, {"$set": {f"{kind}.{data['key']}": {"done": done, "at": _now().isoformat() if done else None, "by": request.user.get("name", "")}}}, upsert=True)
        audit(request.user, emp, f"{kind.title()} - {data['key']}", "" if done else "done", "done" if done else "")
    return jsonify(_checklist_payload(emp_id, kind)), 200


# ── employee documents (versioned) ───────────────────────────────────────────

def _ser_doc(d):
    return {"_id": str(d["_id"]), "kind": d["kind"], "name": d.get("name", ""), "version": d.get("version", 1), "url": d.get("url", ""), "expiry": d.get("expiry", ""),
            "uploaded_by": d.get("uploaded_by", ""), "uploaded_at": d["uploaded_at"].isoformat(), "current": bool(d.get("current"))}


@bp.route("/api/hris/employees/<emp_id>/documents", methods=["GET", "POST"])
@token_required
def person_documents(emp_id):
    try:
        emp = users_col.find_one({"_id": ObjectId(emp_id)})
    except Exception:
        emp = None
    if not emp:
        return jsonify({"message": "Employee not found"}), 404
    me = request.user
    if not (_hr(me) or str(emp["_id"]) == str(me["_id"])):
        return jsonify({"message": "Unauthorized"}), 403
    if request.method == "POST":
        if not _hr(me):
            return _forbid()
        kind, f = _s(request.form.get("kind")), request.files.get("file")
        if kind not in DOC_KINDS:
            return jsonify({"message": "Choose the document type."}), 400
        if not f or not f.filename:
            return jsonify({"message": "Choose a file to upload."}), 400
        data = f.read()
        if len(data) > 10 * 1024 * 1024:
            return jsonify({"message": "The file is larger than 10 MB."}), 400
        exp = _s(request.form.get("expiry"))
        if exp and not _d(exp):
            return jsonify({"message": "Expiry date must be dd/mm/yyyy."}), 400
        if kind in ("passport", "visa", "emirates_id") and not exp:
            return jsonify({"message": "Expiry date is required for passport, visa and Emirates ID copies."}), 400
        if exp and _d(exp) < _today_ist():
            return jsonify({"message": "That document has already expired."}), 400
        try:
            url = cloudinary.uploader.upload(data, folder=f"hris/{emp_id}", resource_type="auto").get("secure_url", "")
        except Exception:
            return jsonify({"message": "Upload failed - please try again."}), 502
        last = docs_col.find_one({"user_id": emp_id, "kind": kind}, sort=[("version", -1)])
        ver = (last or {}).get("version", 0) + 1
        docs_col.update_many({"user_id": emp_id, "kind": kind}, {"$set": {"current": False}})
        docs_col.insert_one({"user_id": emp_id, "kind": kind, "name": _s(f.filename, 150), "version": ver, "url": url, "expiry": _iso(exp), "current": True,
                             "uploaded_by": me.get("name", ""), "uploaded_at": _now()})
        audit(me, emp, f"Document - {kind}", f"v{ver - 1}" if ver > 1 else "", f"v{ver}")
    return jsonify([_ser_doc(d) for d in docs_col.find({"user_id": emp_id}).sort([("kind", 1), ("version", -1)])]), 200


# ── gratuity / WPS ───────────────────────────────────────────────────────────

def gratuity(basic, start, end, unpaid_days=0, contract="unlimited"):
    """UAE Labour Law (Federal Decree-Law 33 of 2021): 21 days' basic wage per year for the first 5 years, 30 days per
    year after; pro-rata for part years; nothing under 1 year; capped at 2 years' wages. Daily wage = basic / 30."""
    days = max(0, (end - start).days - int(unpaid_days))
    years = days / 365.0
    if years < 1:
        return {"service_days": days, "years": round(years, 2), "amount": 0.0, "eligible": False, "daily_wage": round(basic / 30, 2),
                "note": "Less than one year of service - no gratuity is due."}
    daily = basic / 30
    first, rest = min(years, 5), max(0, years - 5)
    amount = daily * 21 * first + daily * 30 * rest
    cap = basic * 24
    capped = amount > cap
    return {"service_days": days, "years": round(years, 2), "daily_wage": round(daily, 2), "first_five_years": round(daily * 21 * first, 2),
            "after_five_years": round(daily * 30 * rest, 2), "amount": round(min(amount, cap), 2), "eligible": True, "capped": capped,
            "note": "Capped at 2 years' wages." if capped else ""}


@bp.route("/api/hris/employees/<emp_id>/gratuity", methods=["GET"])
@token_required
def gratuity_api(emp_id):
    if not _hr(request.user):
        return _forbid()
    pr = profiles_col.find_one({"user_id": emp_id})
    if not pr or not pr.get("salary"):
        return jsonify({"message": "Add the salary details first."}), 400
    sal = pr["salary"]
    start = _d(sal.get("gratuity_start")) or _d((pr.get("job") or {}).get("doj"))
    end = _d(request.args.get("end")) or _today_ist()
    if not start:
        return jsonify({"message": "Set the gratuity start date (or the joining date) first."}), 400
    if end < start:
        return jsonify({"message": "The end date is before the start date."}), 400
    out = gratuity(float(sal.get("basic") or 0), start, end, request.args.get("unpaid_days", 0))
    return jsonify({**out, "start": start.isoformat(), "end": end.isoformat(), "basic": sal.get("basic", 0), "currency": sal.get("currency", "AED")}), 200


@bp.route("/api/hris/wps", methods=["GET"])
@token_required
def wps_file():
    """Prepare the Wages Protection System SIF file for a month from the saved salary + bank details."""
    if not _hr(request.user):
        return _forbid()
    month = request.args.get("month") or _today_ist().strftime("%Y-%m")
    if not re.match(r"^\d{4}-(0[1-9]|1[0-2])$", month):
        return jsonify({"message": "month must be YYYY-MM"}), 400
    st = settings()
    y, m = int(month[:4]), int(month[5:])
    first, last = date(y, m, 1), date(y, m, _cal.monthrange(y, m)[1])
    problems, lines, total = [], [], 0.0
    if not st.get("employer_id") or not re.match(r"^\d{13,15}$", st["employer_id"]):
        problems.append("Settings: enter the employer's MOHRE establishment ID (13-15 digits) before generating the file.")
    if not st.get("employer_bank_routing") or not re.match(r"^\d{9}$", st["employer_bank_routing"]):
        problems.append("Settings: enter the employer bank's 9-digit routing code.")
    for pr in profiles_col.find({}):
        u = users_col.find_one({"_id": ObjectId(pr["user_id"])}, {"name": 1, "resignation": 1})
        if not u or is_offboarded(u):
            continue
        sal, j = pr.get("salary") or {}, pr.get("job") or {}
        if sal.get("pay_mode") not in (None, "", "Bank"):
            continue
        doj = _d(j.get("doj"))
        if doj and doj > last:
            continue
        bank = sal.get("bank") or {}
        who = u.get("name", "")
        need = []
        if not sal.get("total"):
            need.append("salary")
        if not norm_iban(bank.get("iban")):
            need.append("IBAN")
        if not re.match(r"^\d{9}$", _s(bank.get("routing"))):
            need.append("bank routing code")
        if not _s(bank.get("wps_person_id")):
            need.append("WPS person ID")
        if need:
            problems.append(f"{who}: missing {', '.join(need)}.")
            continue
        start = max(first, doj) if doj else first
        days = (last - start).days + 1
        fixed = round(float(sal["total"]) * days / ((last - first).days + 1), 2)
        total += fixed
        lines.append(f"EDR,{_s(bank['wps_person_id'])},{bank['routing']},{norm_iban(bank['iban'])},{start.isoformat()},{last.isoformat()},{days},{fixed:.2f},0.00,0")
    now = datetime.now(IST)
    scr = f"SCR,{st.get('employer_id', '')},{st.get('employer_bank_routing', '')},{now.date().isoformat()},{now.strftime('%H%M')},{m:02d}{y},{len(lines)},{total:.2f},AED,{st.get('employer_id', '')}"
    content = "\n".join(lines + [scr]) + "\n"
    return jsonify({"file_name": f"{st.get('employer_id', 'EMPLOYER')}{m:02d}{str(y)[2:]}01.SIF", "content": content, "records": len(lines), "total": round(total, 2),
                    "problems": problems, "ready": not problems and bool(lines)}), 200


# ── leave entitlement (UAE labour law) ───────────────────────────────────────

def leave_entitlement(doj, on, opening=0.0):
    """Annual leave per UAE law: nothing before 6 months; 2 days per month worked between 6 and 12 months; 30 calendar days
    per year afterwards. Sick leave: up to 90 days a year after probation (15 full pay, 30 half pay, 45 unpaid)."""
    if not doj:
        return {"service_months": 0, "annual_days": 0, "note": "Joining date missing."}
    months = (on.year - doj.year) * 12 + on.month - doj.month - (1 if on.day < doj.day else 0)
    if months < 6:
        annual, note = 0, "Annual leave starts after 6 months of service."
    elif months < 12:
        annual, note = 2 * months, "2 days for each month of service during the first year."
    else:
        annual, note = 30, "30 calendar days per year."
    return {"service_months": months, "annual_days": annual, "annual_note": note, "sick_days": 90 if months >= 6 else 0,
            "sick_note": "15 days full pay, 30 days half pay, 45 days unpaid." if months >= 6 else "Sick leave is available after probation.",
            "hajj": "One unpaid Hajj leave of up to 30 days, after 1 year of service." if months >= 12 else "Hajj leave needs 1 year of service.", "opening": opening}


@bp.route("/api/hris/employees/<emp_id>/leave-entitlement", methods=["GET"])
@token_required
def leave_entitlement_api(emp_id):
    try:
        emp = users_col.find_one({"_id": ObjectId(emp_id)})
    except Exception:
        emp = None
    if not emp or not _may_view(request.user, emp):
        return jsonify({"message": "Not found"}), 404
    pr = profiles_col.find_one({"user_id": emp_id}) or {}
    doj = _d((pr.get("job") or {}).get("doj") or emp.get("doj"))
    out = leave_entitlement(doj, _today_ist(), (pr.get("leave") or {}).get("opening_annual", 0))
    out["carry_forward_max_days"] = settings()["carry_forward_max_days"]
    return jsonify(out), 200


# ── reports ──────────────────────────────────────────────────────────────────

@bp.route("/api/hris/reports/<name>", methods=["GET"])
@token_required
def reports(name):
    if not _hr(request.user):
        return _forbid()
    today = _today_ist()
    people = list(users_col.find({"role": {"$in": ["employee", "manager"]}}))
    profs = {p["user_id"]: p for p in profiles_col.find({})}
    if name == "headcount":
        rows = []
        for u in people:
            pr = profs.get(str(u["_id"])) or {}
            j = pr.get("job") or {}
            rows.append([u.get("employee_code", ""), u.get("name", ""), u.get("department", ""), u.get("position", ""), j.get("office") or u.get("location", ""),
                         j.get("employment_type") or u.get("employment_type", ""), j.get("status") or ("Exited" if is_offboarded(u) else "Active"), u.get("doj", "")])
        return jsonify({"title": "Staff list", "columns": ["ID", "Name", "Department", "Job title", "Office", "Employment type", "Status", "Joined"], "rows": rows,
                        "summary": f"{sum(1 for r in rows if r[6] != 'Exited')} active of {len(rows)} on record"}), 200
    if name == "leavers":
        rows = []
        for u in people:
            pr = profs.get(str(u["_id"])) or {}
            res = u.get("resignation") or {}
            st_ = (pr.get("job") or {}).get("status")
            if res or st_ in ("Serving Notice", "Exited"):
                rows.append([u.get("employee_code", ""), u.get("name", ""), u.get("department", ""), st_ or "Serving Notice", _iso(res.get("last_working_day")) or "", res.get("reason", "")])
        return jsonify({"title": "Staff leaving", "columns": ["ID", "Name", "Department", "Status", "Last working day", "Reason"], "rows": rows, "summary": f"{len(rows)} leaving or left"}), 200
    if name == "leave-balances":
        rows = []
        for u in people:
            pr = profs.get(str(u["_id"])) or {}
            doj = _d((pr.get("job") or {}).get("doj") or u.get("doj"))
            ent = leave_entitlement(doj, today)
            taken = sum(max(0, ((_d(l.get("to_date")) or today) - (_d(l.get("from_date")) or today)).days + 1) for l in leaves_col.find(
                {"user_id": str(u["_id"]), "status": "Approved", "type": {"$not": {"$regex": "sick", "$options": "i"}}}) if (_d(l.get("from_date")) or today).year == today.year)
            opening = float((pr.get("leave") or {}).get("opening_annual") or 0)
            rows.append([u.get("employee_code", ""), u.get("name", ""), ent["service_months"], ent["annual_days"], opening, taken, round(ent["annual_days"] + opening - taken, 1)])
        return jsonify({"title": "Leave balances", "columns": ["ID", "Name", "Months of service", "Entitlement", "Opening balance", "Taken this year", "Balance"], "rows": rows,
                        "summary": "Annual leave only. Entitlement follows UAE labour law."}), 200
    if name == "attendance":
        month = request.args.get("month") or today.strftime("%Y-%m")
        counts = {}
        for r in attendance_col.find({"date": {"$regex": f"^{month}"}, "type": "checkin"}):
            counts[r["user_id"]] = counts.get(r["user_id"], 0) + 1
        from helpers import is_weekend_day, get_company_holiday_dates
        hol = get_company_holiday_dates()
        y, mo = int(month[:4]), int(month[5:7])
        workdays = sum(1 for dd in range(1, _cal.monthrange(y, mo)[1] + 1) if date(y, mo, dd) <= today and not is_weekend_day(date(y, mo, dd).isoformat(), hol))
        rows = [[u.get("employee_code", ""), u.get("name", ""), u.get("department", ""), workdays, counts.get(str(u["_id"]), 0), max(0, workdays - counts.get(str(u["_id"]), 0))] for u in people if not is_offboarded(u)]
        return jsonify({"title": f"Attendance summary {month}", "columns": ["ID", "Name", "Department", "Working days so far", "Days present", "Days not present"], "rows": rows,
                        "summary": "Weekly offs and public holidays are not counted."}), 200
    if name == "expiries":
        items = collect_expiries(int(request.args.get("within", 90)))
        return jsonify({"title": "Documents about to expire", "columns": ["Employee", "Department", "What", "Date", "Days left"],
                        "rows": [[i["employee"], i["department"], i["label"], i["date"], i["days"]] for i in items], "summary": f"{len(items)} items within 90 days"}), 200
    return jsonify({"message": "Unknown report"}), 404
