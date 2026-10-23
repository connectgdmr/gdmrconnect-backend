"""
seed_demo.py — fill a DEMO database with fake data for a sales demo.

Run it against a SEPARATE database only:

    set MONGO_URI=<atlas uri>
    set MONGO_DB_NAME=aieque_demo
    set DEMO_MODE=1
    set SECRET_KEY=<anything long>
    python tools/seed_demo.py

It refuses to run unless DEMO_MODE=1 and MONGO_DB_NAME is not the production database, and it
WIPES every collection in that database first (so it doubles as the "reset the demo" button).
All people, numbers and clients are invented.
"""
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEMO_PASSWORD = "Demo@12345"
COMPANY = "aieque Trademark Services L.L.C"
DOMAIN = "aieque-demo.com"


def seed(app, db, log=print):
    """Seed `db` (already pointed at the demo database). `app` is the Flask app (used for API-driven parts)."""
    import bcrypt
    import jwt
    from bson import ObjectId
    from config import IST
    from helpers import is_weekend_day

    rnd = random.Random(7)
    now = datetime.now(timezone.utc)
    today = datetime.now(IST).date()
    D = lambda n: (today + timedelta(days=n)).isoformat()

    # ── wipe ──────────────────────────────────────────────────────────────────
    for name in db.list_collection_names():
        if not name.startswith("system."):
            db[name].delete_many({})
    log("wiped demo database")

    # ── people ────────────────────────────────────────────────────────────────
    pw_hash = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt(8)).decode()

    def mk(name, role, dept, position, code=None, doj=None, mgr=None, phone=None, email=None, **kw):
        slug = name.lower().replace(" ", ".")
        u = {
            "name": name, "email": email or f"{slug}@{DOMAIN}", "password": pw_hash, "password_changed": True,
            "role": role, "department": dept, "position": position, "location": "Dubai, UAE",
            "employee_code": code, "doj": doj or D(-rnd.randint(120, 1400)), "phone": phone or f"+971 5{rnd.randint(0, 9)} {rnd.randint(100, 999)} {rnd.randint(1000, 9999)}",
            "shift": "general", "employment_type": "Permanent", "contract_months": None,
            "manager_id": mgr, "created_at": now, "late_checkin_count_monthly": 0, "last_late_checkin_month": None,
            "failed_login_attempts": 0, "locked_until": None, "token_version": 0, **kw,
        }
        u["_id"] = db["users"].insert_one(u).inserted_id
        return u

    admin = mk("Sarah Mitchell", "admin", "Administration", "Managing Director", email=f"admin@{DOMAIN}", doj="2019-03-01")
    mgr_ops = mk("Omar Al Farsi", "manager", "Trademark Operations", "Head of Trademark Operations", "AIQ-002", email=f"manager@{DOMAIN}", doj="2020-02-10")
    mgr_cs = mk("Layla Hassan", "manager", "Client Success", "Client Success Manager", "AIQ-003", doj="2020-09-14")
    mgr_fin = mk("Rahul Menon", "manager", "Finance & Accounts", "Finance Manager", "AIQ-004", doj="2021-01-18")
    mid = lambda u: str(u["_id"])

    staff_spec = [
        ("Aisha Khan", "Trademark Operations", "Trademark Filing Specialist", mgr_ops, "employee"),
        ("Yusuf Rahman", "Trademark Operations", "Trademark Analyst", mgr_ops, None),
        ("Priya Nair", "Trademark Operations", "Docketing Coordinator", mgr_ops, None),
        ("Daniel Foster", "Trademark Operations", "IP Paralegal", mgr_ops, None),
        ("Fatima Al Mansoori", "Trademark Operations", "Trademark Filing Specialist", mgr_ops, None),
        ("Karim Haddad", "Client Success", "Account Executive", mgr_cs, None),
        ("Emma Walker", "Client Success", "Client Onboarding Lead", mgr_cs, None),
        ("Sanjay Pillai", "Client Success", "Client Support Associate", mgr_cs, None),
        ("Noor Siddiqui", "Legal & Compliance", "Compliance Officer", mgr_ops, None),
        ("Marcus Reed", "Legal & Compliance", "Legal Counsel", mgr_ops, None),
        ("Hana Takeda", "Finance & Accounts", "Senior Accountant", mgr_fin, None),
        ("Ibrahim Saleh", "Finance & Accounts", "Accounts Executive", mgr_fin, None),
        ("Meera Joseph", "HR & Admin", "HR Executive", admin, None),
        ("Tariq Aziz", "IT & Systems", "Systems Administrator", admin, None),
    ]
    staff = []
    for i, (name, dept, pos, m, force) in enumerate(staff_spec):
        email = f"employee@{DOMAIN}" if i == 0 else None
        staff.append(mk(name, "employee", dept, pos, f"AIQ-{10 + i:03d}", mgr=mid(m), email=email))
    # one person serving notice, one who has left (shows the exit flow + certificates)
    notice = mk("Victor Alvarez", "employee", "Client Success", "Account Executive", "AIQ-030", mgr=mid(mgr_cs), doj="2022-04-04",
                resignation={"notice_date": D(-12), "last_working_day": D(18), "reason": "Relocating"})
    left = mk("Zainab Qureshi", "employee", "Finance & Accounts", "Accounts Executive", "AIQ-031", mgr=mid(mgr_fin), doj="2021-06-01",
              resignation={"notice_date": D(-60), "last_working_day": D(-10), "reason": "Higher studies"})
    everyone = [mgr_ops, mgr_cs, mgr_fin] + staff + [notice]
    log(f"users: {db['users'].count_documents({})}")

    # ── departments ───────────────────────────────────────────────────────────
    heads = {"Trademark Operations": mgr_ops, "Client Success": mgr_cs, "Finance & Accounts": mgr_fin}
    blurbs = {
        "Trademark Operations": "Searches, filings and prosecution across UAE and GCC registries.",
        "Client Success": "Onboarding, renewals and day-to-day client relationships.",
        "Legal & Compliance": "Opposition, enforcement and regulatory compliance.",
        "Finance & Accounts": "Invoicing, fees, payroll and reporting.",
        "HR & Admin": "People operations, hiring and office administration.",
        "IT & Systems": "Internal systems, security and tooling.",
        "Administration": "Leadership and company administration.",
    }
    for dname, desc in blurbs.items():
        h = heads.get(dname)
        db["departments"].insert_one({"name": dname, "description": desc, "head_ids": [mid(h)] if h else [], "head_id": mid(h) if h else None,
                                      "created_at": now, "updated_at": now})

    # ── holidays (UAE-flavoured) ──────────────────────────────────────────────
    hol = [(-70, "Eid Al Adha"), (-40, "Islamic New Year"), (-5, "Prophet's Birthday"), (38, "Commemoration Day"), (40, "UAE National Day"), (41, "UAE National Day Holiday"), (68, "New Year's Day")]
    hol_dates = set()
    for off, nm in hol:
        ds = D(off)
        hol_dates.add(ds)
        db["holidays"].insert_one({"date": ds, "day": datetime.strptime(ds, "%Y-%m-%d").strftime("%A"), "name": nm})

    # ── leaves first (so attendance skips those days) ─────────────────────────
    leave_days = {}

    def leave(u, start, end, ltype="full", status="Approved", reason="Personal", period="Full Day"):
        approved = status == "Approved"
        mgr_status = "N/A" if u["role"] == "manager" else ("Approved" if status != "Pending" else "Pending")
        db["leaves"].insert_one({
            "user_id": mid(u), "applicant_role": u["role"], "from_date": D(start), "to_date": D(end), "date": D(start),
            "type": ltype, "period": period, "reason": reason, "comp_off": False, "status": status,
            "manager_status": mgr_status, "admin_status": "Approved" if approved else ("Rejected" if status == "Rejected" else "Pending"),
            "applied_at": now - timedelta(days=abs(start) + 3), "attachment_url": None,
        })
        if approved:
            for k in range(start, end + 1):
                leave_days.setdefault(mid(u), set()).add(D(k))

    leave(staff[0], -20, -19, reason="Family event")
    leave(staff[1], -9, -9, reason="Medical appointment")
    leave(staff[2], -33, -31, reason="Annual vacation")
    leave(staff[3], -14, -14, "half", period="Half Day (Afternoon)", reason="Visa appointment")
    leave(staff[5], -25, -24, reason="Travel")
    leave(staff[6], -6, -6, reason="Not feeling well")
    leave(staff[0], 7, 8, status="Pending", reason="Trip to Abu Dhabi")
    leave(staff[4], 12, 14, status="Pending", reason="Family visit")
    leave(staff[7], 3, 3, status="Pending", reason="Bank work")
    leave(staff[9], -4, -3, status="Rejected", reason="Personal")
    leave(mgr_cs, 20, 22, status="Pending", reason="Conference")
    db["comp_off_ledger"].insert_one({"user_id": mid(staff[1]), "days": 1.0, "kind": "grant", "reason": "Worked on a public holiday", "by": mid(mgr_ops),
                                      "by_name": mgr_ops["name"], "created_at": now - timedelta(days=15)})

    # ── 60 days of attendance ─────────────────────────────────────────────────
    def ist_to_utc(d, h, m):
        return datetime(d.year, d.month, d.day, h, m, tzinfo=IST).astimezone(timezone.utc)

    att = []
    for u in everyone:
        uid = mid(u)
        for back in range(60, -1, -1):
            d = today - timedelta(days=back)
            ds = d.isoformat()
            if is_weekend_day(ds, hol_dates) or ds in leave_days.get(uid, set()):
                continue
            if ds < u["doj"]:
                continue
            if back == 0 and u is not staff[0]:
                # today: most people are already in; the demo employee is left to check in live
                pass
            if back == 0 and u is staff[0]:
                continue
            r = rnd.random()
            if r < 0.04:
                att.append({"user_id": uid, "type": "absent", "date": ds, "time": ist_to_utc(d, 11, 0)})
                continue
            late = r > 0.82
            h, m = (10, rnd.randint(1, 14)) if late else (9, rnd.randint(0, 58))
            half = r > 0.97
            att.append({"user_id": uid, "type": "checkin", "date": ds, "day_type": "half-day" if half else "full", "time": ist_to_utc(d, h, m),
                        "photo_url": None, "status_indicator": "Half Day" if half else ("Present (Late)" if late else "Present (On-Time)"),
                        "location": None, "method": "photo"})
            if back > 0 or rnd.random() > 0.9:
                att.append({"user_id": uid, "type": "checkout", "date": ds, "day_type": "half-day" if half else "full", "time": ist_to_utc(d, 18, rnd.randint(0, 40)),
                            "photo_url": None, "status_indicator": "On Time", "location": None, "method": "photo"})
    if att:
        db["attendance"].insert_many(att)
    log(f"attendance rows: {len(att)}")

    # ── announcements, achievements, assets ───────────────────────────────────
    for title, msg, back in [
        ("Welcome to the new ERP", "All HR, attendance, leave, payroll and recruitment activity now lives in one place.", 2),
        ("UAE National Day arrangements", "The office will be closed on 2 and 3 December. Please close any open client deadlines before then.", 6),
        ("Q4 trademark renewal drive", "Client Success and Operations are running a joint renewal campaign. Weekly status every Thursday.", 11),
        ("Reminder: submit your daily work plan", "Please submit your plan before 10:30 so managers can balance the day.", 19),
    ]:
        db["announcements"].insert_one({"title": title, "message": msg, "created_at": now - timedelta(days=back)})
    for who, typ, title, desc, back in [
        (staff[0], "Star Performer", "Filed 40 trademarks in a month", "Highest filing volume with zero office actions.", 12),
        (staff[5], "Client Appreciation", "Renewed three key accounts", "Praised by clients for fast, clear communication.", 24),
        (staff[10], "Process Improvement", "Cut invoice turnaround to 1 day", "Automated fee reconciliation.", 36),
    ]:
        db["achievements"].insert_one({"employee_id": mid(who), "employee_name": who["name"], "type": typ, "title": title, "description": desc,
                                       "month": (today - timedelta(days=back)).strftime("%Y-%m"), "created_at": now - timedelta(days=back)})
    for who, name, reason, mst, ast, st, back in [
        (staff[0], "Dual monitor setup", "Reviewing registry documents side by side", "Approved", "Approved", "Approved", 16),
        (staff[3], "Ergonomic chair", "Back support for long filing sessions", "Approved", "Pending", "Pending", 5),
        (staff[7], "Headset with microphone", "Daily client calls", "Pending", "Pending", "Pending", 2),
        (staff[1], "Laptop — battery replacement", "Battery no longer holds charge", "Approved", "Approved", "Approved", 30),
    ]:
        db["assets"].insert_one({"user_id": mid(who), "employee_name": who["name"], "department": who["department"], "asset_name": name, "reason": reason,
                                 "request_type": "Damage/Service" if "battery" in name else "New Asset", "manager_status": mst, "admin_status": ast,
                                 "status": st, "created_at": now - timedelta(days=back)})

    # ── sticky-note goals for the demo employee ───────────────────────────────
    for title, color, dl, done in [("Finish GCC filing checklist", "yellow", D(5), False), ("Complete trademark law refresher", "blue", D(12), False),
                                   ("Clear backlog of office-action replies", "green", D(-2), True)]:
        db["goals"].insert_one({"user_id": mid(staff[0]), "title": title, "done": done, "done_by": [], "shared_with": [], "color": color, "notes": "",
                                "start_date": D(-7), "deadline": dl, "created_at": now - timedelta(days=7)})

    # ── clients (Aieque's own clients — fictional) ────────────────────────────
    client_names = ["Al Noor Textiles", "Gulf Horizon Foods", "Desert Bloom Cosmetics", "Falcon Logistics", "Pearl Coast Hotels", "Sahara Tech Labs"]
    for cn in client_names:
        try:
            db["clients"].insert_one({"name": cn, "departments": ["Trademark Operations", "Client Success"], "created_at": now, "created_by": mid(admin)})
        except Exception:
            pass

    # ── daily work plans (last 5 working days, a few people) ──────────────────
    work_types = ["Trademark Search", "Filing", "Client Communication", "Renewal", "Documentation", "Review"]
    titles = ["Prepare filing for class 25", "Reply to office action", "Client call — brand strategy", "Renewal reminders batch", "Registry data entry",
              "Conflict search report", "Draft opposition response", "Update docket"]
    for u in staff[:8] + [mgr_ops]:
        for back in range(1, 7):
            d = today - timedelta(days=back)
            if is_weekend_day(d.isoformat(), hol_dates):
                continue
            tasks = []
            for _ in range(rnd.randint(2, 4)):
                tasks.append({"id": os.urandom(6).hex(), "title": rnd.choice(titles), "work_type": rnd.choice(work_types), "priority": rnd.choice(["Low", "Medium", "High"]),
                              "est_time": rnd.choice(["30m", "1h", "2h", "3h"]), "project": "", "client": rnd.choice(client_names),
                              "status": rnd.choice(["Completed", "Completed", "Completed", "In Progress"])})
            db["work_plans"].insert_one({"employee_id": mid(u), "employee_name": u["name"], "department": u["department"], "date": d.isoformat(), "tasks": tasks,
                                         "status": "submitted", "submitted_at": now - timedelta(days=back), "created_at": now - timedelta(days=back),
                                         "updated_at": now - timedelta(days=back), "manager_comment": "Good progress." if rnd.random() > 0.6 else None})

    # ── chat ──────────────────────────────────────────────────────────────────
    def dm(a, b, lines):
        conv = db["conversations"].insert_one({"type": "dm", "name": None, "members": [mid(a), mid(b)], "created_by": mid(a), "last_message": lines[-1][1],
                                               "last_at": now - timedelta(minutes=30), "created_at": now - timedelta(days=2)}).inserted_id
        for i, (who, text) in enumerate(lines):
            db["messages"].insert_one({"conversation_id": str(conv), "sender_id": mid(who), "sender_name": who["name"], "text": text,
                                       "created_at": now - timedelta(minutes=120 - i * 15), "read_by": [mid(who)]})
    dm(staff[0], mgr_ops, [(mgr_ops, "Morning Aisha, can you prioritise the Falcon Logistics filing today?"), (staff[0], "On it — draft will be with you by noon."),
                           (mgr_ops, "Perfect, thanks.")])
    dm(staff[0], admin, [(admin, "Welcome to the new portal. Tell me if anything looks off!"), (staff[0], "Looks great so far.")])

    # ── people-ops via the real API (guarantees correct document shapes) ──────
    def token(u):
        return jwt.encode({"user_id": mid(u), "tv": 0, "exp": now + timedelta(hours=2)}, app.config["SECRET_KEY"], algorithm="HS256")

    cl = app.test_client()
    H = {"Authorization": f"Bearer {token(admin)}"}

    def api(method, path, body=None, who=None):
        h = {"Authorization": f"Bearer {token(who)}"} if who else H
        r = getattr(cl, method)(path, json=body, headers=h)
        if r.status_code >= 400:
            log(f"  ! {method.upper()} {path} -> {r.status_code} {(r.get_json(silent=True) or {}).get('message', '')}")
        return r

    # payroll (AED) — structures, 2 completed months, loans
    for u in everyone + [admin]:
        base = rnd.choice([5500, 6500, 7500, 9000, 11000]) if u["role"] == "employee" else 16000
        api("put", f"/api/admin/payroll/salaries/{mid(u)}", {
            "basic": base, "da": round(base * 0.1), "hra": round(base * 0.4), "travel_allowance": 800, "other_allowance": 500,
            "pf": 0, "esi": 0, "lop": 0, "tds": 0, "other_deductions": 0, "professional_tax": 0, "gratuity": 0, "bonus": 0,
            "designation": u["position"], "employee_code": u.get("employee_code") or "AIQ-001", "days_worked": 26,
            "bank_detail": "Emirates NBD ••••" + str(rnd.randint(1000, 9999)), "transaction_detail": "Complete",
        })
    for back_m in (2, 1):
        y, m = today.year, today.month - back_m
        while m <= 0:
            m += 12
            y -= 1
        api("post", "/api/admin/payroll/run", {"month": m, "year": y})
        for p in db["payslips"].find({"month": m, "year": y}):
            db["payslips"].update_one({"_id": p["_id"]}, {"$set": {"status": "Paid", "paid_at": now - timedelta(days=back_m * 28)}})
    api("post", "/api/admin/payroll/loans", {"employee_id": mid(staff[1]), "type": "advance", "amount": 3000, "emi_per_month": 1000, "repayment_months": 3,
                                            "disbursed_date": D(-20), "reason": "Relocation advance"})

    # jobs + ATS pipeline
    jobs = [
        ("Trademark Attorney", "Legal & Compliance", "Dubai, UAE", 14000, 22000),
        ("Client Success Executive", "Client Success", "Dubai, UAE", 7000, 10000),
        ("Docketing Specialist", "Trademark Operations", "Abu Dhabi, UAE", 6000, 8500),
    ]
    for t, dpt, loc, lo, hi in jobs:
        api("post", "/api/admin/career/jobs", {"title": t, "department": dpt, "location": loc, "employment_type": "Full-time", "salary_min": lo, "salary_max": hi,
                                               "salary_visible": True, "referral_open": True, "status": "active",
                                               "description": f"Join our {dpt} team to protect clients' brands across the GCC.",
                                               "requirements": ["2+ years relevant experience", "Strong written English", "Attention to detail"]})
    people = [("Amira Zaki", "Trademark Attorney", "Shortlisted"), ("Jonathan Pierce", "Trademark Attorney", "Technical Interview"),
              ("Lina Saab", "Client Success Executive", "HR Interview"), ("Rohit Verma", "Client Success Executive", "Resume Screening"),
              ("Mariam Yusuf", "Docketing Specialist", "New Application"), ("Chris Dalton", "Docketing Specialist", "Screening Call Scheduled"),
              ("Salma Idris", "Trademark Attorney", "Offer Discussion"), ("Pooja Shah", "Client Success Executive", "New Application"),
              ("Ahmed Barakat", "Docketing Specialist", "Resume Screening"), ("Nadia Rahim", "Trademark Attorney", "New Application")]
    for i, (n, role, status) in enumerate(people):
        r = api("post", "/api/admin/ats/candidates", {"name": n, "email": f"{n.lower().replace(' ', '.')}@mailbox-demo.com", "phone": f"05{rnd.randint(0, 9)}{rnd.randint(1000000, 9999999)}",
                                                      "job_role": role, "department": role, "source": rnd.choice(["LinkedIn", "Referral", "Website", "Indeed"]),
                                                      "experience": rnd.randint(1, 9), "skills": ["Trademarks", "IP law", "Client service"],
                                                      "current_company": rnd.choice(["Gulf IP Partners", "Falcon Legal", "Crescent Advisory"]), "current_location": "Dubai"})
        j = r.get_json(silent=True) or {}
        cid = j.get("_id") or j.get("id")
        if cid and status != "New Application":
            db["ats_candidates"].update_one({"_id": ObjectId(cid)}, {"$set": {"status": status},
                                            "$push": {"status_history": {"status": status, "at": now - timedelta(days=rnd.randint(1, 9)), "by": mid(admin)}}})

    # learning course
    api("post", "/api/admin/lms/courses", {"title": "Trademark Law Essentials (UAE & GCC)", "description": "Registration, opposition and renewal basics.",
                                           "category": "Compliance", "course_code": "TM-101",
                                           "modules": [{"title": "Fundamentals", "lessons": [{"title": "What is a trademark?", "type": "text", "content": "Overview"},
                                                                                              {"title": "Classes of goods and services", "type": "text", "content": "Nice classification"}]}]})
    # PMS form
    api("post", "/api/admin/pms-template", {"department": "All", "cycle_name": "Q4 Performance Review", "due_date": D(20), "recurring": False,
                                             "assigned_to": [mid(u) for u in staff[:6]],
                                             "sessions": [{"name": "Delivery", "weight": 50, "questions": [{"text": "Quality of work delivered", "type": "scale"},
                                                                                                           {"text": "Meets deadlines consistently", "type": "scale"}]},
                                                          {"name": "Collaboration", "weight": 50, "questions": [{"text": "Communicates clearly with the team", "type": "scale"}]}]})

    log("demo data ready")
    return {"admin": admin, "manager": mgr_ops, "employee": staff[0]}


def main():
    from config import DEMO_MODE, MONGO_DB_NAME
    if not DEMO_MODE:
        sys.exit("Refusing to run: set DEMO_MODE=1 (this script wipes the database it points at).")
    if MONGO_DB_NAME == "attendance_db":
        sys.exit("Refusing to run: MONGO_DB_NAME must be a separate demo database, never attendance_db.")
    import app_new
    seed(app_new.app, app_new.db)
    print(f"\nDone. Logins (password {DEMO_PASSWORD}):\n  admin@{DOMAIN}\n  manager@{DOMAIN}\n  employee@{DOMAIN}")


if __name__ == "__main__":
    main()
