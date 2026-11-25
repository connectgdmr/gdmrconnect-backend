"""
jobs/work_reports.py — GDMR Connect
=====================================
Department-wise work status emails with an AI-written summary (Groq; falls back to a plain-English summary built
from the numbers if the AI is unavailable):

  morning  (daily, after check-in)  -> admins + owners   : who is in, who has planned, what is planned
  evening  (daily, end of day)      -> admins + owners   : what got done, what is pending and why, who didn't update
  weekly   (Monday, previous week)  -> each department's managers (their department) + owners (all departments)
  monthly  (1st, previous month)    -> each department's managers (their department) + owners (all departments)

Plus two nudges: people who checked in without a plan, and people with a plan but no end-of-day update.
`preview(kind)` builds a report without sending it (used by the admin "preview / send test" endpoint).
"""
import html as _h
import threading
import requests
from datetime import datetime, timedelta, timezone
from bson import ObjectId

from database import users_col, work_plans_col, attendance_col, work_tasks_col, departments_col, leaves_col
from config import IST, OWNER_EMAILS, GROQ_API_KEY, GROQ_MODEL, WORK_REMINDERS
from helpers import _is_task_done, is_offboarded, is_weekend_day, get_company_holiday_dates
from utils import send_email

FRONTEND_NOTE = "Sent automatically by the work-status system."


# ── people / departments ────────────────────────────────────────────────────

def _primary_dept(u):
    d = u.get("department")
    if isinstance(d, list):
        d = next((x for x in d if x), "")
    return (d or "").strip()


def _roster():
    """{department: [user, ...]} of active employees and managers."""
    out = {}
    for u in users_col.find({"role": {"$in": ["employee", "manager"]}}, {"name": 1, "email": 1, "department": 1, "role": 1, "resignation": 1}):
        if is_offboarded(u):
            continue
        d = _primary_dept(u)
        if d:
            out.setdefault(d, []).append(u)
    return out


def _admin_emails(roles=("admin", "owner")):
    seen, emails = set(), []
    for u in users_col.find({"role": {"$in": list(roles)}}, {"email": 1}):
        e = (u.get("email") or "").strip()
        if e and e.lower() not in seen:
            seen.add(e.lower()); emails.append(e)
    for e in OWNER_EMAILS:
        if e.lower() not in seen:
            seen.add(e.lower()); emails.append(e)
    return emails


def _owner_emails():
    return _admin_emails(roles=("owner",))


def _manager_emails(dept):
    seen, emails = set(), []

    def _add(u):
        e = (u.get("email") or "").strip() if u else ""
        if e and e.lower() not in seen:
            seen.add(e.lower()); emails.append(e)
    for u in users_col.find({"role": "manager"}, {"email": 1, "department": 1}):
        ds = u.get("department") if isinstance(u.get("department"), list) else [u.get("department")]
        if dept in [x for x in ds if x]:
            _add(u)
    d = departments_col.find_one({"name": dept}) or {}
    for hid in (d.get("head_ids") or ([d.get("head_id")] if d.get("head_id") else [])):
        try:
            _add(users_col.find_one({"_id": ObjectId(hid)}, {"email": 1}))
        except Exception:
            pass
    return emails


# ── has this person actually updated their work? ─────────────────────────────

def _ist_day(value):
    if not isinstance(value, datetime):
        return ""
    if value.tzinfo is None:                      # Mongo returns naive UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(IST).date().isoformat()


def day_activity(uid, date_str):
    """What `uid` did about work on `date_str`, counting BOTH places work lives (daily plan and Add work / assigned work).
      added    - put work in for the day (submitted a plan, or added a work item that day)
      updated  - posted any update that day (end-of-day update, a status change from My work, or a daily update on a work item)
      has_open - has something that still needs an update (a submitted plan or an open work item assigned to them)"""
    plan = work_plans_col.find_one({"employee_id": uid, "date": date_str}) or {}
    submitted = plan.get("status") == "submitted"
    updated = bool(plan.get("evening_submitted_at")) or _ist_day(plan.get("last_update_at")) == date_str
    added = submitted
    has_open = submitted
    for t in work_tasks_col.find({"$or": [{"assignees.user_id": uid}, {"created_by": uid}]},
                                 {"assignees": 1, "updates": 1, "created_by": 1, "created_at": 1, "status": 1}):
        if t.get("created_by") == uid and _ist_day(t.get("created_at")) == date_str:
            added = True
        if any(u.get("user_id") == uid and u.get("date") == date_str and u.get("type") != "comment" for u in t.get("updates") or []):
            updated = True
        mine = next((a for a in t.get("assignees", []) if a.get("user_id") == uid), None)
        if mine and mine.get("status") != "Completed" and t.get("status") != "Completed":
            has_open = True
    return {"added": added, "updated": updated, "has_open": has_open}


# ── numbers ─────────────────────────────────────────────────────────────────

def _days(start, end, holidays):
    d, out = start, []
    while d <= end:
        if not is_weekend_day(d.isoformat(), holidays):
            out.append(d.isoformat())
        d += timedelta(days=1)
    return out


def collect(start, end, dept_filter=None):
    """Per-department statistics for working days in [start, end] (dates)."""
    holidays = get_company_holiday_dates()
    days = _days(start, end, holidays)
    s_iso, e_iso = start.isoformat(), end.isoformat()
    today_iso = datetime.now(IST).date().isoformat()
    result = []
    for dept, people in sorted(_roster().items()):
        if dept_filter and dept != dept_filter:
            continue
        ids = [str(p["_id"]) for p in people]
        name = {str(p["_id"]): p.get("name", "") for p in people}
        checkins = {(a["user_id"], a["date"]) for a in attendance_col.find({"user_id": {"$in": ids}, "type": "checkin", "date": {"$gte": s_iso, "$lte": e_iso}}, {"user_id": 1, "date": 1})}
        on_leave = set()
        for lv in leaves_col.find({"user_id": {"$in": ids}, "status": "Approved", "from_date": {"$lte": e_iso}, "to_date": {"$gte": s_iso}}, {"user_id": 1}):
            on_leave.add(lv["user_id"])
        plans = list(work_plans_col.find({"employee_id": {"$in": ids}, "date": {"$gte": s_iso, "$lte": e_iso}, "status": "submitted"}))
        total = done = 0
        pending, completed_titles, remarks = [], [], []
        for p in plans:
            for t in p.get("tasks") or []:
                if not str(t.get("title", "")).strip():
                    continue
                total += 1
                rec = {"who": p.get("employee_name", ""), "title": t.get("title", ""), "status": t.get("status", "Pending"), "remarks": t.get("remarks", ""), "date": p.get("date")}
                if _is_task_done(t):
                    done += 1
                    completed_titles.append(rec)
                else:
                    pending.append(rec)
                if rec["remarks"]:
                    remarks.append(rec)
        single = start == end
        present = sorted({name[u] for (u, d) in checkins if d in days}) if single else []
        planned_ids = {p["employee_id"] for p in plans}
        evening_ids = {p["employee_id"] for p in plans if p.get("evening_submitted_at")}
        checked_ids = {u for (u, d) in checkins}
        missing_plan, missing_evening = [], []
        if single:
            acts = {u: day_activity(u, s_iso) for u in checked_ids | planned_ids}
            missing_plan = sorted(name[u] for u in checked_ids if not (acts[u]["added"] or acts[u]["updated"]))
            missing_evening = sorted(name[u] for u, a in acts.items() if (a["added"] or a["has_open"]) and not a["updated"])
        absent = sorted(name[u] for u in set(ids) - checked_ids - on_leave) if single and days else []
        # assigned work touching this department
        at_q = {"assignees.user_id": {"$in": ids}}
        assigned = list(work_tasks_col.find(at_q))
        a_open = [t for t in assigned if t.get("status") != "Completed"]
        a_over = [t for t in a_open if t.get("deadline") and t["deadline"] < today_iso]
        a_done = [t for t in assigned if t.get("status") == "Completed" and s_iso <= (t.get("updated_at").astimezone(IST).date().isoformat() if isinstance(t.get("updated_at"), datetime) else "") <= e_iso]
        a_updates = [(t, u) for t in assigned for u in (t.get("updates") or []) if u.get("user_id") in ids and s_iso <= str(u.get("date")) <= e_iso]
        result.append({
            "dept": dept, "headcount": len(ids), "working_days": len(days), "attendance_days": len({(u, d) for (u, d) in checkins if d in days}),
            "plans": len(plans), "tasks": total, "done": done, "pct": round(done / total * 100) if total else 0,
            "pending": pending, "completed": completed_titles, "remarks": remarks,
            "present": present, "missing_plan": missing_plan, "missing_evening": missing_evening, "absent": absent,
            "evening_updates": len(evening_ids), "assigned_open": len(a_open), "assigned_overdue": [(t["title"], t.get("deadline"), [a["name"] for a in t.get("assignees", [])]) for t in a_over],
            "assigned_done": len(a_done), "assigned_updates": a_updates,
        })
    return result


# ── AI summary ──────────────────────────────────────────────────────────────

def _facts(kind, d):
    lines = [f"Department: {d['dept']} ({d['headcount']} people)"]
    if kind in ("morning",):
        lines += [f"Checked in: {len(d['present'])}/{d['headcount']}", f"Work plans submitted: {d['plans']}", f"Tasks planned: {d['tasks']}"]
        if d["missing_plan"]:
            lines.append("Checked in but no plan yet: " + ", ".join(d["missing_plan"]))
        if d["absent"]:
            lines.append("Not checked in (no approved leave): " + ", ".join(d["absent"]))
        for t in (d["pending"] + d["completed"])[:12]:
            lines.append(f"Planned — {t['who']}: {t['title']}")
    else:
        lines += [f"Working days covered: {d['working_days']}", f"Attendance days: {d['attendance_days']}", f"Tasks: {d['tasks']}, completed {d['done']} ({d['pct']}%)"]
        if kind == "evening" and d["missing_evening"]:
            lines.append("Did not submit end-of-day update: " + ", ".join(d["missing_evening"]))
        for t in d["pending"][:12]:
            lines.append(f"Pending — {t['who']}: {t['title']} [{t['status']}]" + (f" — remark: {t['remarks']}" if t["remarks"] else ""))
        lines.append(f"Assigned work: {d['assigned_open']} open, {len(d['assigned_overdue'])} overdue, {d['assigned_done']} completed in the period")
        for title, dl, who in d["assigned_overdue"][:6]:
            lines.append(f"Overdue — {title} (due {dl}) — {', '.join(who)}")
    return "\n".join(lines)


def _fallback_summary(kind, d):
    if kind == "morning":
        txt = f"{len(d['present'])} of {d['headcount']} people have checked in and {d['plans']} work plan(s) are submitted covering {d['tasks']} task(s)."
        if d["missing_plan"]:
            txt += f" Waiting on a plan from {', '.join(d['missing_plan'])}."
        return txt
    txt = f"{d['done']} of {d['tasks']} planned task(s) are completed ({d['pct']}%)."
    if kind == "evening" and d["missing_evening"]:
        txt += f" No end-of-day update from {', '.join(d['missing_evening'])}."
    if d["assigned_overdue"]:
        txt += f" {len(d['assigned_overdue'])} assigned task(s) are overdue."
    return txt


def ai_summary(kind, d):
    if not GROQ_API_KEY:
        return _fallback_summary(kind, d)
    when = {"morning": "this morning's plan", "evening": "today's progress", "weekly": "last week", "monthly": "last month"}[kind]
    prompt = (f"You write brief management status notes. From the facts below write 2-4 plain sentences about {when} for this department: "
              "what is going well, what is pending or at risk (name people only when they missed something), and one suggested follow-up. "
              "No headings, no bullet points, no invented numbers.\n\n" + _facts(kind, d))
    try:
        r = requests.post("https://api.groq.com/openai/v1/chat/completions",
                          headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                          json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.3, "max_tokens": 220}, timeout=12)
        r.raise_for_status()
        out = r.json()["choices"][0]["message"]["content"].strip()
        return out or _fallback_summary(kind, d)
    except Exception as e:
        print(f"[work_reports] AI summary failed for {d['dept']}: {e}")
        return _fallback_summary(kind, d)


# ── rendering ───────────────────────────────────────────────────────────────

E = _h.escape


def _li(items, limit=8):
    shown = "".join(f"<li>{i}</li>" for i in items[:limit])
    more = f"<li>… and {len(items) - limit} more</li>" if len(items) > limit else ""
    return f"<ul style='margin:4px 0 0 18px;padding:0'>{shown}{more}</ul>" if items else ""


def _section(kind, d, summary):
    stat = lambda label, val: f"<td style='padding:6px 12px;border:1px solid #e5e7eb;text-align:center'><div style='font-size:18px;font-weight:700'>{val}</div><div style='font-size:11px;color:#64748b'>{label}</div></td>"
    if kind == "morning":
        cells = stat("Checked in", f"{len(d['present'])}/{d['headcount']}") + stat("Plans submitted", d["plans"]) + stat("Tasks planned", d["tasks"])
    else:
        cells = stat("Tasks", d["tasks"]) + stat("Completed", f"{d['done']} ({d['pct']}%)") + stat("Assigned open", d["assigned_open"]) + stat("Overdue", len(d["assigned_overdue"]))
    parts = [f"<h3 style='margin:22px 0 6px;color:#0f172a'>{E(d['dept'])}</h3>", f"<p style='margin:0 0 10px;color:#334155;line-height:1.5'>{E(summary)}</p>",
             f"<table style='border-collapse:collapse'><tr>{cells}</tr></table>"]
    flags = []
    if d["missing_plan"]:
        flags.append("<b>Checked in, no plan:</b> " + E(", ".join(d["missing_plan"])))
    if kind == "evening" and d["missing_evening"]:
        flags.append("<b>No end-of-day update:</b> " + E(", ".join(d["missing_evening"])))
    if kind == "morning" and d["absent"]:
        flags.append("<b>Not checked in:</b> " + E(", ".join(d["absent"])))
    for f in flags:
        parts.append(f"<div style='margin-top:8px;padding:8px 10px;background:#fffbeb;border:1px solid #fde68a;border-radius:6px;font-size:13px'>{f}</div>")
    if kind != "morning" and d["pending"]:
        parts.append("<div style='margin-top:10px;font-size:13px'><b>Pending / in progress</b>" + _li(
            [f"{E(t['who'])} — {E(t['title'])} <i>[{E(t['status'])}]</i>" + (f"<br><span style='color:#64748b'>Remark: {E(t['remarks'])}</span>" if t["remarks"] else "") for t in d["pending"]]) + "</div>")
    if kind == "morning" and (d["pending"] or d["completed"]):
        parts.append("<div style='margin-top:10px;font-size:13px'><b>Planned for today</b>" + _li([f"{E(t['who'])} — {E(t['title'])}" for t in d["pending"] + d["completed"]], 12) + "</div>")
    if d["assigned_overdue"]:
        parts.append("<div style='margin-top:10px;font-size:13px'><b style='color:#b91c1c'>Overdue assigned work</b>" + _li(
            [f"{E(t)} — due {E(str(dl))} — {E(', '.join(w))}" for t, dl, w in d["assigned_overdue"]]) + "</div>")
    return "".join(parts)


def _wrap(title, subtitle, body):
    return (f"<div style='font-family:Segoe UI,Arial,sans-serif;max-width:720px;margin:auto;color:#0f172a'>"
            f"<h2 style='margin:0'>{E(title)}</h2><div style='color:#64748b;margin-bottom:6px'>{E(subtitle)}</div>{body}"
            f"<hr style='margin-top:26px;border:none;border-top:1px solid #e5e7eb'><div style='color:#94a3b8;font-size:11px'>{FRONTEND_NOTE}</div></div>")


def _plain(blocks):
    out = []
    for d, s in blocks:
        out.append(f"== {d['dept']} ==\n{s}\n")
    return "\n".join(out)


# ── report builders ─────────────────────────────────────────────────────────

def _build(kind, start, end, dept=None):
    data = collect(start, end, dept)
    if kind == "morning":
        data = [d for d in data if d["headcount"]]
    elif kind == "evening":
        data = [d for d in data if d["attendance_days"] or d["tasks"]]
    blocks = [(d, ai_summary(kind, d)) for d in data]
    label = {"morning": "Morning work status", "evening": "End-of-day work status", "weekly": "Weekly work report", "monthly": "Monthly work report"}[kind]
    rng = start.strftime("%a %d %b %Y") if start == end else f"{start.strftime('%d %b')} – {end.strftime('%d %b %Y')}"
    return label, rng, blocks


def _render(kind, start, end, dept=None):
    label, rng, blocks = _build(kind, start, end, dept)
    title = f"{label} — {dept}" if dept else label
    html = _wrap(title, rng, "".join(_section(kind, d, s) for d, s in blocks) or "<p>No activity recorded.</p>")
    return f"{title} — {rng}", html, _plain(blocks), bool(blocks)


def _mail(to, subject, html, text):
    threading.Thread(target=send_email, args=(to, subject, text), kwargs={"html_body": html}, daemon=True).start()


def _today():
    return datetime.now(IST).date()


def _is_working_day(d):
    return not is_weekend_day(d.isoformat(), get_company_holiday_dates())


def preview(kind, dept=None):
    """(subject, html, text) for the report as it would be sent now — nothing is emailed."""
    s, e = _period(kind)
    subject, html, text, _has = _render(kind, s, e, dept)
    return subject, html, text


def _period(kind):
    t = _today()
    if kind in ("morning", "evening"):
        return t, t
    if kind == "weekly":
        monday = t - timedelta(days=t.weekday())
        return monday - timedelta(days=7), monday - timedelta(days=1)
    first = t.replace(day=1)
    last_prev = first - timedelta(days=1)
    return last_prev.replace(day=1), last_prev


# ── scheduled jobs ──────────────────────────────────────────────────────────

def send_daily_report(kind):
    if not _is_working_day(_today()):
        return
    s, e = _period(kind)
    subject, html, text, has = _render(kind, s, e)
    if not has:
        return
    for to in _admin_emails():
        _mail(to, subject, html, text)
    print(f"[work_reports] {kind} report sent to {len(_admin_emails())} recipient(s)")


def send_morning_report():
    send_daily_report("morning")


def send_evening_report():
    send_daily_report("evening")


def _send_period_report(kind):
    s, e = _period(kind)
    owners = _owner_emails()
    org_html, org_text, any_data = [], [], False
    for dept in sorted(_roster()):
        subject, html, text, has = _render(kind, s, e, dept)
        if not has:
            continue
        any_data = True
        for to in _manager_emails(dept):
            _mail(to, subject, html, text)
        org_html.append(html); org_text.append(text)
    if any_data and owners:
        label, rng, _ = ("Weekly work report" if kind == "weekly" else "Monthly work report"), None, None
        subject = f"{label} — all departments — {s.strftime('%d %b')} to {e.strftime('%d %b %Y')}"
        for to in owners:
            _mail(to, subject, "<hr>".join(org_html), "\n".join(org_text))


def send_weekly_report():
    _send_period_report("weekly")


def send_monthly_report():
    if _today().day == 1:
        _send_period_report("monthly")


def _reminder(kind):
    if not WORK_REMINDERS or not _is_working_day(_today()):
        return
    today = _today().isoformat()
    for dept, people in _roster().items():
        for p in people:
            uid, email = str(p["_id"]), p.get("email")
            if not email or not attendance_col.find_one({"user_id": uid, "type": "checkin", "date": today}):
                continue
            act = day_activity(uid, today)
            # never nag someone who has already put in or updated their work today, wherever they did it
            if kind == "plan" and not (act["added"] or act["updated"]):
                _mail(email, "Reminder: submit today's work plan", f"<p>Hi {E(p.get('name',''))}, you've checked in but haven't submitted today's work plan yet. Please open the Dashboard and submit it.</p>",
                      f"Hi {p.get('name','')}, you've checked in but haven't submitted today's work plan yet. Please open the Dashboard and submit it.")
            if kind == "update" and act["has_open"] and not act["updated"]:
                _mail(email, "Reminder: end-of-day work update before check-out", f"<p>Hi {E(p.get('name',''))}, please update the status and remarks of today's work before you check out (Dashboard → End-of-day update).</p>",
                      f"Hi {p.get('name','')}, please update the status and remarks of today's work before you check out (Dashboard → End-of-day update).")


def send_plan_reminders():
    _reminder("plan")


def send_update_reminders():
    _reminder("update")
