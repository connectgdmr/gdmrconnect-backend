"""
jobs/scheduler.py — GDMR Connect
=====================================
APScheduler background jobs:
  - PMS review reminders          (10:00 AM IST daily)
  - Access-grant expiry sweeper   (every 30 min)
  - Daily work-plan summaries     (11:00 AM IST)
  - Owner HTML daily digest       (11:30 AM IST)
  - Weekly work-plan reports      (Monday 9:00 AM IST)
"""
import threading
import html as _html
from datetime import datetime, timedelta
from bson import ObjectId

from database import (
    users_col, pms_reviews_col, access_grants_col,
    work_plans_col, attendance_col,
)
from config import IST, OWNER_EMAILS
from helpers import _is_task_done, _checkin_map, format_datetime_ist
from utils import send_email


# =============================================================================
# PMS reminders
# =============================================================================

def send_pms_reminders():
    """10 AM IST — email managers about pending PMS reviews."""
    print("Running PMS Reminder Job...")
    pending = list(pms_reviews_col.find({"status": "Pending Review"}))
    manager_map: dict = {}
    for rev in pending:
        mgr_id = rev.get("manager_id")
        if mgr_id:
            manager_map.setdefault(mgr_id, []).append(rev)

    for mgr_id, reviews in manager_map.items():
        try:
            manager = users_col.find_one({"_id": ObjectId(mgr_id)}, {"email": 1, "name": 1})
        except Exception:
            continue
        if not manager or not manager.get("email"):
            continue

        lines = [
            f"Hello {manager.get('name', '')},",
            "",
            f"You have {len(reviews)} PMS review(s) pending:",
            "",
        ]
        for r in reviews:
            lines.append(f"  • {r.get('employee_name', 'Unknown')} — {r.get('period', '')}")
        lines += ["", "Please log in to GDMR Connect to complete the reviews."]
        body = "\n".join(lines)
        try:
            threading.Thread(
                target=send_email,
                args=(manager["email"], f"Pending PMS Reviews — {len(reviews)} action(s) required", body),
                daemon=True
            ).start()
        except Exception as e:
            print(f"PMS reminder email failed for {manager.get('email')}: {e}")


# =============================================================================
# Access grant expiry
# =============================================================================

def auto_expire_grants():
    """Every 30 min — deactivate access grants whose end_date has passed."""
    now_ist = datetime.now(IST)
    today   = str(now_ist.date())
    expired = access_grants_col.find({
        "is_active": True,
        "end_date":  {"$lt": today},
    })
    count = 0
    for grant in expired:
        access_grants_col.update_one(
            {"_id": grant["_id"]},
            {"$set": {"is_active": False}}
        )
        count += 1
    if count:
        print(f"[auto_expire_grants] deactivated {count} expired grant(s).")


# =============================================================================
# Daily work-plan summary for managers
# =============================================================================

def _today_str():
    return str(datetime.now(IST).date())


def send_daily_work_summaries():
    """11 AM IST — email each manager their team's submitted work plans for today."""
    print("Running Daily Work-Plan Summary Job...")
    today = _today_str()

    all_today_plans = list(
        work_plans_col.find({"date": today, "status": "submitted"})
        .sort([("department", 1), ("employee_name", 1)])
    )

    for m in users_col.find({"role": "manager"}, {"name": 1, "email": 1, "department": 1}):
        dept = m.get("department")
        if not dept or not m.get("email"):
            continue

        plans = [p for p in all_today_plans if p.get("department") == dept]
        if not plans:
            continue

        checkins = _checkin_map([p["employee_id"] for p in plans], today)
        lines    = [
            f"Daily Work Plan Summary — {today}",
            f"Department: {dept}",
            f"Submitted plans: {len(plans)}",
            "",
        ]
        for p in plans:
            ci = checkins.get(p["employee_id"]) or "—"
            lines.append(f"• {p.get('employee_name', '')}  (check-in: {ci})")
            for t in p.get("tasks", []):
                done = "✓" if _is_task_done(t) else " "
                lines.append(
                    f"    [{done}] {t.get('title', '')}"
                    f"  | priority: {t.get('priority', '-')}"
                    f"  | est: {t.get('est_time', '-')}"
                    f"  | project: {t.get('project', '-')}"
                )
            if p.get("manager_comment"):
                lines.append(f"    ↳ comment: {p['manager_comment']}")
            lines.append("")

        body = "\n".join(lines)
        try:
            threading.Thread(
                target=send_email,
                args=(m["email"], f"Team Work Plans — {today}", body),
                daemon=True
            ).start()
        except Exception as e:
            print(f"Daily summary email failed for {m.get('email')}: {e}")


# =============================================================================
# Owner daily HTML digest
# =============================================================================

def send_owner_daily_digest():
    """11:30 AM IST — HTML digest to company owners: every submitted plan grouped by department."""
    print("Running Owner Daily Digest Job...")
    today = _today_str()

    plans = list(
        work_plans_col.find({"date": today, "status": "submitted"})
        .sort([("department", 1), ("employee_name", 1)])
    )

    if not plans:
        print("Owner digest: no submitted plans today, skipping.")
        return

    all_uids = [p["employee_id"] for p in plans]
    role_map = {
        str(u["_id"]): u.get("role", "employee").capitalize()
        for u in users_col.find(
            {"_id": {"$in": [ObjectId(uid) for uid in all_uids if uid]}},
            {"role": 1}
        )
    }
    checkins = _checkin_map(all_uids, today)

    by_dept: dict = {}
    for p in plans:
        dept = (p.get("department") or "—").strip()
        by_dept.setdefault(dept, []).append(p)

    txt_lines = [f"Daily Work Updates — {today}", f"Total plans: {len(plans)}", ""]
    for dept, dept_plans in by_dept.items():
        txt_lines.append(f"=== {dept.upper()} ===")
        for p in dept_plans:
            uid  = p["employee_id"]
            role = role_map.get(uid, "Employee")
            ci   = checkins.get(uid) or "not checked in"
            txt_lines.append(f"  {p.get('employee_name', '')} ({role}) · check-in: {ci}")
            for t in p.get("tasks", []):
                done = "✓" if _is_task_done(t) else "○"
                pri  = t.get("priority", "")
                txt_lines.append(f"    {done} {t.get('title', '')}{'  [' + pri + ']' if pri else ''}")
            if p.get("manager_comment"):
                txt_lines.append(f"    ↳ {p['manager_comment']}")
            txt_lines.append("")
        txt_lines.append("")
    plain_body = "\n".join(txt_lines)

    PRIORITY_COLOR = {"High": "#e53e3e", "Medium": "#d97706", "Low": "#16a34a"}
    dept_html_parts = []
    for dept, dept_plans in by_dept.items():
        rows = []
        for p in dept_plans:
            uid  = p["employee_id"]
            role = role_map.get(uid, "Employee")
            ci   = checkins.get(uid) or "not checked in"
            task_items = []
            for t in p.get("tasks", []):
                done  = _is_task_done(t)
                pri   = (t.get("priority") or "").strip()
                color = PRIORITY_COLOR.get(pri, "#6b7280")
                e_pri = _html.escape(pri)
                badge = (
                    f'<span style="background:{color};color:#fff;font-size:10px;'
                    f'padding:1px 6px;border-radius:10px;margin-left:6px;">{e_pri}</span>'
                    if pri else ""
                )
                check   = "✓" if done else "○"
                style   = "color:#16a34a;font-weight:600;" if done else "color:#374151;"
                e_est   = _html.escape(str(t["est_time"])) if t.get("est_time") else ""
                e_proj  = _html.escape(str(t["project"]))  if t.get("project")  else ""
                e_title = _html.escape(t.get("title", ""))
                est     = f'<span style="color:#9ca3af;font-size:11px;"> · {e_est}</span>' if e_est else ""
                proj    = f'<span style="color:#9ca3af;font-size:11px;"> · {e_proj}</span>' if e_proj else ""
                task_items.append(f'<li style="margin:3px 0;{style}">{check} {e_title}{badge}{est}{proj}</li>')
            tasks_html = (
                f'<ul style="margin:6px 0 6px 16px;padding:0;list-style:none;">{"".join(task_items)}</ul>'
                if task_items else ""
            )
            e_comment    = _html.escape(str(p["manager_comment"])) if p.get("manager_comment") else ""
            comment_html = (
                f'<div style="margin:4px 0 0 16px;color:#6b7280;font-size:12px;font-style:italic;">↳ {e_comment}</div>'
                if e_comment else ""
            )
            e_emp_name = _html.escape(p.get("employee_name", ""))
            e_role     = _html.escape(role)
            e_ci       = _html.escape(str(ci))
            rows.append(f"""
            <div style="border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;margin-bottom:10px;background:#fff;">
              <div style="font-weight:600;color:#111827;">{e_emp_name}</div>
              <div style="font-size:12px;color:#6b7280;margin-bottom:6px;">{e_role} · checked in: {e_ci}</div>
              {tasks_html}{comment_html}
            </div>""")

        dept_html_parts.append(f"""
        <div style="margin-bottom:28px;">
          <h3 style="margin:0 0 10px;font-size:13px;font-weight:700;letter-spacing:.08em;
                     color:#fff;background:#1f2937;padding:6px 14px;border-radius:6px;
                     text-transform:uppercase;">{dept}</h3>
          {"".join(rows)}
        </div>""")

    html_body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
             background:#f3f4f6;margin:0;padding:20px;">
  <div style="max-width:640px;margin:0 auto;">
    <div style="background:#1f2937;color:#fff;padding:20px 24px;border-radius:10px 10px 0 0;">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.1em;opacity:.7;">GDMR Foundation</div>
      <h1 style="margin:4px 0 0;font-size:20px;">Daily Work Updates</h1>
      <div style="font-size:13px;opacity:.8;margin-top:4px;">{today} &nbsp;·&nbsp; {len(plans)} plans submitted</div>
    </div>
    <div style="background:#f9fafb;padding:20px 24px;border-radius:0 0 10px 10px;border:1px solid #e5e7eb;border-top:none;">
      {"".join(dept_html_parts)}
    </div>
    <div style="text-align:center;font-size:11px;color:#9ca3af;margin-top:12px;">
      GDMR Connect HRMS &nbsp;·&nbsp; Automated daily digest
    </div>
  </div>
</body></html>"""

    for email in OWNER_EMAILS:
        try:
            threading.Thread(
                target=send_email,
                args=(email, f"Daily Work Updates — {today}", plain_body),
                kwargs={"html_body": html_body},
                daemon=True
            ).start()
        except Exception as e:
            print(f"Owner daily digest failed for {email}: {e}")


# =============================================================================
# Weekly work-plan reports
# =============================================================================

def send_weekly_work_reports():
    """Monday 9 AM IST — weekly productivity report (per-dept to managers, org-wide to admins)."""
    print("Running Weekly Work-Plan Report Job...")
    from datetime import timedelta as _td
    today_date = datetime.now(IST).date()
    start_date = today_date - _td(days=6)
    start_str, today_str = start_date.isoformat(), today_date.isoformat()

    all_plans = list(work_plans_col.find({
        "status": "submitted",
        "date":   {"$gte": start_str, "$lte": today_str}
    }))

    def _report_body(plans, scope_label):
        submitted = sum(len(p.get("tasks", [])) for p in plans)
        completed = sum(1 for p in plans for t in p.get("tasks", []) if _is_task_done(t))
        by_dept, by_emp, by_proj, by_day = {}, {}, {}, {}
        for p in plans:
            d    = p.get("department", "—")
            name = p.get("employee_name", "—")
            by_dept[d]    = by_dept.get(d, 0)    + len(p.get("tasks", []))
            by_emp[name]  = by_emp.get(name, 0)  + len(p.get("tasks", []))
            by_day[p.get("date", "")] = by_day.get(p.get("date", ""), 0) + len(p.get("tasks", []))
            for t in p.get("tasks", []):
                proj = (t.get("project") or "Unassigned").strip() or "Unassigned"
                by_proj[proj] = by_proj.get(proj, 0) + 1

        rate     = round(completed / submitted * 100) if submitted else 0
        top_emps = sorted(by_emp.items(), key=lambda x: x[1], reverse=True)[:5]

        lines = [
            f"Weekly Work Report ({scope_label}) — {start_str} to {today_str}",
            "", f"Tasks submitted: {submitted}", f"Tasks completed: {completed}  ({rate}%)", "",
            "Department activity:",
        ]
        for d, c in sorted(by_dept.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"   {d}: {c} tasks")
        lines += ["", "Most active employees:"]
        for name, c in top_emps:
            lines.append(f"   {name}: {c} tasks")
        lines += ["", "Project allocation:"]
        for proj, c in sorted(by_proj.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"   {proj}: {c} tasks")
        lines += ["", "Daily trend:"]
        cur = start_date
        while cur <= today_date:
            lines.append(f"   {cur.strftime('%a %d')}: {by_day.get(cur.isoformat(), 0)}")
            cur += _td(days=1)
        return "\n".join(lines)

    if all_plans:
        org_body   = _report_body(all_plans, "Organisation")
        recipients = [a["email"] for a in users_col.find({"role": "admin"}, {"email": 1}) if a.get("email")]
        for email in OWNER_EMAILS:
            if email not in recipients:
                recipients.append(email)
        for email in recipients:
            try:
                threading.Thread(target=send_email, args=(email, f"Weekly Work Report — {today_str}", org_body), daemon=True).start()
            except Exception as e:
                print(f"Weekly org report failed for {email}: {e}")

    for m in users_col.find({"role": "manager"}, {"email": 1, "department": 1}):
        dept = m.get("department")
        if not dept or not m.get("email"):
            continue
        dept_plans = [p for p in all_plans if p.get("department") == dept]
        if not dept_plans:
            continue
        body = _report_body(dept_plans, dept)
        try:
            threading.Thread(target=send_email, args=(m["email"], f"Weekly Work Report — {dept} — {today_str}", body), daemon=True).start()
        except Exception as e:
            print(f"Weekly manager report failed for {m.get('email')}: {e}")


# =============================================================================
# Scheduler startup — called from create_app()
# =============================================================================

def start_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler
    try:
        scheduler = BackgroundScheduler(timezone=IST)
        scheduler.add_job(func=send_pms_reminders,       trigger="cron",     hour=10, minute=0)
        scheduler.add_job(func=auto_expire_grants,        trigger="interval", minutes=30)
        scheduler.add_job(func=send_daily_work_summaries, trigger="cron",     hour=11, minute=0)
        scheduler.add_job(func=send_owner_daily_digest,   trigger="cron",     hour=11, minute=30)
        scheduler.add_job(func=send_weekly_work_reports,  trigger="cron",     day_of_week="mon", hour=9, minute=0)
        scheduler.start()
        print("Background Job Scheduler initialized successfully.")
    except Exception as e:
        print(f"Warning: Failed to start background scheduler. Error: {e}")
