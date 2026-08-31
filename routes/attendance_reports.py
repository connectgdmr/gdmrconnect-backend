"""
routes/attendance_reports.py — GDMR Connect
==============================================
Two PDF report layouts modeled directly on the HR team's existing manual
spreadsheets, so switching to the app doesn't mean losing a familiar format:

  - Monthly Report: one row per employee, one column per day of a chosen
    month, each cell showing that day's status (Present / PL / HD / LOP /
    Not Checked In), a "Total leaves" column, and an employee Status
    column (Confirmed / Probation / Contract / Intern).
  - Master Tracker: one row per employee, one group of four columns
    (Total Working Days / Attended Days / Leaves / Percentage) per month
    of a chosen year, plus a yearly Total Percentage.

Both are built entirely from data already in this app (attendance_col,
leaves_col, holidays_col, users_col) — no new fields were added. Two
things the reference spreadsheets track that this app has no concept of
at all are intentionally NOT reproduced, rather than faked:
  - Sick Leave vs Planned Leave as distinct categories — every approved
    leave here is just "PL", there's no SL split.
  - Work-From-Home (WFH) — not a request type in this app, so it never
    appears; those days fall back to whatever they'd otherwise show
    (Present if checked in, LOP if not).
A leave counts as "approved" for these reports as soon as the employee's
MANAGER has approved it — it doesn't wait for Admin's final sign-off too,
per how HR actually treats it day to day (see _leave_is_approved below).
"""
import calendar
import csv
import io
from datetime import datetime, timezone

from flask import Blueprint, request, send_file

from database import attendance_col, leaves_col, users_col, holidays_col
from decorators import token_required
from helpers import (
    _is_admin, _has_module_grant, is_offboarded, is_weekend_day,
    get_company_holiday_dates, _date_str,
)
from config import IST

bp = Blueprint("attendance_reports", __name__)


def _reports_allowed(user):
    return _is_admin(user) or _has_module_grant(user, "attendance") or _has_module_grant(user, "summary")


def _leave_is_approved(leave):
    """A leave counts as approved for reporting the moment the employee's
    manager has signed off — it doesn't wait for Admin's separate final
    approval too. (Admin-submitted leaves have no manager in the loop at
    all, so those go by the overall status instead.)"""
    return leave.get("manager_status") == "Approved" or leave.get("status") == "Approved"


def _report_employee_status(emp):
    """Confirmed / Probation / Contract / Intern — derived, not stored
    anywhere: Contract/Internship employment_type map straight across,
    everyone else is Probation until their confirmation_date has passed."""
    et = emp.get("employment_type") or "Permanent"
    if et == "Contract":
        return "Contract"
    if et == "Internship":
        return "Intern"
    conf = _date_str(emp.get("confirmation_date"))
    today = str(datetime.now(IST).date())
    return "Confirmed" if conf and conf <= today else "Probation"


def _active_employees():
    rows = list(users_col.find(
        {"role": {"$in": ["employee", "manager"]}},
        {"name": 1, "employee_code": 1, "department": 1, "employment_type": 1,
         "confirmation_date": 1, "doj": 1, "resignation": 1},
    ))
    return [e for e in rows if not is_offboarded(e)]


def _dept_of(emp):
    d = emp.get("department")
    return ", ".join(d) if isinstance(d, list) else (d or "—")


# ── Monthly Report ──────────────────────────────────────────────────────────

def _build_monthly_report_rows(month, year):
    days_in_month = calendar.monthrange(year, month)[1]
    month_str     = f"{year:04d}-{month:02d}"
    today_str     = str(datetime.now(IST).date())
    holiday_dates = get_company_holiday_dates()
    holiday_names = {h["date"]: h.get("name") for h in holidays_col.find(
        {"date": {"$in": list(holiday_dates)}}, {"date": 1, "name": 1}
    )}

    employees = _active_employees()
    uids      = [str(e["_id"]) for e in employees]

    checkins = {}  # {uid: {date_str}}
    for rec in attendance_col.find(
        {"user_id": {"$in": uids}, "type": "checkin", "date": {"$regex": f"^{month_str}"}},
        {"user_id": 1, "date": 1},
    ):
        checkins.setdefault(rec["user_id"], set()).add(rec["date"])

    month_start = f"{month_str}-01"
    month_end   = f"{month_str}-{days_in_month:02d}"
    leaves_by_uid = {}
    for lv in leaves_col.find({
        "user_id": {"$in": uids},
        "from_date": {"$lte": month_end}, "to_date": {"$gte": month_start},
        "status": {"$nin": ["Rejected", "Cancelled"]},
    }):
        if _leave_is_approved(lv):
            leaves_by_uid.setdefault(lv["user_id"], []).append(lv)

    day_headers, dow_headers, day_is_off = [], [], []
    for d in range(1, days_in_month + 1):
        day_str = f"{month_str}-{d:02d}"
        dt = datetime(year, month, d)
        day_headers.append(str(d))
        dow_headers.append(dt.strftime("%a"))
        day_is_off.append(is_weekend_day(day_str, holiday_dates))

    rows = []
    for emp in sorted(employees, key=lambda e: (e.get("name") or "")):
        uid = str(emp["_id"])
        joined = _date_str(emp.get("doj"))
        lwd    = _date_str((emp.get("resignation") or {}).get("last_working_day"))
        emp_checkins = checkins.get(uid, set())
        emp_leaves   = leaves_by_uid.get(uid, [])

        cells = []
        total_leave_days = 0.0
        for d in range(1, days_in_month + 1):
            day_str = f"{month_str}-{d:02d}"
            if day_is_off[d - 1]:
                cells.append(holiday_names.get(day_str, ""))
                continue
            if (joined and day_str < joined) or (lwd and day_str > lwd):
                cells.append("")
                continue
            if day_str in emp_checkins:
                cells.append("Present")
                continue
            leave_today = next((lv for lv in emp_leaves if lv.get("from_date", "") <= day_str <= lv.get("to_date", "")), None)
            if leave_today:
                is_half = leave_today.get("type") == "half"
                total_leave_days += 0.5 if is_half else 1.0
                cells.append("HD" if is_half else "PL")
                continue
            if day_str == today_str:
                cells.append("Not Checked In")
            elif day_str > today_str:
                cells.append("")
            else:
                cells.append("LOP")

        rows.append({
            "employee_code": emp.get("employee_code") or "—",
            "name":          emp.get("name") or "",
            "department":    _dept_of(emp),
            "status":        _report_employee_status(emp),
            "total_leaves":  total_leave_days,
            "cells":         cells,
        })

    return rows, day_headers, dow_headers, day_is_off


def _render_monthly_report_pdf(rows, day_headers, dow_headers, day_is_off, month, year):
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    n_days = len(day_headers)
    # Custom wide page — 31 day columns plus 5 fixed columns needs far more
    # width than any standard sheet size gives; height stays A3-landscape-ish.
    page_w = (34 * 5 + 13 * n_days + 20) * mm
    page_h = 297 * mm
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=(page_w, page_h),
        leftMargin=6 * mm, rightMargin=6 * mm, topMargin=8 * mm, bottomMargin=8 * mm,
    )

    fixed_labels = ["Employee ID", "Employee Name", "Department", "Status", "Total Leaves"]
    fixed_weights = [1.1, 1.8, 1.5, 1.0, 0.9]
    day_weight = 0.55
    weights = fixed_weights + [day_weight] * n_days
    total_weight = sum(weights)
    col_widths = [doc.width * (w / total_weight) for w in weights]

    hdr_style   = ParagraphStyle("hdr", fontSize=6.5, leading=7.5, alignment=1, fontName="Helvetica-Bold")
    cell_style  = ParagraphStyle("cell", fontSize=5.5, leading=6.5, alignment=1)

    row1 = [""] * 5 + [Paragraph(d, hdr_style) for d in day_headers]
    row2 = [Paragraph(l, hdr_style) for l in fixed_labels] + [Paragraph(d, hdr_style) for d in dow_headers]

    STATUS_COLOR = {
        "Present": rl_colors.HexColor("#16a34a"),
        "PL":      rl_colors.HexColor("#d97706"),
        "HD":      rl_colors.HexColor("#d97706"),
        "LOP":     rl_colors.HexColor("#dc2626"),
        "Not Checked In": rl_colors.HexColor("#94a3b8"),
    }
    body_rows = []
    for r in rows:
        row = [
            Paragraph(r["employee_code"], cell_style),
            Paragraph(r["name"], cell_style),
            Paragraph(r["department"], cell_style),
            Paragraph(r["status"], cell_style),
            Paragraph(f'{r["total_leaves"]:g}', cell_style),
        ]
        for c in r["cells"]:
            color = STATUS_COLOR.get(c)
            style = cell_style if not color else ParagraphStyle("cellc", parent=cell_style, textColor=color, fontName="Helvetica-Bold")
            row.append(Paragraph(c, style))
        body_rows.append(row)

    title = Paragraph(f"<b>Monthly Attendance Report — {calendar.month_name[month]} {year}</b>", getSampleStyleSheet()["Heading3"])
    table = Table([row1, row2] + body_rows, colWidths=col_widths, repeatRows=2)

    style = [
        ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",   (0, 0), (-1, -1), 0.3, rl_colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 1), rl_colors.HexColor("#1e293b")),
        ("TEXTCOLOR",  (0, 0), (-1, 1), rl_colors.white),
        ("ROWBACKGROUNDS", (0, 2), (-1, -1), [rl_colors.white, rl_colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 1.5), ("RIGHTPADDING", (0, 0), (-1, -1), 1.5),
        ("SPAN", (0, 0), (0, 1)), ("SPAN", (1, 0), (1, 1)), ("SPAN", (2, 0), (2, 1)),
        ("SPAN", (3, 0), (3, 1)), ("SPAN", (4, 0), (4, 1)),
    ]
    # Weekend/holiday day columns get the same soft-yellow highlight the
    # reference sheet uses, across every row including the header.
    for i, off in enumerate(day_is_off):
        if off:
            col = 5 + i
            style.append(("BACKGROUND", (col, 2), (col, -1), rl_colors.HexColor("#fef9c3")))
    table.setStyle(TableStyle(style))

    doc.build([title, table])
    buf.seek(0)
    return buf


@bp.route("/api/admin/reports/monthly-attendance-pdf", methods=["GET"])
@token_required
def monthly_attendance_pdf():
    if not _reports_allowed(request.user):
        return "Unauthorized", 403
    try:
        month = int(request.args.get("month"))
        year  = int(request.args.get("year"))
    except (TypeError, ValueError):
        return "month (1-12) and year are required", 400
    if not (1 <= month <= 12) or year < 2000:
        return "Invalid month or year", 400

    rows, day_headers, dow_headers, day_is_off = _build_monthly_report_rows(month, year)
    buf = _render_monthly_report_pdf(rows, day_headers, dow_headers, day_is_off, month, year)
    filename = f"Monthly_Attendance_Report_{calendar.month_name[month]}_{year}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)


def _render_monthly_report_csv(rows, day_headers):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Employee ID", "Employee Name", "Department", "Status", "Total Leaves"] + day_headers)
    for r in rows:
        w.writerow([r["employee_code"], r["name"], r["department"], r["status"], f'{r["total_leaves"]:g}'] + r["cells"])
    out = io.BytesIO(buf.getvalue().encode("utf-8-sig"))  # BOM so Excel opens it without mangling names
    out.seek(0)
    return out


@bp.route("/api/admin/reports/monthly-attendance-csv", methods=["GET"])
@token_required
def monthly_attendance_csv():
    if not _reports_allowed(request.user):
        return "Unauthorized", 403
    try:
        month = int(request.args.get("month"))
        year  = int(request.args.get("year"))
    except (TypeError, ValueError):
        return "month (1-12) and year are required", 400
    if not (1 <= month <= 12) or year < 2000:
        return "Invalid month or year", 400

    rows, day_headers, _dow, _off = _build_monthly_report_rows(month, year)
    buf = _render_monthly_report_csv(rows, day_headers)
    filename = f"Monthly_Attendance_Report_{calendar.month_name[month]}_{year}.csv"
    return send_file(buf, mimetype="text/csv", as_attachment=True, download_name=filename)


# ── Master Tracker (yearly) ─────────────────────────────────────────────────

def _month_working_stats(uid, year, month, holiday_dates, leaves_for_emp, joined, lwd):
    """(total_working_days, attended_days, leave_days) for one employee/month."""
    days_in_month = calendar.monthrange(year, month)[1]
    today_str     = str(datetime.now(IST).date())
    month_str     = f"{year:04d}-{month:02d}"

    checkin_dates = {
        rec["date"] for rec in attendance_col.find(
            {"user_id": uid, "type": "checkin", "date": {"$regex": f"^{month_str}"}}, {"date": 1}
        )
    }

    total, attended, leave_days = 0, 0.0, 0.0
    for d in range(1, days_in_month + 1):
        day_str = f"{month_str}-{d:02d}"
        if day_str > today_str:
            continue
        if is_weekend_day(day_str, holiday_dates):
            continue
        if (joined and day_str < joined) or (lwd and day_str > lwd):
            continue
        total += 1
        if day_str in checkin_dates:
            attended += 1
            continue
        leave_today = next((lv for lv in leaves_for_emp if lv.get("from_date", "") <= day_str <= lv.get("to_date", "")), None)
        if leave_today:
            is_half = leave_today.get("type") == "half"
            leave_days += 0.5 if is_half else 1.0
            if is_half:
                attended += 0.5
        # else: LOP — counts toward total (worked-day expected) but not attended

    return total, attended, leave_days


def _build_master_tracker_rows(year):
    holiday_dates = get_company_holiday_dates()
    employees = _active_employees()
    uids      = [str(e["_id"]) for e in employees]

    year_start = f"{year:04d}-01-01"
    year_end   = f"{year:04d}-12-31"
    leaves_by_uid = {}
    for lv in leaves_col.find({
        "user_id": {"$in": uids},
        "from_date": {"$lte": year_end}, "to_date": {"$gte": year_start},
        "status": {"$nin": ["Rejected", "Cancelled"]},
    }):
        if _leave_is_approved(lv):
            leaves_by_uid.setdefault(lv["user_id"], []).append(lv)

    rows = []
    for emp in sorted(employees, key=lambda e: (e.get("name") or "")):
        uid    = str(emp["_id"])
        joined = _date_str(emp.get("doj"))
        lwd    = _date_str((emp.get("resignation") or {}).get("last_working_day"))
        emp_leaves = leaves_by_uid.get(uid, [])

        months = []
        yr_total, yr_attended = 0.0, 0.0
        for m in range(1, 13):
            total, attended, leave_days = _month_working_stats(uid, year, m, holiday_dates, emp_leaves, joined, lwd)
            pct = round(attended / total * 100, 1) if total else None
            months.append({"total": total, "attended": attended, "leaves": leave_days, "pct": pct})
            yr_total += total
            yr_attended += attended

        rows.append({
            "employee_code": emp.get("employee_code") or "—",
            "name":          emp.get("name") or "",
            "department":    _dept_of(emp),
            "months":        months,
            "year_pct":      round(yr_attended / yr_total * 100, 1) if yr_total else None,
        })
    return rows


def _render_master_tracker_pdf(rows, year):
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    sub_labels = ["Total", "Attended", "Leaves", "%"]
    n_months = 12
    page_w = (30 * 3 + 15 * n_months * 4 + 22) * mm
    page_h = 297 * mm
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=(page_w, page_h),
        leftMargin=6 * mm, rightMargin=6 * mm, topMargin=8 * mm, bottomMargin=8 * mm,
    )

    fixed_labels  = ["Employee ID", "Employee Name", "Department"]
    fixed_weights = [1.0, 1.8, 1.5]
    sub_weight    = 0.6
    weights = fixed_weights + [sub_weight] * (n_months * 4) + [1.0]
    total_weight = sum(weights)
    col_widths = [doc.width * (w / total_weight) for w in weights]

    hdr_style  = ParagraphStyle("hdr", fontSize=6, leading=7, alignment=1, fontName="Helvetica-Bold")
    cell_style = ParagraphStyle("cell", fontSize=5.5, leading=6.5, alignment=1)

    row1 = [""] * 3 + sum(([Paragraph(calendar.month_abbr[m], hdr_style)] + [""] * 3 for m in range(1, 13)), []) + [Paragraph("Total %", hdr_style)]
    row2 = [Paragraph(l, hdr_style) for l in fixed_labels] + [Paragraph(l, hdr_style) for _ in range(12) for l in sub_labels] + [""]

    body_rows = []
    for r in rows:
        row = [
            Paragraph(r["employee_code"], cell_style),
            Paragraph(r["name"], cell_style),
            Paragraph(r["department"], cell_style),
        ]
        for mo in r["months"]:
            row.append(Paragraph(f'{mo["total"]:g}' if mo["total"] else "", cell_style))
            row.append(Paragraph(f'{mo["attended"]:g}' if mo["total"] else "", cell_style))
            row.append(Paragraph(f'{mo["leaves"]:g}' if mo["total"] else "", cell_style))
            pct_style = cell_style
            if mo["pct"] is not None and mo["pct"] < 90:
                pct_style = ParagraphStyle("pctlow", parent=cell_style, textColor=rl_colors.HexColor("#dc2626"), fontName="Helvetica-Bold")
            row.append(Paragraph(f'{mo["pct"]}' if mo["pct"] is not None else "", pct_style))
        row.append(Paragraph(f'{r["year_pct"]}' if r["year_pct"] is not None else "", ParagraphStyle("yr", parent=cell_style, fontName="Helvetica-Bold")))
        body_rows.append(row)

    title = Paragraph(f"<b>Attendance Master Tracker — {year}</b>", getSampleStyleSheet()["Heading3"])
    table = Table([row1, row2] + body_rows, colWidths=col_widths, repeatRows=2)

    style = [
        ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",   (0, 0), (-1, -1), 0.3, rl_colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 1), rl_colors.HexColor("#1e293b")),
        ("TEXTCOLOR",  (0, 0), (-1, 1), rl_colors.white),
        ("ROWBACKGROUNDS", (0, 2), (-1, -1), [rl_colors.white, rl_colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 1.5), ("RIGHTPADDING", (0, 0), (-1, -1), 1.5),
        ("SPAN", (0, 0), (0, 1)), ("SPAN", (1, 0), (1, 1)), ("SPAN", (2, 0), (2, 1)),
        ("SPAN", (-1, 0), (-1, 1)),
    ]
    for m in range(12):
        start = 3 + m * 4
        style.append(("SPAN", (start, 0), (start + 3, 0)))
    table.setStyle(TableStyle(style))

    doc.build([title, table])
    buf.seek(0)
    return buf


@bp.route("/api/admin/reports/master-tracker-pdf", methods=["GET"])
@token_required
def master_tracker_pdf():
    if not _reports_allowed(request.user):
        return "Unauthorized", 403
    try:
        year = int(request.args.get("year"))
    except (TypeError, ValueError):
        return "year is required", 400
    if year < 2000:
        return "Invalid year", 400

    rows = _build_master_tracker_rows(year)
    buf  = _render_master_tracker_pdf(rows, year)
    filename = f"Attendance_Master_Tracker_{year}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)


def _render_master_tracker_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    header = ["Employee ID", "Employee Name", "Department"]
    for m in range(1, 13):
        name = calendar.month_abbr[m]
        header += [f"{name} Total", f"{name} Attended", f"{name} Leaves", f"{name} %"]
    header.append("Total %")
    w.writerow(header)
    for r in rows:
        row = [r["employee_code"], r["name"], r["department"]]
        for mo in r["months"]:
            row += [
                f'{mo["total"]:g}' if mo["total"] else "",
                f'{mo["attended"]:g}' if mo["total"] else "",
                f'{mo["leaves"]:g}' if mo["total"] else "",
                mo["pct"] if mo["pct"] is not None else "",
            ]
        row.append(r["year_pct"] if r["year_pct"] is not None else "")
        w.writerow(row)
    out = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    out.seek(0)
    return out


@bp.route("/api/admin/reports/master-tracker-csv", methods=["GET"])
@token_required
def master_tracker_csv():
    if not _reports_allowed(request.user):
        return "Unauthorized", 403
    try:
        year = int(request.args.get("year"))
    except (TypeError, ValueError):
        return "year is required", 400
    if year < 2000:
        return "Invalid year", 400

    rows = _build_master_tracker_rows(year)
    buf  = _render_master_tracker_csv(rows)
    filename = f"Attendance_Master_Tracker_{year}.csv"
    return send_file(buf, mimetype="text/csv", as_attachment=True, download_name=filename)
