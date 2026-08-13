"""
routes/leaves.py — GDMR Connect
==================================
Leave management: apply, admin/manager view, update status, employee history.
"""
import html as _html
import threading
import traceback
import cloudinary.uploader
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database import leaves_col, users_col
from decorators import token_required
from helpers import _is_admin, _has_module_grant
from config import IST, HR_EMAIL, DASHBOARD_URL
from utils import send_email

bp = Blueprint("leaves", __name__)


def _send_leave_notification(leave_doc: dict, employee: dict):
    """Build and send a leave-request notification email to the manager and HR.
    Runs inside a background daemon thread; logs every step so failures are diagnosable."""
    print("[leave-notify] thread started")
    try:
        emp_name    = employee.get("name", "Employee")
        department  = employee.get("department", "")
        designation = employee.get("position", "")
        emp_email   = employee.get("email", "")

        from_date  = leave_doc.get("from_date", "")
        to_date    = leave_doc.get("to_date", "")
        leave_type = leave_doc.get("type", "") or ""
        period     = leave_doc.get("period", "") or ""
        reason     = leave_doc.get("reason", "Not provided")
        att_url    = leave_doc.get("attachment_url")
        applied_at = leave_doc.get("applied_at")

        def _fmt(ds):
            try:
                d = datetime.strptime(str(ds)[:10], "%Y-%m-%d")
                return f"{d.day} {d.strftime('%b')} {d.year}"
            except Exception:
                return str(ds or "")

        from_str = _fmt(from_date)
        to_str   = _fmt(to_date)

        try:
            f_d   = datetime.strptime(str(from_date)[:10], "%Y-%m-%d").date()
            t_d   = datetime.strptime(str(to_date)[:10],   "%Y-%m-%d").date()
            delta = (t_d - f_d).days + 1
        except Exception:
            delta = 1

        is_half = leave_type == "half" or ("half" in period.lower())
        if is_half:
            day_count_str = "0.5 days (Half Day)"
        elif delta == 1:
            day_count_str = "1 day"
        else:
            day_count_str = f"{delta} days"

        if isinstance(applied_at, datetime):
            _applied    = applied_at.astimezone(IST)
            applied_str = (f"{_applied.day} {_applied.strftime('%b')} {_applied.year}, "
                           f"{_applied.strftime('%I:%M %p')} IST")
        else:
            applied_str = str(applied_at or "")

        # Leaves this employee applied in the current calendar month
        monthly_leave_count = 0
        monthly_breakdown   = ""
        try:
            emp_uid_str = str(employee.get("_id", ""))
            now_utc     = datetime.now(timezone.utc)
            month_start = now_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            status_counts = {
                r["_id"]: r["n"]
                for r in leaves_col.aggregate([
                    {"$match": {"user_id": emp_uid_str, "applied_at": {"$gte": month_start}}},
                    {"$group": {"_id": "$status", "n": {"$sum": 1}}},
                ])
            }
            monthly_leave_count = sum(status_counts.values())
            parts = []
            if status_counts.get("Approved"): parts.append(f"{status_counts['Approved']} Approved")
            if status_counts.get("Pending"):  parts.append(f"{status_counts['Pending']} Pending")
            if status_counts.get("Rejected"): parts.append(f"{status_counts['Rejected']} Rejected")
            monthly_breakdown = " · ".join(parts) if parts else ""
        except Exception:
            pass

        monthly_detail = (f"{monthly_leave_count} applied · {monthly_breakdown}"
                          if monthly_breakdown else str(monthly_leave_count))

        # Resolve manager
        manager_email = None
        manager_id    = employee.get("manager_id")
        print(f"[leave-notify] employee={emp_name!r} manager_id={manager_id!r} dept={department!r}")
        if manager_id:
            try:
                mgr = users_col.find_one({"_id": ObjectId(str(manager_id))}, {"email": 1})
                if mgr:
                    manager_email = mgr.get("email")
                    print(f"[leave-notify] manager found by id: {manager_email!r}")
            except Exception as mgr_exc:
                print(f"[leave-notify] manager lookup error: {mgr_exc}")

        if not manager_email and department:
            try:
                dept_mgr = users_col.find_one({"role": "manager", "department": department}, {"email": 1})
                if dept_mgr:
                    manager_email = dept_mgr.get("email")
                    print(f"[leave-notify] manager found by dept: {manager_email!r}")
            except Exception as dept_exc:
                print(f"[leave-notify] dept manager lookup error: {dept_exc}")

        to_email = manager_email or HR_EMAIL
        cc_list  = [HR_EMAIL] if manager_email and manager_email.lower() != HR_EMAIL.lower() else []
        reply_to = emp_email or None
        print(f"[leave-notify] to={to_email!r} cc={cc_list!r} reply_to={reply_to!r}")

        subject = f"Leave Request — {emp_name} ({leave_type.title()}, {from_str} to {to_str})"

        e_name  = _html.escape(emp_name)
        e_dept  = _html.escape(department)
        e_desig = _html.escape(designation)
        e_type  = _html.escape(leave_type.title())
        e_rsn   = _html.escape(str(reason))

        att_row = (
            f'<tr><td style="padding:8px 0;color:#94a3b8;width:140px">Attachment</td>'
            f'<td style="padding:8px 0"><a href="{_html.escape(att_url)}" style="color:#34a06a">View document</a></td></tr>'
            if att_url else ""
        )

        html_body = f"""
<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:auto;border:1px solid #e6eaef;border-radius:12px;overflow:hidden">
  <div style="background:#34a06a;color:#fff;padding:18px 24px">
    <h2 style="margin:0;font-size:18px">GDMR Connect — New Leave Request</h2>
  </div>
  <div style="padding:24px;color:#0f172a">
    <p style="margin:0 0 16px;font-size:14px;color:#475569">A new leave request has been submitted and requires your review.</p>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <tr><td style="padding:8px 0;color:#94a3b8;width:140px">Employee</td><td style="padding:8px 0;font-weight:600">{e_name}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8">Department</td><td style="padding:8px 0">{e_dept}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8">Designation</td><td style="padding:8px 0">{e_desig}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8">Leave Type</td><td style="padding:8px 0">{e_type}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8">From</td><td style="padding:8px 0">{from_str}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8">To</td><td style="padding:8px 0">{to_str}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8">Total Days</td><td style="padding:8px 0">{day_count_str}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8;vertical-align:top">Reason</td><td style="padding:8px 0">{e_rsn}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8">Applied On</td><td style="padding:8px 0">{applied_str}</td></tr>
      <tr><td style="padding:8px 0;color:#94a3b8">Leaves This Month</td><td style="padding:8px 0;font-weight:600">{monthly_detail}</td></tr>
      {att_row}
    </table>
    <a href="{DASHBOARD_URL}" style="display:inline-block;margin-top:22px;background:#34a06a;color:#fff;text-decoration:none;padding:11px 22px;border-radius:8px;font-weight:600;font-size:14px">Review in Dashboard</a>
  </div>
  <div style="background:#f8fafc;padding:14px 24px;font-size:12px;color:#94a3b8;text-align:center">
    This is an automated message from GDMR Connect HRMS. Do not reply directly to this email.
  </div>
</div>"""

        plain = (
            f"New Leave Request — {emp_name}\n\n"
            f"Employee:    {emp_name}\n"
            f"Department:  {department}\n"
            f"Designation: {designation}\n"
            f"Leave Type:  {leave_type.title()}\n"
            f"From:        {from_str}\n"
            f"To:          {to_str}\n"
            f"Total Days:  {day_count_str}\n"
            f"Reason:      {reason}\n"
            f"Applied On:  {applied_str}\n"
            f"Leaves This Month: {monthly_detail}\n"
            + (f"Attachment:  {att_url}\n" if att_url else "")
            + f"\nReview at: {DASHBOARD_URL}"
        )

        print(f"[leave-notify] calling send_email subject={subject!r}")
        ok = send_email(to_email=to_email, subject=subject, body=plain,
                        html_body=html_body, cc_emails=cc_list, reply_to=reply_to)
        print(f"[leave-notify] send_email returned {ok}")

        # Also notify all Business Owners
        try:
            owners = list(users_col.find({"role": "owner"}, {"email": 1, "name": 1}))
            for owner in owners:
                owner_email = owner.get("email")
                if not owner_email or owner_email.lower() == to_email.lower():
                    continue
                ok_o = send_email(to_email=owner_email, subject=subject, body=plain,
                                  html_body=html_body, reply_to=reply_to)
                print(f"[leave-notify] owner notified {owner_email!r}: {ok_o}")
        except Exception as owner_exc:
            print(f"[leave-notify] owner notify error: {owner_exc}")

    except Exception as exc:
        print(f"[leave-notify] EXCEPTION: {exc}\n{traceback.format_exc()}")


@bp.route("/api/leaves", methods=["POST"])
@token_required
def apply_leave():
    if request.user.get("role") not in ["employee", "manager"]:
        return jsonify({"message": "Unauthorized"}), 403

    from_date = request.form.get("from_date")
    to_date   = request.form.get("to_date")

    if not from_date and request.form.get("date"):
        from_date = request.form.get("date")
        to_date   = request.form.get("date")

    leave_type = request.form.get("type", "full")
    period     = request.form.get("period")
    reason     = request.form.get("reason", "")

    if not from_date or not to_date:
        return jsonify({"message": "Start and End dates are required"}), 400

    try:
        f_date = datetime.strptime(from_date, "%Y-%m-%d").date()
        t_date = datetime.strptime(to_date,   "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"message": "Invalid date format."}), 400

    if t_date < f_date:
        return jsonify({"message": "End date cannot be before start date"}), 400

    now_ist_date  = datetime.now(IST).date()
    max_past_date = now_ist_date - timedelta(days=7)
    if f_date < max_past_date:
        return jsonify({"message": "Leave application for past dates is limited to 7 days."}), 400

    # Block duplicate/overlapping leave requests for the same employee.
    # The one legitimate way two records can share a date is a half-day
    # "First Half" leave paired with a half-day "Second Half" leave on
    # that exact same single day — everything else that overlaps an
    # existing Pending/Approved request is rejected.
    uid = str(request.user["_id"])
    existing = leaves_col.find(
        {
            "user_id":   uid,
            "status":    {"$in": ["Pending", "Approved"]},
            "from_date": {"$lte": to_date},
            "to_date":   {"$gte": from_date},
        },
        {"from_date": 1, "to_date": 1, "type": 1, "period": 1, "status": 1},
    )
    for ex in existing:
        same_single_day = (
            from_date == to_date
            and ex.get("from_date") == ex.get("to_date") == from_date
        )
        distinct_half_day_pair = (
            same_single_day
            and leave_type == "half" and ex.get("type") == "half"
            and period and ex.get("period")
            and period != ex.get("period")
        )
        if distinct_half_day_pair:
            continue
        return jsonify({
            "message": f"You already have a {ex.get('status', 'Pending').lower()} leave request covering "
                       f"{ex.get('from_date')}"
                       f"{' to ' + ex.get('to_date') if ex.get('to_date') != ex.get('from_date') else ''}."
        }), 409

    attachment_url = None
    file = request.files.get("attachment")
    if file:
        try:
            upload_result  = cloudinary.uploader.upload(file, folder="leave_attachments")
            attachment_url = upload_result.get("secure_url")
        except Exception:
            return jsonify({"message": "File upload failed"}), 500

    leave = {
        "user_id":       str(request.user["_id"]),
        "from_date":     from_date,
        "to_date":       to_date,
        "date":          from_date,
        "type":          leave_type,
        "period":        period,
        "reason":        reason,
        "status":        "Pending",
        "manager_status": "Pending",
        "admin_status":  "Pending",
        "applied_at":    datetime.now(timezone.utc),
        "attachment_url": attachment_url,
    }

    res = leaves_col.insert_one(leave)
    threading.Thread(target=_send_leave_notification,
                     args=(leave, dict(request.user)), daemon=True).start()
    return jsonify({"message": "Applied", "id": str(res.inserted_id)}), 201


@bp.route("/api/admin/leaves", methods=["GET"])
@token_required
def admin_view_leaves():
    role = request.user.get("role")
    # A read-only "Attendance" grant needs this too — the Attendance page's
    # "On Leave Today" stat and its detail modal both call this endpoint.
    # Writes (approve/reject in update_leave below) stay gated to "leaves" only.
    has_delegated = _has_module_grant(request.user, "leaves") or _has_module_grant(request.user, "attendance")
    if role not in ["admin", "owner", "manager"] and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    query = {}
    if role == "manager" and not has_delegated:
        mgr_id         = str(request.user["_id"])
        managed_users  = [str(u["_id"]) for u in users_col.find({"manager_id": mgr_id}, {"_id": 1})]
        query          = {"user_id": {"$in": managed_users}}

    employees = {str(e["_id"]): e for e in users_col.find({}, {"name": 1, "department": 1})}
    rows = []
    for l in leaves_col.find(query).sort("applied_at", -1):
        l["_id"]  = str(l["_id"])
        user      = employees.get(l.get("user_id"))
        if user:
            l["employee_name"]       = user["name"]
            l["employee_department"] = user.get("department")
        else:
            l["employee_name"]       = "Unknown"
            l["employee_department"] = ""
        l["applied_at_str"] = l["applied_at"].strftime("%Y-%m-%d") if l.get("applied_at") else l.get("date")
        rows.append(l)
    return jsonify(rows), 200


@bp.route("/api/admin/leaves/<leave_id>", methods=["PUT"])
@token_required
def update_leave(leave_id):
    role          = request.user.get("role")
    has_delegated = _has_module_grant(request.user, "leaves")
    if role not in ["admin", "owner", "manager"] and not has_delegated:
        return jsonify({"message": "Unauthorized"}), 403

    data   = request.json
    action = data.get("status")
    if action not in ("Approved", "Rejected", "Pending"):
        return jsonify({"message": "Invalid status"}), 400

    update_fields = {}
    if role in ("admin", "owner"):
        update_fields["admin_status"] = action
    elif has_delegated:
        if not _has_module_grant(request.user, "leaves", write=True):
            return jsonify({"message": "Unauthorized: Your delegated access is View Only."}), 403
        update_fields["admin_status"] = action
    elif role == "manager":
        leave_doc  = leaves_col.find_one({"_id": ObjectId(leave_id)}, {"user_id": 1})
        if not leave_doc:
            return jsonify({"message": "Leave not found"}), 404
        leave_owner = users_col.find_one({"_id": ObjectId(leave_doc["user_id"])}, {"manager_id": 1})
        if not leave_owner or str(leave_owner.get("manager_id")) != str(request.user["_id"]):
            return jsonify({"message": "Unauthorized: employee is not in your team"}), 403
        update_fields["manager_status"] = action

    leaves_col.update_one({"_id": ObjectId(leave_id)}, {"$set": update_fields})

    leave = leaves_col.find_one({"_id": ObjectId(leave_id)})
    ms    = leave.get("manager_status", "Pending")
    as_   = leave.get("admin_status",   "Pending")

    if ms == "Rejected" or as_ == "Rejected":
        final_status = "Rejected"
    elif ms == "Approved" and as_ == "Approved":
        final_status = "Approved"
    else:
        final_status = "Pending"

    leaves_col.update_one({"_id": ObjectId(leave_id)}, {"$set": {"status": final_status}})

    try:
        user = users_col.find_one({"_id": ObjectId(leave["user_id"])})
        if user:
            threading.Thread(target=send_email,
                             args=(user["email"], "Leave Update", f"Your leave status is now: {final_status}"),
                             daemon=True).start()
    except Exception as e:
        print("Email notification error:", e)

    return jsonify({"message": "Leave updated successfully"}), 200


@bp.route("/api/leaves/<leave_id>/revoke", methods=["POST"])
@token_required
def revoke_leave(leave_id):
    """
    Cancels a leave request. Allowed for:
      - the employee who applied for it (their own leave, any status except
        already Rejected/Cancelled)
      - that employee's manager
      - admin/owner
    Sets status straight to "Cancelled" — manager_status/admin_status are left
    untouched as an audit trail of whatever approval state it was in.
    """
    try:
        obj = ObjectId(leave_id)
    except Exception:
        return jsonify({"message": "Invalid leave ID"}), 400

    leave = leaves_col.find_one({"_id": obj})
    if not leave:
        return jsonify({"message": "Leave not found"}), 404

    role = request.user.get("role")
    uid  = str(request.user["_id"])
    is_owner = leave.get("user_id") == uid

    allowed = False
    if is_owner:
        allowed = True
    elif role in ("admin", "owner"):
        allowed = True
    elif role == "manager":
        leave_owner = users_col.find_one({"_id": ObjectId(leave["user_id"])}, {"manager_id": 1})
        if leave_owner and str(leave_owner.get("manager_id")) == uid:
            allowed = True

    if not allowed:
        return jsonify({"message": "Unauthorized"}), 403

    if leave.get("status") in ("Cancelled", "Rejected"):
        return jsonify({"message": f"Leave is already {leave['status']}."}), 400

    leaves_col.update_one({"_id": obj}, {"$set": {
        "status":            "Cancelled",
        "cancelled_at":      datetime.now(timezone.utc),
        "cancelled_by_role": role,
    }})

    if not is_owner:
        try:
            emp = users_col.find_one({"_id": ObjectId(leave["user_id"])}, {"email": 1})
            if emp and emp.get("email"):
                threading.Thread(
                    target=send_email,
                    args=(emp["email"], "Leave Revoked",
                          f"Your leave request ({leave.get('from_date', '')} to {leave.get('to_date', '')}) "
                          f"has been revoked by your {role}."),
                    daemon=True,
                ).start()
        except Exception as e:
            print("Revoke email notification error:", e)

    return jsonify({"message": "Leave revoked."}), 200


@bp.route("/api/my/leaves", methods=["GET"])
@token_required
def my_leaves():
    uid  = str(request.user["_id"])
    rows = []
    for l in leaves_col.find({"user_id": uid}).sort("applied_at", -1):
        l["_id"] = str(l["_id"])
        rows.append(l)
    return jsonify(rows), 200
