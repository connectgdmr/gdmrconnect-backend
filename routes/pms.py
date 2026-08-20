"""
routes/pms.py — GDMR Connect
================================
Performance Management System (PMS 2.0) — templates, submissions,
manager review, calibration, acknowledge, dashboard, export.
"""
import csv
import io
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, send_file
from bson import ObjectId

from database import pms_templates_col, pms_reviews_col, users_col
from decorators import token_required
from helpers import _is_admin, _mgr_depts, _has_module_grant
from config import IST

bp = Blueprint("pms", __name__)


@bp.route("/api/admin/pms-template", methods=["POST"])
@token_required
def save_pms_template():
    # PMSWorkspace.jsx (scope="admin") is what a delegated "pms" grant
    # renders — this whole file predates the Grant Access system and only
    # ever checked real role, so a delegate (role usually "employee") always
    # 403'd here regardless of their grant. Every endpoint below gets the
    # same _has_module_grant(..., "pms") addition for that reason.
    if request.user.get("role") not in ("admin", "owner", "manager") \
            and not _has_module_grant(request.user, "pms", write=True):
        return jsonify({"message": "Unauthorized"}), 403

    data       = request.json
    mgr_id     = str(request.user["_id"])
    is_manager = request.user.get("role") == "manager"

    dept_to_store    = _mgr_depts(request.user) if is_manager else data.get("department", "All")
    assigned_to_list = data.get("assigned_to", [])

    if not assigned_to_list:
        return jsonify({"message": "You must assign the template to at least one employee."}), 400

    template_record = {
        "department": dept_to_store,
        "sessions":   data.get("sessions", []),
        "assigned_to": assigned_to_list,
        "cycle_name": data.get("cycle_name", ""),
        "due_date":   data.get("due_date", ""),
        "created_by": mgr_id,
        "updated_at": datetime.now(timezone.utc),
    }

    upsert_key = {"created_by": mgr_id} if is_manager else {"department": dept_to_store}
    pms_templates_col.update_one(upsert_key, {"$set": template_record}, upsert=True)
    return jsonify({"message": f"PMS Form Assigned to {len(assigned_to_list)} employees successfully!"}), 200


@bp.route("/api/pms-template", methods=["GET"])
@token_required
def get_pms_template():
    uid      = str(request.user["_id"])
    template = pms_templates_col.find_one({"assigned_to": uid})
    if not template:
        return jsonify({"sessions": [], "message": "No active evaluations assigned to you."}), 200

    # Already submitted a self-assessment against this exact template —
    # without this check the assignment (and its now-blank form, since the
    # frontend clears its local answers right after a successful submit)
    # kept showing on the employee's screen forever instead of disappearing
    # once completed.
    already_submitted = pms_reviews_col.find_one(
        {"user_id": uid, "template_id": str(template["_id"])}, {"_id": 1}
    )
    if already_submitted:
        return jsonify({
            "sessions": [], "already_submitted": True,
            "message": "You've already submitted this evaluation — see PMS History below.",
        }), 200

    template.pop("_id", None)
    return jsonify(template), 200


@bp.route("/api/pms/submit", methods=["POST"])
@token_required
def submit_pms_review():
    uid   = str(request.user["_id"])
    data  = request.json
    month = datetime.now(IST).strftime("%Y-%m")

    template   = pms_templates_col.find_one({"assigned_to": uid})
    cycle_name = template.get("cycle_name", "") if template else ""
    owner_id   = template.get("created_by") if template else None
    owner_role = None
    if owner_id:
        try:
            owner_user = users_col.find_one({"_id": ObjectId(owner_id)}, {"role": 1})
            owner_role = owner_user.get("role") if owner_user else None
        except Exception:
            pass
    # A pms_templates_col document can only ever be created via
    # POST /api/admin/pms-template, gated to role admin/owner/manager OR a
    # delegated "pms" write grant — a delegate's real DB role is still
    # "employee" though, so `owner_role` here would read "employee" for a
    # template a delegate built with PMSWorkspace's scope="admin" UI. Any
    # role outside admin/owner/manager reaching this point can only mean
    # that delegate path, so treat it as admin-owned — otherwise
    # get_admin_pms()'s `owner_role in ["admin","owner"]` filter (and this
    # same check re-used for the delegate's own "Reviews" tab, which hits
    # that identical endpoint) never matches and the review is invisible to
    # everyone forever, with no manager anywhere in the loop to "Share with
    # Admin" either.
    if owner_role not in ("admin", "owner", "manager"):
        owner_role = "admin"

    submission = {
        "user_id":                uid,
        "department":             request.user.get("department"),
        "manager_id":             request.user.get("manager_id"),
        "month":                  month,
        "cycle_name":             cycle_name,
        "template_id":            str(template["_id"]) if template else None,
        "owner_id":               owner_id,
        "owner_role":             owner_role,
        "shared_with_admin":      False,
        "shared_with_manager":    False,
        "responses":              data.get("responses", []),
        "status":                 "Pending Review",
        "self_assessment_date":   datetime.now(timezone.utc),
        "manager_review_date":    None,
        "manager_scores":         [],
        "manager_feedback":       "",
        "overall_rating":         None,
        "development_plan":       "",
        "manager_comments":       [],
        "acknowledged_by_employee": False,
    }
    pms_reviews_col.insert_one(submission)
    return jsonify({"message": "Self Assessment Submitted for Manager Review."}), 201


@bp.route("/api/manager/pms", methods=["GET"])
@token_required
def get_manager_pms():
    """
    Fetches all pending and completed PMS reviews for a manager's department.
    Reviews owned by admin/owner (built directly by them, not by this manager)
    are excluded unless admin has explicitly clicked "Share with Manager" —
    otherwise every admin-built review in the department would leak through
    the department filter below.
    """
    if request.user.get("role") not in ("manager", "admin", "owner") \
            and not _has_module_grant(request.user, "pms"):
        return jsonify({"message": "Unauthorized"}), 403

    depts = _mgr_depts(request.user)
    if request.user.get("role") == "manager":
        query = {
            "department": {"$in": depts},
            "$or": [
                {"owner_role": {"$nin": ["admin", "owner"]}},
                {"shared_with_manager": True},
            ],
        }
    else:
        query = {}
    reviews = list(pms_reviews_col.find(query).sort("self_assessment_date", -1))

    uids = []
    for r in reviews:
        try:
            uids.append(ObjectId(r["user_id"]))
        except Exception:
            pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": uids}}, {"name": 1})}

    rows = []
    for r in reviews:
        r["_id"]           = str(r["_id"])
        r["employee_name"] = emp_map.get(r.get("user_id"), "Unknown")
        rows.append(r)
    return jsonify(rows), 200


@bp.route("/api/manager/pms/<review_id>/share", methods=["POST"])
@token_required
def share_pms_with_admin(review_id):
    """
    Marks a manager-owned review as visible on Admin's PMS page. Managers may
    only share reviews in their own department; admin/owner can share (or
    re-share) any review. One-way from this endpoint (no unshare).
    """
    if request.user.get("role") not in ("manager", "admin", "owner") \
            and not _has_module_grant(request.user, "pms", write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        review = pms_reviews_col.find_one({"_id": ObjectId(review_id)})
    except Exception:
        return jsonify({"message": "Invalid review ID"}), 400
    if not review:
        return jsonify({"message": "Review not found"}), 404
    if request.user.get("role") == "manager" and review.get("department") not in _mgr_depts(request.user):
        return jsonify({"message": "Unauthorized — this review isn't in your department."}), 403
    pms_reviews_col.update_one({"_id": ObjectId(review_id)}, {"$set": {"shared_with_admin": True}})
    return jsonify({"message": "Shared with Admin."}), 200


@bp.route("/api/manager/pms/<review_id>/share-with-manager", methods=["POST"])
@token_required
def share_pms_with_manager(review_id):
    """
    Marks an admin/owner-owned review as visible to the employee's department
    manager(s) via GET /api/manager/pms. Admin/owner only. One-way (no unshare).
    """
    if request.user.get("role") not in ("admin", "owner") \
            and not _has_module_grant(request.user, "pms", write=True):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        review = pms_reviews_col.find_one({"_id": ObjectId(review_id)})
    except Exception:
        return jsonify({"message": "Invalid review ID"}), 400
    if not review:
        return jsonify({"message": "Review not found"}), 404
    pms_reviews_col.update_one({"_id": ObjectId(review_id)}, {"$set": {"shared_with_manager": True}})
    return jsonify({"message": "Shared with Manager."}), 200


@bp.route("/api/admin/pms", methods=["GET"])
@token_required
def get_admin_pms():
    """
    Admin's PMS page: every review admin/owner built themselves (always
    visible to them, regardless of shared_with_admin) plus every manager-owned
    review that's been explicitly shared (manager clicked "Share with Admin").
    NOT department-scoped like /api/manager/pms — deliberately org-wide, since
    Admin's page groups by department on the client instead.
    """
    if request.user.get("role") not in ("admin", "owner") \
            and not _has_module_grant(request.user, "pms"):
        return jsonify({"message": "Unauthorized"}), 403

    reviews = list(pms_reviews_col.find({
        "$or": [
            {"shared_with_admin": True},
            {"owner_role": {"$in": ["admin", "owner"]}},
        ]
    }).sort("self_assessment_date", -1))
    uids    = []
    for r in reviews:
        try:
            uids.append(ObjectId(r["user_id"]))
        except Exception:
            pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": uids}}, {"name": 1})}

    rows = []
    for r in reviews:
        r["_id"]           = str(r["_id"])
        r["employee_name"] = emp_map.get(r.get("user_id"), "Unknown")
        rows.append(r)
    return jsonify(rows), 200


@bp.route("/api/manager/pms-calibration", methods=["GET"])
@token_required
def pms_calibration():
    if request.user.get("role") not in ("manager", "admin", "owner") \
            and not _has_module_grant(request.user, "pms"):
        return jsonify({"message": "Unauthorized"}), 403

    month = request.args.get("month", datetime.now(IST).strftime("%Y-%m"))

    if request.user.get("role") == "manager":
        query = {
            "month": month,
            "department": {"$in": _mgr_depts(request.user)},
            "$or": [
                {"owner_role": {"$nin": ["admin", "owner"]}},
                {"shared_with_manager": True},
            ],
        }
    else:
        # Admin/owner calibration is scoped to what's actually visible on their
        # PMS page (own reviews, or manager-shared), same rule as GET /api/admin/pms.
        query = {
            "month": month,
            "$or": [
                {"shared_with_admin": True},
                {"owner_role": {"$in": ["admin", "owner"]}},
            ],
        }

    reviews = list(pms_reviews_col.find(query))
    uids    = []
    for r in reviews:
        try:
            uids.append(ObjectId(r["user_id"]))
        except Exception:
            pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": uids}}, {"name": 1})}

    def _to_num(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    result = []
    for r in reviews:
        self_scores = [_to_num(res.get("self_score")) for res in r.get("responses", []) if _to_num(res.get("self_score")) is not None]
        mgr_scores  = [_to_num(ms.get("score"))       for ms  in r.get("manager_scores", []) if _to_num(ms.get("score")) is not None]
        result.append({
            "employee_name": emp_map.get(r.get("user_id"), "Unknown"),
            "self_avg":      round(sum(self_scores) / len(self_scores), 2) if self_scores else None,
            "manager_avg":   round(sum(mgr_scores)  / len(mgr_scores),  2) if mgr_scores  else None,
            "overall_rating": r.get("overall_rating"),
        })
    return jsonify(result), 200


@bp.route("/api/manager/finalize-pms", methods=["POST"])
@token_required
def finalize_pms_review():
    if request.user.get("role") not in ("manager", "admin", "owner") \
            and not _has_module_grant(request.user, "pms", write=True):
        return jsonify({"message": "Unauthorized"}), 403

    data      = request.json
    review_id = data.get("review_id")
    if not review_id:
        return jsonify({"message": "Review ID missing"}), 400

    overall_rating = data.get("overall_rating")
    VALID_RATINGS  = {"Exceptional", "Exceeds Expectations", "Meets Expectations", "Needs Improvement", "Unsatisfactory"}
    if overall_rating and overall_rating not in VALID_RATINGS:
        return jsonify({"message": f"Invalid overall_rating. Allowed: {', '.join(sorted(VALID_RATINGS))}"}), 400

    try:
        obj = ObjectId(review_id)
    except Exception:
        return jsonify({"message": "Invalid review ID"}), 400

    if request.user.get("role") == "manager":
        review_doc = pms_reviews_col.find_one({"_id": obj}, {"department": 1})
        if not review_doc:
            return jsonify({"message": "Review not found"}), 404
        if review_doc.get("department") not in _mgr_depts(request.user):
            return jsonify({"message": "Unauthorized: review belongs to a different department"}), 403

    try:
        pms_reviews_col.update_one(
            {"_id": obj},
            {"$set": {
                "manager_scores":    data.get("manager_scores", []),
                "manager_feedback":  data.get("manager_feedback", ""),
                "overall_rating":    overall_rating,
                "development_plan":  data.get("development_plan", ""),
                "manager_comments":  data.get("manager_comments", []),
                "status":            "Manager Review Completed",
                "manager_review_date": datetime.now(timezone.utc),
            }},
        )
    except Exception:
        return jsonify({"message": "Invalid review ID"}), 400

    return jsonify({"message": "PMS Evaluation Review Completed successfully!"}), 200


@bp.route("/api/my/pms", methods=["GET"])
@token_required
def my_pms():
    uid  = str(request.user["_id"])
    rows = []
    for p in pms_reviews_col.find({"user_id": uid}).sort("month", -1):
        p["_id"] = str(p["_id"])
        rows.append(p)
    return jsonify(rows), 200


@bp.route("/api/pms/acknowledge", methods=["POST"])
@token_required
def acknowledge_pms_review():
    uid       = str(request.user["_id"])
    data      = request.json
    review_id = data.get("review_id")

    if not review_id:
        return jsonify({"message": "review_id is required"}), 400

    try:
        review = pms_reviews_col.find_one({"_id": ObjectId(review_id)})
    except Exception:
        return jsonify({"message": "Invalid review ID"}), 400

    if not review:
        return jsonify({"message": "Review not found"}), 404
    if review.get("user_id") != uid:
        return jsonify({"message": "Unauthorized. You can only acknowledge your own review."}), 403
    if review.get("status") != "Manager Review Completed":
        return jsonify({"message": "Review has not been finalised by your manager yet."}), 400

    pms_reviews_col.update_one({"_id": ObjectId(review_id)}, {"$set": {"acknowledged_by_employee": True}})
    return jsonify({"message": "Review acknowledged"}), 200


@bp.route("/api/admin/pms-dashboard", methods=["GET"])
@token_required
def pms_dashboard():
    if request.user.get("role") not in ("admin", "owner", "manager") \
            and not _has_module_grant(request.user, "pms"):
        return jsonify({"message": "Unauthorized"}), 403

    month          = request.args.get("month", datetime.now(IST).strftime("%Y-%m"))
    dashboard_data = {}

    if request.user.get("role") == "manager":
        departments = _mgr_depts(request.user)
    else:
        departments = users_col.distinct("department")

    for d in departments:
        if d:
            total_emps = users_col.count_documents({"department": d, "role": "employee"})
            dashboard_data[d] = {"total_employees": total_emps, "completed_pms": 0, "total_score": 0, "avg_score": 0}

    review_query = {"month": month, "status": "Manager Review Completed", "department": {"$in": departments}}
    if request.user.get("role") == "manager":
        review_query["$or"] = [
            {"owner_role": {"$nin": ["admin", "owner"]}},
            {"shared_with_manager": True},
        ]
    else:
        # Admin/owner dashboard is scoped to what's visible on their PMS page.
        review_query["$or"] = [
            {"shared_with_admin": True},
            {"owner_role": {"$in": ["admin", "owner"]}},
        ]

    def _to_num(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0

    for r in pms_reviews_col.find(review_query):
        dept = r.get("department")
        if dept and dept in dashboard_data:
            dashboard_data[dept]["completed_pms"] += 1
            mgr_total = sum(_to_num(ms.get("score", 0)) for ms in r.get("manager_scores", []))
            dashboard_data[dept]["total_score"] += mgr_total

    final_output = []
    for dept, data in dashboard_data.items():
        data["avg_score"] = round(data["total_score"] / data["completed_pms"], 2) if data["completed_pms"] > 0 else 0
        final_output.append({
            "department":    dept,
            "average_score": data["avg_score"],
            "total_employees": data["total_employees"],
            "completed_pms": data["completed_pms"],
        })

    return jsonify(final_output), 200


@bp.route("/api/admin/export-pms", methods=["GET"])
@token_required
def export_pms():
    if request.user.get("role") not in ("admin", "owner", "manager") \
            and not _has_module_grant(request.user, "pms"):
        return jsonify({"message": "Unauthorized"}), 403

    month = request.args.get("month", datetime.now(IST).strftime("%Y-%m"))
    query = {"month": month}
    if request.user.get("role") == "manager":
        query["department"] = {"$in": _mgr_depts(request.user)}
        query["$or"] = [
            {"owner_role": {"$nin": ["admin", "owner"]}},
            {"shared_with_manager": True},
        ]
    else:
        # Admin/owner export is scoped to what's visible on their PMS page.
        query["$or"] = [
            {"shared_with_admin": True},
            {"owner_role": {"$in": ["admin", "owner"]}},
        ]

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Employee Name", "Department", "Month", "Status", "Self Score Total", "Manager Score Total", "Manager Feedback"])

    reviews = list(pms_reviews_col.find(query).sort("department", 1))
    uids    = []
    for r in reviews:
        try:
            uids.append(ObjectId(r["user_id"]))
        except Exception:
            pass
    emp_map = {str(e["_id"]): e["name"] for e in users_col.find({"_id": {"$in": uids}}, {"name": 1})}

    def _to_num(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0

    for r in reviews:
        emp_name  = emp_map.get(r.get("user_id"), "Unknown")
        self_total = sum(_to_num(res.get("self_score", 0)) for res in r.get("responses", []))
        mgr_total  = sum(_to_num(ms.get("score", 0)) for ms in r.get("manager_scores", []))
        cw.writerow([emp_name, r.get("department"), r.get("month"), r.get("status"), self_total, mgr_total, r.get("manager_feedback", "")])

    output = io.BytesIO(si.getvalue().encode("utf-8"))
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name=f"PMS_Report_{month}.csv")
