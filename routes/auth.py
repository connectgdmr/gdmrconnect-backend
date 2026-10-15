"""
routes/auth.py — GDMR Connect
================================
Authentication routes: login (with optional two-step verification), password
reset by emailed link, change password, "log out everywhere", admin force-logout.

Security notes
--------------
* Failed logins are counted per EMAIL in login_throttle for every email typed,
  existing or not, so a lock-out looks identical for real and made-up accounts.
* "Forgot password" never changes the password. It emails a single-use link that
  expires in 30 minutes; only opening it and choosing a new password changes it.
* Tokens carry a token_version. Bumping it on the user (password change/reset,
  log-out-everywhere, admin force-logout, MFA disable) revokes every older token.
"""
import hashlib
import hmac
import secrets
import jwt
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from flask import Blueprint, request, jsonify, current_app
from flask_limiter.util import get_remote_address

from config import DASHBOARD_URL, REQUIRE_ADMIN_MFA
from database import users_col, login_throttle_col, password_resets_col
from decorators import token_required
from extensions import bcrypt, limiter
from helpers import _sanitize, _valid_email, is_strong_password, is_offboarded, _is_admin
from utils import send_email

bp = Blueprint("auth", __name__)

LOCK_AFTER      = 5     # wrong passwords before a temporary lock
LOCK_MINUTES    = 15
TOKEN_HOURS     = 4
RESET_MINUTES   = 30
_GENERIC_FAIL   = {"message": "Incorrect email or password."}


# ── Rate-limit key functions ──────────────────────────────────────────────────

def _login_rate_key():
    """Key login rate limiting by email so CGNAT users (Jio etc.) don't share a bucket."""
    data  = request.get_json(silent=True, force=True)
    email = data.get("email") if isinstance(data, dict) else None
    # Only a string counts as an email here — anything else (an object, a list)
    # must not crash the rate limiter, it just falls back to the caller's IP.
    email = email.strip().lower() if isinstance(email, str) else ""
    return email if email else get_remote_address()


def _forgot_pw_key():
    """Rate-limit key = IP + normalised email so per-account hammering is capped too."""
    data  = request.get_json(silent=True)
    email = data.get("email") if isinstance(data, dict) else ""
    return f"{get_remote_address()}:{_sanitize(email, 254).lower()}"


# ── Tokens ────────────────────────────────────────────────────────────────────

def _jwt(payload, hours=None, minutes=None):
    exp = datetime.now(timezone.utc) + (timedelta(hours=hours) if hours else timedelta(minutes=minutes))
    return jwt.encode({**payload, "exp": exp, "iat": datetime.now(timezone.utc)},
                      current_app.config["SECRET_KEY"], algorithm="HS256")


def issue_session_token(user):
    return _jwt({"user_id": str(user["_id"]), "tv": int(user.get("token_version", 0))}, hours=TOKEN_HOURS)


def _login_payload(user):
    out = {
        "token":            issue_session_token(user),
        "role":             user.get("role", "employee"),
        "password_changed": user.get("password_changed", False),
        "user": {
            "_id":        str(user["_id"]),
            "name":       user.get("name"),
            "email":      user.get("email"),
            "role":       user.get("role", "employee"),
            "department": user.get("department", ""),
            "photo_url":  user.get("photo_url"),
        },
    }
    if REQUIRE_ADMIN_MFA and _is_admin(user) and not user.get("mfa_enabled"):
        out["mfa_setup_required"] = True
    return out


# ── Login throttle (same behaviour for real and made-up emails) ───────────────

def _aware(dt):
    if dt is not None and dt.tzinfo is None:        # MongoDB returns naive UTC
        return dt.replace(tzinfo=timezone.utc)
    return dt


def lock_minutes_left(key):
    doc = login_throttle_col.find_one({"_id": key})
    until = _aware(doc.get("locked_until")) if doc else None
    now = datetime.now(timezone.utc)
    if until and until > now:
        return max(1, int((until - now).total_seconds() / 60) + 1)
    return 0


def record_failure(key):
    now = datetime.now(timezone.utc)
    doc = login_throttle_col.find_one({"_id": key}) or {}
    until = _aware(doc.get("locked_until"))
    attempts = 0 if (until and until <= now) else int(doc.get("attempts", 0))   # an expired lock starts fresh
    attempts += 1
    update = {"attempts": attempts, "updated_at": now, "locked_until": None}
    if attempts >= LOCK_AFTER:
        update["locked_until"] = now + timedelta(minutes=LOCK_MINUTES)
    login_throttle_col.update_one({"_id": key}, {"$set": update}, upsert=True)


def clear_failures(key):
    login_throttle_col.delete_one({"_id": key})


def _locked_response(mins):
    return jsonify({"message": f"Account locked due to too many failed attempts. Try again in {mins} minute(s)."}), 423


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute", key_func=_login_rate_key)
def login():
    data     = request.get_json(silent=True)
    data     = data if isinstance(data, dict) else {}
    email    = _sanitize(data.get("email"), max_len=254).lower()
    password = data.get("password") if isinstance(data.get("password"), str) else ""

    if not email or not password:
        return jsonify({"message": "Email and password are required."}), 400
    if not _valid_email(email):
        return jsonify(_GENERIC_FAIL), 401

    mins = lock_minutes_left(email)
    if mins:
        return _locked_response(mins)

    user = users_col.find_one({"email": email})

    # No such account, or an account that has no portal login (contract records):
    # do the same amount of work and give the same answer as a wrong password, so
    # the login page can't be used to find out which emails exist.
    if not user or not user.get("password"):
        bcrypt.check_password_hash(bcrypt.generate_password_hash("__dummy__sentinel__").decode(), password)
        record_failure(email)
        return jsonify(_GENERIC_FAIL), 401

    if not bcrypt.check_password_hash(user["password"], password):
        record_failure(email)
        return jsonify(_GENERIC_FAIL), 401

    clear_failures(email)

    # Offboarded employees (resignation notice + last working day already
    # passed — same rule used to block attendance check-in/out) lose portal
    # access too, even though their password/account still exists.
    if is_offboarded(user):
        return jsonify({"message": "Your employment has ended. Portal access is no longer available."}), 403

    if user.get("mfa_enabled"):
        # Second step: the password was right, now ask for the authenticator code.
        return jsonify({"mfa_required": True,
                        "mfa_token": _jwt({"user_id": str(user["_id"]), "typ": "mfa"}, minutes=5)}), 200

    return jsonify(_login_payload(user)), 200


@bp.route("/api/my/set-password", methods=["POST"])
@token_required
def set_own_password():
    """Allows an authenticated user to update their password."""
    data         = request.get_json(silent=True)
    data         = data if isinstance(data, dict) else {}
    old_password = data.get("oldPassword")
    new_password = data.get("password")

    if not isinstance(old_password, str) or not old_password:
        return jsonify({"message": "Current password is required."}), 400

    if not request.user.get("password") or not bcrypt.check_password_hash(request.user["password"], old_password):
        return jsonify({"message": "Incorrect current password. Please try again."}), 400

    if not isinstance(new_password, str) or not is_strong_password(new_password):
        return jsonify({"message": "Password must be at least 8 characters and contain 1 uppercase, 1 lowercase, 1 number, and 1 special character."}), 400

    hashed = bcrypt.generate_password_hash(new_password).decode("utf-8")
    new_tv = int(request.user.get("token_version", 0)) + 1       # every older session ends
    users_col.update_one(
        {"_id": request.user["_id"]},
        {"$set": {"password": hashed, "password_changed": True, "token_version": new_tv}}
    )
    fresh = {**request.user, "token_version": new_tv}
    return jsonify({"message": "Password updated successfully!", "token": issue_session_token(fresh)}), 200


# ── Forgot / reset password (emailed single-use link) ─────────────────────────

def _hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()


@bp.route("/api/forgot-password", methods=["POST"])
@limiter.limit("5 per hour", key_func=_forgot_pw_key)
def forgot_password():
    data  = request.get_json(silent=True)
    data  = data if isinstance(data, dict) else {}
    email = _sanitize(data.get("email"), max_len=254).lower()
    generic = jsonify({"message": "If this email exists, a password reset link has been sent."}), 200

    user = users_col.find_one({"email": email}) if _valid_email(email) else None
    # Same answer whether or not the account exists. Contract employees (and any
    # record with no password) are data-only records with no portal login — a
    # reset link would hand them one, so they never get a link.
    if not user or user.get("employment_type") == "Contract" or not user.get("password"):
        return generic

    token = secrets.token_urlsafe(32)
    password_resets_col.delete_many({"user_id": str(user["_id"]), "used": False})      # only the newest link works
    password_resets_col.insert_one({
        "user_id": str(user["_id"]), "token_hash": _hash_token(token), "used": False,
        "created_at": datetime.now(timezone.utc), "expires_at": datetime.now(timezone.utc) + timedelta(minutes=RESET_MINUTES),
    })
    link = f"{DASHBOARD_URL.rstrip('/')}/reset-password/{token}"
    body = (
        f"Hello {user.get('name') or ''},\n\n"
        "We received a request to reset your GDMR Connect password.\n\n"
        f"Open this link to choose a new password (it works once and expires in {RESET_MINUTES} minutes):\n{link}\n\n"
        "If you did not ask for this, you can ignore this email — your password has NOT been changed."
    )
    ok = send_email(email, "GDMR Connect - Reset your password", body)
    print(f"[forgot-password] reset link {'sent' if ok else 'FAILED to send'} for a request")
    return generic


@bp.route("/api/reset-password", methods=["POST"])
@limiter.limit("10 per hour")
def reset_password():
    data     = request.get_json(silent=True)
    data     = data if isinstance(data, dict) else {}
    token    = data.get("token")
    password = data.get("password")
    bad_link = jsonify({"message": "This reset link is invalid or has expired. Please request a new one."}), 400

    if not isinstance(token, str) or not (20 <= len(token) <= 200):
        return bad_link
    rec = password_resets_col.find_one({"token_hash": _hash_token(token), "used": False})
    if not rec or _aware(rec["expires_at"]) <= datetime.now(timezone.utc):
        return bad_link
    if not isinstance(password, str) or not is_strong_password(password):
        return jsonify({"message": "Password must be at least 8 characters and contain 1 uppercase, 1 lowercase, 1 number, and 1 special character."}), 400

    try:
        user = users_col.find_one({"_id": ObjectId(rec["user_id"])})
    except Exception:
        user = None
    if not user:
        return bad_link

    users_col.update_one({"_id": user["_id"]}, {"$set": {
        "password": bcrypt.generate_password_hash(password).decode("utf-8"), "password_changed": True,
        "token_version": int(user.get("token_version", 0)) + 1,
    }})
    password_resets_col.update_one({"_id": rec["_id"]}, {"$set": {"used": True, "used_at": datetime.now(timezone.utc)}})
    if user.get("email"):
        clear_failures(user["email"].lower())      # the owner proved they hold the mailbox: lift any lock
    return jsonify({"message": "Your password has been changed. You can now log in."}), 200


# ── Log out everywhere / force logout ─────────────────────────────────────────

@bp.route("/api/my/logout-all", methods=["POST"])
@token_required
def logout_all():
    users_col.update_one({"_id": request.user["_id"]}, {"$set": {"token_version": int(request.user.get("token_version", 0)) + 1}})
    return jsonify({"message": "You have been logged out of all devices."}), 200


@bp.route("/api/admin/employees/<emp_id>/force-logout", methods=["POST"])
@token_required
def force_logout(emp_id):
    """Admin/owner ends every session of one person (e.g. a lost phone, a suspected account takeover)."""
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        oid = ObjectId(emp_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    emp = users_col.find_one({"_id": oid}, {"token_version": 1})
    if not emp:
        return jsonify({"message": "Employee not found."}), 404
    users_col.update_one({"_id": oid}, {"$set": {"token_version": int(emp.get("token_version", 0)) + 1}})
    return jsonify({"message": "All sessions for this account have been ended."}), 200
