"""
routes/auth.py — GDMR Connect
================================
Authentication routes: login, set-password, forgot-password.
"""
import jwt
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, current_app
from flask_limiter.util import get_remote_address

from database import users_col
from decorators import token_required
from extensions import bcrypt, limiter
from helpers import _sanitize, _valid_email, is_strong_password, is_offboarded
from utils import send_email, generate_random_password

bp = Blueprint("auth", __name__)


# ── Rate-limit key functions ──────────────────────────────────────────────────

def _login_rate_key():
    """Key login rate limiting by email so CGNAT users (Jio etc.) don't share a bucket."""
    data  = request.get_json(silent=True, force=True) or {}
    email = (data.get("email") or "").strip().lower()
    return email if email else get_remote_address()


def _forgot_pw_key():
    """Rate-limit key = IP + normalised email so per-account hammering is capped too."""
    data  = request.get_json(silent=True) or {}
    email = _sanitize(data.get("email") or "", 254).lower()
    return f"{get_remote_address()}:{email}"


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute", key_func=_login_rate_key)
def login():
    data     = request.get_json(silent=True) or {}
    email    = _sanitize(data.get("email") or "", max_len=254).lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"message": "Email and password are required."}), 400
    if not _valid_email(email):
        return jsonify({"message": "Incorrect email or password."}), 401

    user = users_col.find_one({"email": email})

    if not user:
        # Constant-time dummy compare prevents timing-based account enumeration
        _dummy = bcrypt.generate_password_hash("__dummy__sentinel__").decode()
        bcrypt.check_password_hash(_dummy, password)
        return jsonify({"message": "Incorrect email or password."}), 401

    # Contract employees are stored as records only — no portal login was ever
    # created for them, so there's no password hash to compare against.
    if not user.get("password"):
        return jsonify({"message": "This account does not have portal login access. Please contact HR."}), 403

    # Account lockout check
    now          = datetime.now(timezone.utc)
    locked_until = user.get("locked_until")
    if locked_until and locked_until > now:
        mins_left = max(1, int((locked_until - now).total_seconds() / 60) + 1)
        return jsonify({"message": f"Account locked due to too many failed attempts. Try again in {mins_left} minute(s)."}), 423

    if not bcrypt.check_password_hash(user["password"], password):
        attempts    = user.get("failed_login_attempts", 0) + 1
        lock_fields = {"failed_login_attempts": attempts}
        if attempts >= 5:
            lock_fields["locked_until"] = now + timedelta(minutes=15)
        users_col.update_one({"_id": user["_id"]}, {"$set": lock_fields})
        return jsonify({"message": "Incorrect email or password."}), 401

    # Success — clear lockout state
    users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {"failed_login_attempts": 0, "locked_until": None}}
    )

    # Offboarded employees (resignation notice + last working day already
    # passed — same rule used to block attendance check-in/out) lose portal
    # access too, even though their password/account still exists.
    if is_offboarded(user):
        return jsonify({"message": "Your employment has ended. Portal access is no longer available."}), 403

    token = jwt.encode(
        {"user_id": str(user["_id"]), "exp": datetime.now(timezone.utc) + timedelta(hours=4)},
        current_app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    return jsonify({
        "token":            token,
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
    }), 200


@bp.route("/api/my/set-password", methods=["POST"])
@token_required
def set_own_password():
    """Allows an authenticated user to update their password."""
    data         = request.json
    old_password = data.get("oldPassword")
    new_password = data.get("password")

    if not old_password:
        return jsonify({"message": "Current password is required."}), 400

    if not bcrypt.check_password_hash(request.user["password"], old_password):
        return jsonify({"message": "Incorrect current password. Please try again."}), 400

    if not new_password or not is_strong_password(new_password):
        return jsonify({"message": "Password must be at least 8 characters and contain 1 uppercase, 1 lowercase, 1 number, and 1 special character."}), 400

    hashed = bcrypt.generate_password_hash(new_password).decode("utf-8")
    users_col.update_one(
        {"_id": request.user["_id"]},
        {"$set": {"password": hashed, "password_changed": True}}
    )
    return jsonify({"message": "Password updated successfully!"}), 200


@bp.route("/api/forgot-password", methods=["POST"])
@limiter.limit("5 per hour", key_func=_forgot_pw_key)
def forgot_password():
    data  = request.get_json(silent=True) or {}
    email = _sanitize(data.get("email") or "", max_len=254).lower()

    user = users_col.find_one({"email": email})
    if not user:
        return jsonify({"message": "If this email exists, a password reset has been sent."}), 200

    # Contract employees are data-only records with no portal login — don't
    # let a forgot-password request silently grant them one. Same generic
    # response either way so this doesn't leak account status.
    if user.get("employment_type") == "Contract":
        return jsonify({"message": "If this email exists, a password reset has been sent."}), 200

    temp_password = generate_random_password()
    hashed        = bcrypt.generate_password_hash(temp_password).decode("utf-8")
    users_col.update_one({"_id": user["_id"]}, {"$set": {"password": hashed, "password_changed": False}})

    subject = "GDMR Connect - Password Reset Request"
    body    = (
        f"Hello {user['name']},\n\n"
        "We received a request to reset your password.\n"
        f"Your new temporary password is: {temp_password}\n\n"
        "Please login and change your password immediately to secure your account."
    )
    ok = send_email(email, subject, body)
    if ok:
        print(f"[forgot-password] Reset email sent successfully to {email}")
    else:
        print(f"[forgot-password] WARNING: Reset email FAILED for {email}")

    return jsonify({"message": "If this email exists, a password reset has been sent."}), 200
