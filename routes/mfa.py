"""
routes/mfa.py — GDMR Connect
==============================
Optional two-step verification (TOTP authenticator app) with one-time backup codes.

* Anyone can turn it on from Settings. Admins/owners are strongly encouraged to
  (set REQUIRE_ADMIN_MFA=1 and the app prompts them).
* When on, /api/login answers "mfa_required" after a correct password and the
  app then calls /api/login/mfa with the 6-digit code (or a backup code).
* Codes can't be replayed (the last accepted 30-second step is remembered) and
  wrong codes are throttled like wrong passwords.
* An admin/owner can reset someone else's MFA if they lose their phone.
"""
import base64
import hashlib
import hmac
import io
import secrets
from datetime import datetime, timezone

import pyotp
import segno
import jwt
from bson import ObjectId
from flask import Blueprint, request, jsonify, current_app

from database import users_col
from decorators import token_required
from extensions import bcrypt, limiter
from helpers import _is_admin
from routes.auth import (_login_payload, lock_minutes_left, record_failure, clear_failures, _locked_response, _aware)

bp = Blueprint("mfa", __name__)

ISSUER = "GDMR Connect"
BACKUP_CODE_COUNT = 8


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _clean_code(v):
    return "".join(ch for ch in str(v or "") if ch.isalnum()).lower()


def _verify_totp(user, code):
    """True if `code` is a valid, not-yet-used 6-digit code for this user."""
    secret = user.get("mfa_secret")
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if not secret or len(code) != 6:
        return False
    totp = pyotp.TOTP(secret)
    now = datetime.now(timezone.utc)
    last = int(user.get("mfa_last_step", 0))
    for offset in (-1, 0, 1):                       # tolerate small clock drift
        step = int(totp.timecode(now)) + offset
        if step > last and hmac.compare_digest(totp.at(now, offset), code):
            users_col.update_one({"_id": user["_id"]}, {"$set": {"mfa_last_step": step}})
            return True
    return False


def _use_backup_code(user, code):
    h = _sha(_clean_code(code))
    hashes = list(user.get("mfa_backup_hashes") or [])
    if len(_clean_code(code)) < 8 or h not in hashes:
        return False
    hashes.remove(h)
    users_col.update_one({"_id": user["_id"]}, {"$set": {"mfa_backup_hashes": hashes}})
    return True


def _qr_data_uri(text):
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="svg", scale=5, border=2, xmldecl=False, svgns=True, nl=False)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


# ── Login step 2 ──────────────────────────────────────────────────────────────

@bp.route("/api/login/mfa", methods=["POST"])
@limiter.limit("15 per minute")
def login_mfa():
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    token, code = data.get("mfa_token"), data.get("code")
    bad = jsonify({"message": "That code is not correct. Please try again."}), 401
    if not isinstance(token, str) or not isinstance(code, (str, int)):
        return jsonify({"message": "Code is required."}), 400
    try:
        claims = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"], options={"require": ["exp"]})
        if claims.get("typ") != "mfa":
            raise ValueError
        user = users_col.find_one({"_id": ObjectId(claims["user_id"])})
    except Exception:
        return jsonify({"message": "Your sign-in timed out. Please enter your password again."}), 401
    if not user or not user.get("mfa_enabled"):
        return jsonify({"message": "Your sign-in timed out. Please enter your password again."}), 401

    key = f"mfa:{user['_id']}"
    mins = lock_minutes_left(key)
    if mins:
        return _locked_response(mins)
    if _verify_totp(user, code) or _use_backup_code(user, code):
        clear_failures(key)
        return jsonify(_login_payload(users_col.find_one({"_id": user["_id"]}))), 200
    record_failure(key)
    return bad


# ── Manage my MFA ─────────────────────────────────────────────────────────────

@bp.route("/api/my/mfa/status", methods=["GET"])
@token_required
def mfa_status():
    u = request.user
    return jsonify({"enabled": bool(u.get("mfa_enabled")), "backup_codes_left": len(u.get("mfa_backup_hashes") or [])}), 200


@bp.route("/api/my/mfa/setup", methods=["POST"])
@token_required
def mfa_setup():
    if request.user.get("mfa_enabled"):
        return jsonify({"message": "Two-step verification is already on."}), 400
    secret = pyotp.random_base32()
    users_col.update_one({"_id": request.user["_id"]}, {"$set": {"mfa_pending_secret": secret}})
    uri = pyotp.TOTP(secret).provisioning_uri(name=request.user.get("email") or str(request.user["_id"]), issuer_name=ISSUER)
    return jsonify({"secret": secret, "otpauth_uri": uri, "qr": _qr_data_uri(uri)}), 200


@bp.route("/api/my/mfa/enable", methods=["POST"])
@token_required
@limiter.limit("10 per minute")
def mfa_enable():
    pending = request.user.get("mfa_pending_secret")
    code = "".join(ch for ch in str((request.get_json(silent=True) or {}).get("code", "")) if ch.isdigit())
    if not pending:
        return jsonify({"message": "Start the setup first."}), 400
    if len(code) != 6 or not pyotp.TOTP(pending).verify(code, valid_window=1):
        return jsonify({"message": "That code is not correct. Check the time on your phone and try again."}), 400
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(BACKUP_CODE_COUNT)]
    users_col.update_one({"_id": request.user["_id"]}, {
        "$set": {"mfa_enabled": True, "mfa_secret": pending, "mfa_backup_hashes": [_sha(_clean_code(c)) for c in codes],
                 "mfa_last_step": 0, "mfa_enabled_at": datetime.now(timezone.utc)},
        "$unset": {"mfa_pending_secret": ""},
    })
    return jsonify({"message": "Two-step verification is on.", "backup_codes": codes}), 200


@bp.route("/api/my/mfa/disable", methods=["POST"])
@token_required
@limiter.limit("10 per minute")
def mfa_disable():
    u = request.user
    data = request.get_json(silent=True) or {}
    if not u.get("mfa_enabled"):
        return jsonify({"message": "Two-step verification is not on."}), 400
    pw = data.get("password")
    if not isinstance(pw, str) or not u.get("password") or not bcrypt.check_password_hash(u["password"], pw):
        return jsonify({"message": "Incorrect password."}), 400
    code = data.get("code")
    if not (_verify_totp(u, code) or _use_backup_code(u, code)):
        return jsonify({"message": "That code is not correct."}), 400
    users_col.update_one({"_id": u["_id"]}, {
        "$set": {"mfa_enabled": False, "token_version": int(u.get("token_version", 0)) + 1},
        "$unset": {"mfa_secret": "", "mfa_backup_hashes": "", "mfa_last_step": ""},
    })
    return jsonify({"message": "Two-step verification is off. Please log in again."}), 200


# ── Admin: reset someone's MFA (lost phone) ───────────────────────────────────

@bp.route("/api/admin/employees/<emp_id>/reset-mfa", methods=["POST"])
@token_required
def admin_reset_mfa(emp_id):
    if not _is_admin(request.user):
        return jsonify({"message": "Unauthorized"}), 403
    try:
        oid = ObjectId(emp_id)
    except Exception:
        return jsonify({"message": "Invalid ID"}), 400
    emp = users_col.find_one({"_id": oid}, {"token_version": 1})
    if not emp:
        return jsonify({"message": "Employee not found."}), 404
    users_col.update_one({"_id": oid}, {
        "$set": {"mfa_enabled": False, "token_version": int(emp.get("token_version", 0)) + 1},
        "$unset": {"mfa_secret": "", "mfa_backup_hashes": "", "mfa_last_step": "", "mfa_pending_secret": ""},
    })
    return jsonify({"message": "Two-step verification was reset. They can set it up again after logging in."}), 200
