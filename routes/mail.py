"""
routes/mail.py — GDMR Connect
================================
Personal Gmail integration — every user connects their own Gmail via an App
Password (Google Account → Security → App Passwords, requires 2-Step
Verification) and sends/reads mail as themselves through Gmail's own IMAP/
SMTP servers. Purely personal: every route below is scoped to
request.user["_id"] only, no admin or delegated-access angle at all — this
is not a company mailbox, nobody manages anyone else's mail.

See utils_mail.py for the actual IMAP/SMTP/encryption implementation.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify

from database import mail_accounts_col
from decorators import token_required
from utils_mail import (
    encrypt_secret, decrypt_secret, test_login,
    fetch_inbox, fetch_message, send_mail,
    MailAuthError, MailConfigError,
)

bp = Blueprint("mail", __name__)


def _account_for(uid):
    return mail_accounts_col.find_one({"user_id": uid})


@bp.route("/api/mail/status", methods=["GET"])
@token_required
def mail_status():
    uid = str(request.user["_id"])
    acct = _account_for(uid)
    if not acct:
        return jsonify({"connected": False}), 200
    return jsonify({
        "connected": True,
        "email": acct.get("email"),
        "connected_at": acct.get("connected_at"),
    }), 200


@bp.route("/api/mail/connect", methods=["POST"])
@token_required
def mail_connect():
    uid  = str(request.user["_id"])
    data = request.json or {}
    email_addr   = str(data.get("email", "")).strip()
    app_password = str(data.get("app_password", "")).strip().replace(" ", "")
    if not email_addr or not app_password:
        return jsonify({"message": "Email and app password are required."}), 400

    try:
        test_login(email_addr, app_password)  # fail loudly now, not on first inbox load
    except MailConfigError as e:
        return jsonify({"message": str(e)}), 503
    except MailAuthError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return jsonify({"message": f"Unexpected error connecting to Gmail: {e}"}), 500

    mail_accounts_col.update_one(
        {"user_id": uid},
        {"$set": {
            "user_id": uid,
            "email": email_addr,
            "app_password_enc": encrypt_secret(app_password),
            "connected_at": datetime.now(timezone.utc),
        }},
        upsert=True,
    )
    return jsonify({"message": "Gmail connected.", "email": email_addr}), 200


@bp.route("/api/mail/disconnect", methods=["DELETE"])
@token_required
def mail_disconnect():
    uid = str(request.user["_id"])
    mail_accounts_col.delete_one({"user_id": uid})
    return jsonify({"message": "Gmail disconnected."}), 200


@bp.route("/api/mail/inbox", methods=["GET"])
@token_required
def mail_inbox():
    uid  = str(request.user["_id"])
    acct = _account_for(uid)
    if not acct:
        return jsonify({"message": "Connect Gmail first."}), 400

    try:
        limit  = min(int(request.args.get("limit", 25)), 50)
        offset = max(int(request.args.get("offset", 0)), 0)
    except (TypeError, ValueError):
        return jsonify({"message": "limit/offset must be numbers"}), 400

    try:
        app_password = decrypt_secret(acct["app_password_enc"])
        result = fetch_inbox(acct["email"], app_password, limit=limit, offset=offset)
    except MailConfigError as e:
        return jsonify({"message": str(e)}), 503
    except MailAuthError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return jsonify({"message": f"Unexpected error loading inbox: {e}"}), 500

    return jsonify(result), 200


@bp.route("/api/mail/message/<uid_param>", methods=["GET"])
@token_required
def mail_message(uid_param):
    uid  = str(request.user["_id"])
    acct = _account_for(uid)
    if not acct:
        return jsonify({"message": "Connect Gmail first."}), 400

    try:
        app_password = decrypt_secret(acct["app_password_enc"])
        message = fetch_message(acct["email"], app_password, uid_param)
    except MailConfigError as e:
        return jsonify({"message": str(e)}), 503
    except MailAuthError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return jsonify({"message": f"Unexpected error loading message: {e}"}), 500

    if not message:
        return jsonify({"message": "Message not found"}), 404
    return jsonify(message), 200


@bp.route("/api/mail/send", methods=["POST"])
@token_required
def mail_send():
    uid  = str(request.user["_id"])
    acct = _account_for(uid)
    if not acct:
        return jsonify({"message": "Connect Gmail first."}), 400

    data    = request.json or {}
    to      = str(data.get("to", "")).strip()
    cc      = str(data.get("cc", "")).strip() or None
    subject = str(data.get("subject", "")).strip()
    body    = str(data.get("body", "")).strip()
    if not to or not subject or not body:
        return jsonify({"message": "To, subject, and body are required."}), 400

    try:
        app_password = decrypt_secret(acct["app_password_enc"])
        send_mail(acct["email"], app_password, to, subject, body, cc=cc)
    except MailConfigError as e:
        return jsonify({"message": str(e)}), 503
    except MailAuthError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return jsonify({"message": f"Failed to send: {e}"}), 400

    return jsonify({"message": "Sent."}), 200
