"""
utils_mail.py — GDMR Connect
===============================
Personal Gmail integration (routes/mail.py) — App Password auth over Gmail's
own IMAP/SMTP servers, not the Google API/OAuth. Every user connects and
reads/sends as themselves; nothing here is shared or company-wide (that's
utils.py's Brevo-based send_email(), a completely separate, unrelated
sender).

Gmail App Passwords require 2-Step Verification to be turned on for the
Google account, and IMAP access enabled in Gmail's own settings — both are
one-time steps on the user's side, called out in the connect error message
below so a failure is actionable instead of a bare "login failed".
"""
import imaplib
import smtplib
import socket
import ssl
import email
import email.utils
import email.header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cryptography.fernet import Fernet, InvalidToken

from config import MAIL_ENCRYPTION_KEY

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

_GMAIL_HELP = (
    "Couldn't sign in to Gmail with that email/app password. Make sure "
    "2-Step Verification is on for this Google account, the App Password "
    "was copied correctly (no spaces), and IMAP is enabled in Gmail's "
    "Settings → \"See all settings\" → Forwarding and POP/IMAP."
)

# Connection-level failures (DNS/timeout/refused/TLS) are NOT imaplib.IMAP4.error
# or smtplib.SMTPAuthenticationError — they're plain socket/ssl errors. Without
# catching these too, they escape as an unhandled 500 with no JSON body, which
# the frontend can't show a reason for. Caught separately so the message is
# honest about "can't reach Gmail's servers" vs. "Gmail rejected the login".
_NETWORK_ERRORS = (socket.timeout, socket.gaierror, OSError, ssl.SSLError)
_NETWORK_HELP = (
    "Couldn't reach Gmail's mail servers ({host}:{port}) from the server. "
    "This isn't a wrong-password issue — either the network blocked the "
    "connection or Gmail's servers didn't respond. Try again in a moment; "
    "if it keeps happening, this server's outbound network may be blocking "
    "IMAP/SMTP ports."
)


class MailAuthError(Exception):
    """Gmail rejected the email/app password (or IMAP/SMTP is disabled)."""


class MailConfigError(Exception):
    """MAIL_ENCRYPTION_KEY isn't set/valid — this deploy can't use mail at all yet."""


# ── Encryption ────────────────────────────────────────────────────────────────

def _cipher():
    if not MAIL_ENCRYPTION_KEY:
        raise MailConfigError(
            "MAIL_ENCRYPTION_KEY is not set on this server — Gmail integration "
            "can't store app passwords securely until it is."
        )
    try:
        return Fernet(MAIL_ENCRYPTION_KEY.encode() if isinstance(MAIL_ENCRYPTION_KEY, str) else MAIL_ENCRYPTION_KEY)
    except (ValueError, TypeError) as e:
        raise MailConfigError(f"MAIL_ENCRYPTION_KEY is set but isn't a valid Fernet key: {e}")


def encrypt_secret(plain: str) -> str:
    return _cipher().encrypt(plain.encode()).decode()


def decrypt_secret(token: str) -> str:
    try:
        return _cipher().decrypt(token.encode()).decode()
    except InvalidToken:
        # Can only happen if MAIL_ENCRYPTION_KEY changed after the password
        # was saved — the stored value is unrecoverable, not just wrong.
        raise MailConfigError(
            "Stored app password can't be decrypted — MAIL_ENCRYPTION_KEY may "
            "have changed since it was saved. Reconnect Gmail to fix this."
        )


# ── Connections ───────────────────────────────────────────────────────────────

def imap_connect(email_addr: str, app_password: str):
    try:
        conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    except _NETWORK_ERRORS as e:
        raise MailConfigError(_NETWORK_HELP.format(host=IMAP_HOST, port=IMAP_PORT) + f" ({e})")
    try:
        conn.login(email_addr, app_password)
        return conn
    except imaplib.IMAP4.error:
        raise MailAuthError(_GMAIL_HELP)
    except _NETWORK_ERRORS as e:
        raise MailConfigError(_NETWORK_HELP.format(host=IMAP_HOST, port=IMAP_PORT) + f" ({e})")


def smtp_connect(email_addr: str, app_password: str):
    try:
        conn = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
    except _NETWORK_ERRORS as e:
        raise MailConfigError(_NETWORK_HELP.format(host=SMTP_HOST, port=SMTP_PORT) + f" ({e})")
    try:
        conn.login(email_addr, app_password)
        return conn
    except smtplib.SMTPAuthenticationError:
        raise MailAuthError(_GMAIL_HELP)
    except _NETWORK_ERRORS as e:
        raise MailConfigError(_NETWORK_HELP.format(host=SMTP_HOST, port=SMTP_PORT) + f" ({e})")


def test_login(email_addr: str, app_password: str):
    """Raises MailAuthError if the credentials don't work. Used by /connect
    so a bad app password fails immediately instead of being saved blind."""
    conn = imap_connect(email_addr, app_password)
    try:
        conn.logout()
    except Exception:
        pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _decode(raw):
    """Decode an RFC 2047-encoded header (From/Subject) into a plain string."""
    if not raw:
        return ""
    parts = email.header.decode_header(raw)
    out = []
    for text, enc in parts:
        if isinstance(text, bytes):
            out.append(text.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)


def _split_from(raw_from):
    name, addr = email.utils.parseaddr(_decode(raw_from))
    return (name or addr), addr


# ── Inbox ─────────────────────────────────────────────────────────────────────

def fetch_inbox(email_addr: str, app_password: str, limit: int = 25, offset: int = 0):
    """Newest-first page of headers. BODY.PEEK[HEADER] (not BODY[HEADER]) so
    listing never marks anything as read — only opening a message does."""
    conn = imap_connect(email_addr, app_password)
    try:
        conn.select("INBOX", readonly=True)
        status, data = conn.search(None, "ALL")
        if status != "OK":
            return {"messages": [], "total": 0}
        uids = data[0].split()
        uids.reverse()  # newest last in IMAP's numbering -> newest first
        total = len(uids)
        page = uids[offset:offset + limit]

        messages = []
        for uid in page:
            status, msg_data = conn.fetch(uid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)] FLAGS)")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            header_bytes = msg_data[0][1]
            flags_raw = msg_data[0][0].decode(errors="replace") if isinstance(msg_data[0][0], bytes) else str(msg_data[0][0])
            msg = email.message_from_bytes(header_bytes)
            from_name, from_addr = _split_from(msg.get("From"))
            messages.append({
                "uid": uid.decode(),
                "from_name": from_name,
                "from_addr": from_addr,
                "subject": _decode(msg.get("Subject")) or "(no subject)",
                "date": msg.get("Date"),
                "unread": "\\Seen" not in flags_raw,
            })
        return {"messages": messages, "total": total}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def fetch_message(email_addr: str, app_password: str, uid: str):
    """Full message body + attachment names. Marks \\Seen — opening a message
    is expected to mark it read, same as any mail client."""
    conn = imap_connect(email_addr, app_password)
    try:
        conn.select("INBOX", readonly=False)
        status, msg_data = conn.fetch(uid.encode(), "(RFC822)")
        if status != "OK" or not msg_data or not msg_data[0]:
            return None
        msg = email.message_from_bytes(msg_data[0][1])
        conn.store(uid.encode(), "+FLAGS", "\\Seen")

        from_name, from_addr = _split_from(msg.get("From"))
        body_plain, body_html, attachments = "", "", []

        if msg.is_multipart():
            for part in msg.walk():
                disp = str(part.get("Content-Disposition") or "")
                ctype = part.get_content_type()
                if "attachment" in disp or part.get_filename():
                    attachments.append(part.get_filename() or "attachment")
                    continue
                if ctype == "text/plain" and not body_plain:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_plain = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                elif ctype == "text/html" and not body_html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace") if payload else ""
            if msg.get_content_type() == "text/html":
                body_html = text
            else:
                body_plain = text

        return {
            "uid": uid,
            "from_name": from_name,
            "from_addr": from_addr,
            "to": _decode(msg.get("To")),
            "subject": _decode(msg.get("Subject")) or "(no subject)",
            "date": msg.get("Date"),
            "body_plain": body_plain,
            "body_html": body_html,
            "attachments": attachments,
        }
    finally:
        try:
            conn.logout()
        except Exception:
            pass


# ── Send ──────────────────────────────────────────────────────────────────────

def send_mail(email_addr: str, app_password: str, to: str, subject: str, body: str, cc: str = None):
    msg = MIMEMultipart()
    msg["From"] = email_addr
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    recipients = [addr.strip() for addr in to.split(",") if addr.strip()]
    if cc:
        recipients += [addr.strip() for addr in cc.split(",") if addr.strip()]

    conn = smtp_connect(email_addr, app_password)
    try:
        conn.sendmail(email_addr, recipients, msg.as_string())
    finally:
        try:
            conn.quit()
        except Exception:
            pass
