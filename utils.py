# utils.py
import os
import requests

BREVO_URL = "https://api.brevo.com/v3/smtp/email"
# The sender must be a VERIFIED sender in Brevo (Brevo -> Senders, Domains & Dedicated IPs). Override on Railway with
# BREVO_SENDER_EMAIL if the verified address is a different one.
DEFAULT_SENDER = "connect.gdmr@gmail.com"
LAST_RESULT = {"ok": None, "status": None, "detail": "", "at": None}      # what the most recent send attempt got back


def sender_email():
    return (os.getenv("BREVO_SENDER_EMAIL") or DEFAULT_SENDER).strip()


def _record(ok, status, detail):
    from datetime import datetime, timezone
    LAST_RESULT.update({"ok": ok, "status": status, "detail": str(detail)[:400], "at": datetime.now(timezone.utc).isoformat()})

def send_email(
    to_email: str,
    subject: str,
    body: str,
    from_name: str = "GDMR Connect",
    html_body: str = None,
    cc_emails: list = None,
    reply_to: str = None,
):
    """Send email via Brevo API. Returns True on success, False on failure.

    Args:
        to_email:   Primary recipient address.
        subject:    Email subject line.
        body:       Plain-text body (required; used as fallback when html_body is given).
        html_body:  Optional HTML body; body becomes the plain-text fallback.
        cc_emails:  Optional list of CC addresses (strings).
        reply_to:   Optional Reply-To address.
    """
    if os.getenv("DEMO_MODE", "").strip().lower() in ("1", "true", "yes"):
        print(f"[demo] email suppressed: {subject!r}")
        return True                 # demo deployment never sends real email
    api_key = (os.getenv("BREVO_API_KEY") or "").strip()
    if not api_key:
        print("[Brevo] ERROR: BREVO_API_KEY environment variable is not set.")
        _record(False, None, "BREVO_API_KEY is not set on the server")
        return False

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json",
    }

    payload = {
        "sender":  {"name": from_name, "email": sender_email()},
        "to":      [{"email": to_email}],
        "subject": subject,
    }
    if html_body:
        payload["htmlContent"] = html_body
        payload["textContent"] = body
    else:
        payload["textContent"] = body
    if cc_emails:
        payload["cc"] = [{"email": e} for e in cc_emails if e]
    if reply_to:
        payload["replyTo"] = {"email": reply_to}

    try:
        res = requests.post(BREVO_URL, headers=headers, json=payload, timeout=10)
        print(f"[Brevo] status={res.status_code} to={to_email} response={res.text[:200]}")
        if res.status_code in (200, 201):
            _record(True, res.status_code, "sent")
            return True
        print(f"[Brevo] FAILED — status {res.status_code}: {res.text}")
        _record(False, res.status_code, res.text)
        return False
    except Exception as e:
        print(f"[Brevo] Exception sending to {to_email}: {e}")
        _record(False, None, f"could not reach Brevo: {e}")
        return False


def diagnose_email():
    """Ask Brevo (without sending anything) why mail might not be going out. Returns plain-English findings."""
    import requests as _rq
    key = (os.getenv("BREVO_API_KEY") or "").strip()
    out = {"api_key_set": bool(key), "sender": sender_email(), "demo_mode": os.getenv("DEMO_MODE", "").strip().lower() in ("1", "true", "yes"),
           "findings": [], "last_send": dict(LAST_RESULT)}
    f = out["findings"]
    if out["demo_mode"]:
        f.append("DEMO_MODE is on: this server never sends real email.")
    if not key:
        f.append("BREVO_API_KEY is not set on the server (Railway -> Variables). Add your Brevo v3 API key and redeploy.")
        return out
    h = {"accept": "application/json", "api-key": key}
    try:
        a = _rq.get("https://api.brevo.com/v3/account", headers=h, timeout=10)
    except Exception as e:
        f.append(f"Could not reach Brevo from the server: {e}")
        return out
    if a.status_code == 401:
        f.append("Brevo rejected the API key (401). The key is wrong, revoked, or is an SMTP key instead of an API (v3) key. Create a new API key in Brevo -> SMTP & API -> API Keys.")
        return out
    if a.status_code != 200:
        f.append(f"Brevo account check failed ({a.status_code}): {a.text[:200]}")
        return out
    acct = a.json()
    plan = (acct.get("plan") or [{}])[0]
    credits = plan.get("credits")
    out["account"] = {"email": acct.get("email"), "plan": plan.get("type"), "credits": credits}
    if credits is not None and credits <= 0:
        f.append("The Brevo account has no email credits left (daily limit reached or plan exhausted).")
    try:
        s = _rq.get("https://api.brevo.com/v3/senders", headers=h, timeout=10)
        if s.status_code == 200:
            senders = s.json().get("senders", [])
            mine = [x for x in senders if str(x.get("email", "")).lower() == out["sender"].lower()]
            out["verified_senders"] = [{"email": x.get("email"), "active": x.get("active")} for x in senders]
            if not mine:
                f.append(f"The sender {out['sender']} is not a sender in Brevo. Add and verify it in Brevo -> Senders, Domains & Dedicated IPs, "
                         "or set BREVO_SENDER_EMAIL on the server to one of the verified senders listed here.")
            elif not mine[0].get("active"):
                f.append(f"The sender {out['sender']} exists in Brevo but is not verified/active yet. Open the verification email Brevo sent to it.")
            elif out["sender"].lower().endswith(("@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com")):
                f.append("The sender is a free-mail address (gmail etc.). Brevo can send from it but many inboxes reject or spam-folder it. "
                         "Use an address on your own domain (e.g. no-reply@gdmrfoundation.com) with the domain authenticated in Brevo.")
    except Exception:
        pass
    if not f:
        f.append("Brevo accepts the key and the sender looks fine. Use the test button to send a real message and see Brevo's exact answer.")
    return out


# Password Generator
import secrets, string
def generate_random_password(length: int = 10) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(chars) for _ in range(length))
