# utils.py
import os
import requests

BREVO_URL = "https://api.brevo.com/v3/smtp/email"

def send_email(to_email: str, subject: str, body: str, from_name="GDMR Connect"):
    """Send email via Brevo API. Returns True on success, False on failure."""

    # Read fresh every call — avoids the import-time race with load_dotenv()
    api_key = os.getenv("BREVO_API_KEY")

    if not api_key:
        print("[Brevo] ERROR: BREVO_API_KEY environment variable is not set.")
        return False

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json",
    }

    payload = {
        "sender": {"name": from_name, "email": "connect.gdmr@gmail.com"},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": body
    }

    try:
        res = requests.post(BREVO_URL, headers=headers, json=payload, timeout=10)
        print(f"[Brevo] status={res.status_code} to={to_email} response={res.text[:200]}")
        if res.status_code in (200, 201):
            return True
        else:
            print(f"[Brevo] FAILED — status {res.status_code}: {res.text}")
            return False
    except Exception as e:
        print(f"[Brevo] Exception sending to {to_email}: {e}")
        return False


# Password Generator
import secrets, string
def generate_random_password(length: int = 10) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(chars) for _ in range(length))
