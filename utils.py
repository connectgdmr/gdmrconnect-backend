# utils.py
import os
import requests

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_URL = "https://api.brevo.com/v3/smtp/email"

def send_email(to_email: str, subject: str, body: str, from_name="GDMR Attendance App"):
    """Send email via Brevo API. Returns True/False."""
    if not BREVO_API_KEY:
        print("Brevo API key missing")
        return False

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
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
        print("Brevo response:", res.status_code, res.text)
        return res.status_code in (200, 201)
    except Exception as e:
        print("Brevo email error:", e)
        return False


# Password Generator
import random, string
def generate_random_password(length: int = 10) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(random.choice(chars) for _ in range(length))