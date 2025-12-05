# utils.py
import os
import smtplib
import ssl
from email.message import EmailMessage
import random
import string

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))   # 465 for SSL, 587 for STARTTLS
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "10"))  # seconds

def send_email(to_email: str, subject: str, body: str, from_name: str = None) -> bool:
    """Send email. Return True if success, False otherwise.
       Important: never call sys.exit() here."""
    if not (SMTP_USER and SMTP_PASS):
        print("Email not sent: SMTP_USER or SMTP_PASS not configured.")
        return False

    try:
        msg = EmailMessage()
        msg["From"] = f"{from_name} <{SMTP_USER}>" if from_name else SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        # Use SMTP_SSL if port 465, otherwise use STARTTLS (587)
        if SMTP_PORT == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context) as smtp:
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
        else:
            # STARTTLS flow
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)

        return True
    except Exception as e:
        # Log details for debugging but DO NOT exit the process
        print("send_email error:", repr(e))
        return False

def generate_random_password(length: int = 10) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(random.choice(chars) for _ in range(length))
