import smtplib
import os
from email.mime.text import MIMEText
import random
import string
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER)

# Debug print
print("SMTP_HOST:", SMTP_HOST)
print("SMTP_USER:", SMTP_USER)
print("SMTP_PASS Loaded:", bool(SMTP_PASS))


def send_email(to_email, subject, body):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        raise Exception("SMTP not configured")

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = FROM_EMAIL
    msg['To'] = to_email

    s = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    s.starttls()
    s.login(SMTP_USER, SMTP_PASS)
    s.sendmail(FROM_EMAIL, [to_email], msg.as_string())
    s.quit()


def generate_random_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%&"
    return ''.join(random.choice(chars) for _ in range(length))
