import smtplib
import os
from email.mime.text import MIMEText
import random
import string
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST")
# Default to 465 if not set, as it's safer for Railway/Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT", 465)) 
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER)

# Debug print
print(f"SMTP Config: Host={SMTP_HOST}, Port={SMTP_PORT}, User={SMTP_USER}, PassLoaded={bool(SMTP_PASS)}")

def send_email(to_email, subject, body):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        print("❌ SMTP keys missing in environment variables.")
        return # Don't crash the app, just log it

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = FROM_EMAIL
    msg['To'] = to_email

    try:
        # ✅ AUTO-DETECT: Use SSL for Port 465, otherwise use TLS
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls() # Upgrade connection for 587

        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(FROM_EMAIL, [to_email], msg.as_string())
        server.quit()
        print(f"✅ Email sent successfully to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        # We catch the error so the User Add process doesn't crash

def generate_random_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%&"
    return ''.join(random.choice(chars) for _ in range(length))