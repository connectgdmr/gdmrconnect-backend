"""
config.py — GDMR Connect
========================
All environment variables and application-level constants.
Import from here; never call os.getenv() directly in route modules.
"""
import os
import pytz
from dotenv import load_dotenv

load_dotenv()

# ── Timezone ──────────────────────────────────────────────────────────────────
IST = pytz.timezone("Asia/Kolkata")

# ── Security ──────────────────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("SECRET_KEY")
CRON_SECRET = os.getenv("CRON_SECRET")
REDIS_URL   = os.getenv("REDIS_URL", "memory://")

# ── Database ──────────────────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI")

# ── Cloudinary ────────────────────────────────────────────────────────────────
CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY    = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")

# ── Groq LLM (optional) ───────────────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL   = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# ── Personal Gmail integration (routes/mail.py) ──────────────────────────────
# Encrypts each user's Gmail App Password at rest (Fernet — symmetric,
# reversible, unlike the one-way bcrypt hashing used for login passwords;
# this one has to be decrypted again to actually authenticate to Gmail's
# IMAP/SMTP). Must be a valid Fernet key (Fernet.generate_key() output) —
# routes/mail.py refuses to start a connect/inbox/send call without it
# rather than silently failing partway through.
MAIL_ENCRYPTION_KEY = os.getenv("MAIL_ENCRYPTION_KEY")

# ── Company constants ─────────────────────────────────────────────────────────
# Owners always receive org-wide work-plan digests and leave notifications.
OWNER_EMAILS  = ["gina.gdmr@gmail.com", "githi@gdmrfoundation.com"]
HR_EMAIL      = "hr@gdmrfoundation.com"
DASHBOARD_URL = "https://www.gdmrconnect.com"

# ── File uploads ──────────────────────────────────────────────────────────────
UPLOAD_FOLDER = "uploads/attendance_photos"
