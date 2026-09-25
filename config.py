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
# llama-3.3-70b-versatile was decommissioned by Groq (announced 2026-06-17,
# stopped serving entirely by August 2026) -- every assistant call was
# silently failing against a dead model until this was caught. Groq's own
# migration guidance points to gpt-oss-120b, which also supports tool use
# (required for the assistant's tool-calling orchestrator).
GROQ_MODEL   = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

# ── Company constants ─────────────────────────────────────────────────────────
# Owners always receive org-wide work-plan digests and leave notifications.
OWNER_EMAILS  = ["gina.gdmr@gmail.com", "githi@gdmrfoundation.com"]
HR_EMAIL      = "hr@gdmrfoundation.com"
DASHBOARD_URL = "https://www.gdmrconnect.com"
# The backend's own public URL — shown to Admin as the "Cloud Server
# Address" to type into a biometric device's on-screen menu (routes/biometric.py).
# Same host the frontend already hardcodes as its API fallback (src/api.jsx).
BACKEND_PUBLIC_URL = os.getenv("BACKEND_PUBLIC_URL", "https://gdmrconnect-backend-production.up.railway.app")

# ── File uploads ──────────────────────────────────────────────────────────────
UPLOAD_FOLDER = "uploads/attendance_photos"
