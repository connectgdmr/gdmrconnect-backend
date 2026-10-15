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

# Websites allowed to call this API from a browser (CORS). Comma-separated env
# var CORS_ORIGINS adds to the defaults — e.g. a Vercel preview URL.
CORS_ORIGINS = [o.strip() for o in (
    "https://www.gdmrconnect.com,https://gdmrconnect.com,http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173"
    + ("," + os.getenv("CORS_ORIGINS", "") if os.getenv("CORS_ORIGINS") else "")
).split(",") if o.strip()]
# Set REQUIRE_ADMIN_MFA=1 to make the login response tell the app that admins/owners
# should turn on two-step verification (the app then prompts them).
REQUIRE_ADMIN_MFA = os.getenv("REQUIRE_ADMIN_MFA", "").strip().lower() in ("1", "true", "yes")
# Set STRICT_SECRET=1 to refuse to start when SECRET_KEY is shorter than 32 characters.
STRICT_SECRET = os.getenv("STRICT_SECRET", "").strip().lower() in ("1", "true", "yes")

# Relieving cum Service Certificate (routes/certificates.py) — wording/numbering from the approved template.
COE_PREFIX        = os.getenv("COE_PREFIX", "EMC")
# Number the NEXT certificate gets. The approved template's sample code is EMC11, so numbering
# starts at 12; set COE_START_NUMBER on Railway if HR has already issued more letters by hand.
# Only read the first time a certificate is generated.
COE_START_NUMBER  = int(os.getenv("COE_START_NUMBER", "12") or 12)
COE_SIGNATORY_NAME        = os.getenv("COE_SIGNATORY_NAME", "Jofin Mejo Jacob")
COE_SIGNATORY_DESIGNATION = os.getenv("COE_SIGNATORY_DESIGNATION", "Head Of Human Resources")
COE_DEFAULT_POSTING       = os.getenv("COE_DEFAULT_POSTING", "Thiruvananthapuram office")

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
