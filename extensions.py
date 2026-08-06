"""
extensions.py — GDMR Connect
==============================
Flask extension instances (uninitialised).
Call init_app(app) on each inside create_app() in app.py.
"""
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import REDIS_URL

bcrypt = Bcrypt()

# storage_uri: memory:// resets on restart and isn't shared across gunicorn
# workers — set REDIS_URL in the environment for persistent, worker-shared
# rate limiting (matches the original app.py's Limiter setup).
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=REDIS_URL,
)
