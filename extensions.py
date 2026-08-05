"""
extensions.py — GDMR Connect
==============================
Flask extension instances (uninitialised).
Call init_app(app) on each inside create_app() in app.py.
"""
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

bcrypt = Bcrypt()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
)
