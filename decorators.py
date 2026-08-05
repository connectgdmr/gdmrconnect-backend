"""
decorators.py — GDMR Connect
==============================
JWT auth middleware shared by all route modules.
"""
from functools import wraps
from flask import request, jsonify, current_app
import jwt
from bson import ObjectId
from database import users_col


def token_required(f):
    """
    Decorator to protect routes using JWT authentication.
    Decodes the Bearer token, looks up the user document, and sets
    request.user so route functions can access the caller's profile.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            parts = request.headers["Authorization"].split(" ")
            if len(parts) == 2:
                token = parts[1]

        if not token:
            return jsonify({"message": "Authentication Token is missing! Please log in."}), 401

        try:
            data = jwt.decode(
                token, current_app.config["SECRET_KEY"], algorithms=["HS256"]
            )
            user_id = data.get("user_id")
            current_user = users_col.find_one({"_id": ObjectId(user_id)})

            if not current_user:
                return jsonify({"message": "Invalid token. User not found in database."}), 401

            request.user = current_user

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Session expired. Please log in again."}), 401
        except Exception as e:
            return jsonify({"message": "Token is invalid!", "error": str(e)}), 401

        return f(*args, **kwargs)
    return decorated
