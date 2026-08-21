"""
app_new.py — GDMR Connect
============================
Application factory.  This replaces the 8000-line monolithic app.py
with a clean Blueprint-based structure.

Usage (production):
    gunicorn app_new:app

Usage (development):
    python app_new.py
"""

import os
import gzip
import cloudinary
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

from config import SECRET_KEY
from extensions import bcrypt, limiter
from database import db, mongo_client  # db import is also for side-effect (indexes, migration)


def create_app():
    load_dotenv()

    app = Flask(__name__)

    # ── Security ──────────────────────────────────────────────────────────────
    if not SECRET_KEY or SECRET_KEY == "replace-this-secret-with-a-secure-key-in-production":
        raise RuntimeError(
            "SECRET_KEY environment variable is not set or is using the insecure default. "
            "Set a strong random value (32+ chars) in your Railway environment variables."
        )
    app.config["SECRET_KEY"]        = SECRET_KEY
    app.config["BCRYPT_LOG_ROUNDS"] = 12

    # ── Reverse-proxy (Railway) ───────────────────────────────────────────────
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # ── Extensions ────────────────────────────────────────────────────────────
    bcrypt.init_app(app)
    limiter.init_app(app)

    @limiter.request_filter
    def _exempt_options():
        """OPTIONS preflight must never be rate-limited."""
        return request.method == "OPTIONS"

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS(app, resources={
        r"/*": {
            "origins":             "*",
            "supports_credentials": False,
            "allow_headers":       ["Content-Type", "Authorization"],
            "methods":             ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "max_age":             3600,
        }
    })

    # ── Cloudinary ────────────────────────────────────────────────────────────
    try:
        cloudinary.config(
            cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME"),
            api_key    = os.getenv("CLOUDINARY_API_KEY"),
            api_secret = os.getenv("CLOUDINARY_API_SECRET"),
        )
        print("Cloudinary configured successfully.")
    except Exception as e:
        print(f"Warning: Cloudinary configuration failed. Error: {e}")

    # ── gzip compression ──────────────────────────────────────────────────────
    @app.after_request
    def _gzip_response(response):
        if (
            "gzip" in request.headers.get("Accept-Encoding", "")
            and response.status_code == 200
            and response.content_type.startswith(("application/json", "text/"))
            and response.content_length
            and response.content_length > 500
        ):
            data = gzip.compress(response.get_data(), compresslevel=6)
            response.set_data(data)
            response.headers["Content-Encoding"]   = "gzip"
            response.headers["Content-Length"]     = len(data)
            response.headers["Vary"]               = "Accept-Encoding"
        return response

    # ── Health check ──────────────────────────────────────────────────────────
    @app.route("/")
    def home():
        return "GDMR Connect Backend is running normally ✅", 200

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    @app.route("/api/health", methods=["GET"])
    def health_check():
        try:
            mongo_client.admin.command("ping")
            return jsonify({"status": "ok", "db": "connected"}), 200
        except Exception as e:
            return jsonify({"status": "error", "db": "disconnected", "detail": str(e)}), 503

    # ── Local file uploads (fallback for anything not stored on Cloudinary) ────
    @app.route("/uploads/<path:filename>")
    def serve_upload(filename):
        uploads_dir = os.path.join(os.getcwd(), "uploads")
        return send_from_directory(uploads_dir, filename)

    # ── Static / SPA file serving ─────────────────────────────────────────────
    # Uncomment if you serve a built React app from this same process.
    # @app.route("/", defaults={"path": ""})
    # @app.route("/<path:path>")
    # def serve_spa(path):
    #     if path and os.path.exists(os.path.join(app.static_folder, path)):
    #         return send_from_directory(app.static_folder, path)
    #     return send_from_directory(app.static_folder, "index.html")

    # ── Blueprints ────────────────────────────────────────────────────────────
    from routes.auth          import bp as auth_bp
    from routes.employees     import bp as employees_bp
    from routes.access        import bp as access_bp
    from routes.pms           import bp as pms_bp
    from routes.attendance    import bp as attendance_bp
    from routes.leaves        import bp as leaves_bp
    from routes.assistant     import bp as assistant_bp
    from routes.assets        import bp as assets_bp
    from routes.announcements import bp as announcements_bp
    from routes.notifications import bp as notifications_bp
    from routes.stats         import bp as stats_bp
    from routes.assessment    import bp as assessment_bp
    from routes.lms           import bp as lms_bp
    from routes.career        import bp as career_bp
    from routes.payroll       import bp as payroll_bp
    from routes.work_plans    import bp as work_plans_bp
    from routes.clients       import bp as clients_bp
    from routes.ats           import bp as ats_bp
    from routes.achievements  import bp as achievements_bp
    from routes.chat          import bp as chat_bp
    from routes.calendar      import bp as calendar_bp
    from routes.mail          import bp as mail_bp

    for bp in (
        auth_bp, employees_bp, access_bp, pms_bp, attendance_bp,
        leaves_bp, assistant_bp, assets_bp, announcements_bp,
        notifications_bp, stats_bp, assessment_bp, lms_bp,
        career_bp, payroll_bp, work_plans_bp, clients_bp,
        ats_bp, achievements_bp, chat_bp, calendar_bp, mail_bp,
    ):
        app.register_blueprint(bp)

    # ── Background scheduler ──────────────────────────────────────────────────
    # Guard: don't start the scheduler during testing or when Flask reloader
    # spawns a child process (which would create duplicate cron jobs).
    if not app.testing and os.environ.get("WERKZEUG_RUN_MAIN") != "false":
        from jobs.scheduler import start_scheduler
        start_scheduler()

    return app


# Entry point
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
