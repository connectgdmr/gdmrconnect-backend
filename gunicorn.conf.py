"""
gunicorn.conf.py — GDMR Connect
==================================
Production server config. Auto-picked up by `gunicorn app_new:app` — no
start-command change needed on Railway, this file IS the config.

WHY THIS EXISTS:
Without it, gunicorn ran with its default of 1 sync worker — meaning the
whole backend served exactly one request at a time, with everything else
(every other user, every parallel fetch a single dashboard load fires)
queued behind it. `workers` below fixes that.

THE SCHEDULER GOTCHA THIS FILE SPECIFICALLY GUARDS AGAINST:
jobs/scheduler.py runs real cron jobs (PMS reminders, the owner's daily
digest, weekly work reports, LMS expiry reminders) that each send emails.
Each gunicorn worker is a separate OS process that imports and runs
app_new.py's create_app() independently — so naively going from 1 worker
to N would make every one of those jobs fire N times, i.e. N duplicate
reminder emails to every employee, every time. `when_ready` below starts
the scheduler exactly ONCE, in the gunicorn master process, before any
workers are forked — regardless of how many workers you run. app_new.py's
own start_scheduler() call was removed to match (it now only fires when
running the Flask dev server directly via `python app_new.py`).
"""
import os

# Railway sets WEB_CONCURRENCY automatically based on the plan's CPU count
# on some plan tiers; falls back to 4 if it isn't set. Raise this later if
# you upgrade the plan and want to use the extra CPU — safe to change any
# time, doesn't touch application code.
workers = int(os.environ.get("WEB_CONCURRENCY", 4))
threads = 1
worker_class = "sync"
# 120s (was 60): the yearly HR spreadsheet reports (Master Tracker + its
# Dep-wise / Leave-Monitoring / Late-Coming sheets) do a lot of work in one
# request; 60s was tight enough to kill the worker mid-build on a full roster.
timeout = 120


def when_ready(server):
    from jobs.scheduler import start_scheduler
    start_scheduler()
