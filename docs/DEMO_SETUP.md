# Aieque sales demo — go online (no database needed)

Two new things, both from the SAME repos, both separate from production:

## A. Demo backend — Railway: New Service -> same backend repo
Variables:
- DEMO_MODE=1
- DEMO_INMEMORY=1
- WEB_CONCURRENCY=1   (important: one worker so everyone sees the same data)
- SECRET_KEY=<any long random text>
- CORS_ORIGINS=https://<your-demo-vercel-url>   (add after step B, then redeploy)
Settings -> Networking -> Generate Domain. Test: https://<domain>/api/demo-info shows {"demo":true}.
The demo starts EMPTY: only three logins, no sample data. Whatever the client enters lives in memory and is wiped whenever the service restarts.

## B. Demo site — Vercel: Add New Project -> same frontend repo
Environment variables:
- VITE_BRAND=aieque
- VITE_API_URL=https://<railway-domain>/api
Deploy. Share the Vercel link and these logins (password Aieque@2026): admin@aieque.com, manager@aieque.com, employee@aieque.com.
Modules shown: Dashboard, Attendance, Leave, Assets, Announcements, Payroll (+ Workforce / Departments for the admin). No chat, courses, special access, work or sales modules.

## After the visit
Delete both. Nothing else was touched.
