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
The data is fake, lives in memory, and resets whenever the service restarts.

## B. Demo site — Vercel: Add New Project -> same frontend repo
Environment variables:
- VITE_BRAND=aieque
- VITE_API_URL=https://<railway-domain>/api
Deploy. Share the Vercel link. Login page has Admin / Manager / Employee buttons.

## After the visit
Delete both. Nothing else was touched.
