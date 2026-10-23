# Aieque sales demo — setup (temporary, separate from production)

The demo is the same code running as a second, disposable copy with its own database full of fake data.
Nothing here touches GDMR production data.

## 1. Database (MongoDB Atlas)
Use the same cluster; the demo uses a different database name, `aieque_demo` (created automatically).

## 2. Demo backend (new Railway service from the same backend repo)
Environment variables:
- `DEMO_MODE=1`
- `MONGO_DB_NAME=aieque_demo`
- `MONGO_URI` — same Atlas URI
- `SECRET_KEY` — any new long random string (do NOT reuse production's)
- `CORS_ORIGINS=https://<your-demo-vercel-domain>`
No email / Cloudinary / scheduler keys are needed (emails are suppressed, uploads stubbed, cron off).

## 3. Load the fake data (run once on your PC, also = "reset the demo")
```
set MONGO_URI=<atlas uri>
set MONGO_DB_NAME=aieque_demo
set DEMO_MODE=1
set SECRET_KEY=anything-long-and-random-1234567890
python tools/seed_demo.py
```
It refuses to run on `attendance_db`. Logins (password `Demo@12345`): admin@ / manager@ / employee@aieque-demo.com.

## 4. Demo frontend (new Vercel project from the same frontend repo)
Environment variables:
- `VITE_BRAND=aieque`
- `VITE_API_URL=https://<demo-railway-domain>/api`
Open the site: login page has one-click Admin / Manager / Employee buttons.

## 5. After the visit
Delete the two demo services and drop the `aieque_demo` database.
