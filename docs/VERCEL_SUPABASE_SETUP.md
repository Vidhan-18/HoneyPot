# Vercel + Supabase + AWS EC2 Deployment

Architecture **A**: honeypots on **AWS EC2**, dashboard on **Vercel**, data in **Supabase**.

```
Attackers → AWS EC2 (Docker honeypots)
                ↓ files (/sessions, /logs, …)
            supabase-sync container
                ↓
            Supabase Postgres
                ↓ Realtime + REST
            Vercel (Flask dashboard)
```

---

## 1. Supabase project

1. Create a project at [supabase.com](https://supabase.com).
2. Open **SQL Editor** → run the full script: [`supabase/schema.sql`](../supabase/schema.sql).
3. Enable **Realtime** for tables (if `ALTER PUBLICATION` fails in SQL):
   - **Database → Replication**
   - Enable `honeypot_sessions` and `honeypot_logs`
4. Copy API keys from **Settings → API**:
   - `Project URL` → `SUPABASE_URL`
   - `anon` `public` → `SUPABASE_ANON_KEY` (Vercel + browser)
   - `service_role` `secret` → `SUPABASE_SERVICE_ROLE_KEY` (AWS EC2 sync + Vercel server only)

Never commit `service_role` to git or expose it in the browser.

---

## 2. Vercel (dashboard)

1. Import this GitHub repo in [Vercel](https://vercel.com).
2. Root directory: repository root (uses root `vercel.json`).
3. Set **Environment Variables** (Production + Preview):

| Variable | Value |
|----------|--------|
| `ENVIRONMENT` | `production` |
| `SECRET_KEY` | random 64-char hex |
| `ADMIN_USERNAME` | your admin user |
| `ADMIN_PASSWORD` | strong password |
| `SUPABASE_URL` | `https://xxx.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | service role key |
| `SUPABASE_ANON_KEY` | anon key |
| `USE_SUPABASE_REALTIME` | `true` |

4. Deploy. Open `https://your-app.vercel.app/login`.

`vercel.json` routes all traffic to the Flask `app` in `monitoring/web-dashboard/web_dashboard.py`.

---

## 3. Supabase Realtime (replaces Socket.IO)

The dashboard subscribes in the browser to **INSERT** events:

- `honeypot_sessions` → refresh stats + sessions tab
- `honeypot_logs` → refresh logs tab

Requirements:

1. Realtime enabled on those tables (step 1.3).
2. RLS policies allow **SELECT** (included in `schema.sql`).
3. `SUPABASE_ANON_KEY` set on Vercel (injected into `dashboard.html`).

If Realtime fails, the UI falls back to **polling every 5s** (`/api/stats` + `loadData()`).

Status line meanings:

- **Live (Supabase)** — Realtime connected
- **Polling Mode** — fallback (missing keys or Realtime off)

---

## 4. AWS EC2 (honeypots + sync)

On the VM:

```bash
git clone <your-repo>
cd HoneyPot-main
cp .env.example .env
# Edit .env: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, alerting, etc.

docker compose up -d
docker compose --profile supabase up -d supabase-sync
```

`supabase-sync` watches `./data/sessions`, `./data/logs`, `./data/iocs`, `./data/pcaps` and upserts into Supabase every 15s (configurable via `SUPABASE_SYNC_INTERVAL`).

Open AWS Security Groups for honeypot ports (2222, 8080, 21, 445, etc.) — only expose what you intend to trap.

---

## 5. Verify end-to-end

1. Trigger a test connection to HTTP honeypot on the VM.
2. Wait ~15s for sync.
3. Check Supabase **Table Editor** → `honeypot_sessions` has a row.
4. Vercel dashboard should update live (or within 5s polling).

---

## 6. Local development

Without Supabase (filesystem mode):

```bash
cd monitoring/web-dashboard
pip install -r requirements.txt
export FLASK_ENV=development
export ENABLE_MOCK_API=true
python web_dashboard.py
```

With Supabase locally, set `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` in `.env`.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Login fails on Vercel | Set `ADMIN_PASSWORD` or `DASHBOARD_PASSWORD_HASH` |
| Empty dashboard | Confirm `supabase-sync` running; check Supabase tables |
| Realtime stuck on Polling | Enable Replication; verify `SUPABASE_ANON_KEY` on Vercel |
| Mock data on map | Set `ENVIRONMENT=production`; do not set `ENABLE_MOCK_API` |
