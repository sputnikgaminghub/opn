# Deploy to Render (Production)

This app is Render-ready with `render.yaml`.

## 1) Create the service
- In Render, create a **New Web Service** from your GitHub repo.
- Render will detect `render.yaml` and provision:
  - A web service (`apro-airdrop`)
  - A Postgres database (`apro-db`)

## 2) Set required environment variables
In the Render dashboard for the web service, set:
- `ADMIN_API_KEY` (legacy / optional) — fallback key used if a per-dashboard key is not set
- `ADMIN_TASKS_KEY` (recommended) — tasks dashboard login key
- `ADMIN_WITHDRAWALS_KEY` (recommended) — withdrawals dashboard login key
- `ADMIN_ANNOUNCEMENTS_KEY` (recommended) — announcements dashboard login key
- `ADMIN_PRESALE_KEY` (recommended) — presale dashboard login key
- `ADMIN_WALLET` (optional) — wallet used for admin bootstrap (defaults to the value in `render.yaml`)
- `ETH_RPC_URL` (required for ETH fee validation)
- `BSC_RPC_URL` (required for BSC fee validation)

Web3 gateway (recommended for presale payments):
- `WALLETCONNECT_PROJECT_ID` — required for WalletConnect (mobile + desktop QR)
- `SOL_PRESALE_WALLET` — required to enable SOL payments (Solana tab)
- `SOL_RPC_URL` — required for SOL transactions (do NOT use `https://api.mainnet-beta.solana.com` in browsers; use a provider like Helius/QuickNode/Alchemy)

Price feed:
- `PRICE_CACHE_TTL_SECONDS` (optional) — server-side price cache TTL (default: 25 seconds). This reduces CoinGecko 429 rate limits for users.

Recommended:
- `RATE_LIMIT_STORAGE_URL` — set to a Redis URL if you run multiple instances (otherwise keep `memory://`).

## 3) Start command
Already configured:

`gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4`

## 4) Notes
- The app auto-creates tables at startup (`db.create_all()`).
- If you later switch schemas or need migrations, add a migration tool (Alembic/Flask-Migrate).
## 5) Web Push Notifications (Android + Desktop)

### Required env vars
Set these on the web service (and the cron job if you use it):
- `VAPID_PUBLIC_KEY` — base64url (no padding)
- `VAPID_PRIVATE_KEY` — PEM (multiline). Keep the `-----BEGIN PRIVATE KEY-----` block intact.
- `VAPID_SUBJECT` — e.g. `mailto:admin@example.com` (required by the Web Push spec)

### Generate VAPID keys
Run locally:
- `python scripts/generate_vapid_keys.py`

Copy:
- the printed `VAPID_PUBLIC_KEY` into Render env var `VAPID_PUBLIC_KEY`
- the printed PEM block into Render env var `VAPID_PRIVATE_KEY`

### Daily send schedule (12:00 UTC)
This repo includes a scheduler-friendly script:
- `python scripts/send_daily_push.py`

If you use Render Cron Jobs, schedule it at:
- `0 12 * * *` (12:00 UTC)

Notes:
- The backend enforces **max 1 notification per subscription per UTC day**.
- Users must opt in via the browser permission prompt. The site shows a small prompt ~15 seconds after load.


## Staking module env vars
Set these on the **web** service (and worker if you add it):
- `STAKE_HOLDING_WALLET_ETH` = your ETH holding wallet
- `STAKE_HOLDING_WALLET_BSC` = your BSC holding wallet
- `ADMIN_STAKING_KEY` = staking admin login key for `/admin/staking/login`

  (Back-compat: the code will also read `STAKE_ADMIN_GATE_KEY` if `ADMIN_STAKING_KEY` is not set.)
- `STAKE_REWARD_PER_ETH_PER_DAY` (default 200)
- `STAKE_REWARD_PER_BNB_PER_DAY` (default 50)
- `STAKE_ETH_CONFIRMATIONS` (default 12)
- `STAKE_BSC_CONFIRMATIONS` (default 15)
- `STAKE_WATCHER_INTERVAL_SECONDS` (default 25)

### Worker (recommended)
Create a **Background Worker** on Render:
- Build: `pip install -r requirements.txt`
- Start: `python staking_worker.py`
Use the same DATABASE_URL and env vars as the web service.


## Important
- Set `SECRET_KEY` on Render (required for sessions / staking login).

## Session hardening (recommended)
- `SESSION_LIFETIME_HOURS` (default: 1)
- `SESSION_IDLE_TIMEOUT_MINUTES` (default: 15)
- `SESSION_COOKIE_SAMESITE` (default: Lax)
- Optional server-side sessions: set `USE_SERVER_SIDE_SESSIONS=1` and `SESSION_REDIS_URL` (or `REDIS_URL`)