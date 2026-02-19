# Raw SQL migrations

This folder contains manual (raw SQL) migrations for the Tasks v2 system:
- daily recurring tasks (UTC date boundary)
- automated vs manual verification
- dual currency rewards (OPN/USDT)
- snapshot rewards
- unified reward ledger
- redeem code system

Run the appropriate SQL file for your production DB:
- `001_tasks_v2_postgres.sql`
- `001_tasks_v2_mysql.sql`

Notes:
- MySQL: you may need to drop the *old* unique index on `(user_wallet, task_id)` in `task_submissions`.
  Use `SHOW INDEX FROM task_submissions;` to find the name, then uncomment/adjust the DROP INDEX line.
