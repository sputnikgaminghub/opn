BEGIN;

ALTER TABLE tasks ADD COLUMN IF NOT EXISTS task_type VARCHAR(16) NOT NULL DEFAULT 'one_time';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS verification_type VARCHAR(16) NOT NULL DEFAULT 'manual';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS reward_currency VARCHAR(8) NOT NULL DEFAULT 'OPN';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS reward_amount NUMERIC(20,8);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS category VARCHAR(64) NOT NULL DEFAULT 'General';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS sort_order INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE tasks SET reward_amount = COALESCE(reward_amount, reward);

ALTER TABLE task_submissions ADD COLUMN IF NOT EXISTS period_key VARCHAR(16);
ALTER TABLE task_submissions ADD COLUMN IF NOT EXISTS proof_payload JSONB;
ALTER TABLE task_submissions ADD COLUMN IF NOT EXISTS reviewer VARCHAR(128);
ALTER TABLE task_submissions ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP;
ALTER TABLE task_submissions ADD COLUMN IF NOT EXISTS reward_currency_snapshot VARCHAR(8);
ALTER TABLE task_submissions ADD COLUMN IF NOT EXISTS reward_amount_snapshot NUMERIC(20,8);

UPDATE task_submissions SET period_key='ONE_TIME' WHERE period_key IS NULL;

UPDATE task_submissions s
SET reward_currency_snapshot = COALESCE(s.reward_currency_snapshot, t.reward_currency, 'OPN'),
    reward_amount_snapshot   = COALESCE(s.reward_amount_snapshot, t.reward_amount, t.reward, 0)
FROM tasks t
WHERE t.id = s.task_id
  AND (s.reward_currency_snapshot IS NULL OR s.reward_amount_snapshot IS NULL);

UPDATE task_submissions SET approved_at = COALESCE(approved_at, reviewed_at, submitted_at)
WHERE status='approved' AND approved_at IS NULL;

-- Replace old unique constraint if present (adjust name if different)
ALTER TABLE task_submissions DROP CONSTRAINT IF EXISTS uq_task_submission_wallet_task;
ALTER TABLE task_submissions DROP CONSTRAINT IF EXISTS uq_task_submission_wallet_task_period;
ALTER TABLE task_submissions ADD CONSTRAINT uq_task_submission_wallet_task_period
  UNIQUE (user_wallet, task_id, period_key);

CREATE TABLE IF NOT EXISTS reward_ledger (
  id BIGSERIAL PRIMARY KEY,
  wallet VARCHAR(42) NOT NULL,
  source_type VARCHAR(16) NOT NULL,
  source_id BIGINT,
  currency VARCHAR(8) NOT NULL,
  amount NUMERIC(20,8) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_reward_ledger_source UNIQUE (source_type, source_id, currency)
);
CREATE INDEX IF NOT EXISTS idx_reward_ledger_wallet_currency ON reward_ledger (wallet, currency);

INSERT INTO reward_ledger (wallet, source_type, source_id, currency, amount, created_at)
SELECT tr.user_wallet, 'task', s.id, COALESCE(s.reward_currency_snapshot,'OPN'),
       COALESCE(tr.amount, s.reward_amount_snapshot, 0), COALESCE(tr.created_at, NOW())
FROM task_reward_transactions tr
JOIN task_submissions s
  ON s.user_wallet = tr.user_wallet AND s.task_id = tr.task_id AND s.period_key='ONE_TIME'
ON CONFLICT (source_type, source_id, currency) DO NOTHING;

CREATE TABLE IF NOT EXISTS redeem_codes (
  id BIGSERIAL PRIMARY KEY,
  code VARCHAR(64) NOT NULL UNIQUE,
  valid_date VARCHAR(10) NOT NULL,
  reward_currency VARCHAR(8) NOT NULL DEFAULT 'USDT',
  reward_amount NUMERIC(20,8) NOT NULL DEFAULT 0,
  max_uses INTEGER,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS redeem_redemptions (
  id BIGSERIAL PRIMARY KEY,
  wallet VARCHAR(42) NOT NULL,
  code_id BIGINT NOT NULL REFERENCES redeem_codes(id),
  valid_date VARCHAR(10) NOT NULL,
  redeemed_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_redeem_wallet_day UNIQUE (wallet, valid_date),
  CONSTRAINT uq_redeem_wallet_code UNIQUE (wallet, code_id)
);

COMMIT;
