-- Tasks v2 migration (MySQL)

-- 1) tasks table extensions
ALTER TABLE tasks
  ADD COLUMN task_type VARCHAR(16) NOT NULL DEFAULT 'one_time',
  ADD COLUMN verification_type VARCHAR(16) NOT NULL DEFAULT 'manual',
  ADD COLUMN reward_currency VARCHAR(8) NOT NULL DEFAULT 'OPN',
  ADD COLUMN reward_amount DECIMAL(20,8) NULL,
  ADD COLUMN category VARCHAR(64) NOT NULL DEFAULT 'General',
  ADD COLUMN sort_order INT NOT NULL DEFAULT 0,
  ADD COLUMN metadata JSON NULL;

UPDATE tasks
SET reward_amount = IFNULL(reward_amount, reward);

-- 2) task_submissions extensions
ALTER TABLE task_submissions
  ADD COLUMN period_key VARCHAR(16) NULL,
  ADD COLUMN proof_payload JSON NULL,
  ADD COLUMN reviewer VARCHAR(128) NULL,
  ADD COLUMN approved_at DATETIME NULL,
  ADD COLUMN reward_currency_snapshot VARCHAR(8) NULL,
  ADD COLUMN reward_amount_snapshot DECIMAL(20,8) NULL;

UPDATE task_submissions
SET period_key = 'ONE_TIME'
WHERE period_key IS NULL;

UPDATE task_submissions
SET proof_payload = JSON_OBJECT('proof_url', proof_url)
WHERE proof_payload IS NULL
  AND proof_url IS NOT NULL
  AND LENGTH(TRIM(proof_url)) > 0;

UPDATE task_submissions s
JOIN tasks t ON t.id = s.task_id
SET
  s.reward_currency_snapshot = IFNULL(s.reward_currency_snapshot, IFNULL(t.reward_currency, 'OPN')),
  s.reward_amount_snapshot   = IFNULL(s.reward_amount_snapshot, IFNULL(t.reward_amount, IFNULL(t.reward, 0)))
WHERE s.reward_currency_snapshot IS NULL OR s.reward_amount_snapshot IS NULL;

UPDATE task_submissions
SET approved_at = IFNULL(approved_at, IFNULL(reviewed_at, submitted_at))
WHERE status = 'approved' AND approved_at IS NULL;

-- Drop old unique index (adjust name after SHOW INDEX if needed)
-- ALTER TABLE task_submissions DROP INDEX user_wallet_task_id;

ALTER TABLE task_submissions
  ADD UNIQUE KEY task_submissions_wallet_task_period_uniq (user_wallet, task_id, period_key);

-- 3) unified reward ledger
CREATE TABLE IF NOT EXISTS reward_ledger (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  wallet VARCHAR(64) NOT NULL,
  source_type VARCHAR(16) NOT NULL,
  source_id BIGINT NULL,
  currency VARCHAR(8) NOT NULL,
  amount DECIMAL(20,8) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY reward_ledger_source_uniq (source_type, source_id, currency),
  KEY reward_ledger_wallet_currency_idx (wallet, currency)
);

INSERT IGNORE INTO reward_ledger (wallet, source_type, source_id, currency, amount, created_at)
SELECT
  tr.user_wallet AS wallet,
  'task' AS source_type,
  s.id AS source_id,
  IFNULL(s.reward_currency_snapshot, 'OPN') AS currency,
  IFNULL(tr.amount, IFNULL(s.reward_amount_snapshot, 0)) AS amount,
  IFNULL(tr.created_at, NOW()) AS created_at
FROM task_reward_transactions tr
JOIN task_submissions s
  ON s.user_wallet = tr.user_wallet
 AND s.task_id = tr.task_id
 AND s.period_key = 'ONE_TIME';

-- 4) redeem codes
CREATE TABLE IF NOT EXISTS redeem_codes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(64) NOT NULL UNIQUE,
  valid_date VARCHAR(10) NOT NULL,
  reward_currency VARCHAR(8) NOT NULL DEFAULT 'USDT',
  reward_amount DECIMAL(20,8) NOT NULL DEFAULT 0,
  max_uses INT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS redeem_redemptions (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  wallet VARCHAR(64) NOT NULL,
  code_id BIGINT NOT NULL,
  valid_date VARCHAR(10) NOT NULL,
  redeemed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY redeem_wallet_day_uniq (wallet, valid_date),
  UNIQUE KEY redeem_wallet_code_uniq (wallet, code_id),
  CONSTRAINT fk_redeem_code FOREIGN KEY (code_id) REFERENCES redeem_codes(id)
);
