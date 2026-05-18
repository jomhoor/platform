-- +migrate Up

-- M5 — ZK-nullifier recovery anchor.
-- POST /v1/wallets/recover looks up the most recent zk_verified assertion by
-- nullifier_hash to find the prior wallet_id. Without an index this is a full
-- table scan on every recovery attempt.
CREATE INDEX IF NOT EXISTS assertions_nullifier_hash_idx
    ON assertions(nullifier_hash)
    WHERE nullifier_hash IS NOT NULL;

-- +migrate Down

DROP INDEX IF EXISTS assertions_nullifier_hash_idx;
