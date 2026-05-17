-- +migrate Up

-- Assertion data is no longer stored on transient auth codes (M2.5).
-- The /v1/tokens/validate endpoint fetches zk_verified live from the assertions table,
-- so carrying a stale snapshot here was both redundant and a privacy concern.
ALTER TABLE sso_auth_codes DROP COLUMN IF EXISTS zk_verified;

-- +migrate Down

ALTER TABLE sso_auth_codes ADD COLUMN IF NOT EXISTS zk_verified BOOLEAN NOT NULL DEFAULT FALSE;
