-- +migrate Up

-- Short-lived nonces for wallet registration (M2).
-- Kept separate from sso_challenges because registration has no client_id / PKCE.
CREATE TABLE IF NOT EXISTS wallet_challenges (
    nonce      TEXT        PRIMARY KEY,
    platform   TEXT        NOT NULL CHECK (platform IN ('ios', 'android')),
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS wallet_challenges_expires_idx ON wallet_challenges(expires_at);

-- +migrate Down

DROP TABLE IF EXISTS wallet_challenges;
