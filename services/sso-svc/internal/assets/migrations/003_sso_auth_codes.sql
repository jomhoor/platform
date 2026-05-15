-- +migrate Up

-- One-time authorization codes issued by POST /v1/authorize/verify and
-- consumed by POST /v1/tokens/exchange (auth-code + PKCE flow, M3).
--
-- Each row binds a code to (client, pairwise subject, PKCE code_challenge).
-- The `used` column is flipped atomically on consumption to prevent replay.
CREATE TABLE IF NOT EXISTS sso_auth_codes (
    code              TEXT        PRIMARY KEY,            -- random 32-byte hex
    client_id         TEXT        NOT NULL REFERENCES sso_clients(id),
    pairwise_subject  TEXT        NOT NULL,               -- already pseudonymous; safe to store
    code_challenge    TEXT        NOT NULL,               -- S256 challenge from /authorize
    zk_verified       BOOLEAN     NOT NULL DEFAULT FALSE, -- snapshot at consent time
    expires_at        TIMESTAMPTZ NOT NULL,
    used              BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sso_auth_codes_expires_idx ON sso_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS sso_auth_codes_client_idx  ON sso_auth_codes(client_id);

-- +migrate Down

DROP TABLE IF EXISTS sso_auth_codes;
