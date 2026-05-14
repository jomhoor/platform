-- +migrate Up

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Root wallet registry. Internal identifiers only.
-- walletAddress and public key material stay here; never exposed to relying parties.
CREATE TABLE IF NOT EXISTS wallets (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(66) NOT NULL UNIQUE,  -- "0x" + 32-byte hex; internal root id
    public_key_x   VARCHAR(66) NOT NULL,          -- 0x-prefixed, 32 bytes zero-padded
    public_key_y   VARCHAR(66) NOT NULL,          -- 0x-prefixed, 32 bytes zero-padded
    registered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- App-level attestation credentials.
-- One row per attested device/install. A wallet can have at most one active
-- credential per platform (previous rows are revoked on re-install).
CREATE TABLE IF NOT EXISTS app_credentials (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id           UUID        NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    platform            TEXT        NOT NULL CHECK (platform IN ('ios', 'android')),
    credential_id       TEXT        NOT NULL,     -- App Attest key ID or Play Integrity token ID
    attestation_key_id  TEXT,                     -- iOS App Attest key ID (stored separately from credential_id for assertion verification)
    attestation_status  TEXT        NOT NULL DEFAULT 'verified'
                                    CHECK (attestation_status IN ('verified', 'revoked')),
    attested_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS app_credentials_wallet_id_idx ON app_credentials(wallet_id);
CREATE INDEX IF NOT EXISTS app_credentials_status_idx    ON app_credentials(attestation_status);

-- Minimal trust assertions. SSO reads only these, not raw identity tables.
-- assertion_type examples: zk_verified, kyc_passed, organizer_role
CREATE TABLE IF NOT EXISTS assertions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id       UUID        NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    assertion_type  TEXT        NOT NULL,
    status          BOOLEAN     NOT NULL DEFAULT TRUE,
    nullifier_hash  BYTEA,                        -- populated only for zk_verified; recovery anchor
    source          TEXT        NOT NULL,          -- zkp-svc | kyc-svc | admin-panel
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS assertions_wallet_id_type_idx ON assertions(wallet_id, assertion_type);

-- SSO client (relying party) registry.
-- Created before pairwise_subjects and sso_challenges because both reference it.
CREATE TABLE IF NOT EXISTS sso_clients (
    id            TEXT        PRIMARY KEY,         -- client_id, e.g. "taraaz.jomhoor.org"
    name          TEXT        NOT NULL,
    logo_url      TEXT,
    redirect_uris TEXT[]      NOT NULL DEFAULT '{}',
    client_secret TEXT        NOT NULL,            -- hashed; never stored in plaintext
    zk_required   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-client pseudonymous subjects. One row per (wallet, client) pair.
-- This is the only identifier relying parties may receive.
CREATE TABLE IF NOT EXISTS pairwise_subjects (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id  UUID        NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    client_id  TEXT        NOT NULL REFERENCES sso_clients(id),
    subject    TEXT        NOT NULL UNIQUE,       -- HMAC(secret, walletId||clientId)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (wallet_id, client_id)
);

CREATE INDEX IF NOT EXISTS pairwise_subjects_wallet_idx ON pairwise_subjects(wallet_id);

-- Short-lived login challenge state (auth-code + PKCE flow).
CREATE TABLE IF NOT EXISTS sso_challenges (
    nonce          TEXT        PRIMARY KEY,
    client_id      TEXT        NOT NULL REFERENCES sso_clients(id),
    redirect_uri   TEXT        NOT NULL,
    state          TEXT        NOT NULL,
    code_challenge TEXT        NOT NULL,           -- S256 PKCE challenge from client
    expires_at     TIMESTAMPTZ NOT NULL,
    used           BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS sso_challenges_expires_idx ON sso_challenges(expires_at);

-- +migrate Down

DROP TABLE IF EXISTS sso_challenges;
DROP TABLE IF EXISTS pairwise_subjects;
DROP TABLE IF EXISTS assertions;
DROP TABLE IF EXISTS app_credentials;
DROP TABLE IF EXISTS wallets;
DROP TABLE IF EXISTS sso_clients;
