-- Single-use PKCE state for Jomhoor SSO. One row per /api/sso/start.
-- Rows are deleted on the matching /api/sso/callback (or by lazy cleanup).

CREATE TABLE IF NOT EXISTS sso_pkce (
  state         TEXT    PRIMARY KEY,
  code_verifier TEXT    NOT NULL,
  user_ref      TEXT    NOT NULL,  -- whatever identifies your user row
  expires_at    INTEGER NOT NULL   -- unix epoch seconds
);

CREATE INDEX IF NOT EXISTS sso_pkce_expires_idx ON sso_pkce (expires_at);

-- And add these to your existing user table:
--   ALTER TABLE users ADD COLUMN sso_subject TEXT;
--   ALTER TABLE users ADD COLUMN sso_verified_at DATETIME;
