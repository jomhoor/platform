# Jomhoor SSO — Cloudflare Workers reference

Drop-in OAuth2 auth-code + PKCE integration for any Cloudflare Workers + D1
relying party. Implements the two endpoints every RP must expose
(`/api/sso/start`, `/api/sso/callback`).

Live example: **DIFCongress** —
[`difcongress/worker/src/sso.js`](https://github.com/difcongress/difcongress).
Node/Fastify reference: **Taraaz** —
[`taraaz/services/api/src/service/sso.ts`](../../../../../taraaz/services/api/src/service/sso.ts).

## Files

| File | Purpose |
|------|---------|
| `sso.js` | Generic `handleSsoStart` + `handleSsoCallback` |
| `migration.sql` | D1 schema (`sso_pkce` table + user columns) |

## Setup

1. Copy `sso.js` into your Worker's `src/`.
2. Run `migration.sql` against your D1 database. Adjust the `ALTER TABLE` lines
   to match your user table name and primary key.
3. Wire the two routes in your `fetch` handler:
   ```js
   import { handleSsoStart, handleSsoCallback } from './sso.js';

   if (url.pathname === '/api/sso/start')    return handleSsoStart(url, env);
   if (url.pathname === '/api/sso/callback') return handleSsoCallback(url, env);
   ```
4. Set env + secrets in `wrangler.toml`:
   ```toml
   [vars]
   JOMHOOR_SSO_URL = "https://sso.jomhoor.org"
   JOMHOOR_CLIENT_ID = "your-client-id"
   ```
   ```bash
   wrangler secret put JOMHOOR_CLIENT_SECRET
   ```
5. Coordinate with the Jomhoor team to register your `client_id`,
   `client_secret` (bcrypt), `redirect_uris`, and `zk_required` flag in
   `sso_clients`.

## What you adapt

There are exactly two "Adapt-me" points in `sso.js`:

1. The `userRef` lookup in `handleSsoStart`. Most RPs pass an opaque, short-lived
   token in the link they emailed to the user.
2. The `UPDATE users SET sso_subject = ?, sso_verified_at = ...` write in
   `handleSsoCallback`. Replace the table name and key column.

Everything else (PKCE generation, state single-use, token exchange, JWT `sub`
extraction, optional `/v1/tokens/validate` check for `zk_verified`) is the same
for every relying party and should not be customised.

## Security invariants

- `code_verifier` never leaves the Worker.
- `state` is 128-bit random, single-use (row deleted on first callback).
- PKCE rows expire after 5 minutes.
- `client_secret` is a Worker secret, never in source.
- JWT signature is not verified locally — exchange is server-to-server over
  HTTPS with `sso.jomhoor.org`, which is the trust boundary.

See `docs/SSO/INTEGRATION.md` in the Platform repo for the full contract.
