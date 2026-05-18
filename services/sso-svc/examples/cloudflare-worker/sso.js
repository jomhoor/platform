// Jomhoor SSO — Cloudflare Workers reference integration.
//
// Drop-in template. Adapt the `Adapt-me` blocks for your storage and your
// "user row" concept; everything else (PKCE, state, exchange, JWT parse) is
// generic across relying parties.
//
// Required env vars (wrangler.toml `[vars]` or secrets):
//   JOMHOOR_SSO_URL          e.g. https://sso.jomhoor.org   (default if unset)
//   JOMHOOR_CLIENT_ID        your client_id, agreed with Jomhoor
//   JOMHOOR_CLIENT_SECRET    secret value (sso-svc stores its bcrypt hash)
//   WORKER_URL               public base URL of this Worker (optional)
//
// Required D1 schema: see migration.sql in this directory.
//
// Wire in your fetch handler:
//
//   if (url.pathname === '/api/sso/start')    return handleSsoStart(url, env);
//   if (url.pathname === '/api/sso/callback') return handleSsoCallback(url, env);

const PKCE_TTL_SECONDS = 5 * 60;

function ssoBase(env)          { return env.JOMHOOR_SSO_URL || 'https://sso.jomhoor.org'; }
function clientID(env)         { return env.JOMHOOR_CLIENT_ID; }
function workerBase(env, url)  { return env.WORKER_URL || `${url.protocol}//${url.host}`; }

// ─── Web Crypto helpers ───────────────────────────────────────────────────────

function base64UrlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function randomVerifier() {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
}
async function s256Challenge(verifier) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(hash));
}
function parseJwtSub(token) {
  try {
    const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const payload = JSON.parse(atob(padded));
    return typeof payload.sub === 'string' ? payload.sub : null;
  } catch { return null; }
}

// ─── GET /api/sso/start ───────────────────────────────────────────────────────

export async function handleSsoStart(url, env) {
  // Adapt-me: identify which of your user rows is starting SSO. Most RPs pass
  // a short-lived token in the query string of an email/UI link.
  const userRef = url.searchParams.get('token');
  if (!userRef) return new Response('Missing token', { status: 400 });

  const state = crypto.randomUUID();
  const codeVerifier = randomVerifier();
  const codeChallenge = await s256Challenge(codeVerifier);
  const expiresAt = Math.floor(Date.now() / 1000) + PKCE_TTL_SECONDS;

  await env.DB.prepare(
    `INSERT INTO sso_pkce (state, code_verifier, user_ref, expires_at) VALUES (?, ?, ?, ?)`
  ).bind(state, codeVerifier, userRef, expiresAt).run();

  const params = new URLSearchParams({
    client_id: clientID(env),
    redirect_uri: `${workerBase(env, url)}/api/sso/callback`,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });
  return Response.redirect(`${ssoBase(env)}/v1/authorize?${params}`, 302);
}

// ─── GET /api/sso/callback ────────────────────────────────────────────────────

export async function handleSsoCallback(url, env) {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) return new Response('Missing code or state', { status: 400 });

  const pkce = await env.DB.prepare(
    'SELECT code_verifier, user_ref, expires_at FROM sso_pkce WHERE state = ?'
  ).bind(state).first();
  if (pkce) await env.DB.prepare('DELETE FROM sso_pkce WHERE state = ?').bind(state).run();
  if (!pkce) return new Response('Unknown or already-used state', { status: 400 });
  if (pkce.expires_at < Math.floor(Date.now() / 1000)) {
    return new Response('SSO session expired', { status: 400 });
  }

  const resp = await fetch(`${ssoBase(env)}/v1/tokens/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      client_id: clientID(env),
      client_secret: env.JOMHOOR_CLIENT_SECRET,
      code_verifier: pkce.code_verifier,
    }),
  });
  if (!resp.ok) {
    console.error('[SSO] exchange failed:', resp.status, await resp.text());
    return new Response('Identity verification failed', { status: 400 });
  }
  const { access_token: accessToken } = await resp.json();
  const subject = parseJwtSub(accessToken);
  if (!subject) return new Response('Invalid token from SSO', { status: 502 });

  // Optional live trust check (only needed if zk_required is true for your client):
  //   const v = await fetch(`${ssoBase(env)}/v1/tokens/validate`, {
  //     headers: { Authorization: `Bearer ${accessToken}` } });
  //   const { assertions } = await v.json();
  //   const zk = assertions?.some(a => a.assertion_type === 'zk_verified' && a.status === 'active');

  // Adapt-me: stamp `subject` against your user row (here: `pkce.user_ref`).
  await env.DB.prepare(
    `UPDATE users SET sso_subject = ?, sso_verified_at = datetime('now') WHERE token = ?`
  ).bind(subject, pkce.user_ref).run();

  return new Response('Identity verified.', { status: 200 });
}
