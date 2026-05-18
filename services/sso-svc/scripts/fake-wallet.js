#!/usr/bin/env node
// Fake-wallet smoke runner for the Jomhoor SSO loop.
//
// Drives /v1/wallets/{challenge,register} and /v1/authorize{,/verify}
// against a local sso-svc, then follows the auth-code redirect into a
// local relying-party Worker so we can confirm the RP row gets stamped.
//
// Usage:
//   node platform/services/sso-svc/scripts/fake-wallet.js \
//        --signup-url "http://127.0.0.1:8787/api/sso/start?token=<token>"
//
// Flags:
//   --sso        sso-svc base URL                (default http://localhost:8003)
//   --signup-url RP-side /api/sso/start URL      (required)
//   --sk-hex     32-byte BabyJubjub private key  (default random)
//
// Trust-mode assumption: sso-svc is running with attestation.enabled=false.
// In that mode `appAttestation` / `appAssertion` are accepted as empty.

const path = require('node:path');
const Module = require('node:module');

// Borrow @iden3/js-crypto from jomhoor-wallet so we do not need to install.
const walletNodeModules = path.resolve(__dirname, '../../../../jomhoor-wallet/node_modules');
const jsCryptoEntry = require.resolve('@iden3/js-crypto', { paths: [walletNodeModules] });
const { babyJub, eddsa, ffUtils, Hex, poseidon, PublicKey, Signature } = require(jsCryptoEntry);
const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');

// ─── args ─────────────────────────────────────────────────────────────────────

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, tok, i, arr) => {
    if (tok.startsWith('--')) acc.push([tok.replace(/^--/, ''), arr[i + 1]]);
    return acc;
  }, []),
);
const SSO = (args.sso || 'http://localhost:8003').replace(/\/$/, '');
const SIGNUP_URL = args['signup-url'];
const SK_HEX = args['sk-hex'] || crypto.randomBytes(32).toString('hex');

if (!SIGNUP_URL) {
  console.error('error: --signup-url is required');
  console.error('example: --signup-url "http://127.0.0.1:8787/api/sso/start?token=<token>"');
  process.exit(2);
}

// ─── BabyJubjub key + signer (mirror of jomhoor-wallet/scripts/gen-sig-vector.js) ──

const BN254_FP = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);

const skBuff = Hex.decodeString(SK_HEX);
const sk = ffUtils.beBuff2int(skBuff);
const pkPoint = babyJub.mulPointEScalar(babyJub.Base8, sk);
const pk = new PublicKey(pkPoint);
const [pkX, pkY] = pk.p;
const subOrder = babyJub.subOrder;

const hexPad = (n) => '0x' + n.toString(16).padStart(64, '0');
const PUB_X = hexPad(pkX);
const PUB_Y = hexPad(pkY);
const WALLET_ADDR =
  '0x' + Buffer.from(ffUtils.beInt2Buff(poseidon.hash([pkX, pkY]), 32)).toString('hex');

function signChallenge(challengeHex) {
  const nonceBytes = Buffer.from(challengeHex.replace(/^0x/, ''), 'hex');
  const nonceBig = ffUtils.beBuff2int(Buffer.from(nonceBytes));
  const msg = nonceBig % BN254_FP;
  const r = poseidon.hash([sk, msg]) % subOrder;
  const R8 = babyJub.mulPointEScalar(babyJub.Base8, r);
  const hm = poseidon.hash([R8[0], R8[1], pkX, pkY, msg]);
  const S = (r + ((8n * hm * sk) % subOrder)) % subOrder;
  return '0x' + Buffer.from(eddsa.packSignature(new Signature(R8, S))).toString('hex');
}

// ─── small fetch helper ───────────────────────────────────────────────────────

async function jsonPost(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await resp.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch { parsed = text; }
  if (!resp.ok) {
    throw new Error(`${url} → ${resp.status}: ${text}`);
  }
  return parsed;
}

// ─── main ─────────────────────────────────────────────────────────────────────

(async () => {
  console.log(`[fake-wallet] sk=${SK_HEX}`);
  console.log(`[fake-wallet] walletAddress=${WALLET_ADDR}`);

  // 1. Register the wallet (idempotent — re-registering with a fresh challenge
  //    rotates the credential row).
  console.log('\n[1/4] POST /v1/wallets/challenge');
  const ch1 = await jsonPost(`${SSO}/v1/wallets/challenge`, { platform: 'ios' });
  console.log('  challenge =', ch1.challenge);

  console.log('\n[2/4] POST /v1/wallets/register');
  const reg = await jsonPost(`${SSO}/v1/wallets/register`, {
    walletAddress: WALLET_ADDR,
    publicKey: { x: PUB_X, y: PUB_Y },
    challenge: ch1.challenge,
    walletSignature: signChallenge(ch1.challenge),
    appAttestation: {},   // accepted when attestation.enabled=false
  });
  console.log('  registered =', reg);

  // 2. Drive the RP-side /api/sso/start to allocate PKCE + redirect to sso-svc.
  console.log(`\n[3/4] GET ${SIGNUP_URL}  (expect 302 → sso-svc)`);
  const startResp = await fetch(SIGNUP_URL, { redirect: 'manual' });
  if (startResp.status !== 302) {
    throw new Error(`RP /api/sso/start returned ${startResp.status}: ${await startResp.text()}`);
  }
  const authorizeURL = startResp.headers.get('location');
  console.log('  → ', authorizeURL);

  //    Hit /v1/authorize ourselves; sso-svc will 302 to jomhoor://auth/sso?challenge=...
  const authResp = await fetch(authorizeURL, { redirect: 'manual' });
  if (authResp.status !== 302) {
    throw new Error(`sso-svc /v1/authorize returned ${authResp.status}: ${await authResp.text()}`);
  }
  const deepLink = new URL(authResp.headers.get('location'));
  const authChallenge = deepLink.searchParams.get('challenge');
  const ssoState = deepLink.searchParams.get('state');
  console.log('  deepLink =', deepLink.toString());
  console.log('  challenge =', authChallenge);

  // 3. Sign the auth challenge and POST /v1/authorize/verify.
  console.log('\n[4/4] POST /v1/authorize/verify');
  const verifyResp = await jsonPost(`${SSO}/v1/authorize/verify`, {
    challenge: authChallenge,
    walletAddress: WALLET_ADDR,
    walletSignature: signChallenge(authChallenge),
    appAssertion: {},     // accepted when attestation.enabled=false
  });
  console.log('  redirect_url =', verifyResp.redirect_url);

  //    Drive the redirect back into the Worker; this is what the browser would
  //    do in a real flow. Worker exchanges the code server-to-server and stamps
  //    the signups row.
  const cbResp = await fetch(verifyResp.redirect_url, { redirect: 'manual' });
  console.log(`  worker /api/sso/callback → ${cbResp.status}`);
  console.log('  body[0..400]:', (await cbResp.text()).slice(0, 400));

  console.log(`\n[done] state echoed: ${ssoState}`);
})().catch((err) => {
  console.error('\n[fake-wallet] failed:', err.message);
  process.exit(1);
});
