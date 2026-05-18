# Jomhoor Platform

Backend infrastructure for [Jomhoor](https://jomhoor.org) — identity registration and voting services for the [Iranians.Vote.](https://Iranians.Vote.)

**Repository:** [github.com/Jomhoor/platform](https://github.com/Jomhoor/platform)
**Branch:** `NID` (National ID card support)

---

## Overview

This directory contains all backend services, smart contracts, deployment configurations, and utility scripts that power the Jomhoor platform. The mobile app communicates with these services to register verified identities and submit votes on the Rarimo L2 blockchain.

```
Mobile App ──► nginx gateway (:8000)
                  ├── /integrations/registration-relayer/*  → Identity registration
                  ├── /integrations/proof-verification-relayer/*  → Voting
                  └── sso.jomhoor.org  → sso-svc  ("Sign in with Jomhoor")
                                          │
                              ┌────────────┴────────────┐
                              ▼                         ▼
                        Rarimo L2                  PostgreSQL
                       Blockchain                   Database
```

## Directory Structure

```
platform/
├── configs/                          # Service configuration files
│   ├── nginx.conf                    # API gateway routing
│   ├── registration-relayer*.yaml    # Identity registration config (local/testnet/prod)
│   ├── proof-verification-relayer*.yaml  # Voting config (local/testnet/prod)
│   └── sso-svc*.yaml                 # "Sign in with Jomhoor" config (env placeholders only)
├── deploy/                           # Production deployment
│   ├── deploy.sh                     # Deploy script (start/stop/update/logs)
│   ├── docker-compose.production.yaml
│   ├── docker-compose.agora.yaml     # Agora deliberation stack
│   └── nginx-vhosts/                  # Nginx vhost configs for api.iranians.vote
├── scripts/                          # Development & debugging utilities
│   ├── setup-local.sh                # One-command local setup (Hardhat + contracts + Docker)
│   ├── check-proposals.js            # Inspect on-chain proposals
│   ├── decode-proposals.js           # Decode proposal parameters
│   ├── debug-inid-citizenship.js     # Debug INID citizenship mask issues
│   ├── check-mainnet-contract.js     # Verify mainnet contract state
│   └── helpers/                      # Proposal creation & contract deployment helpers
├── services/                         # Backend services (Git submodules / clones)
│   ├── passport-contracts/           # Identity registration smart contracts (Solidity)
│   ├── passport-voting-contracts/    # Voting smart contracts (NoirIDVoting, IDCardVoting)
│   ├── registration-relayer/         # Go service — submits registration txs to Rarimo L2
│   ├── proof-verification-relayer/   # Go service — submits vote txs (feat/noir-voting branch)
│   ├── sso-svc/                      # Go service — "Sign in with Jomhoor" OAuth2 + PKCE
│   ├── passport-zk-circuits/         # ZK circuits (Circom/Noir) for identity proofs
│   ├── passport-identity-provider/   # Identity provider service (Rarimo reference)
│   ├── verificator-svc/              # ZK proof verification service (Rarimo reference)
│   ├── auth-svc/                     # Authentication service
│   ├── decentralized-auth-svc/       # Decentralized JWT authentication
│   ├── geo-points-svc/               # Points & events tracking
│   └── relayer-svc/                  # Generic relayer (Rarimo reference)
├── docker-compose.yaml               # Local development stack
├── docker-compose-local.yaml         # Hardhat-targeted local stack
├── init-db.sql                       # Database initialization
└── .local-addresses.json             # Auto-generated local contract addresses
```

## Quick Start — Local Development

### Prerequisites

- Node.js ≥ 18, npm
- Docker & Docker Compose
- `proof-verification-relayer` on `feat/noir-voting` branch

### One-Command Setup

```bash
cd platform
bash scripts/setup-local.sh
```

This script:
1. Starts a local Hardhat node (`--hostname 0.0.0.0`)
2. Deploys passport-contracts (Registration2, StateKeeper, SMTs)
3. Deploys passport-voting-contracts (NoirIDVoting, IDCardVoting, ProposalsState)
4. Deploys MockEvidenceRegistry
5. Starts Docker services (PostgreSQL, relayers, nginx)
6. Creates a test INID proposal
7. Generates `.env.local` for the mobile app
8. Writes contract addresses to `.local-addresses.json`

### Manual Setup

```bash
# Terminal 1: Hardhat node (keep running)
cd services/passport-contracts && npm install && npx hardhat node --hostname 0.0.0.0

# Terminal 2: Deploy identity contracts
cd services/passport-contracts && npx hardhat migrate --network localhost
node scripts/deploy-mock-evidence-registry.js  # Required for SMT

# Terminal 3: Deploy voting contracts
cd services/passport-voting-contracts && npm install && npx hardhat migrate --network localhost

# Terminal 4: Docker services
docker-compose up -d postgres registration-relayer proof-verification-relayer nginx

# Verify
cd services/passport-contracts && node scripts/verify-local-setup.js
```

## Services

### Core Services (Required)

| Service | Port | Purpose |
|---------|------|---------|
| **nginx** | 8000 | API gateway — routes to relayers and sso-svc |
| **registration-relayer** | 8001 | Submits identity registration transactions to Rarimo L2 |
| **proof-verification-relayer** | 8002 | Submits vote transactions to Rarimo L2 |
| **sso-svc** | 8003 | "Sign in with Jomhoor" — wallet-based OAuth2 + PKCE with mandatory app attestation |
| **postgres** | 5432 | Database for proof-verification-relayer and sso-svc |

### Smart Contracts

| Contract Suite | Directory | Purpose |
|---------------|-----------|---------|
| **passport-contracts** | `services/passport-contracts/` | Registration2, StateKeeper, PoseidonSMT — identity registration on-chain |
| **passport-voting-contracts** | `services/passport-voting-contracts/` | NoirIDVoting, IDCardVoting, ProposalsState — voting with ZK proofs |

### Reference Services (Not required for local dev)

| Service | Purpose |
|---------|---------|
| `auth-svc` | JWT authentication |
| `decentralized-auth-svc` | Decentralized authentication (UCAN-based) |
| `geo-points-svc` | Points & event tracking |
| `passport-identity-provider` | Rarimo's identity provider (reference) |
| `verificator-svc` | ZK proof verification (used by Agora integration) |

## Configuration

Config files live in `configs/`. Each service has up to three variants:

| Suffix | Target | RPC |
|--------|--------|-----|
| `-local.yaml` | Local Hardhat (chain 31337) | `http://host.docker.internal:8545` |
| `.yaml` | Rarimo Testnet (chain 7369) | `https://l2.testnet.rarimo.com` |
| `.production.yaml` | Rarimo Mainnet (chain 7368) | `https://l2.rarimo.com` |

**Required config:** Both relayers need a `private_key` for a wallet funded with RMO tokens.

**Secrets policy:** `config.yaml` files must reference environment variables only — never commit literal values for `private_key`, `jwt.secret_key`, `pairwise.secret_key`, `db.url` passwords, or per-client `client_secret`s. Local development uses gitignored `.env` files; staging and production inject env vars from the deployment vault under `/opt/iranians-vote/`.

---

## SSO (Sign in with Jomhoor)

`sso-svc` issues OAuth2 auth-code + PKCE tokens to relying parties (Taraaz, Compass, DIFCongress, …) on behalf of wallets registered with the Jomhoor mobile app. App attestation (App Attest on iOS, Play Integrity on Android) is a **hard gate** at wallet registration in production. Relying parties never see the root wallet identifier — only a per-client pairwise subject.

**Canonical specification:** [`../docs/SSO/plan.txt`](../docs/SSO/plan.txt). Mobile-app surface: [`../jomhoor-wallet/README.md`](../jomhoor-wallet/README.md#jomhoor-sso).

### Public HTTP surface (served at `https://sso.jomhoor.org` in production)

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/.well-known/apple-app-site-association` | iOS Universal Links |
| GET    | `/.well-known/assetlinks.json`            | Android App Links |
| GET    | `/auth/sso`                               | Universal-Link fallback page |
| POST   | `/v1/wallets/challenge`                   | Issue registration nonce |
| POST   | `/v1/wallets/register`                    | Bind wallet (BabyJubjub `{x,y}`) + verified app credential |
| GET    | `/v1/authorize`                           | OAuth2 authorize entry (stores `code_challenge`, redirects to wallet) |
| POST   | `/v1/authorize/verify`                    | Wallet posts signed challenge + assertion → one-time `code` |
| POST   | `/v1/tokens/exchange`                     | RP exchanges `code` + `code_verifier` → access + refresh JWT |
| GET    | `/v1/tokens/validate`                     | Introspection — live assertion lookup |
| GET    | `/v1/clients/{id}`                        | Public client metadata (name, logo, redirect URIs, `zk_required`) |
| POST   | `/v1/assertions/zk`                       | Wallet submits a Rarimo `queryIdentity` Groth16 proof → inserts a `zk_verified` assertion |

`client_secret` values are never returned by any endpoint.

### Invariants the backend enforces

- JWT `sub` is always the per-client **pairwise subject**, never `walletAddress` or the wallet public key.
- JWT carries no assertion data. `zk_verified` is fetched live from the `assertions` table inside `/v1/tokens/validate`.
- App attestation is mandatory in production. The service refuses to start when `KIT_ENV=production` and `attestation.enabled=false`.
- `client_secret` is stored bcrypt-hashed in `sso_clients`. Plain-text seeds are rejected.
- Only `sso.jomhoor.org` is listed in AASA / `assetlinks.json` — single trust anchor host.
- `assertion_type` stays `"zk_verified"` uniformly across all circuits. The wallet's `circuit_id` is captured only in `assertions.source` for audit — RPs see only the boolean via `/v1/tokens/validate`, no document class leakage.

### ZK assertion verification (multi-circuit)

`POST /v1/assertions/zk` accepts a stable `circuit_id` string with every proof so the wallet can submit proofs from different document classes (Iranian passport variants, INID, future ECDSA passports) without backend code changes. Each entry in `config.yaml#zkp.circuits` carries its own verification-key path and public-signal layout. Adding a new variant = drop a snarkjs VK JSON file in and add an entry; zero code change.

Initial registry (`configs/sso-svc.yaml`):

| `circuit_id` | Document class |
|--------------|----------------|
| `passport_rsa_2048_sha256_e65537` | Most international biometric passports (modern Iranian, US, FR, …) |
| `passport_rsa_2048_sha1_e58333`   | Iranian passport Variant A (Type 6) |
| `inid_rsa_2048`                   | Iranian National ID card (`queryIdentity_inid_ca`) |

The verifier (`internal/zkp`) pre-loads all VKs at startup, pins the global `event_id` against `pub_signals[event_id_index]`, optionally validates `pub_signals[smt_root_index]` against `RegistrationSMT.isRootValid(bytes32)` via Rarimo L2 JSON-RPC (`eth_call`, selector `0x71f6a410`), verifies the Groth16 proof against the per-circuit pinned VK, then writes the nullifier (raw 32-byte big-endian) into `assertions.nullifier_hash`. Unknown `circuit_id` → 400.

### Database tables (created by sso-svc migrations)

| Table | Purpose |
|-------|---------|
| `wallets`            | Root wallet identifier + BabyJubjub public key coordinates |
| `app_credentials`    | App Attest / Play Integrity verification result bound to wallet |
| `assertions`         | `(wallet_id, assertion_type, status, nullifier_hash, source, issued_at, expires_at)` — live trust source |
| `pairwise_subjects`  | Per-(wallet, client) derived subject — stable, unique |
| `sso_clients`        | Client registry: redirect URIs, bcrypt `client_secret`, `zk_required`, name, logo URL |
| `sso_challenges`     | `/v1/authorize` nonces + stored `code_challenge` |
| `sso_auth_codes`     | One-time codes (no assertion columns; trust is fetched live) |

### Configuration

Config file: `configs/sso-svc.yaml` (env placeholders only). Required env vars at runtime:

- `SSO_DB_URL` — PostgreSQL connection string
- `SSO_JWT_SECRET` — access/refresh token signing key
- `SSO_PAIRWISE_SECRET` — HMAC key for pairwise subject derivation (rotating this re-keys every relying party — treat as one-way)
- iOS App Attest: team ID, bundle ID, environment
- Android Play Integrity: package name, signing-cert digest allow-list

### Initial relying parties

| Client | `zk_required` | Status |
|--------|---------------|--------|
| Taraaz (Agora fork, branch `feat/sso-jomhoor-login`) | false | Live in production |
| Compass (Civic-Compass) | false | Integration planned |
| DIFCongress | true (for ZK-participant role) | Integration test pending |

## Roadmap — Sovereign Identity Stack on Rarimo L2 (M6)

> **Important — we are NOT leaving Rarimo L2.** Chain id stays `7368`, gas token stays RMO, block explorer stays `scan.rarimo.com`, and we keep using Rarimo's open-source `passport-zk-circuits` family. M6 replaces only the **identity-registry contracts** (and their governance) — not the chain they run on.

Identity contracts on mainnet (Registration2 / StateKeeper / RegistrationSMT / CertificatesSMT / dispatchers) are currently Rarimo-deployed and Rarimo-governed. The next milestone (`feat/sovereign-l2`) deploys **our own copies** of those contracts on Rarimo L2 (chain 7368) seeded with the extended ICAO tree from `jomhoor-wallet/assets/certificates/master_000316.pem` (857 CSCAs incl. German). This unblocks Iranian passport Variant B (RSA-3072 SHA-1 E33259, currently blocked by a missing dispatcher and an upstream `keyByteLength` bug — see `docs/rarimo-dispatcher-bug-report.md`) and removes the Rarimo governance dependency that contradicts Jomhoor's sovereign-civic-infrastructure mission. FreedomTool interop is lost intentionally — we own the identity graph end-to-end. ICAO root admin starts as a single EOA during the test phase and migrates to a Gnosis Safe multisig before public launch. See [`../docs/SSO/plan.txt`](../docs/SSO/plan.txt) §M6 for the full scope.

## Contract Addresses

### Mainnet (Chain ID: 7368)

| Contract | Address |
|----------|---------|
| Registration2 | `0x11BB4B14AA6e4b836580F3DBBa741dD89423B971` |
| StateKeeper | `0x61aa5b68D811884dA4FEC2De4a7AA0464df166E1` |
| RegistrationSMT | `0x479F84502Db545FA8d2275372E0582425204A879` |
| CertificatesSMT | `0xA8b350d699632569D5351B20ffC1b31202AcEDD8` |
| NoirIDVoting | `0x4Fb46c52C3dFB374D0059866862992389fB25D5f` |
| ProposalsState | `0xa16d9BC3d71acfC4F188A51417811660b285428A` |

### Testnet (Chain ID: 7369)

| Contract | Address |
|----------|---------|
| Registration | `0x511B5Ad9E911Ad5E87e3acb5862976F1398F9A68` |
| StateKeeper | `0x29516F57C90459c279CF1981D8BEb3b6C1d5B3dB` |
| CertPoseidonSMT | `0x0473D9354069f1bD16A710b1A7d0494C61833Fff` |
| RegistrationPoseidonSMT | `0xBdFA8630701e989E0436dAed6a8bFBa442D4FCC1` |
| NoirIdVoting | `0x8ac45fc343Cd0D66cFC12bcdcD485DEF1DC1C11C` |

### Local Hardhat (Chain ID: 31337)

Auto-generated after deployment — see `.local-addresses.json`.

## Production Deployment

Server: `api.iranians.vote` (relayers) and `sso.jomhoor.org` (sso-svc).

```bash
ssh iranians-vote-vps
cd /opt/iranians-vote/repo/platform/deploy

./deploy.sh status    # Check service status
./deploy.sh update    # Pull latest + restart
./deploy.sh logs      # View all logs
```

SSO production notes:

- nginx vhost: `deploy/nginx-vhosts/sso-jomhoor-org.conf` (TLS via Let's Encrypt, HSTS, `proxy_pass` to `sso-svc:8000`)
- `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json` MUST be served from `sso.jomhoor.org` root
- Secrets injected from env files under `/opt/iranians-vote/` — never committed
- Production guard refuses to start sso-svc if `attestation.enabled=false`

See [deploy/README.md](deploy/README.md) for full deployment documentation.

## Utility Scripts

| Script | Purpose |
|--------|---------|
| `scripts/setup-local.sh` | Full local environment setup |
| `scripts/check-proposals.js` | List proposals on any network |
| `scripts/decode-proposals.js` | Decode proposal config parameters |
| `scripts/debug-inid-citizenship.js` | Debug INID citizenship mask encoding |
| `scripts/check-mainnet-contract.js` | Query mainnet contract state |
| `scripts/helpers/create-inid-proposal.js` | Create an INID test proposal |
| `scripts/helpers/deploy-idcard-voting.js` | Deploy IDCardVoting contract |

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `function call to a non-contract account` | MockEvidenceRegistry not deployed | `cd services/passport-contracts && node scripts/deploy-mock-evidence-registry.js` |
| `getProof returns 0x` | Two Hardhat nodes (Docker + CLI) | `docker stop hardhat-node` — use CLI only |
| Port 5432 conflict | Another PostgreSQL running | `lsof -i :5432` then stop the conflicting process |
| Relayer 403 "Insufficient funds" | Proposal not funded in DB | `docker exec rarimo-postgres psql -U rarimo -d proof_verification -c "UPDATE voting_contract_accounts SET residual_balance = 10000000000000000000 WHERE voting_id = <ID>;"` |
| Relayer 500 `InvalidDate` | Hardhat time behind real time | `cd services/passport-contracts && node scripts/advance-time.js` |
| `invalid icao proof` | ICAO root mismatch | Redeploy contracts (migration sets root) |

## Related Repositories

| Repository | Purpose |
|-----------|---------|
| [Jomhoor-citizen-wallet-mobile](https://github.com/jomhoor/Jomhoor-citizen-wallet-mobile) | Mobile app (iOS/Android) |
| [agora](https://github.com/jomhoor/agora) | Deliberation platform (fork of zkorum/agora) |
| [rarimo/registration-relayer](https://github.com/rarimo/registration-relayer) | Upstream relayer |
| [rarimo/proof-verification-relayer](https://github.com/rarimo/proof-verification-relayer) | Upstream voting relayer |

## License

See individual service directories for license information.
