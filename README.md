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
                  └── /integrations/proof-verification-relayer/*  → Voting
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
│   └── proof-verification-relayer*.yaml  # Voting config (local/testnet/prod)
├── deploy/                           # Production deployment
│   ├── deploy.sh                     # Deploy script (start/stop/update/logs)
│   ├── docker-compose.production.yaml
│   ├── docker-compose.agora.yaml     # Agora deliberation stack
│   └── civic-nginx/                  # Nginx vhost configs for api.iranians.vote
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
| **nginx** | 8000 | API gateway — routes to relayers |
| **registration-relayer** | 8001 | Submits identity registration transactions to Rarimo L2 |
| **proof-verification-relayer** | 8002 | Submits vote transactions to Rarimo L2 |
| **postgres** | 5432 | Database for proof-verification-relayer (proposal tracking, gas budgets) |

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

Server: `api.iranians.vote` (173.212.214.147)

```bash
ssh iranians-vote-vps
cd /opt/iranians-vote/repo/platform/deploy

./deploy.sh status    # Check service status
./deploy.sh update    # Pull latest + restart
./deploy.sh logs      # View all logs
```

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
