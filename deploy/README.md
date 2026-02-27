# Iranians.Vote Production Deployment

Server: `173.212.214.147` (api.iranians.vote)

## Quick Start

```bash
# SSH to VPS
ssh iranians-vote-vps

# Create deploy directory
sudo mkdir -p /opt/iranians-vote
sudo chown $USER:$USER /opt/iranians-vote
cd /opt/iranians-vote

# Clone repo
git clone https://github.com/ArmaniranEmpire/IV.git repo

# Setup environment
cd repo/platform/deploy
cp .env.example .env
nano .env  # Set RELAYER_PRIVATE_KEY

# Start services
./deploy.sh start
```

## Deploy Commands

```bash
./deploy.sh pull      # Pull latest code
./deploy.sh start     # Start services
./deploy.sh stop      # Stop services
./deploy.sh restart   # Restart services
./deploy.sh logs      # View all logs
./deploy.sh logs proof-verification-relayer  # View specific logs
./deploy.sh status    # Check service status
./deploy.sh update    # Pull + restart
```

## Nginx / TLS Setup

api.iranians.vote is served by **civic-nginx** — the nginx container from the
Civic Compass stack (`/opt/civic-compass`). This same container also serves
`compass.jomhoor.org`. There is **no host-level nginx** on the server.

### How It Works

```
Internet → civic-nginx (ports 80/443)
              ├── compass.jomhoor.org → civic-web:3000
              └── api.iranians.vote   → registration-relayer:8000
                                        proof-verification-relayer:8000
```

civic-nginx reaches the relayers because it is connected to two Docker networks:
- `civic-compass_civic` (its own stack)
- `iranians-vote_default` (this stack, declared as external)

### Setup (Already Done)

These steps are documented for reference — they are already applied on the server.

1. **Connect networks** — declared in civic-compass `docker-compose.production.yml`:
   ```yaml
   # In civic-compass docker-compose, under nginx service:
   networks:
     civic:
     iranians-vote:
       external: true
       name: iranians-vote_default

   # And at top-level:
   networks:
     civic:
       driver: bridge
     iranians-vote:
       external: true
       name: iranians-vote_default
   ```

2. **Nginx vhost** — the config file is version-controlled at
   `deploy/civic-nginx/api-iranians-vote.conf` and deployed to
   `/opt/civic-compass/nginx/conf.d/api-iranians-vote.conf` on the server.

3. **SSL certificates** — managed by certbot (webroot authenticator) running
   inside the civic-compass stack. Certs live in the certbot volume at
   `/etc/letsencrypt/live/api.iranians.vote/`. Auto-renewal is configured.

### Updating the Nginx Config

```bash
# Copy updated config to server
scp deploy/civic-nginx/api-iranians-vote.conf \
    iranians-vote-vps:/opt/civic-compass/nginx/conf.d/api-iranians-vote.conf

# Reload nginx (no downtime)
ssh iranians-vote-vps 'docker exec civic-nginx nginx -s reload'
```

### SSL Certificate Renewal

Certbot runs on a loop inside the civic-compass stack and renews automatically.
To test manually:

```bash
ssh iranians-vote-vps 'docker exec civic-certbot certbot renew --dry-run'
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RELAYER_PRIVATE_KEY` | Private key (without 0x) for relayer wallet |
| `POSTGRES_USER` | Database user (default: rarimo) |
| `POSTGRES_PASSWORD` | Database password (default: rarimo) |

## Contract Addresses (Rarimo L2 Mainnet - Chain ID: 7368)

### Identity (Rarimo's deployment)
| Contract | Address |
|----------|---------|
| Registration2 | `0x11BB4B14AA6e4b836580F3DBBa741dD89423B971` |
| StateKeeper | `0x61aa5b68D811884dA4FEC2De4a7AA0464df166E1` |
| RegistrationSMT | `0x479F84502Db545FA8d2275372E0582425204A879` |

### Voting (Our deployment - Jan 15, 2026)
| Contract | Address |
|----------|---------|
| ProposalsState | `0xa16d9BC3d71acfC4F188A51417811660b285428A` |
| NoirIDVoting | `0x4Fb46c52C3dFB374D0059866862992389fB25D5f` |
| ProposalSMT | `0x9E298125048e17170f2690AAd82a07693a1b64C6` |

Admin Wallet: `0x7DCFcCd0f80C3eED4dBcac1B597E667E0D0F731c`

## Docker Images

| Service | Image |
|---------|-------|
| registration-relayer | `ghcr.io/rarimo/registration-relayer:v1.0.6` |
| proof-verification-relayer | `ghcr.io/rarimo/proof-verification-relayer:v0.9.0` |

## API Endpoints

Base URL: `https://api.iranians.vote`

| Endpoint | Description |
|----------|-------------|
| `/health` | Health check |
| `/integrations/registration-relayer/v1/register` | Identity registration |
| `/integrations/proof-verification-relayer/v2/proposals` | List proposals |
| `/integrations/proof-verification-relayer/v3/vote` | Submit vote |

## Troubleshooting

```bash
# Check logs
docker logs registration-relayer
docker logs proof-verification-relayer

# Check service status
docker ps

# Restart a specific service
docker restart proof-verification-relayer

# Run database migrations manually
docker exec proof-verification-relayer proof-verification-relayer migrate up
```
