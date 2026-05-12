#!/usr/bin/env bash
# scripts/deploy.sh
# Full production deployment script for vault.msg.
# Handles first-time setup AND updates.
#
# Usage (first time):
#   git clone https://github.com/Sumit-k-Git/E2ee.git && cd E2ee
#   cp .env.example .env   # then edit .env
#   chmod +x scripts/deploy.sh
#   ./scripts/deploy.sh
#
# Usage (update existing):
#   git pull
#   ./scripts/deploy.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[deploy]${NC} $1"; }
ok()   { echo -e "${GREEN}[  ok  ]${NC} $1"; }
warn() { echo -e "${YELLOW}[ warn ]${NC} $1"; }
err()  { echo -e "${RED}[error ]${NC} $1"; exit 1; }

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   vault.msg — Production Deploy${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────

log "Checking prerequisites..."

command -v docker       >/dev/null 2>&1 || err "Docker not installed. Install from https://docs.docker.com/get-docker/"
command -v docker compose >/dev/null 2>&1 || err "Docker Compose not found. Update Docker to v2.x+"

[ -f .env ] || err ".env file missing. Run: cp .env.example .env  and fill in all values."

source .env

[ -z "${JWT_SECRET:-}"         ] && err "JWT_SECRET not set in .env"
[ -z "${JWT_REFRESH_SECRET:-}" ] && err "JWT_REFRESH_SECRET not set in .env"
[ -z "${DOMAIN:-}"             ] && err "DOMAIN not set in .env"
[ -z "${ALLOWED_ORIGIN:-}"     ] && err "ALLOWED_ORIGIN not set in .env"

# Validate secret length (must be at least 64 chars)
[ ${#JWT_SECRET} -lt 64 ]         && err "JWT_SECRET must be at least 64 characters. Generate with: node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\""
[ ${#JWT_REFRESH_SECRET} -lt 64 ] && err "JWT_REFRESH_SECRET must be at least 64 characters."

[ "$JWT_SECRET" = "$JWT_REFRESH_SECRET" ] && err "JWT_SECRET and JWT_REFRESH_SECRET must be different."

ok "Prerequisites OK"

# ── Check for TLS certs ───────────────────────────────────────────────────

if [ ! -f certs/fullchain.pem ] || [ ! -f certs/privkey.pem ]; then
  warn "TLS certificates not found in ./certs/"
  echo ""
  echo "  To get a free Let's Encrypt cert, run:"
  echo "    ./scripts/setup-ssl.sh"
  echo ""
  echo "  For local development (self-signed), run:"
  echo "    ./scripts/gen-self-signed.sh"
  echo ""
  read -p "Continue without TLS (HTTP only — NOT for production)? [y/N] " -n 1 -r
  echo ""
  [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
  warn "Continuing without TLS. Do NOT use this in production."
else
  ok "TLS certificates found"
fi

# ── Replace domain placeholder in nginx config ────────────────────────────

if grep -q "YOUR_DOMAIN" nginx/nginx.conf 2>/dev/null; then
  log "Applying domain to nginx config: $DOMAIN"
  sed -i "s/YOUR_DOMAIN/$DOMAIN/g" nginx/nginx.conf
fi

# ── Build and deploy ──────────────────────────────────────────────────────

log "Pulling latest base images..."
docker compose pull --ignore-pull-failures 2>/dev/null || true

log "Building images (this may take 1-3 minutes)..."
docker compose build --no-cache

log "Stopping old containers gracefully..."
docker compose down --timeout 30 2>/dev/null || true

log "Starting services..."
docker compose up -d

# ── Wait for health checks ────────────────────────────────────────────────

log "Waiting for server health check..."
RETRIES=15
for i in $(seq 1 $RETRIES); do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' vault-server 2>/dev/null || echo "not_found")
  if [ "$STATUS" = "healthy" ]; then
    ok "Server is healthy"
    break
  fi
  if [ "$STATUS" = "unhealthy" ]; then
    err "Server failed health check. Logs: docker compose logs server"
  fi
  echo "  Waiting... ($i/$RETRIES)"
  sleep 4
done

# ── Show status ───────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   Deployment complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  🌐  App:    https://$DOMAIN"
echo "  🔒  API:    https://$DOMAIN/api/health"
echo "  🔌  WSS:    wss://$DOMAIN/ws"
echo ""
echo "  View logs:     docker compose logs -f"
echo "  Stop:          docker compose down"
echo "  Update:        git pull && ./scripts/deploy.sh"
echo ""

docker compose ps
