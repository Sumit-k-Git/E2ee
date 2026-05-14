#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  vault.msg — start.sh
#  The ONLY script you need. Run it once to deploy everything.
#
#  Usage:
#    1. cp .env.example .env   ← fill in your domain + secrets
#    2. ./start.sh             ← that's it
#
#  What this does automatically:
#    ✓ Checks Docker is installed (tells you how if not)
#    ✓ Validates your .env has all required values
#    ✓ Generates JWT secrets if you forgot to
#    ✓ Builds server + client Docker images
#    ✓ Starts all containers
#    ✓ Gets a free Let's Encrypt TLS certificate
#    ✓ Sets up auto-renewal cron job
#    ✓ Waits for health checks and confirms everything is live
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────
B='\033[1m'; R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
BL='\033[0;34m'; M='\033[0;35m'; C='\033[0;36m'; NC='\033[0m'

banner() {
  echo ""
  echo -e "${BL}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BL}${B}   vault.msg — Deployment${NC}"
  echo -e "${BL}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
}

step()  { echo -e "\n${BL}${B}[$1]${NC} $2"; }
ok()    { echo -e "  ${G}✓${NC} $1"; }
warn()  { echo -e "  ${Y}⚠${NC}  $1"; }
err()   { echo -e "\n${R}${B}ERROR:${NC} $1\n"; exit 1; }
info()  { echo -e "  ${C}→${NC} $1"; }

banner

# ──────────────────────────────────────────────────────────────
# STEP 1 — Check Docker
# ──────────────────────────────────────────────────────────────
step "1/6" "Checking Docker..."

if ! command -v docker &>/dev/null; then
  echo ""
  echo -e "${Y}Docker is not installed. Install it now:${NC}"
  echo ""
  echo "  Ubuntu/Debian:"
  echo "    curl -fsSL https://get.docker.com | sh"
  echo "    sudo usermod -aG docker \$USER && newgrp docker"
  echo ""
  echo "  macOS / Windows:"
  echo "    https://www.docker.com/products/docker-desktop"
  echo ""
  err "Please install Docker and re-run ./start.sh"
fi

if ! docker compose version &>/dev/null; then
  err "Docker Compose v2 not found. Update Docker to version 20.10+ from https://docs.docker.com/get-docker/"
fi

ok "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1) + Compose $(docker compose version --short 2>/dev/null || echo 'v2')"

# ──────────────────────────────────────────────────────────────
# STEP 2 — Setup .env
# ──────────────────────────────────────────────────────────────
step "2/6" "Checking configuration..."

if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    warn ".env not found — created from .env.example"
    warn "Please edit .env with your domain and email settings, then re-run ./start.sh"
    echo ""
    echo "  Minimum required settings:"
    echo "    DOMAIN=yourdomain.com"
    echo "    CERT_EMAIL=your@email.com"
    echo "    EMAIL_PROVIDER=dev  (or gmail/smtp with credentials)"
    echo ""
    exit 1
  else
    err ".env file missing and no .env.example found"
  fi
fi

source .env

# Auto-generate JWT secrets if they're still the placeholder
if [ "${JWT_SECRET:-REPLACE}" = "REPLACE_WITH_LONG_RANDOM_SECRET" ] || [ -z "${JWT_SECRET:-}" ]; then
  warn "JWT_SECRET not set — generating one automatically..."
  NEW_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))" 2>/dev/null || \
               python3 -c "import secrets; print(secrets.token_hex(64))" 2>/dev/null || \
               openssl rand -hex 64)
  sed -i "s|JWT_SECRET=.*|JWT_SECRET=${NEW_SECRET}|" .env
  source .env
  ok "JWT_SECRET generated"
fi

if [ "${JWT_REFRESH_SECRET:-REPLACE}" = "REPLACE_WITH_DIFFERENT_LONG_RANDOM_SECRET" ] || [ -z "${JWT_REFRESH_SECRET:-}" ]; then
  warn "JWT_REFRESH_SECRET not set — generating one automatically..."
  NEW_REFRESH=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))" 2>/dev/null || \
                python3 -c "import secrets; print(secrets.token_hex(64))" 2>/dev/null || \
                openssl rand -hex 64)
  sed -i "s|JWT_REFRESH_SECRET=.*|JWT_REFRESH_SECRET=${NEW_REFRESH}|" .env
  source .env
  ok "JWT_REFRESH_SECRET generated"
fi

if [ "${OTP_SECRET:-REPLACE}" = "REPLACE_WITH_THIRD_LONG_RANDOM_SECRET" ] || [ -z "${OTP_SECRET:-}" ]; then
  NEW_OTP=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))" 2>/dev/null || \
            python3 -c "import secrets; print(secrets.token_hex(64))" 2>/dev/null || \
            openssl rand -hex 64)
  sed -i "s|OTP_SECRET=.*|OTP_SECRET=${NEW_OTP}|" .env
  source .env
  ok "OTP_SECRET generated"
fi

# Validate domain
DOMAIN="${DOMAIN:-}"
[ -z "$DOMAIN" ] || [ "$DOMAIN" = "yourdomain.com" ] && \
  err "DOMAIN not set in .env. Edit .env and set DOMAIN=yourdomain.com"

CERT_EMAIL="${CERT_EMAIL:-}"
[ -z "$CERT_EMAIL" ] || [ "$CERT_EMAIL" = "your@email.com" ] && \
  err "CERT_EMAIL not set in .env. Edit .env and set CERT_EMAIL=your@email.com"

ok "Configuration valid (domain: $DOMAIN)"

# Replace domain placeholder in nginx config
if grep -q "YOUR_DOMAIN" nginx/nginx.conf 2>/dev/null; then
  sed -i "s/YOUR_DOMAIN/$DOMAIN/g" nginx/nginx.conf
  ok "Nginx configured for $DOMAIN"
fi

# ──────────────────────────────────────────────────────────────
# STEP 3 — Build images
# ──────────────────────────────────────────────────────────────
step "3/6" "Building Docker images (this takes 2-4 minutes on first run)..."

# Load env for build args
export VITE_API_URL="https://${DOMAIN}/api"
export VITE_WS_URL="wss://${DOMAIN}/ws"

# Update .env with correct URLs
sed -i "s|VITE_API_URL=.*|VITE_API_URL=https://${DOMAIN}/api|" .env
sed -i "s|VITE_WS_URL=.*|VITE_WS_URL=wss://${DOMAIN}/ws|" .env
sed -i "s|ALLOWED_ORIGIN=.*|ALLOWED_ORIGIN=https://${DOMAIN}|" .env

docker compose build --quiet 2>&1 | grep -E "error|Error|ERROR|warning|step|Step" || true
ok "Images built"

# ──────────────────────────────────────────────────────────────
# STEP 4 — Start services
# ──────────────────────────────────────────────────────────────
step "4/6" "Starting services..."

docker compose down --timeout 10 2>/dev/null || true
docker compose up -d

ok "Containers started"

# ──────────────────────────────────────────────────────────────
# STEP 5 — TLS Certificate (Let's Encrypt)
# ──────────────────────────────────────────────────────────────
step "5/6" "Setting up TLS certificate..."

mkdir -p certs

if [ -f certs/fullchain.pem ] && [ -f certs/privkey.pem ]; then
  # Check if cert expires in more than 30 days
  EXPIRY=$(openssl x509 -enddate -noout -in certs/fullchain.pem 2>/dev/null | cut -d= -f2)
  EXPIRY_SEC=$(date -d "${EXPIRY}" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "${EXPIRY}" +%s 2>/dev/null || echo 0)
  NOW_SEC=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_SEC - NOW_SEC) / 86400 ))
  if [ "$DAYS_LEFT" -gt 30 ]; then
    ok "TLS certificate valid ($DAYS_LEFT days remaining)"
    SKIP_CERT=true
  else
    warn "Certificate expires in $DAYS_LEFT days — renewing..."
    SKIP_CERT=false
  fi
else
  SKIP_CERT=false
fi

if [ "${SKIP_CERT}" = "false" ]; then
  info "Requesting Let's Encrypt certificate for $DOMAIN..."
  info "Note: DNS must already point to this server's IP"

  # Wait for nginx to be ready for ACME challenge
  sleep 3

  docker compose --profile ssl run --rm certbot 2>&1 | tail -5 || {
    warn "Let's Encrypt failed. Falling back to self-signed certificate for now."
    warn "Make sure your domain DNS points to this server's IP, then re-run ./start.sh"
    # Generate self-signed as fallback
    openssl req -x509 -newkey rsa:4096 -sha256 -days 90 -nodes \
      -keyout certs/privkey.pem \
      -out    certs/fullchain.pem \
      -subj   "/CN=${DOMAIN}" \
      -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null
    cp certs/fullchain.pem certs/chain.pem
    warn "Self-signed cert created (browser will show warning — run ./start.sh again after DNS is set)"
  }

  # Copy certs to flat location expected by nginx
  if [ -d "certs/live/${DOMAIN}" ]; then
    cp "certs/live/${DOMAIN}/fullchain.pem" certs/fullchain.pem
    cp "certs/live/${DOMAIN}/privkey.pem"   certs/privkey.pem
    cp "certs/live/${DOMAIN}/chain.pem"     certs/chain.pem
    ok "Let's Encrypt certificate installed"
  fi

  # Restart nginx to pick up certificate
  docker compose restart nginx 2>/dev/null || true
fi

# Setup auto-renewal cron (twice daily — Let's Encrypt recommendation)
CRON_CMD="0 0,12 * * * cd $(pwd) && docker compose --profile ssl run --rm certbot && docker compose exec nginx nginx -s reload >> /var/log/vault-cert-renew.log 2>&1"
if ! crontab -l 2>/dev/null | grep -q "vault-cert-renew\|vault-msg.*certbot"; then
  (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -
  ok "Auto-renewal cron job installed (runs twice daily)"
fi

# ──────────────────────────────────────────────────────────────
# STEP 6 — Health check
# ──────────────────────────────────────────────────────────────
step "6/6" "Waiting for health checks..."

HEALTHY=false
for i in $(seq 1 20); do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' vault-server 2>/dev/null || echo "waiting")
  if [ "$STATUS" = "healthy" ]; then
    HEALTHY=true
    break
  fi
  echo -ne "  ${C}Waiting${NC} ($i/20)...\r"
  sleep 3
done
echo ""

if [ "$HEALTHY" = "true" ]; then
  ok "Server is healthy"
else
  warn "Health check inconclusive — check logs: docker compose logs server"
fi

# ──────────────────────────────────────────────────────────────
# Done!
# ──────────────────────────────────────────────────────────────
echo ""
echo -e "${G}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${G}${B}   Deployment complete!${NC}"
echo -e "${G}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  🌐  ${B}App:${NC}    https://${DOMAIN}"
echo -e "  🔒  ${B}API:${NC}    https://${DOMAIN}/api/health"
echo -e "  🔌  ${B}WSS:${NC}    wss://${DOMAIN}/ws"
echo ""
echo -e "  ${C}View logs:${NC}   docker compose logs -f"
echo -e "  ${C}Stop:${NC}        docker compose down"
echo -e "  ${C}Update:${NC}      git pull && ./start.sh"
echo -e "  ${C}Backup DB:${NC}   docker compose exec server sh -c 'sqlite3 /data/vault.db .dump' > backup.sql"
echo ""
if [ "${EMAIL_PROVIDER:-dev}" = "dev" ]; then
  echo -e "  ${Y}⚠  EMAIL_PROVIDER=dev — OTP codes are printed to logs, not emailed.${NC}"
  echo -e "  ${Y}   To see OTPs: docker compose logs -f server${NC}"
  echo -e "  ${Y}   To enable real email: edit .env and set EMAIL_PROVIDER=gmail${NC}"
  echo ""
fi

docker compose ps
