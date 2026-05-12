#!/usr/bin/env bash
# scripts/setup-ssl.sh
# Provisions a Let's Encrypt TLS certificate using Certbot + Docker.
# Run this ONCE on your server after DNS is pointing to it.
# After first issue, certs auto-renew via the certbot container.
#
# Usage:
#   chmod +x scripts/setup-ssl.sh
#   ./scripts/setup-ssl.sh

set -euo pipefail

# ── Load .env ─────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  echo "ERROR: .env file not found. Copy .env.example to .env and fill it in."
  exit 1
fi
source .env

if [ -z "${DOMAIN:-}" ] || [ -z "${CERT_EMAIL:-}" ]; then
  echo "ERROR: DOMAIN and CERT_EMAIL must be set in .env"
  exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " vault.msg — TLS Setup"
echo " Domain: $DOMAIN"
echo " Email:  $CERT_EMAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1 — Replace YOUR_DOMAIN placeholder in nginx config
echo "[1/5] Updating nginx config with domain: $DOMAIN"
sed -i "s/YOUR_DOMAIN/$DOMAIN/g" nginx/nginx.conf

# Step 2 — Start nginx on HTTP only (for ACME challenge)
echo "[2/5] Starting nginx (HTTP only for ACME challenge)..."
docker compose up -d nginx

sleep 3

# Step 3 — Issue certificate
echo "[3/5] Requesting Let's Encrypt certificate..."
docker compose --profile ssl up certbot

# Step 4 — Copy certs to expected location
echo "[4/5] Organising certificates..."
mkdir -p certs
if [ -d "certs/live/$DOMAIN" ]; then
  cp certs/live/$DOMAIN/fullchain.pem certs/fullchain.pem
  cp certs/live/$DOMAIN/privkey.pem   certs/privkey.pem
  cp certs/live/$DOMAIN/chain.pem     certs/chain.pem
  echo "Certificates copied to ./certs/"
else
  echo "ERROR: Certificate directory not found at certs/live/$DOMAIN"
  echo "Check certbot logs: docker compose logs certbot"
  exit 1
fi

# Step 5 — Restart with HTTPS
echo "[5/5] Restarting with HTTPS enabled..."
docker compose down
docker compose up -d

echo ""
echo "✅ SSL setup complete!"
echo "   Your app is live at: https://$DOMAIN"
echo ""
echo "   To auto-renew certs, add this to cron (runs twice daily):"
echo "   0 0,12 * * * cd $(pwd) && docker compose --profile ssl up certbot && docker compose exec nginx nginx -s reload"
echo ""
