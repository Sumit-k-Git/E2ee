#!/usr/bin/env bash
# scripts/gen-self-signed.sh
# Generates a self-signed TLS cert for LOCAL development only.
# For production, use scripts/setup-ssl.sh (Let's Encrypt).

set -euo pipefail

mkdir -p certs

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout certs/privkey.pem \
  -out    certs/fullchain.pem \
  -subj   "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

cp certs/fullchain.pem certs/chain.pem

echo ""
echo "✅ Self-signed cert created in ./certs/"
echo "   Valid for 365 days. For production use setup-ssl.sh instead."
echo ""
echo "   Your browser will show a security warning — this is expected for self-signed certs."
echo "   Click 'Advanced' → 'Proceed' to continue."
