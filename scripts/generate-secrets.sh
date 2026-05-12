#!/bin/sh
# generate-secrets.sh — Run this ONCE before first deployment

set -e
echo ""
echo "=== vault.msg Secret Generator ==="
echo ""
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
JWT_REFRESH_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
echo "Copy into server/.env:"
echo ""
echo "JWT_SECRET=$JWT_SECRET"
echo "JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET"
echo ""
echo "WARNING: Never commit these to git. Rotating them logs out all users."
