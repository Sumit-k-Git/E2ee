#!/bin/sh
# backup-db.sh — SQLite online backup (safe while server is running)
# Usage: ./scripts/backup-db.sh
# Cron: 0 2 * * * /path/to/vault-msg/scripts/backup-db.sh

set -e
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_DIR:-./backups}"
DB_PATH="${DB_PATH:-./server/vault.db}"

mkdir -p "$BACKUP_DIR"

# SQLite .backup command is safe for live databases
sqlite3 "$DB_PATH" ".backup $BACKUP_DIR/vault_$TIMESTAMP.db"

# Keep only last 30 backups
ls -t "$BACKUP_DIR"/vault_*.db | tail -n +31 | xargs -r rm

echo "[backup] vault_$TIMESTAMP.db created"
