#!/usr/bin/env bash
# vault.msg — start-local.sh
# Runs vault.msg locally. No Docker needed.
# Works on: macOS, Linux, Windows (Git Bash or WSL)

set -euo pipefail

# Always resolve to the directory this script lives in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

G='\033[0;32m'; Y='\033[1;33m'; BL='\033[0;34m'; R='\033[0;31m'; M='\033[0;35m'; B='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${G}✓${NC} $1"; }
warn() { echo -e "  ${Y}⚠${NC}  $1"; }
err()  { echo -e "\n${R}${B}ERROR:${NC} $1\n"; exit 1; }
info() { echo -e "  ${BL}→${NC} $1"; }

echo -e "\n${BL}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BL}${B}   vault.msg — Local Startup${NC}"
echo -e "${BL}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# ── 1. Check Node.js ─────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo -e "${Y}Node.js is not installed.${NC}\n"
  echo "  Install it:"
  echo "  • Ubuntu/Debian: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs"
  echo "  • macOS:         brew install node"
  echo "  • Windows:       https://nodejs.org  (download LTS)"
  err "Install Node.js 18+ then re-run this script."
fi
VER=$(node -e "process.stdout.write(String(process.versions.node.split('.')[0]))")
[ "$VER" -lt 18 ] && err "Node.js 18+ required. You have $(node --version). Get it from https://nodejs.org"
ok "Node.js $(node --version)"

# ── 2. Install server dependencies (always run — npm is smart about skipping) ──
info "Installing server packages..."
(cd "$SCRIPT_DIR/server" && npm install)
ok "Server packages ready"

# ── 3. Install client dependencies ───────────────────────────────
info "Installing client packages..."
(cd "$SCRIPT_DIR/client" && npm install)
ok "Client packages ready"

# ── 4. Setup .env files ───────────────────────────────────────────
[ ! -f "$SCRIPT_DIR/server/.env" ] && cp "$SCRIPT_DIR/server/.env.example" "$SCRIPT_DIR/server/.env"
[ ! -f "$SCRIPT_DIR/client/.env" ] && cp "$SCRIPT_DIR/client/.env.example" "$SCRIPT_DIR/client/.env"

# Auto-generate missing JWT secrets
node - << 'GENSCRIPT'
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const file = path.join(process.cwd(), 'server', '.env');
let env    = fs.readFileSync(file, 'utf8');
let changed = false;

for (const key of ['JWT_SECRET', 'JWT_REFRESH_SECRET', 'OTP_SECRET']) {
  const pattern = new RegExp(`^${key}=\\s*$`, 'm');
  if (pattern.test(env)) {
    const secret = crypto.randomBytes(64).toString('hex');
    env     = env.replace(pattern, `${key}=${secret}`);
    changed = true;
  }
}

if (changed) {
  fs.writeFileSync(file, env);
  console.log('  \x1b[32m✓\x1b[0m JWT secrets auto-generated');
} else {
  console.log('  \x1b[32m✓\x1b[0m Secrets already configured');
}
GENSCRIPT

# ── 5. Free ports if busy ─────────────────────────────────────────
free_port() {
  local p=$1
  if command -v lsof &>/dev/null; then
    local pids; pids=$(lsof -ti:"$p" 2>/dev/null || true)
    if [ -n "$pids" ]; then
      warn "Port $p in use — freeing it..."
      echo "$pids" | xargs kill -9 2>/dev/null || true
      sleep 1
    fi
  elif command -v fuser &>/dev/null; then
    fuser -k "${p}/tcp" 2>/dev/null || true
  fi
}
free_port 4000
free_port 5173

# ── 6. Start services ─────────────────────────────────────────────
cleanup() {
  echo -e "\n${Y}Shutting down…${NC}"
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" 2>/dev/null || true
  wait "${SERVER_PID:-}" 2>/dev/null || true
  wait "${CLIENT_PID:-}" 2>/dev/null || true
  echo -e "${G}Stopped. Goodbye!${NC}\n"
  exit 0
}
trap cleanup SIGINT SIGTERM

info "Starting backend server..."
(
  cd "$SCRIPT_DIR/server"
  node index.js 2>&1 | while IFS= read -r line; do
    echo -e "${BL}[server]${NC} $line"
  done
) &
SERVER_PID=$!

# Wait for health check
echo -ne "  ${BL}Waiting for server to be ready${NC}"
READY=false
for i in $(seq 1 30); do
  sleep 1
  if curl -sf http://localhost:4000/api/health >/dev/null 2>&1; then
    READY=true
    echo -e "\r  ${G}✓ Server ready${NC}                          "
    break
  fi
  echo -ne "."
done
if [ "$READY" = "false" ]; then
  echo ""
  err "Server failed to start. Check the [server] output above."
fi

info "Starting frontend..."
(
  cd "$SCRIPT_DIR/client"
  npm run dev 2>&1 | while IFS= read -r line; do
    echo -e "${M}[client]${NC} $line"
  done
) &
CLIENT_PID=$!

sleep 2

# Try to open browser (works on mac/linux — on Windows open manually)
command -v xdg-open &>/dev/null && xdg-open "http://localhost:5173" 2>/dev/null &
command -v open     &>/dev/null && open     "http://localhost:5173" 2>/dev/null &

echo ""
echo -e "${G}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${G}${B}   vault.msg is running!${NC}"
echo -e "${G}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  🌐  Open in browser: ${B}http://localhost:5173${NC}"
echo ""
echo -e "  ${Y}Sign-up OTP codes appear in the [server] logs above.${NC}"
echo -e "  ${Y}Look for the ══ box with your 6-digit code.${NC}"
echo ""
echo -e "  Press ${B}Ctrl+C${NC} to stop."
echo ""

wait "$SERVER_PID" "$CLIENT_PID"
