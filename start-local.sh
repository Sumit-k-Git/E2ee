#!/usr/bin/env bash
# vault.msg — start-local.sh
# Single command to run everything locally. No Docker needed.
# Works on: macOS, Linux, Windows (Git Bash or WSL)
#
# Usage:  ./start-local.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

G='\033[0;32m'; Y='\033[1;33m'; BL='\033[0;34m'; R='\033[0;31m'; M='\033[0;35m'; B='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${G}✓${NC} $1"; }
warn() { echo -e "  ${Y}⚠${NC}  $1"; }
err()  { echo -e "\n${R}${B}ERROR:${NC} $1\n"; exit 1; }
info() { echo -e "  ${BL}→${NC} $1"; }

echo -e "\n${BL}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BL}${B}   vault.msg — Starting locally${NC}"
echo -e "${BL}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# ── 1. Check Node.js ────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo -e "${Y}Node.js is not installed.${NC}\n"
  echo "  Install it:"
  echo "  • Ubuntu/Debian: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs"
  echo "  • macOS:         brew install node"
  echo "  • Windows:       https://nodejs.org  (click LTS)"
  err "Please install Node.js 18+ and re-run this script."
fi
VER=$(node -e "process.stdout.write(String(process.versions.node.split('.')[0]))")
[ "$VER" -lt 18 ] && err "Node.js 18+ required. You have $(node --version). Download from https://nodejs.org"
ok "Node.js $(node --version) detected"

# ── 2. Install dependencies ─────────────────────────────────────
if [ ! -d "server/node_modules" ]; then
  info "Installing server packages (first time takes ~1 minute)..."
  cd server && npm install && cd ..
  ok "Server packages installed"
else
  ok "Server packages ready"
fi

if [ ! -d "client/node_modules" ]; then
  info "Installing client packages..."
  cd client && npm install && cd ..
  ok "Client packages installed"
else
  ok "Client packages ready"
fi

# ── 3. Setup .env with auto-generated secrets ───────────────────
if [ ! -f "server/.env" ]; then
  cp server/.env.example server/.env
fi
if [ ! -f "client/.env" ]; then
  cp client/.env.example client/.env
fi

# Auto-generate any missing JWT secrets using Node.js crypto
node - << 'GENSCRIPT'
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const gen    = () => crypto.randomBytes(64).toString('hex');
const file   = path.join(__dirname, 'server', '.env');
let env      = fs.readFileSync(file, 'utf8');
let changed  = false;
for (const key of ['JWT_SECRET', 'JWT_REFRESH_SECRET', 'OTP_SECRET']) {
  if (/^JWT_SECRET=\s*$|^JWT_REFRESH_SECRET=\s*$|^OTP_SECRET=\s*$/m.test(env) || env.match(new RegExp(`^${key}=\\s*$`, 'm'))) {
    env = env.replace(new RegExp(`^${key}=.*$`, 'm'), `${key}=${gen()}`);
    changed = true;
  }
}
if (changed) {
  fs.writeFileSync(file, env);
  console.log('  \x1b[32m✓\x1b[0m JWT secrets generated');
} else {
  console.log('  \x1b[32m✓\x1b[0m Secrets already set');
}
GENSCRIPT

# ── 4. Kill anything on our ports ──────────────────────────────
kill_port() {
  local PORT=$1
  if command -v lsof &>/dev/null; then
    local PIDS=$(lsof -ti:$PORT 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
      warn "Port $PORT busy — freeing it..."
      echo "$PIDS" | xargs kill -9 2>/dev/null || true
      sleep 1
    fi
  elif command -v fuser &>/dev/null; then
    fuser -k ${PORT}/tcp 2>/dev/null || true
  fi
}
kill_port 4000
kill_port 5173

# ── 5. Start server + client ────────────────────────────────────
cleanup() {
  echo -e "\n${Y}Stopping vault.msg…${NC}"
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" 2>/dev/null || true
  wait "${SERVER_PID:-}" 2>/dev/null || true
  wait "${CLIENT_PID:-}" 2>/dev/null || true
  echo -e "${G}Stopped. Goodbye!${NC}\n"
  exit 0
}
trap cleanup SIGINT SIGTERM

info "Starting server..."
cd server
(node index.js 2>&1 | while IFS= read -r line; do
  echo -e "${BL}[server]${NC} $line"
done) &
SERVER_PID=$!
cd ..

# Wait for server health (up to 20s)
echo -ne "  ${BL}Waiting for server${NC}"
for i in $(seq 1 20); do
  sleep 1
  if curl -sf http://localhost:4000/api/health >/dev/null 2>&1; then
    echo -e "\r  ${G}✓ Server ready${NC}          "
    break
  fi
  echo -ne "."
  if [ "$i" -eq 20 ]; then
    echo ""
    err "Server did not start. Check the [server] output above for errors."
  fi
done

info "Starting frontend..."
cd client
(npm run dev 2>&1 | while IFS= read -r line; do
  echo -e "${M}[client]${NC} $line"
done) &
CLIENT_PID=$!
cd ..

sleep 2

# Try to open browser
if command -v xdg-open &>/dev/null; then xdg-open http://localhost:5173 2>/dev/null & fi
if command -v open      &>/dev/null; then open      http://localhost:5173 2>/dev/null & fi
if command -v start     &>/dev/null; then start     http://localhost:5173 2>/dev/null & fi

echo ""
echo -e "${G}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${G}${B}   vault.msg is running!${NC}"
echo -e "${G}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  🌐  ${B}http://localhost:5173${NC}"
echo ""
echo -e "  ${Y}Sign-up OTP codes appear in the [server] logs above.${NC}"
echo -e "  ${Y}(Look for the ═══ box with your 6-digit code)${NC}"
echo ""
echo -e "  Press ${B}Ctrl+C${NC} to stop."
echo ""

wait "$SERVER_PID" "$CLIENT_PID"
