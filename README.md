<<<<<<< HEAD
# E2ee
=======
# vault.msg — Zero-Knowledge E2EE Messenger

A **production-ready**, end-to-end encrypted messaging app.
**Even you, the server operator, mathematically cannot read messages.**

Built with Node.js · SQLite · React · TweetNaCl

---

## How it works

```
Alice's device              Your server (blind relay)         Bob's device
──────────────              ─────────────────────────         ────────────
"Hello Bob"                                                   "Hello Bob"
     │                                                             ▲
     ▼                                                             │
encrypt with           relay stores only               decrypt with
Bob's pubkey  ──────►  ciphertext + nonce  ──────────► Bob's privkey
+ ephemeral key        CANNOT READ ANYTHING            (never leaves device)
(discarded after)
```

### Cryptography used (same as Signal)

| Purpose              | Algorithm                       |
|----------------------|---------------------------------|
| Key agreement        | X25519 (Elliptic-curve DH)      |
| Message encryption   | XSalsa20-Poly1305 (NaCl box)    |
| Forward secrecy      | Fresh ephemeral keypair per msg |
| Password hashing     | bcrypt (12 rounds)              |
| Session tokens       | HMAC-SHA256 JWT (15 min)        |
| Refresh tokens       | SHA-256 hashed in DB            |
| Key fingerprinting   | SHA-256                         |
| Replay protection    | Unique nonce constraint in DB   |

### What the server NEVER sees
- Message plaintext (mathematically impossible without Bob's private key)
- Private keys (generated + stored on client device only)
- Passwords (bcrypt hash only)

---

## Project structure

```
vault-msg/
│
├── server/                     ← Node.js backend
│   ├── index.js                   Express app + all security middleware
│   ├── auth.js                    JWT sign/verify + refresh token rotation
│   ├── database.js                SQLite schema + all query functions
│   ├── routes.js                  REST API endpoints
│   ├── websocket.js               Authenticated WebSocket relay
│   ├── Dockerfile                 Production container (non-root, multi-stage)
│   ├── .dockerignore
│   ├── .env.example               ← Copy to .env and fill in
│   └── package.json
│
├── client/                     ← React frontend
│   ├── src/
│   │   ├── main.jsx               React entry point
│   │   ├── App.jsx                Full app UI + state (connects to real server)
│   │   ├── crypto.js              All E2EE: keygen, encrypt, decrypt, fingerprint
│   │   ├── api.js                 HTTP client + WebSocket client + token refresh
│   │   └── e2ee-messenger.jsx     Standalone in-browser demo (no server needed)
│   ├── public/
│   │   └── favicon.svg
│   ├── index.html                 Security meta tags + CSP
│   ├── vite.config.js             Dev proxy + production build config
│   ├── Dockerfile                 Vite build → Nginx serve (non-root)
│   ├── nginx.conf                 Hardened Nginx for static files
│   ├── .env.example               ← Copy to .env and fill in
│   └── package.json
│
├── nginx/
│   └── nginx.conf              ← Production reverse proxy (TLS, WSS, rate limits)
│
├── scripts/
│   ├── deploy.sh               ← One-command production deployment
│   ├── setup-ssl.sh            ← Let's Encrypt TLS certificate setup
│   └── gen-self-signed.sh      ← Self-signed cert for local dev
│
├── docker-compose.yml          ← Orchestrates server + nginx + certbot
├── .env.example                ← Root env template for Docker Compose
├── .gitignore
└── README.md
```

---

## Quick start — local development

### Prerequisites
- Node.js 18+  →  https://nodejs.org
- npm 9+

### 1 — Install dependencies

```bash
# Server
cd server
npm install

# Client (separate terminal)
cd client
npm install
```

### 2 — Configure the server

```bash
cd server
cp .env.example .env
```

Open `.env` and set strong JWT secrets:

```bash
# Generate two separate secrets (run this twice):
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

Paste the first output as `JWT_SECRET`, second as `JWT_REFRESH_SECRET`.

### 3 — Start both services

```bash
# Terminal 1 — server
cd server
npm run dev
# → listening on http://localhost:4000

# Terminal 2 — client
cd client
cp .env.example .env
npm run dev
# → listening on http://localhost:5173
```

### 4 — Use the app

Open **http://localhost:5173**

1. Create an account → your X25519 keypair is generated in your browser
2. Search for another user by username
3. Send a message → it is encrypted before leaving your device
4. Click **"Verify keys"** to see key fingerprints for out-of-band verification

---

## Production deployment (VPS / cloud server)

### What you need
- A Linux VPS (Ubuntu 22.04 recommended) — DigitalOcean, Hetzner, AWS, etc.
- A domain name pointing to your server's IP (A record)
- Docker + Docker Compose installed

### Install Docker (Ubuntu)

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

### Step-by-step deployment

```bash
# 1 — Clone your repo onto the server
git clone https://github.com/Sumit-k-Git/E2ee.git
cd E2ee

# 2 — Create and fill in the root .env
cp .env.example .env
nano .env
```

Fill in `.env`:

```env
DOMAIN=yourdomain.com
ALLOWED_ORIGIN=https://yourdomain.com
VITE_API_URL=https://yourdomain.com/api
VITE_WS_URL=wss://yourdomain.com/ws
JWT_SECRET=<run: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))">
JWT_REFRESH_SECRET=<run again for a different value>
CERT_EMAIL=your@email.com
```

```bash
# 3 — Get a free TLS certificate (Let's Encrypt)
#     Your domain DNS must already point to this server's IP
chmod +x scripts/setup-ssl.sh
./scripts/setup-ssl.sh

# 4 — Deploy (builds images, starts all containers)
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

Your app is now live at `https://yourdomain.com` ✅

### Auto-renew TLS certificate (cron)

```bash
# Add to crontab: crontab -e
0 3 * * * cd /path/to/E2ee && docker compose --profile ssl up certbot && docker compose exec nginx nginx -s reload
```

---

## Deployment commands reference

```bash
# Start everything
docker compose up -d

# View live logs
docker compose logs -f

# View only server logs
docker compose logs -f server

# Stop everything
docker compose down

# Update to latest code
git pull && ./scripts/deploy.sh

# Open a shell in the server container
docker compose exec server sh

# Backup the database
docker compose exec server sh -c "sqlite3 /data/vault.db .dump" > backup_$(date +%Y%m%d).sql

# Restart only the server
docker compose restart server
```

---

## API reference

### Authentication
| Method | Endpoint              | Auth | Description                  |
|--------|-----------------------|------|------------------------------|
| POST   | `/api/auth/register`  | —    | Register + upload public key |
| POST   | `/api/auth/login`     | —    | Login, receive tokens        |
| POST   | `/api/auth/refresh`   | —    | Rotate refresh token         |
| POST   | `/api/auth/logout`    | JWT  | Revoke all tokens            |

### Users
| Method | Endpoint              | Auth | Description                  |
|--------|-----------------------|------|------------------------------|
| GET    | `/api/users/me`       | JWT  | My profile + public key      |
| GET    | `/api/users/search?q` | JWT  | Search users by username     |
| GET    | `/api/users/:id`      | JWT  | Get user's public key        |
| PUT    | `/api/users/key`      | JWT  | Rotate my public key         |

### Messages
| Method | Endpoint                   | Auth | Description                    |
|--------|----------------------------|------|--------------------------------|
| GET    | `/api/messages/:contactId` | JWT  | Fetch conversation (paginated) |
| POST   | `/api/messages`            | JWT  | Send via REST (fallback)       |
| GET    | `/api/conversations`       | JWT  | List all conversations         |
| DELETE | `/api/messages/:id`        | JWT  | Soft-delete (wipes ciphertext) |

### Prekeys (Signal-style offline E2EE)
| Method | Endpoint                    | Auth | Description               |
|--------|-----------------------------|------|---------------------------|
| POST   | `/api/prekeys`              | JWT  | Upload one-time prekeys   |
| GET    | `/api/prekeys/:userId`      | JWT  | Fetch prekey bundle       |
| GET    | `/api/prekeys/:userId/count`| JWT  | Count remaining prekeys   |

### WebSocket  `ws://localhost:4000/ws`

| Event               | Direction      | Description                              |
|---------------------|----------------|------------------------------------------|
| `auth`              | client→server  | Send JWT to authenticate                 |
| `auth_ok`           | server→client  | Auth confirmed, pending msgs delivered   |
| `send_message`      | client→server  | Send encrypted message                   |
| `message_ack`       | server→client  | Server confirmed delivery                |
| `new_message`       | server→client  | Incoming encrypted message               |
| `pending_messages`  | server→client  | Missed messages since last connection    |
| `typing`            | both           | Typing indicator (never persisted)       |
| `mark_read`         | client→server  | Mark message as read                     |
| `message_read`      | server→client  | Read receipt notification                |
| `ping` / `pong`     | both           | Heartbeat keepalive                      |

---

## Security layers

### Server
1. **Helmet** — 14 security HTTP headers (CSP, HSTS, X-Frame-Options, etc.)
2. **CORS** — strict origin whitelist from `.env`
3. **Rate limiting** — global (100 req/15 min), auth routes (10 req/15 min)
4. **Body size limit** — 64 KB max, prevents payload bombs
5. **JWT** — 15-minute access tokens, rotating 7-day refresh tokens
6. **Refresh tokens** — stored as SHA-256 hashes, never raw
7. **Input validation** — every field validated on every route
8. **Parameterized SQL** — all queries use prepared statements (no SQL injection)
9. **WebSocket auth** — token required within 10 seconds or connection is dropped
10. **Nonce uniqueness** — DB UNIQUE constraint prevents replay attacks
11. **Timing-safe login** — bcrypt always runs even for unknown users (no enumeration)
12. **SQLite hardening** — WAL, foreign keys, `secure_delete`, `synchronous FULL`
13. **Audit log** — all auth events stored with IP + user agent
14. **Non-root container** — server runs as unprivileged `vault` user

### Client
1. **Keys in IndexedDB** — private keys stored on-device, never sent to server
2. **Tokens in memory** — access tokens never stored in localStorage
3. **Forward secrecy** — fresh ephemeral X25519 keypair per message
4. **Silent token refresh** — access tokens auto-refreshed without user interaction
5. **CSP** — Content Security Policy in both HTML and Nginx
6. **Private key hidden** — never displayed in UI

### Nginx (production)
1. **TLS 1.2 / 1.3 only** — TLS 1.0 and 1.1 disabled
2. **HSTS preload** — `max-age=63072000; includeSubDomains; preload`
3. **OCSP stapling** — faster, more private TLS handshakes
4. **Rate limiting** — 3 tiers: global, API, auth
5. **WebSocket upgrade** — properly proxied with timeout 3600s
6. **Hidden server version** — `server_tokens off`
7. **Attack path blocking** — `.php`, `.asp` etc. return 444 (no response)
8. **Hidden file blocking** — `.env`, `.git` etc. denied

---

## Key verification

To confirm no man-in-the-middle attack:

1. In a conversation, click **"Verify keys"**
2. Compare your fingerprint with your contact's fingerprint via a **separate channel** (phone call, in person)
3. If fingerprints match on both sides → channel is secure

This is the same model used by Signal ("Safety Numbers") and WhatsApp ("Security Code").

---

## Changes from your original code (Sumit's updates integrated)

| File              | Change                                          | Status                             |
|-------------------|-------------------------------------------------|------------------------------------|
| `index.js`        | CSP updated for Vite (`unsafe-inline`, `blob:`) | ✅ Kept                            |
| `index.js`        | `Cache-Control: no-store` header added          | ✅ Kept                            |
| `index.js`        | `referrerPolicy: no-referrer` set explicitly    | ✅ Kept                            |
| `database.js`     | Nonce UNIQUE constraint (replay protection)     | ✅ Fixed (moved after table CREATE)|
| `database.js`     | Stray `create()` block outside object           | ✅ Fixed (merged into messageQueries)|
| `database.js`     | Extra performance indexes                       | ✅ Kept (renamed to avoid collision)|
| `routes.js`       | New `POST /api/messages` REST endpoint          | ✅ Fixed (`ephemeral_pub` handled) |
| `e2ee-messenger`  | Private key hidden in key modal                 | ✅ Kept                            |
| `e2ee-messenger`  | Broken async/await + WebSocket in `send()`      | ✅ Fixed (removed, demo is sync)   |

---

## License

MIT — see LICENSE file.
>>>>>>> ae4725e (Initial commit)
