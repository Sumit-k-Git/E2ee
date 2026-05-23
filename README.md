# vault.msg

Zero-knowledge end-to-end encrypted messenger. Even the server operator cannot read messages.

## Run locally (one command)

```bash
./start-local.sh
```

Opens at **http://localhost:5173**

OTP codes print in the terminal during sign-up (no email setup needed).

---

## Deploy to Railway (free)

### Backend (server)

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Set **Root Directory** to `server`
4. Add environment variables:

```
NODE_ENV=production
JWT_SECRET=          ← generate: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_REFRESH_SECRET=  ← generate again (different value)
OTP_SECRET=          ← generate again
EMAIL_PROVIDER=dev   ← or gmail (see below)
ALLOWED_ORIGIN=      ← your Vercel frontend URL (fill in after deploying frontend)
```

5. Railway gives you a URL like `https://vault-msg-server.up.railway.app`

### Frontend (client)

1. Go to [vercel.com](https://vercel.com) → New Project → Import same GitHub repo
2. Set **Root Directory** to `client`
3. Framework: **Vite**
4. Add environment variables:

```
VITE_API_URL=https://vault-msg-server.up.railway.app/api
VITE_WS_URL=wss://vault-msg-server.up.railway.app/ws
```

5. Deploy — Vercel gives you a URL like `https://vault-msg.vercel.app`
6. Go back to Railway → add `ALLOWED_ORIGIN=https://vault-msg.vercel.app`
7. Redeploy Railway

---

## Email OTP setup (optional — dev mode works without it)

### Gmail
1. Enable 2FA on your Google account
2. Go to Google Account → Security → App passwords → create one for "Mail"
3. Set in Railway environment variables:
```
EMAIL_PROVIDER=gmail
EMAIL_USER=your@gmail.com
EMAIL_PASS=your_16char_app_password
```

### Free alternative (Brevo — 300 emails/day)
1. Sign up at brevo.com → get SMTP credentials
```
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your_brevo_key
```

---

## How the encryption works

```
Alice types "Hello"
       ↓
Encrypted with Bob's public key (XSalsa20-Poly1305)
using a fresh ephemeral key (forward secrecy)
       ↓
Server receives ciphertext — cannot decrypt
       ↓
Bob receives ciphertext — decrypts with his private key
(stored only in his browser's IndexedDB)
```

- Keys generated in browser, never sent to server
- Server only relays ciphertext — mathematically cannot read messages
- Forward secrecy: each message uses a different ephemeral key

---

## Requirements

| Local dev | Production |
|---|---|
| Node.js 18+ | Railway (free) |
| npm 9+ | Vercel (free) |
| — | Gmail or any SMTP (optional) |

