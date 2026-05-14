# vault.msg — Requirements & Installation Guide

## System Requirements

| Requirement   | Minimum        | Recommended     | Notes                          |
|---------------|----------------|-----------------|--------------------------------|
| OS            | Ubuntu 20.04   | Ubuntu 22.04    | Also works on Debian, CentOS   |
| Docker        | 20.10.0        | 25.x            | Must include Compose v2        |
| RAM           | 512 MB         | 1 GB            | SQLite is very lightweight     |
| Disk          | 1 GB           | 5 GB            | For DB + logs + Docker images  |
| CPU           | 1 vCPU         | 2 vCPU          |                                |
| Domain name   | Required       | Required        | For TLS (Let's Encrypt)        |
| Open ports    | 80, 443        | 80, 443         | HTTP redirect + HTTPS          |

> **For local development only:** Node.js 18+ and npm 9+ (no Docker needed)

---

## What gets installed automatically

When you run `./start.sh`, these are installed inside Docker containers.
**Nothing is installed on your host machine except Docker.**

### Server container (Node.js 18 Alpine)
| Package            | Version   | Purpose                              |
|--------------------|-----------|--------------------------------------|
| express            | ^4.19.2   | HTTP server framework                |
| ws                 | ^8.17.0   | WebSocket server                     |
| better-sqlite3     | ^9.4.3    | SQLite database (zero-config)        |
| bcrypt             | ^5.1.1    | Password hashing (12 rounds)         |
| jsonwebtoken       | ^9.0.2    | JWT access + refresh tokens          |
| nodemailer         | ^6.9.13   | OTP email delivery                   |
| helmet             | ^7.1.0    | HTTP security headers (14 headers)   |
| express-rate-limit | ^7.2.0    | Per-IP rate limiting                 |
| cors               | ^2.8.5    | Cross-origin request control         |
| dotenv             | ^16.4.5   | Environment variable loading         |
| uuid               | ^9.0.1    | UUID generation for message IDs      |
| tweetnacl          | ^1.0.3    | NaCl crypto (X25519 + XSalsa20)      |
| tweetnacl-util     | ^0.15.1   | Base64/UTF8 encoding helpers         |

### Client container (Nginx 1.27 Alpine, serves Vite build)
| Package           | Version   | Purpose                              |
|-------------------|-----------|--------------------------------------|
| react             | ^18.2.0   | UI framework                         |
| react-dom         | ^18.2.0   | DOM rendering                        |
| tweetnacl         | ^1.0.3    | Client-side E2EE crypto              |
| tweetnacl-util    | ^0.15.1   | Base64/UTF8 helpers                  |
| vite              | ^5.2.0    | Build tool (dev server + bundler)    |
| @vitejs/plugin-react | ^4.2.1 | React fast-refresh support          |

---

## Email provider setup (for OTP)

Choose ONE of these options and add the settings to your `.env` file.

### Option A — Gmail (easiest)
1. Go to your Google Account → Security → 2-Step Verification → App passwords
2. Generate an app password for "Mail"
3. Add to `.env`:
```env
EMAIL_PROVIDER=gmail
EMAIL_USER=your.gmail@gmail.com
EMAIL_PASS=xxxx xxxx xxxx xxxx    # 16-char app password (no spaces)
EMAIL_FROM=vault.msg <your.gmail@gmail.com>
```

### Option B — Any SMTP server (Zoho, SendGrid, Mailgun, etc.)
```env
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your@email.com
SMTP_PASS=yourpassword
EMAIL_FROM=vault.msg <noreply@yourdomain.com>
```

### Option C — Development mode (no real email, code printed to console)
```env
EMAIL_PROVIDER=dev
# No other email settings needed
# OTP codes appear in: docker compose logs -f server
```

---

## Local development (no Docker)

### 1 — Install Node.js 18+

**Ubuntu/Debian:**
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version   # should be v18.x or higher
```

**macOS:**
```bash
brew install node@18
```

**Windows:**
Download from https://nodejs.org (LTS version)

### 2 — Install dependencies
```bash
cd server && npm install && cd ..
cd client && npm install && cd ..
```

### 3 — Configure
```bash
cp server/.env.example server/.env
# Edit server/.env — set JWT_SECRET, JWT_REFRESH_SECRET, email settings
```

### 4 — Run
```bash
# Terminal 1
cd server && npm run dev

# Terminal 2
cd client && npm run dev
```

Open http://localhost:5173

---

## Production (Docker)

### Install Docker (Ubuntu)
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
docker --version        # Docker 20.10+
docker compose version  # Docker Compose v2.x
```

### Deploy (2 commands)
```bash
cp .env.example .env   # fill in your domain, secrets, email settings
./start.sh             # builds, starts, gets TLS cert — everything
```

---

## Firewall requirements

Open these ports on your server:

```bash
# Ubuntu UFW
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP (redirects to HTTPS)
sudo ufw allow 443   # HTTPS + WSS
sudo ufw enable

# Or iptables
iptables -A INPUT -p tcp --dport 80  -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

---

## DNS requirements

Before running `./start.sh`, point your domain to your server IP:

| Type | Name           | Value          | TTL  |
|------|----------------|----------------|------|
| A    | yourdomain.com | YOUR_SERVER_IP | 300  |
| A    | www            | YOUR_SERVER_IP | 300  |

Verify with: `dig yourdomain.com +short`

