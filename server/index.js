'use strict';

/**
 * index.js — vault.msg server entry point
 *
 * Security layers applied (in order):
 * 1. Helmet — sets 14 security HTTP headers
 * 2. CORS — whitelist only your frontend origin
 * 3. Rate limiting — per-IP, per-route
 * 4. Body size limit — prevent payload bombs
 * 5. JWT auth — stateless, short-lived access tokens
 * 6. Input validation — on every route
 * 7. Parameterized SQL — all DB queries use prepared statements (no SQLi)
 * 8. WebSocket auth — token required within 10s
 * 9. Secure DB pragmas — WAL, foreign keys, secure_delete, synchronous FULL
 * 10. Audit log — security events recorded
 */

require('dotenv').config();

const http = require('http');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { getDb, tokens } = require('./database');
const routes = require('./routes');
const { createWsServer } = require('./websocket');

const PORT = parseInt(process.env.PORT) || 4000;
// Allow multiple origins for dev/prod; provide comma-separated list in ALLOWED_ORIGIN.
// Example: ALLOWED_ORIGIN=http://localhost:5173,http://127.0.0.1:5173
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);


// ── Initialize DB ─────────────────────────────────────────────────────────
getDb(); // runs schema migrations on first start
console.log('[db] SQLite initialized with WAL + secure_delete + foreign keys');

// ── Express app ───────────────────────────────────────────────────────────
const app = express();

// Trust first proxy (needed for accurate IP in rate limiting behind nginx)
app.set('trust proxy', 1);

// ── Security headers (Helmet) ─────────────────────────────────────────────
app.use(helmet({
  // Content-Security-Policy
  // In local dev, allow both websocket and HTTP API calls to localhost:4000.
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'", 'ws:', 'wss:', 'http://localhost:4000', 'http://127.0.0.1:4000'],
      workerSrc: ["'self'", 'blob:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  // Prevent browsers from caching responses containing tokens
  referrerPolicy: {
  policy: 'no-referrer',
  },
  // Prevent clickjacking
  frameguard: { action: 'deny' },
  // HSTS: force HTTPS for 1 year (uncomment in production with real TLS)
  // hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
// ── CORS ──────────────────────────────────────────────────────────────────
app.use(cors({
  origin: function (origin, cb) {
    // Allow requests with no origin (e.g. curl, same-origin, health checks)
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);

    // Also allow common dev ports if origin is present in ALLOWED_ORIGINS with/without trailing slash

    const normalized = origin?.replace(/\/$/, '');
    if (ALLOWED_ORIGINS.some(o => o.replace(/\/$/, '') === normalized)) return cb(null, true);

    return cb(new Error('CORS origin not allowed'), false);
  },

  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-RateLimit-Remaining'],
}));

// ── Body parsing with size limit ──────────────────────────────────────────
// 64KB max — encrypted messages + metadata; no file uploads expected
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

// ── Global rate limiter ───────────────────────────────────────────────────
app.use(rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down' },
}));

// ── Remove fingerprinting headers ─────────────────────────────────────────
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────
app.use('/api', routes);

// 404 for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler (never leak stack traces to client)
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── HTTP server + WebSocket ───────────────────────────────────────────────
const server = http.createServer(app);
createWsServer(server);

server.listen(PORT, () => {
  console.log(`[server] vault.msg listening on port ${PORT}`);
  console.log(`[server] Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(`[server] NODE_ENV: ${process.env.NODE_ENV}`);
});


// ── Periodic maintenance ──────────────────────────────────────────────────
// Purge expired refresh tokens every hour
setInterval(() => {
  tokens.purgeExpired();
  console.log('[maintenance] Purged expired refresh tokens');
}, 60 * 60 * 1000);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[server] SIGTERM received, closing...');
  server.close(() => {
    getDb().close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  server.close(() => {
    getDb().close();
    process.exit(0);
  });
});
