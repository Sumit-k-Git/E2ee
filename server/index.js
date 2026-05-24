'use strict';

// Load .env FIRST before anything else imports process.env
require('dotenv').config();

const http      = require('http');
const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const { getDb, tokens } = require('./database');
const routes    = require('./routes');
const { createWsServer } = require('./websocket');

const PORT           = parseInt(process.env.PORT) || 3000;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

// ── Auto-generate secrets if missing for seamless workspace execution ───
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = require('crypto').randomBytes(32).toString('hex');
}
if (!process.env.JWT_REFRESH_SECRET) {
  process.env.JWT_REFRESH_SECRET = require('crypto').randomBytes(32).toString('hex');
}

// ── Init DB (creates tables on first run) ─────────────────────────────────
try {
  getDb();
  console.log('[db] SQLite ready');
} catch (e) {
  console.error('[db] Failed to initialize database:', e.message);
  process.exit(1);
}

// ── Express app ───────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);

// ── Security headers ──────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'"],
      styleSrc:       ["'self'", "'unsafe-inline'"],
      imgSrc:         ["'self'", 'data:', 'blob:'],
      connectSrc:     ["'self'", 'ws:', 'wss:'],
      workerSrc:      ["'self'", 'blob:'],
      objectSrc:      ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  referrerPolicy: { policy: 'no-referrer' },
  frameguard:     { action: 'deny' },
}));

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ── CORS — supports multiple comma-separated origins ─────────────────────
const allowedOrigins = ALLOWED_ORIGIN.split(',').map(o => o.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    // Allow no-origin requests (mobile apps, curl, same-origin)
    if (!origin) return cb(null, true);
    if (allowedOrigins.some(o => o === origin || o === '*')) return cb(null, true);
    // Also allow any localhost origin in development
    if (process.env.NODE_ENV !== 'production' && origin.startsWith('http://localhost')) {
      return cb(null, true);
    }
    cb(new Error(`CORS: ${origin} not allowed`));
  },
  credentials:    true,
  methods:        ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Body parsing ──────────────────────────────────────────────────────────
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

// ── Rate limiting ─────────────────────────────────────────────────────────
app.use(rateLimit({
  windowMs:        parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max:             parseInt(process.env.RATE_LIMIT_MAX) || 300,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: 'Too many requests, please slow down' },
  skip: (req) => req.path === '/api/health', // don't rate-limit health checks
}));

// Remove server fingerprinting
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────
app.use('/api', routes);

// Vite Client / Middleware & Static Asset Servicing
if (process.env.NODE_ENV !== "production") {
  const { createServer: createViteServer } = require("vite");
  createViteServer({
    server: { middlewareMode: true },
    appType: "spa",
  }).then((vite) => {
    app.use(vite.middlewares);
    
    // Global error handler
    app.use((err, req, res, _next) => {
      console.error('[error]', err.message);
      if (err.message?.startsWith('CORS:')) {
        return res.status(403).json({ error: err.message });
      }
      res.status(500).json({ error: 'Internal server error' });
    });
  });
} else {
  const path = require("path");
  const distPath = path.join(__dirname, "../dist");
  app.use(express.static(distPath));
  app.get("*", (req, res) => {
    res.sendFile(path.join(distPath, "index.html"));
  });
  
  // 404 handler
  app.use((req, res) => res.status(404).json({ error: 'Not found' }));

  // Global error handler
  app.use((err, req, res, _next) => {
    console.error('[error]', err.message);
    if (err.message?.startsWith('CORS:')) {
      return res.status(403).json({ error: err.message });
    }
    res.status(500).json({ error: 'Internal server error' });
  });
}

// ── HTTP + WebSocket server ───────────────────────────────────────────────
const server = http.createServer(app);
createWsServer(server);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[server] vault.msg running on port ${PORT}`);
  console.log(`[server] NODE_ENV:        ${process.env.NODE_ENV || 'development'}`);
  console.log(`[server] Allowed origins: ${ALLOWED_ORIGIN}`);
  console.log(`[server] Email provider:  ${process.env.EMAIL_PROVIDER || 'dev'}`);
  console.log(`[server] Health check:    http://localhost:${PORT}/api/health`);
});

// ── Maintenance ───────────────────────────────────────────────────────────
setInterval(() => {
  try { tokens.purgeExpired(); } catch {}
}, 60 * 60 * 1000);

// ── Graceful shutdown ─────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n[server] ${signal} received, shutting down gracefully...`);
  server.close(() => {
    try { getDb().close(); } catch {}
    console.log('[server] Closed. Goodbye.');
    process.exit(0);
  });
  // Force exit after 10s if graceful shutdown hangs
  setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  console.error('[server] Uncaught exception:', err);
  shutdown('uncaughtException');
});
process.on('unhandledRejection', (reason) => {
  console.error('[server] Unhandled rejection:', reason);
});
