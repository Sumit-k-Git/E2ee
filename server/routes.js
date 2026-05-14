'use strict';

/**
 * routes.js — REST API endpoints
 * Server never sees plaintext. All message fields are ciphertext only.
 */

const express   = require('express');
const bcrypt    = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const {
  signAccessToken, signRefreshToken, rotateRefreshToken,
  revokeAllTokens, requireAuth, getClientIp,
} = require('./auth');
const { users, messages, prekeys, audit } = require('./database');
const { sendOTP, verifyOTP, validateOTPToken } = require('./otp');

const router = express.Router();
const BCRYPT_ROUNDS = 12;

// ── Rate limiters ─────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX) || 10,
  message: { error: 'Too many auth attempts, try again later' },
  standardHeaders: true, legacyHeaders: false,
});
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many OTP requests, please wait 15 minutes' },
  standardHeaders: true, legacyHeaders: false,
});
const searchLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  message: { error: 'Too many search requests' },
});

// ── Validation helpers ────────────────────────────────────────────────────
function validateUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(u);
}
function validatePassword(p) {
  return typeof p === 'string' && p.length >= 8;
}
function validateEmail(e) {
  return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;
}
function validateBase64(s, maxLen = 200) {
  return typeof s === 'string' && s.length <= maxLen && /^[A-Za-z0-9+/=]+$/.test(s);
}

// ── OTP routes ────────────────────────────────────────────────────────────

/**
 * POST /api/auth/send-otp
 * Body: { email }
 * Sends a 6-digit OTP to the email address.
 */
router.post('/auth/send-otp', otpLimiter, async (req, res) => {
  const { email } = req.body;
  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  try {
    const result = await sendOTP(email);
    // In dev mode return preview URL so developer can see the email
    return res.json({
      sent: true,
      ...(result.previewUrl ? { dev_preview_url: result.previewUrl } : {}),
    });
  } catch (e) {
    return res.status(429).json({ error: e.message });
  }
});

/**
 * POST /api/auth/verify-otp
 * Body: { email, code }
 * Returns { verified: true, otp_token } — pass otp_token to /register
 */
router.post('/auth/verify-otp', otpLimiter, (req, res) => {
  const { email, code } = req.body;
  if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  if (!code || String(code).trim().length !== 6) return res.status(400).json({ error: 'Code must be 6 digits' });
  try {
    const result = verifyOTP(email, code);
    return res.json(result);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
});

// ── Auth ──────────────────────────────────────────────────────────────────

/**
 * POST /api/auth/register
 * Body: { username, password, public_key, key_fingerprint, email, otp_token }
 * otp_token is issued by /verify-otp — proves email was verified.
 */
router.post('/auth/register', authLimiter, async (req, res) => {
  const { username, password, public_key, key_fingerprint, email, otp_token } = req.body;
  const ip = getClientIp(req);

  if (!validateUsername(username))
    return res.status(400).json({ error: 'Username: 3–32 characters, letters/numbers/underscores only' });
  if (!validatePassword(password))
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (!validateEmail(email))
    return res.status(400).json({ error: 'Invalid email address' });
  if (!validateBase64(public_key, 64))
    return res.status(400).json({ error: 'Invalid public key format' });
  if (typeof key_fingerprint !== 'string' || key_fingerprint.length !== 64)
    return res.status(400).json({ error: 'Invalid key fingerprint' });

  // Validate OTP token — confirms email was verified before this request
  if (!otp_token || !validateOTPToken(otp_token, email)) {
    return res.status(403).json({ error: 'Email verification required. Please verify your email with an OTP first.' });
  }

  if (users.findByUsername(username))
    return res.status(409).json({ error: 'Username already taken' });

  const id = uuidv4();
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  users.create(id, username, passwordHash, public_key, key_fingerprint, email);
  audit.log('register', id, ip, req.headers['user-agent']);

  const { token: accessToken } = signAccessToken(id, username);
  const { raw: refreshToken }  = signRefreshToken(id);

  return res.status(201).json({
    user: { id, username, public_key, key_fingerprint },
    access_token: accessToken,
    refresh_token: refreshToken,
  });
});

/**
 * POST /api/auth/login
 * Body: { username, password }
 */
router.post('/auth/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIp(req);

  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const user = users.findByUsername(username);
  // Constant-time: always run bcrypt even for unknown users
  const hash  = user?.password_hash || '$2b$12$invalidhashpaddinginvalidhashpadding..';
  const match = await bcrypt.compare(password, hash);

  if (!user || !match) {
    audit.log('login_fail', null, ip, req.headers['user-agent'], { username });
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  users.updateLastSeen(user.id);
  audit.log('login', user.id, ip, req.headers['user-agent']);

  const { token: accessToken } = signAccessToken(user.id, user.username);
  const { raw: refreshToken }  = signRefreshToken(user.id);

  return res.json({
    user: {
      id: user.id, username: user.username,
      public_key: user.public_key, key_fingerprint: user.key_fingerprint,
    },
    access_token: accessToken,
    refresh_token: refreshToken,
  });
});

router.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'Refresh token required' });
  const result = rotateRefreshToken(refresh_token);
  if (!result) return res.status(401).json({ error: 'Invalid or expired refresh token' });
  const user = users.findById(result.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });
  const { token: accessToken } = signAccessToken(user.id, user.username);
  return res.json({ access_token: accessToken, refresh_token: result.newRefreshToken });
});

router.post('/auth/logout', requireAuth, (req, res) => {
  revokeAllTokens(req.user.id);
  audit.log('logout', req.user.id, getClientIp(req), req.headers['user-agent']);
  return res.json({ ok: true });
});

// ── Users ─────────────────────────────────────────────────────────────────
router.get('/users/me', requireAuth, (req, res) => {
  const user = users.findById(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json(user);
});

router.get('/users/search', requireAuth, searchLimiter, (req, res) => {
  const q = req.query.q?.trim();
  if (!q || q.length < 2) return res.status(400).json({ error: 'Query must be at least 2 characters' });
  const results = users.searchByUsername(q, 20).filter(u => u.id !== req.user.id);
  return res.json(results);
});

router.get('/users/:id', requireAuth, (req, res) => {
  const user = users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json(user);
});

router.put('/users/key', requireAuth, (req, res) => {
  const { public_key, key_fingerprint } = req.body;
  if (!validateBase64(public_key, 64) || typeof key_fingerprint !== 'string' || key_fingerprint.length !== 64)
    return res.status(400).json({ error: 'Invalid key data' });
  users.updatePublicKey(req.user.id, public_key, key_fingerprint);
  audit.log('key_rotation', req.user.id, getClientIp(req), req.headers['user-agent']);
  return res.json({ ok: true });
});

// ── Messages ──────────────────────────────────────────────────────────────
router.get('/messages/:contactId', requireAuth, (req, res) => {
  const limit    = Math.min(parseInt(req.query.limit) || 50, 100);
  const beforeTs = req.query.before_ts ? parseInt(req.query.before_ts) : null;
  const contact  = users.findById(req.params.contactId);
  if (!contact) return res.status(404).json({ error: 'Contact not found' });
  const history = messages.getConversation(req.user.id, req.params.contactId, limit, beforeTs);
  return res.json({ messages: history, contact });
});

router.post('/messages', requireAuth, (req, res) => {
  const { recipient_id, ciphertext, nonce, ephemeral_pub } = req.body;
  if (!recipient_id || typeof recipient_id !== 'string')
    return res.status(400).json({ error: 'recipient_id required' });
  if (!validateBase64(ciphertext, 16384))
    return res.status(400).json({ error: 'Invalid ciphertext' });
  if (!validateBase64(nonce, 64))
    return res.status(400).json({ error: 'Invalid nonce' });
  const recipient = users.findById(recipient_id);
  if (!recipient) return res.status(404).json({ error: 'Recipient not found' });
  if (recipient_id === req.user.id) return res.status(400).json({ error: 'Cannot message yourself' });
  const messageId = uuidv4();
  const now = Date.now();
  if (ephemeral_pub && validateBase64(ephemeral_pub, 64)) {
    messages.insert(messageId, req.user.id, recipient_id, ciphertext, nonce, ephemeral_pub, now);
  } else {
    messages.create({ id: messageId, sender_id: req.user.id, recipient_id, ciphertext, nonce, created_at: now });
  }
  return res.status(201).json({ id: messageId, ok: true, server_ts: now });
});

router.get('/conversations', requireAuth, (req, res) => {
  return res.json(messages.getConversationList(req.user.id));
});

router.delete('/messages/:messageId', requireAuth, (req, res) => {
  const result = messages.softDelete(req.params.messageId, req.user.id);
  if (result.changes === 0)
    return res.status(404).json({ error: 'Message not found or not authorized' });
  return res.json({ ok: true });
});

// ── Prekeys ───────────────────────────────────────────────────────────────
router.post('/prekeys', requireAuth, (req, res) => {
  const batch = req.body.prekeys;
  if (!Array.isArray(batch) || batch.length === 0 || batch.length > 100)
    return res.status(400).json({ error: 'Invalid prekeys batch (1-100 items)' });
  for (const pk of batch) {
    if (!validateBase64(pk.prekey_pub, 64) || !validateBase64(pk.signature, 128))
      return res.status(400).json({ error: 'Invalid prekey format' });
    prekeys.store(uuidv4(), req.user.id, pk.prekey_pub, pk.signature);
  }
  return res.json({ ok: true, stored: batch.length });
});

router.get('/prekeys/:userId', requireAuth, (req, res) => {
  const prekey = prekeys.fetchOne(req.params.userId);
  if (!prekey) return res.status(404).json({ error: 'No prekeys available for this user' });
  const user = users.findById(req.params.userId);
  return res.json({
    user_id: req.params.userId, identity_key: user?.public_key,
    key_fingerprint: user?.key_fingerprint,
    prekey_pub: prekey.prekey_pub, signature: prekey.signature,
  });
});

router.get('/prekeys/:userId/count', requireAuth, (req, res) => {
  return res.json(prekeys.countAvailable(req.params.userId));
});

// ── Health ────────────────────────────────────────────────────────────────
router.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: Date.now(), version: '1.0.0' });
});

module.exports = router;
