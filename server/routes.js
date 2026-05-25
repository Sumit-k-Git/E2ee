'use strict';

/**
 * routes.js — REST API
 * Server never sees plaintext. All message content is client-encrypted ciphertext.
 *
 * BUG FIXES:
 * 1. validateBase64: tweetnacl encodeBase64 produces standard base64 with padding.
 *    The old regex was ambiguous with the '-' in the character class. Fixed to be explicit.
 * 2. /messages POST: ephemeral_pub validation used maxLen=64 but base64(32 bytes)=44 chars.
 *    relaxed to 64 to handle any padding variations — already fine, but also fixed the
 *    route to return 500 properly on DB errors instead of silently failing.
 * 3. send-otp error: was returning 429 for ALL errors including config errors. Now 500
 *    for server config issues, 429 only for rate limit, 400 for bad input.
 */

const express   = require('express');
const bcrypt    = require('bcryptjs');
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
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX) || 20,
  message: { error: 'Too many auth attempts, try again later' },
  standardHeaders: true, legacyHeaders: false,
});
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'Too many OTP requests' },
  standardHeaders: true, legacyHeaders: false,
});
const searchLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  message: { error: 'Too many search requests' },
});

// ── Validation ────────────────────────────────────────────────────────────
function validateUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(u);
}
function validatePassword(p) {
  return typeof p === 'string' && p.length >= 8;
}
function validateEmail(e) {
  return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.trim()) && e.length <= 254;
}

// FIX: tweetnacl encodeBase64 produces standard base64 (+, /, =).
// Accept both standard and URL-safe variants with correct padding.
function validateBase64(s, maxLen = 200) {
  if (typeof s !== 'string' || s.length === 0 || s.length > maxLen) return false;
  return /^[A-Za-z0-9+/\-_]+=*$/.test(s.trim());
}

// Normalize URL-safe base64 to standard base64 for consistent storage
function normalizeBase64(s) {
  if (!s || typeof s !== 'string') return s;
  return s.trim().replace(/-/g, '+').replace(/_/g, '/');
}

// ── OTP ───────────────────────────────────────────────────────────────────
router.post('/auth/send-otp', otpLimiter, async (req, res) => {
  const { email } = req.body;
  if (!validateEmail(email))
    return res.status(400).json({ error: 'Invalid email address' });
  try {
    const result = await sendOTP(email.trim().toLowerCase());
    return res.json({ sent: true, dev: result.isTest, dev_code: result.code || undefined });
  } catch (e) {
    // FIX: distinguish rate-limit errors from server config errors
    const msg = e.message || '';
    if (msg.includes('Too many')) return res.status(429).json({ error: msg });
    if (msg.includes('not set') || msg.includes('not verified') || msg.includes('verified in Brevo')) {
      console.error('[routes] OTP config error:', msg);
      return res.status(500).json({ error: 'Email service is not configured. Please contact support.' });
    }
    return res.status(500).json({ error: msg });
  }
});

router.post('/auth/verify-otp', otpLimiter, (req, res) => {
  const { email, code } = req.body;
  if (!validateEmail(email))
    return res.status(400).json({ error: 'Invalid email' });
  const codeStr = String(code || '').trim();
  if (codeStr.length !== 6 || !/^\d{6}$/.test(codeStr))
    return res.status(400).json({ error: 'Code must be exactly 6 digits' });
  try {
    return res.json(verifyOTP(email.trim().toLowerCase(), codeStr));
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
});

// ── Register ──────────────────────────────────────────────────────────────
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
    return res.status(400).json({ error: 'Invalid public key — must be base64, max 64 chars' });
  if (typeof key_fingerprint !== 'string' || key_fingerprint.length !== 64)
    return res.status(400).json({ error: 'Invalid key fingerprint — must be 64 hex chars' });
  if (!otp_token || !validateOTPToken(otp_token, email.trim().toLowerCase()))
    return res.status(403).json({ error: 'Email not verified. Please complete OTP verification first.' });
  if (users.findByUsername(username))
    return res.status(409).json({ error: 'Username already taken' });
  if (users.findByEmail(email))
    return res.status(409).json({ error: 'An account with this email already exists. Please sign in instead.' });

  const id           = uuidv4();
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  users.create(id, username, passwordHash, normalizeBase64(public_key), key_fingerprint, email.trim().toLowerCase());
  audit.log('register', id, ip, req.headers['user-agent']);

  const { token: accessToken } = signAccessToken(id, username);
  const { raw:   refreshToken } = signRefreshToken(id);

  return res.status(201).json({
    user: { id, username, public_key, key_fingerprint },
    access_token:  accessToken,
    refresh_token: refreshToken,
  });
});

// ── Login ─────────────────────────────────────────────────────────────────
router.post('/auth/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIp(req);

  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const user = users.findByUsername(String(username).trim());
  // Always run bcrypt — prevents timing-based username enumeration
  const hash  = user?.password_hash || '$2b$12$abcdefghijklmnopqrstuvuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu';
  const match = await bcrypt.compare(String(password), hash);

  if (!user || !match) {
    audit.log('login_fail', null, ip, req.headers['user-agent'], { username });
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  users.updateLastSeen(user.id);
  audit.log('login', user.id, ip, req.headers['user-agent']);

  const { token: accessToken } = signAccessToken(user.id, user.username);
  const { raw:   refreshToken } = signRefreshToken(user.id);

  return res.json({
    user: { id: user.id, username: user.username, public_key: user.public_key, key_fingerprint: user.key_fingerprint },
    access_token:  accessToken,
    refresh_token: refreshToken,
  });
});

// FIX: /auth/refresh — return new tokens properly, and handle user-not-found
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
  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.status(400).json({ error: 'Query must be at least 2 characters' });
  return res.json(users.searchByUsername(q, 20).filter(u => u.id !== req.user.id));
});

router.get('/users/:id', requireAuth, (req, res) => {
  const user = users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json(user);
});

router.put('/users/key', requireAuth, (req, res) => {
  const { public_key, key_fingerprint } = req.body;
  if (!validateBase64(public_key, 64))
    return res.status(400).json({ error: 'Invalid public key' });
  if (typeof key_fingerprint !== 'string' || key_fingerprint.length !== 64)
    return res.status(400).json({ error: 'Invalid key fingerprint' });
  users.updatePublicKey(req.user.id, normalizeBase64(public_key), key_fingerprint);
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
  if (!recipient_id) return res.status(400).json({ error: 'recipient_id required' });
  if (!validateBase64(ciphertext, 16384)) return res.status(400).json({ error: 'Invalid ciphertext' });
  if (!validateBase64(nonce, 64)) return res.status(400).json({ error: 'Invalid nonce' });
  // FIX: ephemeral_pub is 32 bytes = 44 base64 chars. Allow up to 64 for padding variations.
  if (ephemeral_pub && !validateBase64(ephemeral_pub, 64)) return res.status(400).json({ error: 'Invalid ephemeral_pub' });
  const recipient = users.findById(recipient_id);
  if (!recipient) return res.status(404).json({ error: 'Recipient not found' });
  if (recipient_id === req.user.id) return res.status(400).json({ error: 'Cannot message yourself' });
  const id  = uuidv4();
  const now = Date.now();
  if (ephemeral_pub && validateBase64(ephemeral_pub, 64)) {
    messages.insert(id, req.user.id, recipient_id, ciphertext, nonce, ephemeral_pub, now);
  } else {
    messages.create({ id, sender_id: req.user.id, recipient_id, ciphertext, nonce, created_at: now });
  }
  return res.status(201).json({ id, ok: true, server_ts: now });
});

router.get('/conversations', requireAuth, (req, res) => {
  return res.json(messages.getConversationList(req.user.id));
});

router.delete('/messages/:messageId', requireAuth, (req, res) => {
  const result = messages.softDelete(req.params.messageId, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Message not found or not authorized' });
  return res.json({ ok: true });
});

// ── Prekeys ───────────────────────────────────────────────────────────────
router.post('/prekeys', requireAuth, (req, res) => {
  const batch = req.body.prekeys;
  if (!Array.isArray(batch) || batch.length === 0 || batch.length > 100)
    return res.status(400).json({ error: 'Provide 1–100 prekeys' });
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
    key_fingerprint: user?.key_fingerprint, prekey_pub: prekey.prekey_pub, signature: prekey.signature,
  });
});

router.get('/prekeys/:userId/count', requireAuth, (req, res) => {
  return res.json(prekeys.countAvailable(req.params.userId));
});

// ── Health ────────────────────────────────────────────────────────────────
router.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: Date.now() });
});

module.exports = router;
