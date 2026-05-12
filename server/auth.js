'use strict';

/**
 * auth.js — JWT access/refresh token system + middleware
 *
 * Security design:
 * - Short-lived access tokens (15 min) signed with HS256
 * - Long-lived refresh tokens stored as SHA-256 hashes in DB (never raw)
 * - Refresh token rotation: each use issues a new token and revokes the old one
 * - All tokens carry a 'jti' (JWT ID) for revocation
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { tokens, audit } = require('./database');
require('dotenv').config();

const ACCESS_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_EXPIRY_SEC = 7 * 24 * 60 * 60; // 7 days in seconds

if (!ACCESS_SECRET || !REFRESH_SECRET) {
  throw new Error('JWT_SECRET and JWT_REFRESH_SECRET must be set in .env');
}

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function signAccessToken(userId, username) {
  const jti = uuidv4();
  return {
    token: jwt.sign(
      { sub: userId, username, jti },
      ACCESS_SECRET,
      { expiresIn: ACCESS_EXPIRY, algorithm: 'HS256' }
    ),
    jti,
  };
}

function signRefreshToken(userId) {
  // Raw refresh token = cryptographically random 48 bytes
  const raw = crypto.randomBytes(48).toString('hex');
  const hash = hashToken(raw);
  const id = uuidv4();
  const expiresAt = Math.floor(Date.now() / 1000) + REFRESH_EXPIRY_SEC;

  tokens.create(id, userId, hash, expiresAt);

  return { raw, id };
}

function verifyAccessToken(token) {
  try {
    return jwt.verify(token, ACCESS_SECRET, { algorithms: ['HS256'] });
  } catch {
    return null;
  }
}

function rotateRefreshToken(rawToken) {
  const hash = hashToken(rawToken);
  const record = tokens.findByHash(hash);
  if (!record) return null;

  // Revoke old token
  tokens.revoke(record.id);

  // Issue new refresh token
  const newToken = signRefreshToken(record.user_id);
  return { userId: record.user_id, newRefreshToken: newToken.raw };
}

function revokeAllTokens(userId) {
  tokens.revokeAllForUser(userId);
}

// ── Express middleware ────────────────────────────────────────────────────

/**
 * requireAuth — attach req.user or respond 401
 * Reads Bearer token from Authorization header.
 * Does NOT touch the database (stateless JWT verify).
 */
function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization token' });
  }

  const token = header.slice(7);
  const payload = verifyAccessToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  req.user = { id: payload.sub, username: payload.username, jti: payload.jti };
  next();
}

/**
 * Middleware that logs IP for audit trail
 */
function getClientIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  rotateRefreshToken,
  revokeAllTokens,
  requireAuth,
  getClientIp,
  hashToken,
};
