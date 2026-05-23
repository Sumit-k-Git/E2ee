'use strict';

/**
 * auth.js — JWT access/refresh token system + middleware
 */

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { tokens } = require('./database');
require('dotenv').config();

// ── Lazy secret getters — crash clearly if missing ────────────────────────
// Using functions (not top-level vars) so startup doesn't throw before
// dotenv has had a chance to load the .env file.
function getAccessSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error('[auth] JWT_SECRET is not set. Check your .env file.');
  return s;
}
function getRefreshSecret() {
  const s = process.env.JWT_REFRESH_SECRET;
  if (!s) throw new Error('[auth] JWT_REFRESH_SECRET is not set. Check your .env file.');
  return s;
}

const ACCESS_EXPIRY      = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_EXPIRY_SEC = 7 * 24 * 60 * 60; // 7 days

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function signAccessToken(userId, username) {
  const jti = uuidv4();
  return {
    token: jwt.sign(
      { sub: userId, username, jti },
      getAccessSecret(),
      { expiresIn: ACCESS_EXPIRY, algorithm: 'HS256' }
    ),
    jti,
  };
}

function signRefreshToken(userId) {
  const raw       = crypto.randomBytes(48).toString('hex');
  const hash      = hashToken(raw);
  const id        = uuidv4();
  const expiresAt = Math.floor(Date.now() / 1000) + REFRESH_EXPIRY_SEC;
  tokens.create(id, userId, hash, expiresAt);
  return { raw, id };
}

function verifyAccessToken(token) {
  try {
    return jwt.verify(token, getAccessSecret(), { algorithms: ['HS256'] });
  } catch { return null; }
}

function rotateRefreshToken(rawToken) {
  const hash   = hashToken(rawToken);
  const record = tokens.findByHash(hash);
  if (!record) return null;
  tokens.revoke(record.id);
  const newToken = signRefreshToken(record.user_id);
  return { userId: record.user_id, newRefreshToken: newToken.raw };
}

function revokeAllTokens(userId) {
  tokens.revokeAllForUser(userId);
}

function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization token' });
  }
  const payload = verifyAccessToken(header.slice(7));
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  req.user = { id: payload.sub, username: payload.username, jti: payload.jti };
  next();
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.socket?.remoteAddress
    || 'unknown';
}

module.exports = {
  signAccessToken, signRefreshToken, verifyAccessToken,
  rotateRefreshToken, revokeAllTokens, requireAuth,
  getClientIp, hashToken,
};
