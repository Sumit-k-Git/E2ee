'use strict';

/**
 * database.js — SQLite schema and query layer
 *
 * The server stores ZERO plaintext content.
 * Every message column is ciphertext + nonce produced by the client.
 * The server cannot decrypt anything here.
 */

const Database = require('better-sqlite3');
const path = require('path');
require('dotenv').config();

const DB_PATH = process.env.DB_PATH || './vault.db';

let db;

function getDb() {
  if (db) return db;
  db = new Database(path.resolve(DB_PATH));

  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('secure_delete = ON');
  db.pragma('synchronous = FULL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id              TEXT PRIMARY KEY,
      username        TEXT UNIQUE NOT NULL,
      password_hash   TEXT NOT NULL,
      public_key      TEXT NOT NULL,
      key_fingerprint TEXT NOT NULL,
      email           TEXT,
      created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
      last_seen       INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id          TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash  TEXT NOT NULL UNIQUE,
      expires_at  INTEGER NOT NULL,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
      revoked     INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_rt_hash ON refresh_tokens(token_hash);

    CREATE TABLE IF NOT EXISTS messages (
      id            TEXT PRIMARY KEY,
      sender_id     TEXT NOT NULL REFERENCES users(id),
      recipient_id  TEXT NOT NULL REFERENCES users(id),
      ciphertext    TEXT NOT NULL,
      nonce         TEXT NOT NULL UNIQUE,
      ephemeral_pub TEXT NOT NULL DEFAULT '',
      client_ts     INTEGER NOT NULL DEFAULT 0,
      server_ts     INTEGER NOT NULL DEFAULT (unixepoch('now', 'subsec') * 1000),
      read_at       INTEGER,
      deleted_at    INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient_id, server_ts);
    CREATE INDEX IF NOT EXISTS idx_msg_sender    ON messages(sender_id, server_ts);
    CREATE INDEX IF NOT EXISTS idx_msg_convo     ON messages(MIN(sender_id, recipient_id), MAX(sender_id, recipient_id), server_ts);
    CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(sender_id, recipient_id, server_ts);
    CREATE INDEX IF NOT EXISTS idx_messages_recipient_ts ON messages(recipient_id, server_ts);

    CREATE TABLE IF NOT EXISTS prekeys (
      id          TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      prekey_pub  TEXT NOT NULL,
      signature   TEXT NOT NULL,
      used        INTEGER NOT NULL DEFAULT 0,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch())
    );
    CREATE INDEX IF NOT EXISTS idx_prekeys_user ON prekeys(user_id, used);

    CREATE TABLE IF NOT EXISTS audit_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      event      TEXT NOT NULL,
      user_id    TEXT,
      ip         TEXT,
      user_agent TEXT,
      metadata   TEXT,
      ts         INTEGER NOT NULL DEFAULT (unixepoch())
    );
    CREATE INDEX IF NOT EXISTS idx_audit_user  ON audit_log(user_id, ts);
    CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event, ts);
  `);

  return db;
}

const userQueries = {
  create(id, username, passwordHash, publicKey, keyFingerprint, email) {
    return getDb()
      .prepare('INSERT INTO users (id, username, password_hash, public_key, key_fingerprint, email) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, username, passwordHash, publicKey, keyFingerprint, email || null);
  },
  findByUsername(username) {
    return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  },
  findById(id) {
    return getDb().prepare('SELECT id, username, public_key, key_fingerprint, created_at, last_seen FROM users WHERE id = ?').get(id);
  },
  searchByUsername(query, limit = 20) {
    return getDb().prepare('SELECT id, username, public_key, key_fingerprint FROM users WHERE username LIKE ? LIMIT ?').all(`${query}%`, limit);
  },
  updateLastSeen(id) {
    return getDb().prepare('UPDATE users SET last_seen = unixepoch() WHERE id = ?').run(id);
  },
  updatePublicKey(id, publicKey, keyFingerprint) {
    return getDb().prepare('UPDATE users SET public_key = ?, key_fingerprint = ? WHERE id = ?').run(publicKey, keyFingerprint, id);
  },
};

const tokenQueries = {
  create(id, userId, tokenHash, expiresAt) {
    return getDb().prepare('INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)').run(id, userId, tokenHash, expiresAt);
  },
  findByHash(tokenHash) {
    return getDb().prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0 AND expires_at > unixepoch()').get(tokenHash);
  },
  revoke(id) {
    return getDb().prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(id);
  },
  revokeAllForUser(userId) {
    return getDb().prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(userId);
  },
  purgeExpired() {
    return getDb().prepare('DELETE FROM refresh_tokens WHERE expires_at <= unixepoch() OR revoked = 1').run();
  },
};

const messageQueries = {
  // Used by WebSocket relay (with forward secrecy ephemeral key)
  insert(id, senderId, recipientId, ciphertext, nonce, ephemeralPub, clientTs) {
    return getDb()
      .prepare('INSERT INTO messages (id, sender_id, recipient_id, ciphertext, nonce, ephemeral_pub, client_ts) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, senderId, recipientId, ciphertext, nonce, ephemeralPub, clientTs);
  },

  // Used by REST POST /api/messages (added by Sumit — no ephemeral key for REST clients)
  create({ id, sender_id, recipient_id, ciphertext, nonce, created_at }) {
    return getDb()
      .prepare('INSERT INTO messages (id, sender_id, recipient_id, ciphertext, nonce, ephemeral_pub, client_ts) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, sender_id, recipient_id, ciphertext, nonce, '', created_at);
  },

  getConversation(userA, userB, limit = 50, beforeTs = null) {
    const base = `
      SELECT id, sender_id, recipient_id, ciphertext, nonce, ephemeral_pub, client_ts, server_ts, read_at
      FROM messages
      WHERE deleted_at IS NULL
        AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
        ${beforeTs ? 'AND server_ts < ?' : ''}
      ORDER BY server_ts DESC LIMIT ?`;
    const params = beforeTs ? [userA, userB, userB, userA, beforeTs, limit] : [userA, userB, userB, userA, limit];
    return getDb().prepare(base).all(...params).reverse();
  },

  getUndelivered(recipientId, sinceTs) {
    return getDb()
      .prepare('SELECT id, sender_id, ciphertext, nonce, ephemeral_pub, client_ts, server_ts FROM messages WHERE recipient_id = ? AND server_ts > ? AND deleted_at IS NULL ORDER BY server_ts ASC')
      .all(recipientId, sinceTs);
  },

  markRead(messageId, recipientId) {
    return getDb()
      .prepare('UPDATE messages SET read_at = unixepoch() WHERE id = ? AND recipient_id = ? AND read_at IS NULL')
      .run(messageId, recipientId);
  },

  softDelete(messageId, requesterId) {
    return getDb()
      .prepare("UPDATE messages SET deleted_at = unixepoch(), ciphertext = '', nonce = '', ephemeral_pub = '' WHERE id = ? AND (sender_id = ? OR recipient_id = ?)")
      .run(messageId, requesterId, requesterId);
  },

  getConversationList(userId) {
    return getDb().prepare(`
      SELECT
        m.id, m.sender_id, m.recipient_id, m.ciphertext, m.nonce,
        m.ephemeral_pub, m.server_ts,
        u.username        AS contact_username,
        u.public_key      AS contact_public_key,
        u.key_fingerprint AS contact_fingerprint,
        SUM(CASE WHEN m.recipient_id = ? AND m.read_at IS NULL AND m.deleted_at IS NULL THEN 1 ELSE 0 END) AS unread_count
      FROM messages m
      JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END
      WHERE (m.sender_id = ? OR m.recipient_id = ?)
        AND m.deleted_at IS NULL
        AND m.id IN (
          SELECT id FROM messages m2
          WHERE ((m2.sender_id = ? AND m2.recipient_id = u.id) OR (m2.recipient_id = ? AND m2.sender_id = u.id))
          AND m2.deleted_at IS NULL
          ORDER BY m2.server_ts DESC LIMIT 1
        )
      GROUP BY u.id
      ORDER BY m.server_ts DESC
    `).all(userId, userId, userId, userId, userId, userId);
  },
};

const prekeyQueries = {
  store(id, userId, prekeyPub, signature) {
    return getDb().prepare('INSERT INTO prekeys (id, user_id, prekey_pub, signature) VALUES (?, ?, ?, ?)').run(id, userId, prekeyPub, signature);
  },
  fetchOne(userId) {
    const row = getDb().prepare('SELECT * FROM prekeys WHERE user_id = ? AND used = 0 ORDER BY created_at ASC LIMIT 1').get(userId);
    if (row) getDb().prepare('UPDATE prekeys SET used = 1 WHERE id = ?').run(row.id);
    return row;
  },
  countAvailable(userId) {
    return getDb().prepare('SELECT COUNT(*) as count FROM prekeys WHERE user_id = ? AND used = 0').get(userId);
  },
};

const auditQueries = {
  log(event, userId, ip, userAgent, metadata = {}) {
    return getDb()
      .prepare('INSERT INTO audit_log (event, user_id, ip, user_agent, metadata) VALUES (?, ?, ?, ?, ?)')
      .run(event, userId || null, ip || null, userAgent || null, JSON.stringify(metadata));
  },
};

module.exports = { getDb, users: userQueries, tokens: tokenQueries, messages: messageQueries, prekeys: prekeyQueries, audit: auditQueries };
