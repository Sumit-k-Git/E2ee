'use strict';

/**
 * database.js — SQLite via better-sqlite3
 * Server stores ZERO plaintext. All message content is client-encrypted.
 */

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
require('dotenv').config();

function resolveDbPath() {
  if (process.env.DB_PATH) return path.resolve(process.env.DB_PATH);
  // Railway/Docker: use /data if writable, else /tmp
  for (const dir of ['/data', '/tmp']) {
    try {
      fs.accessSync(dir, fs.constants.W_OK);
      return path.join(dir, 'vault.db');
    } catch {}
  }
  return path.resolve('./vault.db');
}

let db;

function getDb() {
  if (db) return db;

  const dbPath = resolveDbPath();
  console.log(`[db] Using database at: ${dbPath}`);

  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('secure_delete = ON');
  db.pragma('synchronous = NORMAL');

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
      ciphertext    TEXT NOT NULL DEFAULT '',
      nonce         TEXT NOT NULL DEFAULT '',
      ephemeral_pub TEXT NOT NULL DEFAULT '',
      client_ts     INTEGER NOT NULL DEFAULT 0,
      server_ts     INTEGER NOT NULL DEFAULT (unixepoch('now', 'subsec') * 1000),
      read_at       INTEGER,
      deleted_at    INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient_id, server_ts);
    CREATE INDEX IF NOT EXISTS idx_msg_sender    ON messages(sender_id, server_ts);
    CREATE INDEX IF NOT EXISTS idx_msg_pair      ON messages(sender_id, recipient_id, server_ts);

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
      .prepare('INSERT INTO users (id,username,password_hash,public_key,key_fingerprint,email) VALUES (?,?,?,?,?,?)')
      .run(id, username, passwordHash, publicKey, keyFingerprint, email || null);
  },
  findByUsername(username) {
    return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  },
  findById(id) {
    return getDb()
      .prepare('SELECT id,username,public_key,key_fingerprint,created_at,last_seen FROM users WHERE id = ?')
      .get(id);
  },
  searchByUsername(query, limit = 20) {
    return getDb()
      .prepare('SELECT id,username,public_key,key_fingerprint FROM users WHERE username LIKE ? LIMIT ?')
      .all(`${query}%`, limit);
  },
  updateLastSeen(id) {
    return getDb().prepare('UPDATE users SET last_seen = unixepoch() WHERE id = ?').run(id);
  },
  updatePublicKey(id, publicKey, keyFingerprint) {
    return getDb()
      .prepare('UPDATE users SET public_key = ?, key_fingerprint = ? WHERE id = ?')
      .run(publicKey, keyFingerprint, id);
  },
};

const tokenQueries = {
  create(id, userId, tokenHash, expiresAt) {
    return getDb()
      .prepare('INSERT INTO refresh_tokens (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)')
      .run(id, userId, tokenHash, expiresAt);
  },
  findByHash(tokenHash) {
    return getDb()
      .prepare('SELECT * FROM refresh_tokens WHERE token_hash=? AND revoked=0 AND expires_at>unixepoch()')
      .get(tokenHash);
  },
  revoke(id) {
    return getDb().prepare('UPDATE refresh_tokens SET revoked=1 WHERE id=?').run(id);
  },
  revokeAllForUser(userId) {
    return getDb().prepare('UPDATE refresh_tokens SET revoked=1 WHERE user_id=?').run(userId);
  },
  purgeExpired() {
    return getDb().prepare('DELETE FROM refresh_tokens WHERE expires_at<=unixepoch() OR revoked=1').run();
  },
};

const messageQueries = {
  insert(id, senderId, recipientId, ciphertext, nonce, ephemeralPub, clientTs) {
    return getDb()
      .prepare('INSERT INTO messages (id,sender_id,recipient_id,ciphertext,nonce,ephemeral_pub,client_ts) VALUES (?,?,?,?,?,?,?)')
      .run(id, senderId, recipientId, ciphertext, nonce, ephemeralPub, clientTs);
  },
  create({ id, sender_id, recipient_id, ciphertext, nonce, created_at }) {
    return getDb()
      .prepare("INSERT INTO messages (id,sender_id,recipient_id,ciphertext,nonce,ephemeral_pub,client_ts) VALUES (?,?,?,?,?,'',?)")
      .run(id, sender_id, recipient_id, ciphertext, nonce, created_at);
  },
  getConversation(userA, userB, limit = 50, beforeTs = null) {
    const sql = `
      SELECT id,sender_id,recipient_id,ciphertext,nonce,ephemeral_pub,client_ts,server_ts,read_at
      FROM   messages
      WHERE  deleted_at IS NULL
        AND  ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?))
        ${beforeTs ? 'AND server_ts<?' : ''}
      ORDER  BY server_ts DESC LIMIT ?`;
    const p = beforeTs ? [userA,userB,userB,userA,beforeTs,limit] : [userA,userB,userB,userA,limit];
    return getDb().prepare(sql).all(...p).reverse();
  },
  getUndelivered(recipientId, sinceTs) {
    return getDb()
      .prepare('SELECT id,sender_id,ciphertext,nonce,ephemeral_pub,client_ts,server_ts FROM messages WHERE recipient_id=? AND server_ts>? AND deleted_at IS NULL ORDER BY server_ts ASC')
      .all(recipientId, sinceTs);
  },
  markRead(messageId, recipientId) {
    return getDb()
      .prepare('UPDATE messages SET read_at=unixepoch() WHERE id=? AND recipient_id=? AND read_at IS NULL')
      .run(messageId, recipientId);
  },
  softDelete(messageId, requesterId) {
    return getDb()
      .prepare("UPDATE messages SET deleted_at=unixepoch(),ciphertext='deleted',nonce='del_'||id,ephemeral_pub='' WHERE id=? AND (sender_id=? OR recipient_id=?)")
      .run(messageId, requesterId, requesterId);
  },
  getConversationList(userId) {
    return getDb().prepare(`
      SELECT
        lm.id, lm.sender_id, lm.recipient_id, lm.ciphertext, lm.nonce,
        lm.ephemeral_pub, lm.server_ts,
        u.username        AS contact_username,
        u.public_key      AS contact_public_key,
        u.key_fingerprint AS contact_fingerprint,
        COALESCE(uc.unread_count, 0) AS unread_count
      FROM (
        SELECT
          CASE WHEN sender_id=? THEN recipient_id ELSE sender_id END AS contact_id,
          MAX(server_ts) AS max_ts
        FROM messages
        WHERE (sender_id=? OR recipient_id=?) AND deleted_at IS NULL
        GROUP BY contact_id
      ) AS conv
      JOIN messages lm
        ON  lm.server_ts = conv.max_ts
        AND ((lm.sender_id=? AND lm.recipient_id=conv.contact_id) OR (lm.recipient_id=? AND lm.sender_id=conv.contact_id))
        AND lm.deleted_at IS NULL
      JOIN users u ON u.id = conv.contact_id
      LEFT JOIN (
        SELECT sender_id, COUNT(*) AS unread_count
        FROM messages WHERE recipient_id=? AND read_at IS NULL AND deleted_at IS NULL
        GROUP BY sender_id
      ) AS uc ON uc.sender_id = conv.contact_id
      ORDER BY lm.server_ts DESC
    `).all(userId,userId,userId,userId,userId,userId);
  },
};

const prekeyQueries = {
  store(id, userId, prekeyPub, signature) {
    return getDb().prepare('INSERT INTO prekeys (id,user_id,prekey_pub,signature) VALUES (?,?,?,?)').run(id,userId,prekeyPub,signature);
  },
  fetchOne(userId) {
    const row = getDb().prepare('SELECT * FROM prekeys WHERE user_id=? AND used=0 ORDER BY created_at ASC LIMIT 1').get(userId);
    if (row) getDb().prepare('UPDATE prekeys SET used=1 WHERE id=?').run(row.id);
    return row;
  },
  countAvailable(userId) {
    return getDb().prepare('SELECT COUNT(*) AS count FROM prekeys WHERE user_id=? AND used=0').get(userId);
  },
};

const auditQueries = {
  log(event, userId, ip, userAgent, metadata = {}) {
    return getDb()
      .prepare('INSERT INTO audit_log (event,user_id,ip,user_agent,metadata) VALUES (?,?,?,?,?)')
      .run(event, userId||null, ip||null, userAgent||null, JSON.stringify(metadata));
  },
};

module.exports = { getDb, users:userQueries, tokens:tokenQueries, messages:messageQueries, prekeys:prekeyQueries, audit:auditQueries };
