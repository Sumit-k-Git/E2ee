'use strict';

/**
 * websocket.js — Authenticated WebSocket relay
 *
 * Security design:
 * - Every WS connection must present a valid JWT within 10 seconds of connecting
 *   or it is terminated
 * - The server is a BLIND RELAY: it reads sender_id and recipient_id to route,
 *   but NEVER decrypts or inspects ciphertext
 * - Per-user connection map allows targeted delivery
 * - All messages are stored in DB before ACK so nothing is lost
 */

const { WebSocketServer, WebSocket } = require('ws');
const { v4: uuidv4 } = require('uuid');
const { verifyAccessToken } = require('./auth');
const { messages, users, audit } = require('./database');

// userId → Set<WebSocket>
const connections = new Map();

function broadcast(userId, data) {
  const sockets = connections.get(userId);
  if (!sockets) return;
  const payload = JSON.stringify(data);
  for (const ws of sockets) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  }
}

function addConnection(userId, ws) {
  if (!connections.has(userId)) {
    connections.set(userId, new Set());
  }
  connections.get(userId).add(ws);
}

function removeConnection(userId, ws) {
  const sockets = connections.get(userId);
  if (!sockets) return;
  sockets.delete(ws);
  if (sockets.size === 0) connections.delete(userId);
}

function isOnline(userId) {
  return connections.has(userId) && connections.get(userId).size > 0;
}

function createWsServer(httpServer) {
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws, req) => {
    let userId = null;
    let username = null;

    // Auth timeout: if not authenticated within 10s, close
    const authTimeout = setTimeout(() => {
      if (!userId) {
        ws.close(4001, 'Authentication timeout');
      }
    }, 10_000);

    ws.on('message', (raw) => {
      let msg;
      try {
        // Size guard: reject payloads > 64KB
        if (raw.length > 65536) {
          ws.send(JSON.stringify({ type: 'error', code: 'PAYLOAD_TOO_LARGE' }));
          return;
        }
        msg = JSON.parse(raw);
      } catch {
        ws.send(JSON.stringify({ type: 'error', code: 'INVALID_JSON' }));
        return;
      }

      // ── AUTH ──────────────────────────────────────────────────────────
      if (msg.type === 'auth') {
        if (userId) {
          ws.send(JSON.stringify({ type: 'error', code: 'ALREADY_AUTHENTICATED' }));
          return;
        }
        const payload = verifyAccessToken(msg.token);
        if (!payload) {
          ws.send(JSON.stringify({ type: 'error', code: 'INVALID_TOKEN' }));
          ws.close(4001, 'Invalid token');
          return;
        }
        userId = payload.sub;
        username = payload.username;
        clearTimeout(authTimeout);
        addConnection(userId, ws);
        users.updateLastSeen(userId);

        ws.send(JSON.stringify({ type: 'auth_ok', userId, username }));

        // Deliver any missed messages since last seen
        // (client sends last_ts in auth message)
        const sinceTs = msg.last_ts || 0;
        const pending = messages.getUndelivered(userId, sinceTs);
        if (pending.length > 0) {
          ws.send(JSON.stringify({ type: 'pending_messages', messages: pending }));
        }

        audit.log('ws_connect', userId,
          req.headers['x-forwarded-for'] || req.socket.remoteAddress,
          req.headers['user-agent']);
        return;
      }

      // All other message types require authentication
      if (!userId) {
        ws.send(JSON.stringify({ type: 'error', code: 'UNAUTHENTICATED' }));
        return;
      }

      // ── SEND MESSAGE ──────────────────────────────────────────────────
      if (msg.type === 'send_message') {
        const { recipient_id, ciphertext, nonce, ephemeral_pub, client_ts } = msg;

        // Validate all required fields
        if (!recipient_id || !ciphertext || !nonce || !ephemeral_pub) {
          ws.send(JSON.stringify({ type: 'error', code: 'MISSING_FIELDS', ref: msg.ref }));
          return;
        }

        // Validate field lengths (base64 bounds)
        if (
          ciphertext.length > 16384 ||   // ~12KB max message
          nonce.length > 64 ||            // 24 bytes = 32 base64 chars
          ephemeral_pub.length > 64       // 32 bytes = 44 base64 chars
        ) {
          ws.send(JSON.stringify({ type: 'error', code: 'FIELD_TOO_LARGE', ref: msg.ref }));
          return;
        }

        // Verify recipient exists
        const recipient = users.findById(recipient_id);
        if (!recipient) {
          ws.send(JSON.stringify({ type: 'error', code: 'RECIPIENT_NOT_FOUND', ref: msg.ref }));
          return;
        }

        // Prevent messaging self (optional — remove if you want self-notes)
        if (recipient_id === userId) {
          ws.send(JSON.stringify({ type: 'error', code: 'CANNOT_MESSAGE_SELF', ref: msg.ref }));
          return;
        }

        const msgId = uuidv4();
        const serverTs = Date.now();

        // Persist (server stores only ciphertext — cannot decrypt)
        messages.insert(
          msgId, userId, recipient_id,
          ciphertext, nonce, ephemeral_pub,
          client_ts || serverTs
        );

        // ACK to sender
        ws.send(JSON.stringify({
          type: 'message_ack',
          ref: msg.ref,
          id: msgId,
          server_ts: serverTs,
        }));

        // Deliver to recipient if online
        const envelope = {
          type: 'new_message',
          id: msgId,
          sender_id: userId,
          sender_username: username,
          recipient_id,
          ciphertext,
          nonce,
          ephemeral_pub,
          client_ts: client_ts || serverTs,
          server_ts: serverTs,
        };
        broadcast(recipient_id, envelope);

        // Update last seen
        users.updateLastSeen(userId);
        return;
      }

      // ── MARK READ ─────────────────────────────────────────────────────
      if (msg.type === 'mark_read') {
        if (!msg.message_id) return;
        messages.markRead(msg.message_id, userId);
        // Notify sender that their message was read
        // (we'd need to know sender_id — look it up or trust client to include it)
        if (msg.sender_id) {
          broadcast(msg.sender_id, {
            type: 'message_read',
            message_id: msg.message_id,
            by: userId,
          });
        }
        return;
      }

      // ── TYPING INDICATOR ──────────────────────────────────────────────
      if (msg.type === 'typing') {
        if (!msg.recipient_id) return;
        // Only relay if recipient is online; never persist typing events
        broadcast(msg.recipient_id, {
          type: 'typing',
          from: userId,
          from_username: username,
          active: !!msg.active,
        });
        return;
      }

      // ── PING ─────────────────────────────────────────────────────────
      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
        return;
      }

      ws.send(JSON.stringify({ type: 'error', code: 'UNKNOWN_MESSAGE_TYPE' }));
    });

    ws.on('close', () => {
      clearTimeout(authTimeout);
      if (userId) {
        removeConnection(userId, ws);
        users.updateLastSeen(userId);
      }
    });

    ws.on('error', (err) => {
      console.error('[WS error]', err.message);
      if (userId) removeConnection(userId, ws);
    });
  });

  // Heartbeat: ping all clients every 30s; close dead connections
  const heartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        ws.terminate();
        return;
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, 30_000);

  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
  });

  wss.on('close', () => clearInterval(heartbeat));

  return { wss, broadcast, isOnline };
}

module.exports = { createWsServer, broadcast: (uid, data) => broadcast(uid, data), isOnline };
