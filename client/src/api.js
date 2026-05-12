/**
 * api.js — HTTP + WebSocket client for vault.msg
 *
 * Security features:
 * - Access tokens stored in memory only (never localStorage)
 * - Refresh tokens stored in sessionStorage (cleared on tab close)
 * - Automatic silent refresh when access token expires
 * - All requests over HTTPS in production
 */

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000/api';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:4000/ws';

// ── Token storage (memory + sessionStorage for refresh) ───────────────────
// Access token: memory only (XSS cannot steal it from memory)
// Refresh token: sessionStorage (persists across page refreshes in same tab)
//   → For higher security: use httpOnly cookie set by server instead

let _accessToken = null;

function setAccessToken(t) { _accessToken = t; }
function getAccessToken() { return _accessToken; }

function setRefreshToken(t) {
  if (t) sessionStorage.setItem('rt', t);
  else sessionStorage.removeItem('rt');
}
function getRefreshToken() { return sessionStorage.getItem('rt'); }

export function clearTokens() {
  _accessToken = null;
  setRefreshToken(null);
}

// ── HTTP fetch wrapper ────────────────────────────────────────────────────

async function apiFetch(path, options = {}, retry = true) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (_accessToken) {
    headers['Authorization'] = `Bearer ${_accessToken}`;
  }

  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers,
  });

  // Access token expired → try to refresh silently
  if (res.status === 401 && retry) {
    const refreshed = await silentRefresh();
    if (refreshed) {
      return apiFetch(path, options, false); // retry once
    } else {
      clearTokens();
      window.dispatchEvent(new Event('auth:expired'));
      throw new Error('Session expired');
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${res.status}`);
  }

  return res.json();
}

async function silentRefresh() {
  const rt = getRefreshToken();
  if (!rt) return false;
  try {
    const data = await fetch(`${BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: rt }),
    }).then((r) => (r.ok ? r.json() : null));

    if (!data) return false;
    setAccessToken(data.access_token);
    setRefreshToken(data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

// ── Auth API ──────────────────────────────────────────────────────────────

export const auth = {
  async register(username, password, publicKeyB64, keyFingerprint) {
    const data = await apiFetch('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username,
        password,
        public_key: publicKeyB64,
        key_fingerprint: keyFingerprint,
      }),
    });
    setAccessToken(data.access_token);
    setRefreshToken(data.refresh_token);
    return data;
  },

  async login(username, password) {
    const data = await apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    setAccessToken(data.access_token);
    setRefreshToken(data.refresh_token);
    return data;
  },

  async logout() {
    try {
      await apiFetch('/auth/logout', { method: 'POST' });
    } finally {
      clearTokens();
    }
  },

  // Try to restore session from stored refresh token
  async restore() {
    return silentRefresh();
  },
};

// ── User API ──────────────────────────────────────────────────────────────

export const usersApi = {
  me: () => apiFetch('/users/me'),
  search: (q) => apiFetch(`/users/search?q=${encodeURIComponent(q)}`),
  getById: (id) => apiFetch(`/users/${id}`),
};

// ── Message API ───────────────────────────────────────────────────────────

export const messagesApi = {
  getConversation: (contactId, limit = 50, beforeTs) =>
    apiFetch(`/messages/${contactId}?limit=${limit}${beforeTs ? `&before_ts=${beforeTs}` : ''}`),

  getConversations: () => apiFetch('/conversations'),

  delete: (messageId) => apiFetch(`/messages/${messageId}`, { method: 'DELETE' }),
};

// ── Prekey API ────────────────────────────────────────────────────────────

export const prekeysApi = {
  upload: (prekeys) =>
    apiFetch('/prekeys', { method: 'POST', body: JSON.stringify({ prekeys }) }),

  fetchBundle: (userId) => apiFetch(`/prekeys/${userId}`),
  count: (userId) => apiFetch(`/prekeys/${userId}/count`),
};

// ── WebSocket client ──────────────────────────────────────────────────────

export class VaultSocket {
  constructor(onMessage) {
    this.ws = null;
    this.onMessage = onMessage;
    this.reconnectDelay = 1000;
    this.maxDelay = 30000;
    this.pendingAcks = new Map(); // ref → { resolve, reject, timer }
    this.connected = false;
    this.lastTs = parseInt(localStorage.getItem('last_ws_ts') || '0');
    this._destroyed = false;
  }

  connect() {
    if (this._destroyed) return;
    const token = getAccessToken();
    if (!token) return;

    this.ws = new WebSocket(WS_URL);

    this.ws.onopen = () => {
      this.reconnectDelay = 1000;
      // Authenticate immediately
      this._send({ type: 'auth', token, last_ts: this.lastTs });
      // Start heartbeat
      this._heartbeat = setInterval(() => this._send({ type: 'ping' }), 25000);
    };

    this.ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      this._handleMessage(msg);
    };

    this.ws.onclose = (e) => {
      this.connected = false;
      clearInterval(this._heartbeat);
      if (!this._destroyed && e.code !== 4001) {
        // Auto-reconnect with exponential backoff
        setTimeout(() => this.connect(), this.reconnectDelay);
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxDelay);
      }
      this.onMessage({ type: 'ws_status', status: 'disconnected' });
    };

    this.ws.onerror = () => {
      this.ws.close();
    };
  }

  _handleMessage(msg) {
    if (msg.type === 'auth_ok') {
      this.connected = true;
      this.onMessage({ type: 'ws_status', status: 'connected' });
      return;
    }

    if (msg.type === 'message_ack') {
      const pending = this.pendingAcks.get(msg.ref);
      if (pending) {
        clearTimeout(pending.timer);
        pending.resolve(msg);
        this.pendingAcks.delete(msg.ref);
      }
      return;
    }

    if (msg.type === 'new_message' || msg.type === 'pending_messages') {
      if (msg.server_ts) {
        this.lastTs = Math.max(this.lastTs, msg.server_ts);
        localStorage.setItem('last_ws_ts', String(this.lastTs));
      }
    }

    this.onMessage(msg);
  }

  _send(data) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  /**
   * Send an encrypted message and wait for server ACK.
   * Returns a promise that resolves with { id, server_ts } or rejects on timeout.
   */
  sendMessage(recipientId, ciphertext, nonce, ephemeralPub, clientTs) {
    const ref = Math.random().toString(36).slice(2);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingAcks.delete(ref);
        reject(new Error('Message send timeout'));
      }, 15000);

      this.pendingAcks.set(ref, { resolve, reject, timer });

      this._send({
        type: 'send_message',
        ref,
        recipient_id: recipientId,
        ciphertext,
        nonce,
        ephemeral_pub: ephemeralPub,
        client_ts: clientTs,
      });
    });
  }

  sendTyping(recipientId, active) {
    this._send({ type: 'typing', recipient_id: recipientId, active });
  }

  markRead(messageId, senderId) {
    this._send({ type: 'mark_read', message_id: messageId, sender_id: senderId });
  }

  destroy() {
    this._destroyed = true;
    clearInterval(this._heartbeat);
    this.ws?.close();
  }
}
