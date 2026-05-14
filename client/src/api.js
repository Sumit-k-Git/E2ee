/**
 * api.js — HTTP + WebSocket client for vault.msg
 *
 * Security:
 * - Access tokens in memory only (never localStorage)
 * - Refresh tokens in sessionStorage (cleared on tab close)
 * - Auto silent refresh on 401
 */

const BASE   = import.meta.env.VITE_API_URL || 'http://localhost:4000/api';
const WS_URL = import.meta.env.VITE_WS_URL  || 'ws://localhost:4000/ws';

// ── Token storage ─────────────────────────────────────────────────────────
let _accessToken = null;
const setAccessToken  = (t) => { _accessToken = t; };
const getAccessToken  = ()  => _accessToken;
const setRefreshToken = (t) => t ? sessionStorage.setItem('rt', t) : sessionStorage.removeItem('rt');
const getRefreshToken = ()  => sessionStorage.getItem('rt');

export function clearTokens() {
  _accessToken = null;
  setRefreshToken(null);
}

// ── Core fetch ────────────────────────────────────────────────────────────
async function apiFetch(path, options = {}, retry = true) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });

  if (res.status === 401 && retry) {
    const refreshed = await silentRefresh();
    if (refreshed) return apiFetch(path, options, false);
    clearTokens();
    window.dispatchEvent(new Event('auth:expired'));
    throw new Error('Session expired — please sign in again');
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${res.status})`);
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
    }).then(r => r.ok ? r.json() : null);
    if (!data) return false;
    setAccessToken(data.access_token);
    setRefreshToken(data.refresh_token);
    return true;
  } catch { return false; }
}

// ── Auth API ──────────────────────────────────────────────────────────────
export const auth = {
  // Step 1 of registration — send OTP to email
  sendOTP: (email) =>
    apiFetch('/auth/send-otp', { method: 'POST', body: JSON.stringify({ email }) }),

  // Step 2 — verify OTP, get otp_token
  verifyOTP: (email, code) =>
    apiFetch('/auth/verify-otp', { method: 'POST', body: JSON.stringify({ email, code }) }),

  // Step 3 — complete registration with otp_token
  async register(username, password, publicKeyB64, keyFingerprint, email, otpToken) {
    const data = await apiFetch('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username, password,
        public_key: publicKeyB64,
        key_fingerprint: keyFingerprint,
        email, otp_token: otpToken,
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
    try { await apiFetch('/auth/logout', { method: 'POST' }); } finally { clearTokens(); }
  },

  restore: () => silentRefresh(),
};

// ── Users API ─────────────────────────────────────────────────────────────
export const usersApi = {
  me:        ()    => apiFetch('/users/me'),
  search:    (q)   => apiFetch(`/users/search?q=${encodeURIComponent(q)}`),
  getById:   (id)  => apiFetch(`/users/${id}`),
  updateKey: (publicKeyB64, keyFingerprint) =>
    apiFetch('/users/key', {
      method: 'PUT',
      body: JSON.stringify({ public_key: publicKeyB64, key_fingerprint: keyFingerprint }),
    }),
};

// ── Messages API ──────────────────────────────────────────────────────────
export const messagesApi = {
  getConversation:  (contactId, limit = 50, beforeTs) =>
    apiFetch(`/messages/${contactId}?limit=${limit}${beforeTs ? `&before_ts=${beforeTs}` : ''}`),
  getConversations: () => apiFetch('/conversations'),
  delete:           (id) => apiFetch(`/messages/${id}`, { method: 'DELETE' }),
};

// ── Prekeys API ───────────────────────────────────────────────────────────
export const prekeysApi = {
  upload:      (prekeys) => apiFetch('/prekeys', { method: 'POST', body: JSON.stringify({ prekeys }) }),
  fetchBundle: (userId)  => apiFetch(`/prekeys/${userId}`),
  count:       (userId)  => apiFetch(`/prekeys/${userId}/count`),
};

// ── WebSocket client ──────────────────────────────────────────────────────
export class VaultSocket {
  constructor(onMessage) {
    this.ws             = null;
    this.onMessage      = onMessage;
    this.reconnectDelay = 1000;
    this.maxDelay       = 30000;
    this.pendingAcks    = new Map();
    this.connected      = false;
    this.lastTs         = parseInt(localStorage.getItem('last_ws_ts') || '0');
    this._destroyed     = false;
  }

  connect() {
    if (this._destroyed) return;
    const token = getAccessToken();
    if (!token) return;

    this.ws = new WebSocket(WS_URL);

    this.ws.onopen = () => {
      this.reconnectDelay = 1000;
      this._send({ type: 'auth', token, last_ts: this.lastTs });
      this._heartbeat = setInterval(() => this._send({ type: 'ping' }), 25000);
    };

    this.ws.onmessage = (e) => {
      let msg; try { msg = JSON.parse(e.data); } catch { return; }
      this._handleMessage(msg);
    };

    this.ws.onclose = (e) => {
      this.connected = false;
      clearInterval(this._heartbeat);
      if (!this._destroyed && e.code !== 4001) {
        setTimeout(() => this.connect(), this.reconnectDelay);
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxDelay);
      }
      this.onMessage({ type: 'ws_status', status: 'disconnected' });
    };

    this.ws.onerror = () => this.ws.close();
  }

  _handleMessage(msg) {
    if (msg.type === 'auth_ok') {
      this.connected = true;
      this.onMessage({ type: 'ws_status', status: 'connected' });
      return;
    }
    if (msg.type === 'message_ack') {
      const p = this.pendingAcks.get(msg.ref);
      if (p) { clearTimeout(p.timer); p.resolve(msg); this.pendingAcks.delete(msg.ref); }
      return;
    }
    if (msg.server_ts) {
      this.lastTs = Math.max(this.lastTs, msg.server_ts);
      localStorage.setItem('last_ws_ts', String(this.lastTs));
    }
    this.onMessage(msg);
  }

  _send(data) {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(data));
  }

  sendMessage(recipientId, ciphertext, nonce, ephemeralPub, clientTs) {
    const ref = Math.random().toString(36).slice(2);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingAcks.delete(ref);
        reject(new Error('Message send timeout — check your connection'));
      }, 15000);
      this.pendingAcks.set(ref, { resolve, reject, timer });
      this._send({ type: 'send_message', ref, recipient_id: recipientId, ciphertext, nonce, ephemeral_pub: ephemeralPub, client_ts: clientTs });
    });
  }

  sendTyping(recipientId, active) { this._send({ type: 'typing', recipient_id: recipientId, active }); }
  markRead(messageId, senderId)   { this._send({ type: 'mark_read', message_id: messageId, sender_id: senderId }); }

  destroy() {
    this._destroyed = true;
    clearInterval(this._heartbeat);
    this.ws?.close();
  }
}
