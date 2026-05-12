import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  generateIdentityKeypair, loadIdentityKeypair, computeFingerprint,
  formatFingerprint, encryptMessage, decryptMessage,
  publicKeyToBase64, base64ToBytes,
} from './crypto.js';
import { auth, usersApi, messagesApi, VaultSocket, clearTokens } from './api.js';

// ── Styles ────────────────────────────────────────────────────────────────
const G = {
  bg: '#0c0d11', surface: '#13141a', surface2: '#1a1b23', surface3: '#21222d',
  border: '#272833', accent: '#6c63ff', accent2: '#4fd1c5', accent3: '#ff6b6b',
  text: '#e4e5f0', muted: '#5a5d73', muted2: '#7b7e96',
  sentBg: '#1a193a', sentBorder: '#373578', recvBg: '#16171e',
  online: '#4ade80', danger: '#ff5c5c',
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;1,400&family=Plus+Jakarta+Sans:wght@300;400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${G.bg}; color: ${G.text}; font-family: 'Plus Jakarta Sans', sans-serif; }
  ::-webkit-scrollbar { width: 3px; }
  ::-webkit-scrollbar-thumb { background: ${G.border}; border-radius: 3px; }
  input, textarea, button { font-family: inherit; }
  a { color: ${G.accent}; }

  @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes slideIn { from { opacity:0; transform:translateX(-8px); } to { opacity:1; transform:none; } }

  .msg-enter { animation: fadeIn 0.18s ease-out; }
  .typing-pulse { animation: pulse 1.4s ease-in-out infinite; }
  .spinner { animation: spin 0.8s linear infinite; width:18px; height:18px; border:2px solid ${G.border}; border-top-color:${G.accent}; border-radius:50%; display:inline-block; }

  .app { height:100vh; display:grid; grid-template-columns:300px 1fr; overflow:hidden; }

  /* Sidebar */
  .sidebar { background:${G.surface}; border-right:1px solid ${G.border}; display:flex; flex-direction:column; overflow:hidden; }
  .sidebar-top { padding:18px 16px 12px; border-bottom:1px solid ${G.border}; flex-shrink:0; }
  .brand { font-family:'IBM Plex Mono',monospace; font-size:15px; font-weight:500; color:${G.accent}; letter-spacing:.06em; }
  .brand-sub { font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace; margin-top:1px; }
  .ws-dot { display:inline-block; width:6px; height:6px; border-radius:50%; margin-right:5px; vertical-align:middle; }
  .ws-dot.on { background:${G.online}; }
  .ws-dot.off { background:${G.danger}; }

  .me-card { margin:12px 16px; padding:10px 12px; background:${G.surface2}; border:1px solid ${G.border}; border-radius:10px; }
  .me-name { font-size:13px; font-weight:600; display:flex; align-items:center; gap:6px; }
  .me-fp { font-family:'IBM Plex Mono',monospace; font-size:9px; color:${G.muted}; margin-top:4px; line-height:1.6; word-break:break-all; }
  .me-fp-label { font-size:9px; color:${G.accent2}; font-family:'IBM Plex Mono',monospace; margin-top:2px; }

  .section-label { padding:12px 16px 6px; font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace; text-transform:uppercase; letter-spacing:.07em; }

  .search-wrap { padding:0 12px 10px; }
  .search-input { width:100%; background:${G.surface2}; border:1px solid ${G.border}; border-radius:8px; padding:8px 12px; color:${G.text}; font-size:12px; outline:none; transition:border-color .15s; }
  .search-input:focus { border-color:${G.accent}; }
  .search-input::placeholder { color:${G.muted}; }
  .search-results { padding:0 10px; }
  .search-result-item { display:flex; align-items:center; gap:10px; padding:8px 10px; border-radius:8px; cursor:pointer; transition:background .12s; }
  .search-result-item:hover { background:${G.surface2}; }

  .contacts { flex:1; overflow-y:auto; padding:0 10px 10px; }
  .contact-row { display:flex; align-items:center; gap:10px; padding:9px 10px; border-radius:10px; cursor:pointer; transition:background .12s; margin-bottom:1px; animation:slideIn .15s ease-out; }
  .contact-row:hover { background:${G.surface2}; }
  .contact-row.active { background:${G.sentBg}; border:1px solid ${G.sentBorder}; }
  .contact-info { flex:1; min-width:0; }
  .contact-name { font-size:13px; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .contact-preview { font-size:11px; color:${G.muted}; margin-top:1px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-family:'IBM Plex Mono',monospace; }
  .unread-badge { background:${G.accent}; color:#fff; font-size:10px; font-weight:600; padding:2px 6px; border-radius:10px; min-width:18px; text-align:center; flex-shrink:0; }

  /* Avatar */
  .avatar { border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:600; flex-shrink:0; font-size:13px; }

  /* Chat */
  .chat { display:flex; flex-direction:column; overflow:hidden; background:${G.bg}; }
  .chat-header { padding:13px 20px; border-bottom:1px solid ${G.border}; display:flex; align-items:center; gap:12px; background:${G.surface}; flex-shrink:0; }
  .chat-contact-name { font-size:15px; font-weight:600; }
  .e2ee-tag { font-size:10px; color:${G.accent2}; font-family:'IBM Plex Mono',monospace; background:rgba(79,209,197,.08); border:1px solid rgba(79,209,197,.18); padding:2px 8px; border-radius:20px; margin-top:2px; display:inline-block; }

  .msgs { flex:1; overflow-y:auto; padding:18px 20px; display:flex; flex-direction:column; gap:6px; }
  .day-sep { text-align:center; font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace; margin:10px 0; display:flex; align-items:center; gap:10px; }
  .day-sep::before,.day-sep::after { content:''; flex:1; height:1px; background:${G.border}; }

  .msg-row { display:flex; flex-direction:column; }
  .msg-row.sent { align-items:flex-end; }
  .msg-row.recv { align-items:flex-start; }
  .bubble { max-width:66%; padding:9px 14px; border-radius:16px; font-size:13.5px; line-height:1.55; word-break:break-word; }
  .msg-row.sent .bubble { background:${G.sentBg}; border:1px solid ${G.sentBorder}; border-bottom-right-radius:4px; color:#d5d0ff; }
  .msg-row.recv .bubble { background:${G.recvBg}; border:1px solid ${G.border}; border-bottom-left-radius:4px; }
  .msg-meta { font-size:10px; color:${G.muted}; margin-top:3px; display:flex; align-items:center; gap:5px; font-family:'IBM Plex Mono',monospace; }
  .lock-icon { color:${G.accent2}; font-size:9px; }
  .read-tick { color:${G.accent2}; font-size:10px; }
  .decrypt-fail { color:${G.danger}; font-style:italic; font-size:12px; }

  .cipher-toggle { font-family:'IBM Plex Mono',monospace; font-size:9px; color:${G.muted}; padding:2px 6px; background:rgba(255,255,255,.03); border:1px solid ${G.border}; border-radius:4px; cursor:pointer; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; transition:background .12s; }
  .cipher-toggle:hover { background:rgba(255,255,255,.07); }

  .typing-indicator { padding:4px 20px; font-size:11px; color:${G.muted}; font-style:italic; height:22px; flex-shrink:0; }

  /* Input */
  .input-area { padding:12px 20px 16px; border-top:1px solid ${G.border}; background:${G.surface}; flex-shrink:0; }
  .input-row { display:flex; gap:9px; align-items:flex-end; }
  .msg-input { flex:1; background:${G.surface2}; border:1px solid ${G.border}; border-radius:12px; padding:10px 15px; color:${G.text}; font-size:13.5px; outline:none; resize:none; min-height:43px; max-height:110px; line-height:1.5; transition:border-color .15s; }
  .msg-input:focus { border-color:${G.accent}; }
  .msg-input::placeholder { color:${G.muted}; }
  .send-btn { background:${G.accent}; border:none; border-radius:12px; width:43px; height:43px; display:flex; align-items:center; justify-content:center; cursor:pointer; color:#fff; font-size:17px; transition:all .13s; flex-shrink:0; }
  .send-btn:hover:not(:disabled) { background:#7c73ff; transform:scale(1.05); }
  .send-btn:disabled { background:${G.border}; cursor:not-allowed; transform:none; opacity:.5; }
  .input-hint { font-size:10px; color:${G.muted}; margin-top:7px; font-family:'IBM Plex Mono',monospace; display:flex; align-items:center; gap:5px; }

  /* Empty state */
  .empty { flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:8px; color:${G.muted}; }
  .empty-icon { font-size:38px; opacity:.25; margin-bottom:4px; }
  .empty-title { font-size:15px; color:${G.text}; opacity:.4; font-weight:500; }
  .empty-sub { font-size:12px; text-align:center; max-width:220px; line-height:1.65; }

  /* Auth screen */
  .auth-screen { height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; background:${G.bg}; }
  .auth-logo { font-family:'IBM Plex Mono',monospace; font-size:26px; font-weight:500; color:${G.accent}; letter-spacing:.06em; margin-bottom:4px; }
  .auth-tagline { font-size:12px; color:${G.muted}; margin-bottom:36px; }
  .auth-card { background:${G.surface}; border:1px solid ${G.border}; border-radius:18px; padding:28px; width:360px; }
  .auth-tabs { display:flex; gap:2px; background:${G.surface2}; border-radius:10px; padding:3px; margin-bottom:24px; }
  .auth-tab { flex:1; padding:8px; border-radius:8px; border:none; background:none; color:${G.muted}; font-size:13px; font-weight:500; cursor:pointer; transition:all .15s; font-family:inherit; }
  .auth-tab.active { background:${G.accent}; color:#fff; }
  .field-label { font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace; text-transform:uppercase; letter-spacing:.06em; margin-bottom:6px; }
  .field-input { width:100%; background:${G.surface2}; border:1px solid ${G.border}; border-radius:9px; padding:11px 13px; color:${G.text}; font-size:13.5px; outline:none; margin-bottom:14px; transition:border-color .15s; }
  .field-input:focus { border-color:${G.accent}; }
  .field-input::placeholder { color:${G.muted}; }
  .auth-btn { width:100%; background:${G.accent}; border:none; border-radius:9px; color:#fff; font-size:14px; font-weight:500; padding:12px; cursor:pointer; transition:background .15s; font-family:inherit; display:flex; align-items:center; justify-content:center; gap:8px; }
  .auth-btn:hover:not(:disabled) { background:#7c73ff; }
  .auth-btn:disabled { opacity:.6; cursor:not-allowed; }
  .auth-note { font-size:11px; color:${G.muted}; text-align:center; margin-top:14px; line-height:1.65; }
  .error-msg { font-size:12px; color:${G.danger}; margin-bottom:12px; padding:8px 12px; background:rgba(255,92,92,.08); border:1px solid rgba(255,92,92,.2); border-radius:8px; }
  .pw-strength { height:3px; border-radius:2px; margin-bottom:14px; margin-top:-10px; transition:all .3s; }

  /* Key verify modal */
  .modal-wrap { position:fixed; inset:0; background:rgba(0,0,0,.75); display:flex; align-items:center; justify-content:center; z-index:200; backdrop-filter:blur(6px); }
  .modal { background:${G.surface}; border:1px solid ${G.border}; border-radius:18px; padding:24px; max-width:420px; width:92%; max-height:90vh; overflow-y:auto; }
  .modal-title { font-size:15px; font-weight:600; margin-bottom:18px; }
  .key-block { background:${G.surface2}; border:1px solid ${G.border}; border-radius:10px; padding:12px; margin-bottom:12px; }
  .key-label { font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace; text-transform:uppercase; letter-spacing:.06em; margin-bottom:6px; }
  .key-val { font-family:'IBM Plex Mono',monospace; font-size:10px; word-break:break-all; line-height:1.8; color:${G.accent2}; }
  .key-val.danger { color:${G.danger}; }
  .fp-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:4px; margin-top:4px; }
  .fp-cell { font-family:'IBM Plex Mono',monospace; font-size:11px; text-align:center; padding:4px; background:rgba(255,255,255,.04); border-radius:4px; letter-spacing:.04em; }
  .modal-note { font-size:11px; color:${G.muted}; line-height:1.7; padding:10px 12px; background:rgba(108,99,255,.06); border:1px solid rgba(108,99,255,.15); border-radius:8px; margin-top:12px; }
  .modal-close { margin-top:16px; width:100%; background:${G.surface2}; border:1px solid ${G.border}; border-radius:9px; color:${G.text}; font-family:inherit; font-size:13px; font-weight:500; padding:10px; cursor:pointer; transition:background .15s; }
  .modal-close:hover { background:${G.surface3}; }

  /* Btn row */
  .btn-row { display:flex; gap:8px; align-items:center; }
  .icon-btn { background:none; border:1px solid ${G.border}; color:${G.muted}; padding:5px 11px; border-radius:8px; cursor:pointer; font-size:11px; font-family:'IBM Plex Mono',monospace; transition:all .15s; }
  .icon-btn:hover { border-color:${G.accent}; color:${G.accent}; }

  /* password strength colors */
  .pw-0 { background:${G.border}; width:0%; }
  .pw-1 { background:${G.danger}; width:25%; }
  .pw-2 { background:#f59e0b; width:50%; }
  .pw-3 { background:#84cc16; width:75%; }
  .pw-4 { background:${G.online}; width:100%; }

  /* Add contact panel */
  .add-contact-panel { padding:0 10px 10px; }
`;

// ── Avatar ────────────────────────────────────────────────────────────────
const AVATAR_PALETTE = [
  { bg: '#1e1d3a', c: '#a89fff' }, { bg: '#0d2a28', c: '#4fd1c5' },
  { bg: '#2a1515', c: '#ff8a8a' }, { bg: '#162515', c: '#86efac' },
  { bg: '#1a1a2e', c: '#818cf8' }, { bg: '#2a1a0e', c: '#fb923c' },
];
function Avatar({ name, size = 36 }) {
  const idx = name ? name.charCodeAt(0) % AVATAR_PALETTE.length : 0;
  const { bg, c } = AVATAR_PALETTE[idx];
  return (
    <div className="avatar" style={{ width: size, height: size, background: bg, color: c, fontSize: size * 0.38 }}>
      {name?.[0]?.toUpperCase()}
    </div>
  );
}

// ── Password strength ─────────────────────────────────────────────────────
function pwStrength(pw) {
  let score = 0;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

function formatTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
function formatDate(ts) {
  const d = new Date(ts);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return 'Today';
  return d.toLocaleDateString();
}

// ── Auth screen ───────────────────────────────────────────────────────────
function AuthScreen({ onAuth }) {
  const [tab, setTab] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const strength = pwStrength(password);

  const submit = async () => {
    setError('');
    setLoading(true);
    try {
      let kp = await loadIdentityKeypair();
      let isNew = false;
      if (!kp) {
        kp = await generateIdentityKeypair();
        isNew = true;
      }
      const pubB64 = publicKeyToBase64(kp);
      const fp = await computeFingerprint(kp.publicKey);

      let data;
      if (tab === 'register' || isNew) {
        data = await auth.register(username.trim(), password, pubB64, fp);
      } else {
        data = await auth.login(username.trim(), password);
      }
      onAuth(data.user, kp);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-screen">
      <div className="auth-logo">vault.msg</div>
      <div className="auth-tagline">Zero-knowledge end-to-end encrypted messenger</div>
      <div className="auth-card">
        <div className="auth-tabs">
          {['login', 'register'].map((t) => (
            <button key={t} className={`auth-tab${tab === t ? ' active' : ''}`} onClick={() => { setTab(t); setError(''); }}>
              {t === 'login' ? 'Sign in' : 'Create account'}
            </button>
          ))}
        </div>

        {error && <div className="error-msg">⚠ {error}</div>}

        <div className="field-label">Username</div>
        <input className="field-input" value={username} onChange={e => setUsername(e.target.value)}
          placeholder="3–32 characters" onKeyDown={e => e.key === 'Enter' && submit()} autoFocus />

        <div className="field-label">Password</div>
        <input className="field-input" type="password" value={password} onChange={e => setPassword(e.target.value)}
          placeholder={tab === 'register' ? '12+ chars, mixed case, number, symbol' : 'Your password'}
          onKeyDown={e => e.key === 'Enter' && submit()} />

        {tab === 'register' && (
          <div className={`pw-strength pw-${strength}`} />
        )}

        <button className="auth-btn" onClick={submit} disabled={loading || !username || !password}>
          {loading ? <span className="spinner" /> : null}
          {loading ? 'Working…' : tab === 'login' ? 'Sign in' : 'Create account & generate keys'}
        </button>

        <div className="auth-note">
          {tab === 'register'
            ? 'Your X25519 keypair is generated locally in your browser. Your private key never leaves this device.'
            : 'Your private key is stored only in this browser\'s IndexedDB, never on the server.'}
        </div>
      </div>
    </div>
  );
}

// ── Key verification modal ────────────────────────────────────────────────
function KeyModal({ myKeys, myUser, contact, onClose }) {
  const myFp = useMemo(() => contact ? formatFingerprint(myUser.key_fingerprint || '') : '', [myUser]);
  const theirFp = useMemo(() => formatFingerprint(contact?.key_fingerprint || ''), [contact]);
  const myPubB64 = useMemo(() => publicKeyToBase64(myKeys), [myKeys]);

  return (
    <div className="modal-wrap" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-title">🔑 Key verification — {contact?.username}</div>

        <div className="key-block">
          <div className="key-label">Your public key</div>
          <div className="key-val">{myPubB64}</div>
          <div className="key-label" style={{ marginTop: 8 }}>Your fingerprint</div>
          <div className="fp-grid">
            {(myUser.key_fingerprint || '').match(/.{1,4}/g)?.map((seg, i) => (
              <div key={i} className="fp-cell" style={{ color: G.accent2 }}>{seg}</div>
            ))}
          </div>
        </div>

        <div className="key-block">
          <div className="key-label">{contact?.username}'s public key</div>
          <div className="key-val">{contact?.public_key}</div>
          <div className="key-label" style={{ marginTop: 8 }}>Their fingerprint</div>
          <div className="fp-grid">
            {(contact?.key_fingerprint || '').match(/.{1,4}/g)?.map((seg, i) => (
              <div key={i} className="fp-cell" style={{ color: G.accent }}>{seg}</div>
            ))}
          </div>
        </div>

        <div className="modal-note">
          💡 To confirm no man-in-the-middle attack, compare these fingerprints with {contact?.username} over a separate channel (phone call, in person, Signal). If they match, the channel is secure.
        </div>

        <button className="modal-close" onClick={onClose}>Close</button>
      </div>
    </div>
  );
}

// ── Main app ──────────────────────────────────────────────────────────────
export default function App() {
  const [user, setUser] = useState(null);
  const [myKeys, setMyKeys] = useState(null);
  const [wsStatus, setWsStatus] = useState('disconnected');
  const [contacts, setContacts] = useState({}); // id → { id, username, public_key, key_fingerprint }
  const [messages, setMessages] = useState({}); // contactId → msg[]
  const [activeId, setActiveId] = useState(null);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [typingFrom, setTypingFrom] = useState(null);
  const [searchQ, setSearchQ] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [showCipher, setShowCipher] = useState({});
  const [unread, setUnread] = useState({});
  const [error, setError] = useState('');
  const socketRef = useRef(null);
  const typingTimer = useRef(null);
  const msgsEndRef = useRef(null);

  useEffect(() => { msgsEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages, activeId]);

  // Restore session on mount
  useEffect(() => {
    (async () => {
      const restored = await auth.restore();
      if (restored) {
        const kp = await loadIdentityKeypair();
        if (kp) {
          const me = await usersApi.me().catch(() => null);
          if (me) {
            setUser(me);
            setMyKeys(kp);
          }
        }
      }
    })();
    window.addEventListener('auth:expired', handleExpired);
    return () => window.removeEventListener('auth:expired', handleExpired);
  }, []);

  function handleExpired() {
    setUser(null); setMyKeys(null); clearTokens();
  }

  // Set up WebSocket after login
  useEffect(() => {
    if (!user || !myKeys) return;
    loadConversations();

    const sock = new VaultSocket(handleWsMessage);
    socketRef.current = sock;
    sock.connect();

    return () => sock.destroy();
  }, [user?.id]);

  async function loadConversations() {
    try {
      const convos = await messagesApi.getConversations();
      const contactMap = {};
      convos.forEach(c => {
        const cId = c.sender_id === user.id ? c.recipient_id : c.sender_id;
        contactMap[cId] = {
          id: cId,
          username: c.contact_username,
          public_key: c.contact_public_key,
          key_fingerprint: c.contact_fingerprint,
        };
        if (c.unread_count > 0) {
          setUnread(prev => ({ ...prev, [cId]: c.unread_count }));
        }
      });
      setContacts(prev => ({ ...prev, ...contactMap }));
    } catch {}
  }

  async function loadHistory(contactId) {
    if (!myKeys) return;
    try {
      const { messages: hist, contact } = await messagesApi.getConversation(contactId);
      if (contact) {
        setContacts(prev => ({ ...prev, [contactId]: contact }));
      }
      const decrypted = hist.map(m => decryptIncoming(m, contactId));
      setMessages(prev => ({ ...prev, [contactId]: decrypted }));
    } catch {}
  }

  function decryptIncoming(m, contactId) {
    if (m.sender_id === user.id) {
      // We sent this — we can't decrypt our own sent messages (forward secrecy)
      // In a full implementation, you'd keep a local encrypted copy
      return { ...m, text: '[sent message]', direction: 'sent', cannotDecrypt: true };
    }
    const text = decryptMessage(m.ciphertext, m.nonce, m.ephemeral_pub, myKeys.secretKey);
    return { ...m, text: text || null, direction: 'recv', decryptFailed: !text };
  }

  function handleWsMessage(msg) {
    if (msg.type === 'ws_status') {
      setWsStatus(msg.status);
      return;
    }

    if (msg.type === 'new_message') {
      const contactId = msg.sender_id;
      const contact = contacts[contactId];
      const text = decryptMessage(msg.ciphertext, msg.nonce, msg.ephemeral_pub, myKeys.secretKey);
      const enriched = { ...msg, text, direction: 'recv', decryptFailed: !text };

      setMessages(prev => ({
        ...prev,
        [contactId]: [...(prev[contactId] || []), enriched],
      }));

      if (activeId !== contactId) {
        setUnread(prev => ({ ...prev, [contactId]: (prev[contactId] || 0) + 1 }));
      } else {
        socketRef.current?.markRead(msg.id, msg.sender_id);
      }

      if (!contacts[contactId]) {
        usersApi.getById(contactId).then(u => {
          setContacts(prev => ({ ...prev, [contactId]: u }));
        }).catch(() => {});
      }
      return;
    }

    if (msg.type === 'pending_messages') {
      msg.messages.forEach(m => {
        const contactId = m.sender_id;
        const text = decryptMessage(m.ciphertext, m.nonce, m.ephemeral_pub, myKeys.secretKey);
        const enriched = { ...m, text, direction: 'recv', decryptFailed: !text };
        setMessages(prev => ({
          ...prev,
          [contactId]: [...(prev[contactId] || []), enriched],
        }));
      });
      return;
    }

    if (msg.type === 'typing') {
      setTypingFrom(msg.active ? msg.from_username : null);
      if (msg.active) {
        clearTimeout(typingTimer.current);
        typingTimer.current = setTimeout(() => setTypingFrom(null), 3000);
      }
      return;
    }

    if (msg.type === 'message_read') {
      setMessages(prev => {
        const updated = { ...prev };
        for (const cId of Object.keys(updated)) {
          updated[cId] = updated[cId].map(m =>
            m.id === msg.message_id ? { ...m, read_at: Date.now() } : m
          );
        }
        return updated;
      });
    }
  }

  async function selectContact(contactId) {
    setActiveId(contactId);
    setUnread(prev => ({ ...prev, [contactId]: 0 }));
    if (!messages[contactId]) {
      await loadHistory(contactId);
    }
  }

  async function sendMessage() {
    if (!input.trim() || !activeId || !myKeys || sending) return;
    const contact = contacts[activeId];
    if (!contact) return;

    const text = input.trim();
    setInput('');
    setSending(true);

    try {
      const recipientPubKey = base64ToBytes(contact.public_key);
      const { ciphertext, nonce, ephemeral_pub } = encryptMessage(text, recipientPubKey);
      const clientTs = Date.now();

      // Optimistic UI
      const tempId = 'tmp-' + Date.now();
      const optimistic = { id: tempId, text, direction: 'sent', client_ts: clientTs, server_ts: clientTs, pending: true };
      setMessages(prev => ({
        ...prev,
        [activeId]: [...(prev[activeId] || []), optimistic],
      }));

      const ack = await socketRef.current.sendMessage(activeId, ciphertext, nonce, ephemeral_pub, clientTs);

      // Replace temp message with confirmed
      setMessages(prev => ({
        ...prev,
        [activeId]: prev[activeId].map(m =>
          m.id === tempId ? { ...optimistic, id: ack.id, server_ts: ack.server_ts, pending: false } : m
        ),
      }));
    } catch (e) {
      setError('Failed to send: ' + e.message);
      setTimeout(() => setError(''), 4000);
    } finally {
      setSending(false);
    }
  }

  function handleInputChange(e) {
    setInput(e.target.value);
    if (activeId && socketRef.current) {
      socketRef.current.sendTyping(activeId, true);
      clearTimeout(typingTimer.current);
      typingTimer.current = setTimeout(() => {
        socketRef.current?.sendTyping(activeId, false);
      }, 2000);
    }
  }

  async function searchUsers(q) {
    setSearchQ(q);
    if (q.length < 2) { setSearchResults([]); return; }
    try {
      const results = await usersApi.search(q);
      setSearchResults(results);
    } catch {}
  }

  function addContact(u) {
    setContacts(prev => ({ ...prev, [u.id]: u }));
    setSearchQ('');
    setSearchResults([]);
    selectContact(u.id);
  }

  async function handleLogout() {
    await auth.logout();
    setUser(null); setMyKeys(null);
    socketRef.current?.destroy();
  }

  if (!user || !myKeys) {
    return (
      <>
        <style>{css}</style>
        <AuthScreen onAuth={(u, kp) => { setUser(u); setMyKeys(kp); }} />
      </>
    );
  }

  const activeContact = contacts[activeId];
  const activeMessages = messages[activeId] || [];
  const sortedContacts = Object.values(contacts).sort((a, b) => {
    const lastA = messages[a.id]?.slice(-1)[0]?.server_ts || 0;
    const lastB = messages[b.id]?.slice(-1)[0]?.server_ts || 0;
    return lastB - lastA;
  });

  return (
    <>
      <style>{css}</style>
      <div className="app">
        {/* ── Sidebar ── */}
        <div className="sidebar">
          <div className="sidebar-top">
            <div className="brand">vault.msg</div>
            <div className="brand-sub">
              <span className={`ws-dot ${wsStatus === 'connected' ? 'on' : 'off'}`} />
              {wsStatus === 'connected' ? 'Encrypted · Connected' : 'Reconnecting…'}
            </div>
          </div>

          <div className="me-card">
            <div className="me-name">
              <Avatar name={user.username} size={22} />
              {user.username}
              <button className="icon-btn" style={{ marginLeft: 'auto', fontSize: 10 }} onClick={handleLogout}>
                Sign out
              </button>
            </div>
            <div className="me-fp-label">Your key fingerprint</div>
            <div className="me-fp">{formatFingerprint(user.key_fingerprint || '')}</div>
          </div>

          <div className="section-label">Find people</div>
          <div className="search-wrap">
            <input className="search-input" placeholder="Search username…" value={searchQ}
              onChange={e => searchUsers(e.target.value)} />
          </div>

          {searchResults.length > 0 && (
            <div className="search-results">
              {searchResults.map(u => (
                <div key={u.id} className="search-result-item" onClick={() => addContact(u)}>
                  <Avatar name={u.username} size={30} />
                  <div style={{ fontSize: 13, fontWeight: 500 }}>{u.username}</div>
                </div>
              ))}
            </div>
          )}

          <div className="section-label">Conversations</div>
          <div className="contacts">
            {sortedContacts.map(c => {
              const lastMsg = messages[c.id]?.slice(-1)[0];
              return (
                <div key={c.id} className={`contact-row${activeId === c.id ? ' active' : ''}`}
                  onClick={() => selectContact(c.id)}>
                  <Avatar name={c.username} size={36} />
                  <div className="contact-info">
                    <div className="contact-name">{c.username}</div>
                    <div className="contact-preview">
                      {lastMsg
                        ? (lastMsg.cannotDecrypt ? '🔒 [encrypted]' : lastMsg.text?.slice(0, 36) || '…')
                        : '🔒 E2EE channel'}
                    </div>
                  </div>
                  {(unread[c.id] || 0) > 0 && (
                    <div className="unread-badge">{unread[c.id]}</div>
                  )}
                </div>
              );
            })}
            {sortedContacts.length === 0 && (
              <div style={{ fontSize: 12, color: G.muted, textAlign: 'center', padding: '20px 10px', lineHeight: 1.7 }}>
                Search for a username above<br />to start a conversation
              </div>
            )}
          </div>
        </div>

        {/* ── Chat ── */}
        <div className="chat">
          {!activeContact ? (
            <div className="empty">
              <div className="empty-icon">🔐</div>
              <div className="empty-title">Select a conversation</div>
              <div className="empty-sub">Messages are encrypted before leaving your device. The server is a blind relay.</div>
            </div>
          ) : (
            <>
              <div className="chat-header">
                <Avatar name={activeContact.username} size={38} />
                <div style={{ flex: 1 }}>
                  <div className="chat-contact-name">{activeContact.username}</div>
                  <div className="e2ee-tag">🔒 X25519 · XSalsa20-Poly1305 · Forward Secrecy</div>
                </div>
                <div className="btn-row">
                  <button className="icon-btn" onClick={() => setShowKeyModal(true)}>Verify keys</button>
                </div>
              </div>

              {error && (
                <div style={{ padding: '8px 20px', fontSize: 12, color: G.danger, background: 'rgba(255,92,92,.08)', borderBottom: `1px solid rgba(255,92,92,.2)` }}>
                  ⚠ {error}
                </div>
              )}

              <div className="msgs">
                {activeMessages.map((m, i) => {
                  const showDay = i === 0 || formatDate(activeMessages[i - 1].server_ts) !== formatDate(m.server_ts);
                  return (
                    <div key={m.id}>
                      {showDay && <div className="day-sep">{formatDate(m.server_ts)}</div>}
                      <div className={`msg-row ${m.direction} msg-enter`}>
                        <div className="bubble">
                          {m.decryptFailed
                            ? <span className="decrypt-fail">⚠ Could not decrypt — key mismatch</span>
                            : m.cannotDecrypt
                            ? <span style={{ color: G.muted, fontStyle: 'italic', fontSize: 12 }}>🔒 Sent (encrypted, forward-secret)</span>
                            : m.text}
                        </div>
                        <div className="msg-meta">
                          <span className="lock-icon">🔒</span>
                          {formatTime(m.server_ts || m.client_ts)}
                          {m.pending && <span className="typing-pulse" style={{ fontSize: 10, color: G.muted }}>sending…</span>}
                          {m.read_at && m.direction === 'sent' && <span className="read-tick">✓✓</span>}
                          {!m.cannotDecrypt && !m.decryptFailed && m.ciphertext && (
                            <span className="cipher-toggle" onClick={() => setShowCipher(p => ({ ...p, [m.id]: !p[m.id] }))}>
                              {showCipher[m.id] ? m.ciphertext : `[cipher] ${m.ciphertext?.slice(0, 24)}…`}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
                <div ref={msgsEndRef} />
              </div>

              <div className="typing-indicator">
                {typingFrom && activeId && contacts[activeId]?.username === typingFrom
                  ? <span className="typing-pulse">✍ {typingFrom} is typing…</span>
                  : null}
              </div>

              <div className="input-area">
                <div className="input-row">
                  <textarea className="msg-input" placeholder={`Message ${activeContact.username}… (encrypted before sending)`}
                    value={input} onChange={handleInputChange}
                    onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                    rows={1} />
                  <button className="send-btn" onClick={sendMessage} disabled={!input.trim() || sending}>
                    {sending ? <span className="spinner" style={{ width: 14, height: 14 }} /> : '↑'}
                  </button>
                </div>
                <div className="input-hint">
                  🔒 Encrypted locally · Ephemeral key per message · Enter to send
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {showKeyModal && activeContact && (
        <KeyModal myKeys={myKeys} myUser={user} contact={activeContact} onClose={() => setShowKeyModal(false)} />
      )}
    </>
  );
}
