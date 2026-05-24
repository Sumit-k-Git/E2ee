/**
 * e2ee-messenger.jsx — Standalone in-browser E2EE demo
 *
 * This is a self-contained demo that works WITHOUT a backend server.
 * It simulates multi-user messaging entirely in-browser using real
 * NaCl cryptography (TweetNaCl).
 *
 * For the real app with persistent storage, WebSocket relay, and
 * user accounts — see App.jsx + api.js + crypto.js.
 *
 * Changes from original:
 * - Private key no longer displayed in key modal (security fix)
 * - Removed broken async/await and WebSocket code from send()
 * - Fixed DEMO_CONTACTS reference that was missing
 */

import { useState, useEffect, useRef, useCallback } from "react";

const NACL_CDN  = "https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js";
const NACL_UTIL = "https://cdn.jsdelivr.net/npm/tweetnacl-util@0.15.1/nacl-util.min.js";

const DEMO_CONTACTS = ["Alice", "Bob", "Charlie", "Diana"];

// ── Load NaCl from CDN ────────────────────────────────────────────────────
function useNacl() {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const load = (src) =>
      new Promise((res) => {
        if (document.querySelector(`script[src="${src}"]`)) return res();
        const s = document.createElement("script");
        s.src = src;
        s.onload = res;
        document.head.appendChild(s);
      });
    load(NACL_CDN).then(() => load(NACL_UTIL)).then(() => setReady(true));
  }, []);
  return ready;
}

// ── Crypto helpers ────────────────────────────────────────────────────────
function generateKeyPair() {
  return window.nacl.box.keyPair();
}

function encryptMessage(msg, theirPublicKey, mySecretKey) {
  const nonce     = window.nacl.randomBytes(window.nacl.box.nonceLength);
  const msgUint8  = window.naclUtil.decodeUTF8(msg);
  const encrypted = window.nacl.box(msgUint8, nonce, theirPublicKey, mySecretKey);
  return {
    ciphertext: window.naclUtil.encodeBase64(encrypted),
    nonce:      window.naclUtil.encodeBase64(nonce),
  };
}

function decryptMessage(ciphertext, nonce, theirPublicKey, mySecretKey) {
  try {
    const decrypted = window.nacl.box.open(
      window.naclUtil.decodeBase64(ciphertext),
      window.naclUtil.decodeBase64(nonce),
      theirPublicKey,
      mySecretKey
    );
    if (!decrypted) return null;
    return window.naclUtil.encodeUTF8(decrypted);
  } catch {
    return null;
  }
}

// ── Styles ────────────────────────────────────────────────────────────────
const css = `
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Sora:wght@300;400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0e0f14; --surface: #16181f; --surface2: #1e2029;
    --border: #2a2c37; --accent: #6c63ff; --accent2: #4fd1c5;
    --text: #e8e9f0; --muted: #6b6e82; --danger: #ff5c5c;
    --sent-bg: #1e1d3a; --recv-bg: #1a1d26;
    --font: 'Sora', sans-serif; --mono: 'IBM Plex Mono', monospace;
  }
  .app { font-family: var(--font); background: var(--bg); color: var(--text);
    height: 100vh; display: grid; grid-template-columns: 280px 1fr; overflow: hidden; }
  .sidebar { background: var(--surface); border-right: 1px solid var(--border);
    display: flex; flex-direction: column; overflow: hidden; }
  .sidebar-header { padding: 20px 18px 14px; border-bottom: 1px solid var(--border); }
  .app-title { font-family: var(--mono); font-size: 13px; font-weight: 500;
    color: var(--accent); letter-spacing: .08em; text-transform: uppercase; }
  .app-subtitle { font-size: 11px; color: var(--muted); font-weight: 300; }
  .my-identity { margin: 14px 18px 0; padding: 10px 12px;
    background: var(--surface2); border-radius: 10px; border: 1px solid var(--border); }
  .identity-label { font-size: 10px; color: var(--muted); font-family: var(--mono);
    text-transform: uppercase; letter-spacing: .06em; margin-bottom: 4px; }
  .identity-name { font-size: 13px; font-weight: 500; color: var(--text);
    display: flex; align-items: center; gap: 6px; }
  .identity-dot { width: 7px; height: 7px; border-radius: 50%;
    background: var(--accent2); flex-shrink: 0; }
  .pubkey-display { font-family: var(--mono); font-size: 9px; color: var(--muted);
    margin-top: 4px; word-break: break-all; line-height: 1.5; }
  .contacts-label { padding: 16px 18px 8px; font-size: 10px; color: var(--muted);
    font-family: var(--mono); text-transform: uppercase; letter-spacing: .06em; }
  .contacts-list { flex: 1; overflow-y: auto; padding: 0 10px 10px; }
  .contacts-list::-webkit-scrollbar { width: 3px; }
  .contacts-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  .contact-item { display: flex; align-items: center; gap: 10px; padding: 10px;
    border-radius: 10px; cursor: pointer; transition: background .15s; margin-bottom: 2px; }
  .contact-item:hover { background: var(--surface2); }
  .contact-item.active { background: #1e1d3a; border: 1px solid #3d3a6e; }
  .avatar { border-radius: 50%; display: flex; align-items: center;
    justify-content: center; font-weight: 600; flex-shrink: 0; }
  .contact-info { flex: 1; min-width: 0; }
  .contact-name { font-size: 13px; font-weight: 500;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .contact-status { font-size: 10px; color: var(--muted); margin-top: 1px;
    display: flex; align-items: center; gap: 4px; }
  .lock-icon { font-size: 9px; color: var(--accent2); }
  .unread-badge { background: var(--accent); color: #fff; font-size: 10px;
    font-weight: 600; padding: 2px 6px; border-radius: 10px; min-width: 18px; text-align: center; }
  .chat-area { display: flex; flex-direction: column; overflow: hidden; background: var(--bg); }
  .chat-header { padding: 14px 22px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px; background: var(--surface); flex-shrink: 0; }
  .chat-header-info { flex: 1; }
  .chat-contact-name { font-size: 15px; font-weight: 600; }
  .e2ee-badge { display: inline-flex; align-items: center; gap: 4px; font-size: 10px;
    color: var(--accent2); font-family: var(--mono); background: rgba(79,209,197,.08);
    border: 1px solid rgba(79,209,197,.2); padding: 2px 8px; border-radius: 20px; margin-top: 3px; }
  .key-info-btn { background: none; border: 1px solid var(--border); color: var(--muted);
    padding: 6px 12px; border-radius: 8px; cursor: pointer; font-size: 11px;
    font-family: var(--mono); transition: all .15s; }
  .key-info-btn:hover { border-color: var(--accent); color: var(--accent); }
  .messages-area { flex: 1; overflow-y: auto; padding: 20px 22px;
    display: flex; flex-direction: column; gap: 8px; scroll-behavior: smooth; }
  .messages-area::-webkit-scrollbar { width: 4px; }
  .messages-area::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
  .day-separator { text-align: center; font-size: 10px; color: var(--muted);
    font-family: var(--mono); margin: 8px 0; display: flex; align-items: center; gap: 10px; }
  .day-separator::before, .day-separator::after { content: ''; flex: 1; height: 1px; background: var(--border); }
  .msg-row { display: flex; flex-direction: column; }
  .msg-row.sent { align-items: flex-end; }
  .msg-row.recv { align-items: flex-start; }
  .msg-bubble { max-width: 68%; padding: 10px 14px; border-radius: 16px;
    line-height: 1.55; font-size: 13.5px; word-break: break-word; }
  .msg-row.sent .msg-bubble { background: var(--sent-bg); border: 1px solid #3a386a;
    border-bottom-right-radius: 4px; color: #d8d5ff; }
  .msg-row.recv .msg-bubble { background: var(--recv-bg); border: 1px solid var(--border);
    border-bottom-left-radius: 4px; }
  .msg-meta { font-size: 10px; color: var(--muted); margin-top: 3px;
    display: flex; align-items: center; gap: 5px; font-family: var(--mono); }
  .msg-lock { color: var(--accent2); font-size: 9px; }
  .ciphertext-preview { font-family: var(--mono); font-size: 9px; color: var(--muted);
    padding: 3px 6px; background: rgba(255,255,255,.03); border-radius: 4px;
    border: 1px solid var(--border); max-width: 200px; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap; cursor: pointer; transition: background .15s; }
  .ciphertext-preview:hover { background: rgba(255,255,255,.07); }
  .input-area { padding: 14px 22px 18px; border-top: 1px solid var(--border);
    background: var(--surface); flex-shrink: 0; }
  .input-row { display: flex; gap: 10px; align-items: flex-end; }
  .msg-input { flex: 1; background: var(--surface2); border: 1px solid var(--border);
    border-radius: 12px; padding: 11px 16px; color: var(--text);
    font-family: var(--font); font-size: 13.5px; outline: none; resize: none;
    min-height: 44px; max-height: 120px; line-height: 1.5; transition: border-color .15s; }
  .msg-input:focus { border-color: var(--accent); }
  .msg-input::placeholder { color: var(--muted); }
  .send-btn { background: var(--accent); border: none; border-radius: 12px;
    width: 44px; height: 44px; display: flex; align-items: center; justify-content: center;
    cursor: pointer; flex-shrink: 0; transition: all .15s; color: #fff; font-size: 16px; }
  .send-btn:hover { background: #7c73ff; transform: scale(1.04); }
  .send-btn:disabled { background: var(--border); cursor: not-allowed; transform: none; }
  .input-hint { font-size: 10px; color: var(--muted); margin-top: 8px;
    font-family: var(--mono); display: flex; align-items: center; gap: 5px; }
  .empty-state { flex: 1; display: flex; flex-direction: column; align-items: center;
    justify-content: center; gap: 10px; color: var(--muted); }
  .empty-icon { font-size: 40px; opacity: .35; margin-bottom: 4px; }
  .empty-title { font-size: 15px; font-weight: 500; color: var(--text); opacity: .5; }
  .empty-sub { font-size: 12px; text-align: center; max-width: 240px; line-height: 1.6; }
  .modal-overlay { position: absolute; inset: 0; background: rgba(0,0,0,.7);
    display: flex; align-items: center; justify-content: center; z-index: 100; backdrop-filter: blur(4px); }
  .modal { background: var(--surface); border: 1px solid var(--border);
    border-radius: 18px; padding: 24px; max-width: 420px; width: 90%; }
  .modal-title { font-size: 15px; font-weight: 600; margin-bottom: 16px;
    display: flex; align-items: center; gap: 8px; }
  .key-block { background: var(--surface2); border: 1px solid var(--border);
    border-radius: 10px; padding: 12px; margin-bottom: 12px; }
  .key-block-label { font-size: 10px; color: var(--muted); font-family: var(--mono);
    text-transform: uppercase; letter-spacing: .06em; margin-bottom: 6px; }
  .key-value { font-family: var(--mono); font-size: 10px; word-break: break-all;
    line-height: 1.7; color: var(--accent2); }
  .key-value.hidden { color: var(--muted); font-style: italic; }
  .modal-note { font-size: 11px; color: var(--muted); line-height: 1.65; margin-top: 12px;
    padding: 10px 12px; background: rgba(108,99,255,.06);
    border: 1px solid rgba(108,99,255,.15); border-radius: 8px; }
  .modal-close { margin-top: 16px; width: 100%; background: var(--accent); border: none;
    border-radius: 10px; color: #fff; font-family: var(--font); font-size: 13px;
    font-weight: 500; padding: 10px; cursor: pointer; transition: background .15s; }
  .modal-close:hover { background: #7c73ff; }
  .setup-screen { height: 100vh; display: flex; flex-direction: column; align-items: center;
    justify-content: center; background: var(--bg); gap: 0; }
  .setup-logo { font-family: var(--mono); font-size: 28px; font-weight: 500;
    color: var(--accent); letter-spacing: .05em; margin-bottom: 6px; }
  .setup-tagline { font-size: 13px; color: var(--muted); margin-bottom: 40px; }
  .setup-card { background: var(--surface); border: 1px solid var(--border);
    border-radius: 20px; padding: 32px; width: 360px; }
  .setup-label { font-size: 11px; color: var(--muted); font-family: var(--mono);
    text-transform: uppercase; letter-spacing: .06em; margin-bottom: 8px; }
  .setup-input { width: 100%; background: var(--surface2); border: 1px solid var(--border);
    border-radius: 10px; padding: 12px 14px; color: var(--text); font-family: var(--font);
    font-size: 14px; outline: none; margin-bottom: 20px; transition: border-color .15s; }
  .setup-input:focus { border-color: var(--accent); }
  .setup-btn { width: 100%; background: var(--accent); border: none; border-radius: 10px;
    color: #fff; font-family: var(--font); font-size: 14px; font-weight: 500;
    padding: 13px; cursor: pointer; transition: background .15s; }
  .setup-btn:hover { background: #7c73ff; }
  .setup-btn:disabled { background: var(--border); cursor: not-allowed; }
  .setup-note { font-size: 11px; color: var(--muted); text-align: center;
    margin-top: 14px; line-height: 1.6; }
`;

const AVATAR_COLORS = [
  { bg: "#1e1d3a", color: "#a89fff" },
  { bg: "#0e2a2a", color: "#4fd1c5" },
  { bg: "#2a1e1e", color: "#ff9090" },
  { bg: "#1e2a1e", color: "#7ee87e" },
];

function Avatar({ name, size = 36 }) {
  const idx = name.charCodeAt(0) % AVATAR_COLORS.length;
  const { bg, color } = AVATAR_COLORS[idx];
  return (
    <div className="avatar"
      style={{ width: size, height: size, background: bg, color, fontSize: size * 0.38 }}>
      {name[0]}
    </div>
  );
}

function formatTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function truncate(str, n = 40) {
  return str.length > n ? str.slice(0, n) + "…" : str;
}

// ── Main component ────────────────────────────────────────────────────────
export default function E2EEMessenger() {
  const naclReady       = useNacl();
  const [myName, setMyName]         = useState("");
  const [nameInput, setNameInput]   = useState("");
  const [myKeys, setMyKeys]         = useState(null);
  const [contacts, setContacts]     = useState({});
  const [activeContact, setActiveContact] = useState(null);
  const [messages, setMessages]     = useState({});
  const [input, setInput]           = useState("");
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [showCipher, setShowCipher] = useState({});
  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeContact]);

  const initUser = useCallback(() => {
    if (!naclReady || !nameInput.trim()) return;
    const keys = generateKeyPair();
    const pubs = {};
    DEMO_CONTACTS.filter((c) => c !== nameInput.trim()).forEach((c) => {
      pubs[c] = generateKeyPair();
    });
    setMyKeys(keys);
    setMyName(nameInput.trim());
    setContacts(pubs);
    setMessages({});
  }, [naclReady, nameInput]);

  // Synchronous send — no server in this demo
  const send = useCallback(() => {
    if (!input.trim() || !activeContact || !myKeys || !contacts[activeContact]) return;
    const theirPub = contacts[activeContact].publicKey;
    const { ciphertext, nonce } = encryptMessage(input.trim(), theirPub, myKeys.secretKey);
    const msg = {
      id: Date.now() + Math.random(),
      from: myName,
      to: activeContact,
      text: input.trim(),
      ciphertext,
      nonce,
      ts: Date.now(),
      direction: "sent",
    };
    setMessages((prev) => ({
      ...prev,
      [activeContact]: [...(prev[activeContact] || []), msg],
    }));
    setInput("");
    setTimeout(() => simulateReply(activeContact), 1200 + Math.random() * 1600);
  }, [input, activeContact, myKeys, contacts, myName]);

  const simulateReply = useCallback((contact) => {
    if (!contacts[contact] || !myKeys) return;
    const replies = [
      "Got it, thanks!", "Sounds good 👍", "Interesting! Tell me more.",
      "Haha, okay.", "Sure, I'm in.", "Wait, seriously?",
      "That's encrypted on my end too 🔒", "Nice, everything's secure here.", "Roger that.",
    ];
    const text        = replies[Math.floor(Math.random() * replies.length)];
    const theirSecret = contacts[contact].secretKey;
    const { ciphertext, nonce } = encryptMessage(text, myKeys.publicKey, theirSecret);
    const decrypted   = decryptMessage(ciphertext, nonce, contacts[contact].publicKey, myKeys.secretKey);
    setMessages((prev) => ({
      ...prev,
      [contact]: [...(prev[contact] || []), {
        id: Date.now() + Math.random(),
        from: contact, to: myName,
        text: decrypted || text,
        ciphertext, nonce,
        ts: Date.now(),
        direction: "recv",
      }],
    }));
  }, [contacts, myKeys, myName]);

  const pubKeyStr = (key) => key ? window.naclUtil?.encodeBase64(key) : "";

  // ── Setup screen ────────────────────────────────────────────────────────
  if (!myName || !myKeys) {
    return (
      <>
        <style>{css}</style>
        <div className="setup-screen">
          <div className="setup-logo">vault.msg</div>
          <div className="setup-tagline">Zero-knowledge end-to-end encrypted messenger</div>
          <div className="setup-card">
            <div className="setup-label">Your display name</div>
            <input className="setup-input" placeholder="e.g. Alice" value={nameInput}
              onChange={(e) => setNameInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && initUser()} maxLength={24} autoFocus />
            <div className="setup-label">What happens next</div>
            <div style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.7, marginBottom: 20 }}>
              A unique X25519 keypair is generated <em>locally in your browser</em>.
              Your private key never leaves this device.
              Messages are encrypted with XSalsa20-Poly1305 (NaCl box).
            </div>
            <button className="setup-btn" onClick={initUser} disabled={!naclReady || !nameInput.trim()}>
              {naclReady ? "Generate keys & enter →" : "Loading crypto library…"}
            </button>
            <div className="setup-note">
              Even the app developer cannot read your messages.<br />
              No server. Keys generated locally. 100% in-browser demo.
            </div>
          </div>
        </div>
      </>
    );
  }

  const activeMessages = messages[activeContact] || [];
  const unreadCounts   = Object.keys(contacts).reduce((acc, c) => {
    acc[c] = (messages[c] || []).filter((m) => m.direction === "recv").length;
    return acc;
  }, {});

  // ── Main UI ─────────────────────────────────────────────────────────────
  return (
    <>
      <style>{css}</style>
      <div className="app" style={{ position: "relative" }}>

        {/* Sidebar */}
        <div className="sidebar">
          <div className="sidebar-header">
            <div className="app-title">vault.msg</div>
            <div className="app-subtitle">end-to-end encrypted · demo mode</div>
          </div>
          <div className="my-identity">
            <div className="identity-label">You</div>
            <div className="identity-name">
              <div className="identity-dot" />
              {myName}
            </div>
            <div className="pubkey-display">
              {naclReady && myKeys ? truncate(pubKeyStr(myKeys.publicKey), 48) : "generating…"}
            </div>
          </div>
          <div className="contacts-label">Contacts</div>
          <div className="contacts-list">
            {Object.keys(contacts).map((c) => (
              <div key={c}
                className={`contact-item${activeContact === c ? " active" : ""}`}
                onClick={() => setActiveContact(c)}>
                <Avatar name={c} />
                <div className="contact-info">
                  <div className="contact-name">{c}</div>
                  <div className="contact-status">
                    <span className="lock-icon">🔒</span>E2EE active
                  </div>
                </div>
                {unreadCounts[c] > 0 && (
                  <div className="unread-badge">{unreadCounts[c]}</div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Chat area */}
        <div className="chat-area">
          {!activeContact ? (
            <div className="empty-state">
              <div className="empty-icon">🔐</div>
              <div className="empty-title">Select a contact</div>
              <div className="empty-sub">
                Messages are encrypted with the recipient's public key before sending.
                Not even you can read them from the server.
              </div>
            </div>
          ) : (
            <>
              <div className="chat-header">
                <Avatar name={activeContact} size={38} />
                <div className="chat-header-info">
                  <div className="chat-contact-name">{activeContact}</div>
                  <div className="e2ee-badge">🔒 XSalsa20-Poly1305 · X25519 keys</div>
                </div>
                <button className="key-info-btn" onClick={() => setShowKeyModal(true)}>
                  View keys
                </button>
              </div>

              <div className="messages-area">
                {activeMessages.length === 0 && (
                  <div style={{ textAlign: "center", marginTop: 40 }}>
                    <div style={{ fontSize: 28, marginBottom: 10, opacity: .4 }}>💬</div>
                    <div style={{ fontSize: 12, color: "var(--muted)" }}>
                      No messages yet. Your first message will be encrypted
                      with <strong style={{ color: "var(--accent2)" }}>{activeContact}'s</strong> public key.
                    </div>
                  </div>
                )}
                {activeMessages.map((msg, i) => {
                  const isFirst = i === 0 ||
                    Math.floor(activeMessages[i - 1].ts / 86400000) !== Math.floor(msg.ts / 86400000);
                  return (
                    <div key={msg.id}>
                      {isFirst && (
                        <div className="day-separator">
                          {new Date(msg.ts).toLocaleDateString()}
                        </div>
                      )}
                      <div className={`msg-row ${msg.direction}`}>
                        <div className="msg-bubble">{msg.text}</div>
                        <div className="msg-meta">
                          <span className="msg-lock">🔒</span>
                          {formatTime(msg.ts)}
                          <span className="ciphertext-preview"
                            onClick={() => setShowCipher(p => ({ ...p, [msg.id]: !p[msg.id] }))}
                            title="Click to toggle ciphertext">
                            {showCipher[msg.id]
                              ? msg.ciphertext
                              : `[cipher] ${truncate(msg.ciphertext, 28)}`}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
                <div ref={messagesEndRef} />
              </div>

              <div className="input-area">
                <div className="input-row">
                  <textarea className="msg-input"
                    placeholder={`Message ${activeContact}…`}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
                    rows={1} />
                  <button className="send-btn" onClick={send} disabled={!input.trim()}>↑</button>
                </div>
                <div className="input-hint">
                  🔒 Encrypted locally before sending · Enter to send, Shift+Enter for newline
                </div>
              </div>
            </>
          )}
        </div>

        {/* Key verification modal */}
        {showKeyModal && activeContact && (
          <div className="modal-overlay" onClick={() => setShowKeyModal(false)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-title">🔑 Encryption keys for {activeContact}</div>
              <div className="key-block">
                <div className="key-block-label">Your public key (safe to share)</div>
                <div className="key-value">{naclReady ? pubKeyStr(myKeys.publicKey) : "…"}</div>
              </div>
              <div className="key-block">
                <div className="key-block-label">Your private key</div>
                {/* SECURITY FIX: private key hidden — never display it */}
                <div className="key-value hidden">Hidden for security — never displayed</div>
              </div>
              <div className="key-block">
                <div className="key-block-label">{activeContact}'s public key</div>
                <div className="key-value">
                  {naclReady ? pubKeyStr(contacts[activeContact].publicKey) : "…"}
                </div>
              </div>
              <div className="modal-note">
                💡 Messages to {activeContact} are encrypted with <em>their</em> public key
                using XSalsa20-Poly1305. Only {activeContact}'s private key can decrypt them —
                mathematically impossible for anyone else, including the server operator.
              </div>
              <button className="modal-close" onClick={() => setShowKeyModal(false)}>Close</button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
