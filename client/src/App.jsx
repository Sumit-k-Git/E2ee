import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  generateIdentityKeypair, loadIdentityKeypair, computeFingerprint,
  formatFingerprint, encryptMessage, decryptMessage,
  publicKeyToBase64, base64ToBytes,
} from './crypto.js';
import { auth, usersApi, messagesApi, VaultSocket, clearTokens } from './api.js';

// ── Sent message local cache (fixes "🔒 Encrypted" showing for own messages) ──
// We store sent plaintext in sessionStorage keyed by message ID so we can
// display it after the fact without needing to decrypt from the server.
const sentCache = {
  set(id, text) {
    try { sessionStorage.setItem(`sent:${id}`, text); } catch {}
  },
  get(id) {
    try { return sessionStorage.getItem(`sent:${id}`) || null; } catch { return null; }
  },
};

// ── Design tokens ──────────────────────────────────────────────────────────
const G = {
  bg: '#0c0d11', surface: '#13141a', surface2: '#1a1b23', surface3: '#21222d',
  border: '#272833', accent: '#6c63ff', accent2: '#4fd1c5',
  text: '#e4e5f0', muted: '#5a5d73',
  sentBg: '#1a193a', sentBorder: '#373578', recvBg: '#16171e',
  online: '#4ade80', danger: '#ff5c5c',
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@300;400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${G.bg}; color: ${G.text}; font-family: 'Plus Jakarta Sans', sans-serif; overflow: hidden; }
  ::-webkit-scrollbar { width: 3px; }
  ::-webkit-scrollbar-thumb { background: ${G.border}; border-radius: 3px; }
  input, textarea, button { font-family: inherit; }

  @keyframes fadeIn  { from{opacity:0;transform:translateY(5px)} to{opacity:1;transform:none} }
  @keyframes pulse   { 0%,100%{opacity:1} 50%{opacity:.4} }
  @keyframes spin    { to{transform:rotate(360deg)} }
  @keyframes slideIn { from{opacity:0;transform:translateX(-6px)} to{opacity:1;transform:none} }

  .msg-enter    { animation: fadeIn .15s ease-out; }
  .typing-pulse { animation: pulse 1.4s infinite; }
  .spinner { animation:spin .8s linear infinite; width:16px; height:16px;
    border:2px solid ${G.border}; border-top-color:${G.accent}; border-radius:50%; display:inline-block; flex-shrink:0; }

  /* ── Layout ── */
  .app { height:100vh; display:grid; grid-template-columns:300px 1fr; overflow:hidden; }

  /* ── Sidebar ── */
  .sidebar { background:${G.surface}; border-right:1px solid ${G.border};
    display:flex; flex-direction:column; overflow:hidden; }
  .sidebar-top { padding:16px; border-bottom:1px solid ${G.border}; flex-shrink:0; }
  .brand { font-family:'IBM Plex Mono',monospace; font-size:15px; font-weight:500;
    color:${G.accent}; letter-spacing:.06em; }
  .brand-sub { font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace; margin-top:1px;
    display:flex; align-items:center; gap:4px; }
  .ws-dot { display:inline-block; width:6px; height:6px; border-radius:50%; flex-shrink:0; }
  .ws-dot.on  { background:${G.online}; }
  .ws-dot.off { background:${G.danger}; }

  .me-card { margin:10px 12px; padding:10px 12px; background:${G.surface2};
    border:1px solid ${G.border}; border-radius:10px; flex-shrink:0; }
  .me-name { font-size:13px; font-weight:600; display:flex; align-items:center; gap:6px; }
  .me-fp { font-family:'IBM Plex Mono',monospace; font-size:9px; color:${G.muted};
    margin-top:4px; line-height:1.6; word-break:break-all; }
  .me-fp-label { font-size:9px; color:${G.accent2}; font-family:'IBM Plex Mono',monospace; margin-top:2px; }

  .section-label { padding:10px 16px 6px; font-size:10px; color:${G.muted};
    font-family:'IBM Plex Mono',monospace; text-transform:uppercase; letter-spacing:.07em; flex-shrink:0; }

  .search-wrap { padding:0 12px 8px; flex-shrink:0; }
  .search-input { width:100%; background:${G.surface2}; border:1px solid ${G.border};
    border-radius:8px; padding:8px 12px; color:${G.text}; font-size:13px; outline:none; transition:border-color .15s; }
  .search-input:focus { border-color:${G.accent}; }
  .search-input::placeholder { color:${G.muted}; }

  .search-results { padding:0 10px 6px; flex-shrink:0; }
  .search-result-item { display:flex; align-items:center; gap:10px; padding:8px 10px;
    border-radius:8px; cursor:pointer; transition:background .12s; }
  .search-result-item:hover { background:${G.surface2}; }
  .no-results { padding:8px 22px; font-size:12px; color:${G.muted}; }

  .contacts { flex:1; overflow-y:auto; padding:0 10px 10px; }
  .contact-row { display:flex; align-items:center; gap:10px; padding:9px 10px;
    border-radius:10px; cursor:pointer; transition:background .12s; margin-bottom:1px; animation:slideIn .15s ease-out; }
  .contact-row:hover  { background:${G.surface2}; }
  .contact-row.active { background:${G.sentBg}; border:1px solid ${G.sentBorder}; }
  .contact-info { flex:1; min-width:0; }
  .contact-name    { font-size:13px; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .contact-preview { font-size:11px; color:${G.muted}; margin-top:1px;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .unread-badge { background:${G.accent}; color:#fff; font-size:10px; font-weight:600;
    padding:2px 6px; border-radius:10px; min-width:18px; text-align:center; flex-shrink:0; }
  .signout-btn { background:none; border:1px solid ${G.border}; color:${G.muted};
    font-size:10px; padding:3px 8px; border-radius:6px; cursor:pointer; transition:all .15s; font-family:inherit; margin-left:auto; }
  .signout-btn:hover { border-color:${G.danger}; color:${G.danger}; }

  /* ── Avatar ── */
  .avatar { border-radius:50%; display:flex; align-items:center; justify-content:center;
    font-weight:600; flex-shrink:0; }

  /* ── Chat ── */
  .chat { display:flex; flex-direction:column; overflow:hidden; background:${G.bg}; }
  .chat-header { padding:13px 20px; border-bottom:1px solid ${G.border};
    display:flex; align-items:center; gap:12px; background:${G.surface}; flex-shrink:0; }
  .chat-contact-name { font-size:15px; font-weight:600; }
  .e2ee-tag { font-size:10px; color:${G.accent2}; font-family:'IBM Plex Mono',monospace;
    background:rgba(79,209,197,.08); border:1px solid rgba(79,209,197,.18);
    padding:2px 8px; border-radius:20px; margin-top:2px; display:inline-block; }

  .msgs { flex:1; overflow-y:auto; padding:18px 20px; display:flex; flex-direction:column; gap:6px; }
  .msgs-loading { flex:1; display:flex; align-items:center; justify-content:center; color:${G.muted}; font-size:13px; gap:10px; }

  .day-sep { text-align:center; font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace;
    margin:8px 0; display:flex; align-items:center; gap:10px; }
  .day-sep::before,.day-sep::after { content:''; flex:1; height:1px; background:${G.border}; }

  .msg-row      { display:flex; flex-direction:column; }
  .msg-row.sent { align-items:flex-end; }
  .msg-row.recv { align-items:flex-start; }
  .bubble { max-width:66%; padding:9px 14px; border-radius:16px; font-size:13.5px;
    line-height:1.55; word-break:break-word; white-space:pre-wrap; }
  .msg-row.sent .bubble { background:${G.sentBg}; border:1px solid ${G.sentBorder};
    border-bottom-right-radius:4px; color:#d5d0ff; }
  .msg-row.recv .bubble { background:${G.recvBg}; border:1px solid ${G.border}; border-bottom-left-radius:4px; }
  .msg-meta  { font-size:10px; color:${G.muted}; margin-top:3px;
    display:flex; align-items:center; gap:5px; font-family:'IBM Plex Mono',monospace; }
  .lock-icon { color:${G.accent2}; font-size:9px; }
  .read-tick { color:${G.accent2}; }
  .decrypt-fail { color:${G.danger}; font-style:italic; font-size:12px; }

  .typing-indicator { padding:4px 20px; font-size:11px; color:${G.muted};
    font-style:italic; height:22px; flex-shrink:0; }

  /* ── Input ── */
  .input-area { padding:12px 20px 16px; border-top:1px solid ${G.border};
    background:${G.surface}; flex-shrink:0; }
  .input-row { display:flex; gap:9px; align-items:flex-end; }
  .msg-input { flex:1; background:${G.surface2}; border:1px solid ${G.border};
    border-radius:12px; padding:10px 15px; color:${G.text}; font-size:13.5px;
    outline:none; resize:none; min-height:43px; max-height:110px; line-height:1.5; transition:border-color .15s; }
  .msg-input:focus { border-color:${G.accent}; }
  .msg-input::placeholder { color:${G.muted}; }
  .send-btn { background:${G.accent}; border:none; border-radius:12px; width:43px; height:43px;
    display:flex; align-items:center; justify-content:center; cursor:pointer; color:#fff;
    font-size:17px; transition:all .13s; flex-shrink:0; }
  .send-btn:hover:not(:disabled) { background:#7c73ff; transform:scale(1.05); }
  .send-btn:disabled { background:${G.border}; cursor:not-allowed; transform:none; opacity:.5; }
  .input-hint { font-size:10px; color:${G.muted}; margin-top:7px;
    font-family:'IBM Plex Mono',monospace; }

  /* ── Empty / error states ── */
  .empty { flex:1; display:flex; flex-direction:column; align-items:center;
    justify-content:center; gap:8px; color:${G.muted}; }
  .empty-icon  { font-size:38px; opacity:.25; margin-bottom:4px; }
  .empty-title { font-size:15px; color:${G.text}; opacity:.4; font-weight:500; }
  .empty-sub   { font-size:12px; text-align:center; max-width:220px; line-height:1.65; }
  .error-bar   { padding:8px 20px; font-size:12px; color:${G.danger};
    background:rgba(255,92,92,.08); border-bottom:1px solid rgba(255,92,92,.2); flex-shrink:0; }

  /* ── Auth screen ── */
  .auth-screen { height:100vh; display:flex; flex-direction:column; align-items:center;
    justify-content:center; background:${G.bg}; padding:20px; }
  .auth-logo    { font-family:'IBM Plex Mono',monospace; font-size:26px; font-weight:500;
    color:${G.accent}; letter-spacing:.06em; margin-bottom:4px; }
  .auth-tagline { font-size:12px; color:${G.muted}; margin-bottom:32px; text-align:center; }
  .auth-card    { background:${G.surface}; border:1px solid ${G.border};
    border-radius:18px; padding:28px; width:100%; max-width:380px; }
  .auth-tabs    { display:flex; gap:2px; background:${G.surface2}; border-radius:10px;
    padding:3px; margin-bottom:22px; }
  .auth-tab     { flex:1; padding:8px; border-radius:8px; border:none; background:none;
    color:${G.muted}; font-size:13px; font-weight:500; cursor:pointer; transition:all .15s; font-family:inherit; }
  .auth-tab.active { background:${G.accent}; color:#fff; }

  .field-label  { font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace;
    text-transform:uppercase; letter-spacing:.06em; margin-bottom:6px; }
  .field-input  { width:100%; background:${G.surface2}; border:1px solid ${G.border};
    border-radius:9px; padding:11px 13px; color:${G.text}; font-size:14px;
    outline:none; margin-bottom:14px; transition:border-color .15s; }
  .field-input:focus { border-color:${G.accent}; }
  .field-input::placeholder { color:${G.muted}; }
  .field-hint   { font-size:11px; color:${G.muted}; margin-top:-10px; margin-bottom:14px; line-height:1.5; }

  .auth-btn     { width:100%; background:${G.accent}; border:none; border-radius:9px;
    color:#fff; font-size:14px; font-weight:500; padding:12px; cursor:pointer;
    transition:background .15s; font-family:inherit; display:flex; align-items:center; justify-content:center; gap:8px; }
  .auth-btn:hover:not(:disabled) { background:#7c73ff; }
  .auth-btn:disabled { opacity:.55; cursor:not-allowed; }
  .auth-note    { font-size:11px; color:${G.muted}; text-align:center; margin-top:12px; line-height:1.65; }
  .error-msg    { font-size:12px; color:${G.danger}; margin-bottom:14px; padding:10px 12px;
    background:rgba(255,92,92,.08); border:1px solid rgba(255,92,92,.25); border-radius:8px; line-height:1.5; }
  .pw-bar  { height:3px; border-radius:2px; margin-top:-10px; margin-bottom:14px; transition:all .3s; }
  .pw-0 { background:${G.border}; width:0%; }
  .pw-1 { background:${G.danger}; width:25%; }
  .pw-2 { background:#f59e0b; width:50%; }
  .pw-3 { background:#84cc16; width:75%; }
  .pw-4 { background:${G.online}; width:100%; }

  /* OTP box */
  .otp-info { text-align:center; margin-bottom:18px; }
  .otp-email { font-size:13px; font-weight:600; color:${G.text}; margin-top:4px; }
  .otp-sub   { font-size:12px; color:${G.muted}; margin-top:4px; line-height:1.5; }
  .otp-input { width:100%; background:${G.surface2}; border:2px solid ${G.accent};
    border-radius:12px; padding:14px; color:${G.accent2}; font-size:28px; font-weight:700;
    letter-spacing:14px; text-align:center; font-family:'IBM Plex Mono',monospace;
    outline:none; margin-bottom:14px; transition:border-color .15s; }
  .otp-input:focus { border-color:${G.accent2}; }
  .otp-actions { display:flex; justify-content:space-between; margin-top:10px; }
  .link-btn { background:none; border:none; font-family:inherit; font-size:12px;
    cursor:pointer; padding:0; transition:color .15s; }

  /* ── Key modal ── */
  .modal-wrap  { position:fixed; inset:0; background:rgba(0,0,0,.75);
    display:flex; align-items:center; justify-content:center; z-index:200; backdrop-filter:blur(6px); }
  .modal       { background:${G.surface}; border:1px solid ${G.border}; border-radius:18px;
    padding:24px; max-width:420px; width:92%; max-height:90vh; overflow-y:auto; }
  .modal-title { font-size:15px; font-weight:600; margin-bottom:18px; }
  .key-block   { background:${G.surface2}; border:1px solid ${G.border}; border-radius:10px; padding:12px; margin-bottom:12px; }
  .key-label   { font-size:10px; color:${G.muted}; font-family:'IBM Plex Mono',monospace;
    text-transform:uppercase; letter-spacing:.06em; margin-bottom:6px; }
  .key-val     { font-family:'IBM Plex Mono',monospace; font-size:10px; word-break:break-all; line-height:1.8; color:${G.accent2}; }
  .fp-grid     { display:grid; grid-template-columns:repeat(4,1fr); gap:4px; margin-top:6px; }
  .fp-cell     { font-family:'IBM Plex Mono',monospace; font-size:11px; text-align:center;
    padding:4px; background:rgba(255,255,255,.04); border-radius:4px; }
  .modal-note  { font-size:11px; color:${G.muted}; line-height:1.7; padding:10px 12px;
    background:rgba(108,99,255,.06); border:1px solid rgba(108,99,255,.15); border-radius:8px; margin-top:12px; }
  .modal-close { margin-top:14px; width:100%; background:${G.surface2}; border:1px solid ${G.border};
    border-radius:9px; color:${G.text}; font-family:inherit; font-size:13px; font-weight:500;
    padding:10px; cursor:pointer; transition:background .15s; }
  .modal-close:hover { background:${G.surface3}; }
  .icon-btn { background:none; border:1px solid ${G.border}; color:${G.muted};
    padding:5px 11px; border-radius:8px; cursor:pointer; font-size:11px;
    font-family:'IBM Plex Mono',monospace; transition:all .15s; }
  .icon-btn:hover { border-color:${G.accent}; color:${G.accent}; }
`;

// ── Helpers ───────────────────────────────────────────────────────────────
const PALETTE = [
  {bg:'#1e1d3a',c:'#a89fff'},{bg:'#0d2a28',c:'#4fd1c5'},
  {bg:'#2a1515',c:'#ff8a8a'},{bg:'#162515',c:'#86efac'},
  {bg:'#1a1a2e',c:'#818cf8'},{bg:'#2a1a0e',c:'#fb923c'},
];
function Avatar({ name='?', size=36 }) {
  const {bg,c} = PALETTE[(name.charCodeAt(0)||0) % PALETTE.length];
  return <div className="avatar" style={{width:size,height:size,background:bg,color:c,fontSize:size*.38}}>{name[0]?.toUpperCase()}</div>;
}
function pwStrength(p) {
  let s=0;
  if(p.length>=8)s++; if(p.length>=12)s++;
  if(/[A-Z]/.test(p)&&/[a-z]/.test(p))s++;
  if(/[0-9]/.test(p)||/[^A-Za-z0-9]/.test(p))s++;
  return Math.min(s,4);
}
const fmtTime = ts => new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
const fmtDate = ts => { const d=new Date(ts),t=new Date(); return d.toDateString()===t.toDateString()?'Today':d.toLocaleDateString(); };
const isValidEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e?.trim());

// ── AuthScreen ────────────────────────────────────────────────────────────
function AuthScreen({ onAuth }) {
  const [tab, setTab]           = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');
  // reg steps: 'form' → 'otp' → 'creating'
  const [regStep, setRegStep]   = useState('form');
  const [otpCode, setOtpCode]   = useState('');
  const [otpToken, setOtpToken] = useState('');
  const [otpSending, setOtpSending] = useState(false);
  const [countdown, setCountdown]   = useState(0);
  const [devOtp, setDevOtp]     = useState(''); // shows OTP code in UI for dev mode
  const otpRef = useRef(null);

  const canLogin   = username.trim().length >= 3 && password.length >= 8;
  const canRegForm = canLogin && isValidEmail(email);
  const strength   = pwStrength(password);

  useEffect(() => {
    if (countdown <= 0) return;
    const t = setTimeout(() => setCountdown(c => c-1), 1000);
    return () => clearTimeout(t);
  }, [countdown]);

  useEffect(() => {
    if (regStep === 'otp') setTimeout(() => otpRef.current?.focus(), 120);
  }, [regStep]);

  const switchTab = t => { setTab(t); setError(''); setRegStep('form'); setOtpCode(''); setDevOtp(''); };

  // ── Login ────────────────────────────────────────────────────────────────
  const doLogin = async () => {
    if (!canLogin || loading) return;
    setError(''); setLoading(true);
    try {
      const data = await auth.login(username.trim(), password);
      let kp = await loadIdentityKeypair();
      if (!kp) {
        kp = await generateIdentityKeypair();
        await usersApi.updateKey(publicKeyToBase64(kp), await computeFingerprint(kp.publicKey));
      }
      onAuth(data.user, kp);
    } catch (e) {
      setError(e.message.includes('Invalid username') ? 'Wrong username or password.' : e.message);
    } finally { setLoading(false); }
  };

  // ── Step 1: send OTP ─────────────────────────────────────────────────────
  const doSendOTP = async () => {
    if (!canRegForm || otpSending) return;
    setError(''); setOtpSending(true); setDevOtp('');
    try {
      const res = await auth.sendOTP(email.trim().toLowerCase());
      setRegStep('otp');
      setCountdown(60);
      // Dev mode: server returns the code so we can show it in UI
      if (res.dev_code) setDevOtp(res.dev_code);
    } catch(e) { setError(e.message); }
    finally { setOtpSending(false); }
  };

  // ── Step 2: verify OTP ───────────────────────────────────────────────────
  const doVerifyOTP = async () => {
    if (otpCode.length !== 6 || loading) return;
    setError(''); setLoading(true);
    try {
      const res = await auth.verifyOTP(email.trim().toLowerCase(), otpCode);
      setOtpToken(res.otp_token);
      setRegStep('creating');
      // auto-complete registration immediately
      await doRegister(res.otp_token);
    } catch(e) { setError(e.message); setLoading(false); }
  };

  // ── Step 3: complete registration ────────────────────────────────────────
  const doRegister = async (token) => {
    setError('');
    try {
      const kp     = await generateIdentityKeypair();
      const pubB64 = publicKeyToBase64(kp);
      const fp     = await computeFingerprint(kp.publicKey);
      const data   = await auth.register(username.trim(), password, pubB64, fp, email.trim().toLowerCase(), token);
      onAuth(data.user, kp);
    } catch(e) {
      const msg = e.message || '';
      if (msg.includes('Username already taken')) { setError('That username is taken. Try another.'); setRegStep('form'); }
      else if (msg.includes('verification required')) { setError('Verification expired. Please try again.'); setRegStep('form'); }
      else { setError(msg); setRegStep('form'); }
    } finally { setLoading(false); }
  };

  return (
    <>
      <style>{css}</style>
      <div className="auth-screen">
        <div className="auth-logo">vault.msg</div>
        <div className="auth-tagline">End-to-end encrypted · Open an account and start chatting</div>

        <div className="auth-card">
          <div className="auth-tabs">
            <button className={`auth-tab${tab==='login'?' active':''}`} onClick={()=>switchTab('login')}>Sign in</button>
            <button className={`auth-tab${tab==='register'?' active':''}`} onClick={()=>switchTab('register')}>Create account</button>
          </div>

          {error && <div className="error-msg">⚠ {error}</div>}

          {/* ── LOGIN ── */}
          {tab === 'login' && (
            <>
              <div className="field-label">Username</div>
              <input className="field-input" value={username} autoFocus autoComplete="username"
                onChange={e=>setUsername(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doLogin()}
                placeholder="your username" />

              <div className="field-label">Password</div>
              <input className="field-input" type="password" value={password} autoComplete="current-password"
                onChange={e=>setPassword(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doLogin()}
                placeholder="your password" />

              <button className="auth-btn" onClick={doLogin} disabled={!canLogin||loading}>
                {loading && <span className="spinner"/>}
                {loading ? 'Signing in…' : 'Sign in →'}
              </button>
              <div className="auth-note">🔒 Your private key never leaves this device.</div>
            </>
          )}

          {/* ── REGISTER step 1: form ── */}
          {tab==='register' && regStep==='form' && (
            <>
              <div className="field-label">Email address</div>
              <input className="field-input" type="email" value={email} autoFocus autoComplete="email"
                onChange={e=>setEmail(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doSendOTP()}
                placeholder="you@example.com" />
              <div className="field-hint">A 6-digit code will be sent to verify your email.</div>

              <div className="field-label">Username</div>
              <input className="field-input" value={username} autoComplete="username"
                onChange={e=>setUsername(e.target.value)}
                placeholder="3–32 chars, letters/numbers/_" />

              <div className="field-label">Password</div>
              <input className="field-input" type="password" value={password} autoComplete="new-password"
                onChange={e=>setPassword(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doSendOTP()}
                placeholder="Min 8 characters" />
              {password.length>0 && <div className={`pw-bar pw-${strength}`}/>}

              <button className="auth-btn" onClick={doSendOTP} disabled={!canRegForm||otpSending}>
                {otpSending && <span className="spinner"/>}
                {otpSending ? 'Sending code…' : 'Send verification code →'}
              </button>
              <div className="auth-note">🔑 Your encryption keys are generated in your browser. Your private key never leaves this device.</div>
            </>
          )}

          {/* ── REGISTER step 2: OTP entry ── */}
          {tab==='register' && regStep==='otp' && (
            <>
              <div className="otp-info">
                <div style={{fontSize:30}}>📧</div>
                <div className="otp-email">{email}</div>
                <div className="otp-sub">Enter the 6-digit code we sent you.</div>
                {devOtp && (
                  <div style={{marginTop:10,padding:'8px 12px',background:'rgba(108,99,255,.12)',
                    border:'1px solid rgba(108,99,255,.3)',borderRadius:8,fontSize:12,color:G.accent2}}>
                    <span style={{color:G.muted}}>Dev mode — your code:</span>{' '}
                    <strong style={{letterSpacing:4,fontFamily:'IBM Plex Mono',fontSize:18}}>{devOtp}</strong>
                  </div>
                )}
              </div>

              <input ref={otpRef} className="otp-input" value={otpCode} inputMode="numeric" maxLength={6}
                onChange={e => {
                  const v = e.target.value.replace(/\D/g,'').slice(0,6);
                  setOtpCode(v);
                  if (v.length===6) setTimeout(()=>doVerifyOTP(),80);
                }}
                onKeyDown={e=>e.key==='Enter'&&doVerifyOTP()}
                placeholder="000000" />

              <button className="auth-btn" onClick={doVerifyOTP} disabled={otpCode.length!==6||loading}>
                {loading && <span className="spinner"/>}
                {loading ? 'Verifying & creating account…' : 'Verify & create account →'}
              </button>

              <div className="otp-actions">
                <button className="link-btn" style={{color:G.muted}}
                  onClick={()=>{setRegStep('form');setOtpCode('');setError('');setDevOtp('');}}>
                  ← Change details
                </button>
                <button className="link-btn"
                  style={{color:countdown>0?G.muted:G.accent}}
                  disabled={countdown>0}
                  onClick={()=>{if(countdown===0){setOtpCode('');setError('');doSendOTP();}}}>
                  {countdown>0?`Resend in ${countdown}s`:'Resend code'}
                </button>
              </div>
            </>
          )}

          {/* ── REGISTER step 3: creating ── */}
          {tab==='register' && regStep==='creating' && (
            <div style={{textAlign:'center',padding:'20px 0'}}>
              <div className="spinner" style={{margin:'0 auto 14px',width:28,height:28}}/>
              <div style={{fontSize:13,color:G.muted}}>Generating encryption keys & creating account…</div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ── KeyModal ──────────────────────────────────────────────────────────────
function KeyModal({ myKeys, myUser, contact, onClose }) {
  const myPub64  = useMemo(()=>publicKeyToBase64(myKeys),[myKeys]);
  const mySegs   = (myUser.key_fingerprint ||'').match(/.{1,4}/g)||[];
  const theirSegs= (contact?.key_fingerprint||'').match(/.{1,4}/g)||[];
  return (
    <div className="modal-wrap" onClick={onClose}>
      <div className="modal" onClick={e=>e.stopPropagation()}>
        <div className="modal-title">🔑 Key verification — {contact?.username}</div>
        <div className="key-block">
          <div className="key-label">Your public key</div>
          <div className="key-val">{myPub64}</div>
          <div className="key-label" style={{marginTop:8}}>Your fingerprint</div>
          <div className="fp-grid">{mySegs.map((s,i)=><div key={i} className="fp-cell" style={{color:G.accent2}}>{s}</div>)}</div>
        </div>
        <div className="key-block">
          <div className="key-label">{contact?.username}'s public key</div>
          <div className="key-val">{contact?.public_key}</div>
          <div className="key-label" style={{marginTop:8}}>Their fingerprint</div>
          <div className="fp-grid">{theirSegs.map((s,i)=><div key={i} className="fp-cell" style={{color:G.accent}}>{s}</div>)}</div>
        </div>
        <div className="modal-note">
          💡 Compare fingerprints with {contact?.username} via a separate channel (phone call, in person).
          If they match, your conversation is secure.
        </div>
        <button className="modal-close" onClick={onClose}>Close</button>
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────
export default function App() {
  const [user, setUser]         = useState(null);
  const [myKeys, setMyKeys]     = useState(null);
  const [wsStatus, setWsStatus] = useState('disconnected');
  const [contacts, setContacts] = useState({});
  const [messages, setMessages] = useState({});
  const [activeId, setActiveId] = useState(null);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [input, setInput]       = useState('');
  const [sending, setSending]   = useState(false);
  const [typingFrom, setTypingFrom] = useState(null);
  const [searchQ, setSearchQ]   = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [unread, setUnread]     = useState({});
  const [sendError, setSendError] = useState('');
  const [restoring, setRestoring] = useState(true);

  const socketRef    = useRef(null);
  const typingTimer  = useRef(null);
  const msgsEndRef   = useRef(null);
  // Use a ref for myKeys inside callbacks to avoid stale closures
  const myKeysRef    = useRef(null);

  useEffect(() => { myKeysRef.current = myKeys; }, [myKeys]);

  useEffect(() => {
    msgsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, activeId]);

  // ── Session restore ──────────────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      try {
        const ok = await auth.restore();
        if (ok) {
          const kp = await loadIdentityKeypair();
          if (kp) {
            const me = await usersApi.me().catch(() => null);
            if (me) { setUser(me); setMyKeys(kp); myKeysRef.current = kp; }
          }
        }
      } catch {}
      setRestoring(false);
    })();
    window.addEventListener('auth:expired', handleExpired);
    return () => window.removeEventListener('auth:expired', handleExpired);
  }, []);

  function handleExpired() { setUser(null); setMyKeys(null); clearTokens(); }

  // ── WebSocket ────────────────────────────────────────────────────────────
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
      const map = {};
      convos.forEach(c => {
        const cId = c.sender_id === user.id ? c.recipient_id : c.sender_id;
        map[cId] = { id:cId, username:c.contact_username, public_key:c.contact_public_key, key_fingerprint:c.contact_fingerprint };
        if (c.unread_count > 0) setUnread(p => ({...p, [cId]: c.unread_count}));
      });
      setContacts(p => ({...p, ...map}));
    } catch {}
  }

  async function loadHistory(contactId) {
    const kp = myKeysRef.current;
    if (!kp) return;
    setLoadingHistory(true);
    try {
      const { messages: hist, contact } = await messagesApi.getConversation(contactId);
      if (contact) setContacts(p => ({...p, [contactId]: contact}));
      const decrypted = hist.map(m => decryptMsg(m, kp));
      setMessages(p => ({...p, [contactId]: deduped([...(p[contactId]||[]), ...decrypted])}));
    } catch {}
    finally { setLoadingHistory(false); }
  }

  function decryptMsg(m, kp) {
    const keys = kp || myKeysRef.current;
    if (m.sender_id === user.id) {
      // Try to recover sent text from local cache first
      const cached = sentCache.get(m.id);
      return { ...m, text: cached, direction:'sent', selfSent: !cached };
    }
    const text = decryptMessage(m.ciphertext, m.nonce, m.ephemeral_pub, keys?.secretKey);
    return { ...m, text, direction:'recv', decryptFailed: !text };
  }

  // Deduplicate messages by id
  function deduped(msgs) {
    const seen = new Set();
    return msgs.filter(m => { if (seen.has(m.id)) return false; seen.add(m.id); return true; });
  }

  function handleWsMessage(msg) {
    if (msg.type === 'ws_status') { setWsStatus(msg.status); return; }

    if (msg.type === 'new_message') {
      const cId = msg.sender_id;
      const kp  = myKeysRef.current;
      const text = decryptMessage(msg.ciphertext, msg.nonce, msg.ephemeral_pub, kp?.secretKey);
      const enriched = { ...msg, text, direction:'recv', decryptFailed: !text };
      setMessages(p => ({...p, [cId]: deduped([...(p[cId]||[]), enriched])}));
      setActiveId(cur => {
        if (cur !== cId) setUnread(u => ({...u, [cId]: (u[cId]||0)+1}));
        else socketRef.current?.markRead(msg.id, msg.sender_id);
        return cur;
      });
      if (!contacts[cId]) {
        usersApi.getById(cId).then(u => setContacts(p => ({...p, [cId]: u}))).catch(()=>{});
      }
      return;
    }

    if (msg.type === 'pending_messages') {
      const kp = myKeysRef.current;
      msg.messages.forEach(m => {
        const cId  = m.sender_id;
        const text = decryptMessage(m.ciphertext, m.nonce, m.ephemeral_pub, kp?.secretKey);
        setMessages(p => ({...p, [cId]: deduped([...(p[cId]||[]), {...m, text, direction:'recv', decryptFailed:!text}])}));
      });
      return;
    }

    if (msg.type === 'typing') {
      setTypingFrom(msg.active ? msg.from_username : null);
      clearTimeout(typingTimer.current);
      if (msg.active) typingTimer.current = setTimeout(() => setTypingFrom(null), 3000);
      return;
    }

    if (msg.type === 'message_read') {
      setMessages(p => {
        const u = {...p};
        for (const k of Object.keys(u))
          u[k] = u[k].map(m => m.id===msg.message_id ? {...m, read_at:Date.now()} : m);
        return u;
      });
    }
  }

  async function selectContact(id) {
    setActiveId(id);
    setUnread(p => ({...p, [id]: 0}));
    setSearchQ(''); setSearchResults([]);
    if (!messages[id] || messages[id].length === 0) await loadHistory(id);
  }

  async function sendMessage() {
    if (!input.trim() || !activeId || !myKeys || sending) return;
    const contact = contacts[activeId];
    if (!contact?.public_key) return;
    const text = input.trim();
    setInput('');
    setSending(true);
    setSendError('');
    const tempId = 'tmp-' + Date.now() + Math.random();
    const clientTs = Date.now();
    try {
      const recipientPub = base64ToBytes(contact.public_key);
      const { ciphertext, nonce, ephemeral_pub } = encryptMessage(text, recipientPub);

      // Optimistic message — show immediately with real text
      setMessages(p => ({
        ...p,
        [activeId]: [...(p[activeId]||[]), { id:tempId, text, direction:'sent', client_ts:clientTs, server_ts:clientTs, pending:true }],
      }));

      const ack = await socketRef.current.sendMessage(activeId, ciphertext, nonce, ephemeral_pub, clientTs);

      // Cache the sent text under the real server ID so it survives history reload
      sentCache.set(ack.id, text);

      // Replace temp with confirmed
      setMessages(p => ({
        ...p,
        [activeId]: p[activeId].map(m => m.id===tempId
          ? { ...m, id:ack.id, server_ts:ack.server_ts, pending:false }
          : m),
      }));
    } catch(e) {
      // Remove optimistic on failure
      setMessages(p => ({...p, [activeId]: (p[activeId]||[]).filter(m=>m.id!==tempId)}));
      setSendError('Failed to send — ' + e.message);
      setInput(text); // restore input
      setTimeout(() => setSendError(''), 5000);
    } finally { setSending(false); }
  }

  function handleInputChange(e) {
    setInput(e.target.value);
    if (activeId && socketRef.current) {
      socketRef.current.sendTyping(activeId, true);
      clearTimeout(typingTimer.current);
      typingTimer.current = setTimeout(() => socketRef.current?.sendTyping(activeId, false), 2000);
    }
  }

  async function searchUsers(q) {
    setSearchQ(q);
    if (!q.trim()) { setSearchResults([]); return; }
    if (q.trim().length < 2) return;
    setSearching(true);
    try {
      const res = await usersApi.search(q.trim());
      setSearchResults((res||[]).filter(u => u.id !== user.id));
    } catch {} finally { setSearching(false); }
  }

  async function handleLogout() {
    await auth.logout().catch(()=>{});
    socketRef.current?.destroy();
    setUser(null); setMyKeys(null);
  }

  // ── Loading splash ────────────────────────────────────────────────────
  if (restoring) return (
    <>
      <style>{css}</style>
      <div style={{height:'100vh',display:'flex',alignItems:'center',justifyContent:'center',background:G.bg}}>
        <div style={{textAlign:'center',color:G.muted}}>
          <div className="spinner" style={{margin:'0 auto 14px',width:24,height:24}}/>
          <div style={{fontFamily:'IBM Plex Mono,monospace',fontSize:12}}>Loading…</div>
        </div>
      </div>
    </>
  );

  if (!user || !myKeys) return <AuthScreen onAuth={(u,kp)=>{setUser(u);setMyKeys(kp);myKeysRef.current=kp;}}/>;

  const activeContact  = contacts[activeId];
  const activeMessages = messages[activeId] || [];
  const sortedContacts = Object.values(contacts).sort((a,b) => {
    const la = messages[a.id]?.slice(-1)[0]?.server_ts||0;
    const lb = messages[b.id]?.slice(-1)[0]?.server_ts||0;
    return lb-la;
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
              <span className={`ws-dot ${wsStatus==='connected'?'on':'off'}`}/>
              {wsStatus==='connected' ? 'Connected · Encrypted' : 'Connecting…'}
            </div>
          </div>

          <div className="me-card">
            <div className="me-name">
              <Avatar name={user.username} size={22}/>
              {user.username}
              <button className="signout-btn" onClick={handleLogout}>Sign out</button>
            </div>
            <div className="me-fp-label">Key fingerprint</div>
            <div className="me-fp">{formatFingerprint(user.key_fingerprint||'')}</div>
          </div>

          <div className="section-label">Find people</div>
          <div className="search-wrap">
            <input className="search-input" placeholder="Search username…"
              value={searchQ}
              onChange={e => searchUsers(e.target.value)}/>
          </div>

          {searchQ.trim().length >= 2 && (
            <div className="search-results">
              {searching && <div className="no-results">Searching…</div>}
              {!searching && searchResults.length === 0 && (
                <div className="no-results">No users found for "{searchQ}"</div>
              )}
              {searchResults.map(u => (
                <div key={u.id} className="search-result-item"
                  onClick={()=>{ setContacts(p=>({...p,[u.id]:u})); selectContact(u.id); }}>
                  <Avatar name={u.username} size={30}/>
                  <div>
                    <div style={{fontSize:13,fontWeight:500}}>{u.username}</div>
                    <div style={{fontSize:10,color:G.muted,fontFamily:'IBM Plex Mono,monospace'}}>🔒 E2EE</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="section-label">Conversations</div>
          <div className="contacts">
            {sortedContacts.map(c => {
              const last = messages[c.id]?.slice(-1)[0];
              const preview = last
                ? (last.direction==='sent'
                    ? (last.text ? `You: ${last.text.slice(0,28)}` : 'You: 🔒 sent')
                    : (last.text?.slice(0,30) || '…'))
                : '🔒 Start chatting';
              return (
                <div key={c.id} className={`contact-row${activeId===c.id?' active':''}`}
                  onClick={()=>selectContact(c.id)}>
                  <Avatar name={c.username} size={36}/>
                  <div className="contact-info">
                    <div className="contact-name">{c.username}</div>
                    <div className="contact-preview">{preview}</div>
                  </div>
                  {(unread[c.id]||0)>0 && <div className="unread-badge">{unread[c.id]}</div>}
                </div>
              );
            })}
            {sortedContacts.length===0 && (
              <div style={{fontSize:12,color:G.muted,textAlign:'center',padding:'20px 10px',lineHeight:1.7}}>
                Search for a username above<br/>to start a conversation
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
              <div className="empty-sub">Messages are encrypted before leaving your device. The server cannot read them.</div>
            </div>
          ) : (
            <>
              <div className="chat-header">
                <Avatar name={activeContact.username} size={38}/>
                <div style={{flex:1}}>
                  <div className="chat-contact-name">{activeContact.username}</div>
                  <div className="e2ee-tag">🔒 X25519 · XSalsa20-Poly1305 · Forward Secrecy</div>
                </div>
                <button className="icon-btn" onClick={()=>setShowKeyModal(true)}>Verify keys</button>
              </div>

              {sendError && <div className="error-bar">⚠ {sendError}</div>}

              {loadingHistory ? (
                <div className="msgs-loading">
                  <div className="spinner" style={{width:18,height:18}}/>
                  Loading messages…
                </div>
              ) : (
                <div className="msgs">
                  {activeMessages.length===0 && (
                    <div style={{textAlign:'center',marginTop:60}}>
                      <div style={{fontSize:28,marginBottom:10,opacity:.4}}>👋</div>
                      <div style={{fontSize:13,color:G.muted}}>
                        Say hello to <strong style={{color:G.accent2}}>{activeContact.username}</strong>
                      </div>
                      <div style={{fontSize:11,color:G.muted,marginTop:6}}>
                        Your message will be encrypted before it leaves your device.
                      </div>
                    </div>
                  )}
                  {activeMessages.map((m, i) => {
                    const prev = activeMessages[i-1];
                    const showDay = !prev || fmtDate(prev.server_ts||prev.client_ts) !== fmtDate(m.server_ts||m.client_ts);
                    const ts = m.server_ts || m.client_ts;
                    return (
                      <div key={m.id}>
                        {showDay && <div className="day-sep">{fmtDate(ts)}</div>}
                        <div className={`msg-row ${m.direction} msg-enter`}>
                          <div className="bubble">
                            {m.decryptFailed
                              ? <span className="decrypt-fail">⚠ Decryption failed</span>
                              : (m.text || (m.selfSent
                                  ? <span style={{color:G.muted,fontStyle:'italic',fontSize:12}}>🔒 Encrypted (forward-secret)</span>
                                  : <span style={{color:G.muted,fontStyle:'italic',fontSize:12}}>…</span>))}
                          </div>
                          <div className="msg-meta">
                            <span className="lock-icon">🔒</span>
                            {fmtTime(ts)}
                            {m.pending && <span className="typing-pulse" style={{color:G.muted}}>sending…</span>}
                            {m.read_at && m.direction==='sent' && <span className="read-tick">✓✓</span>}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                  <div ref={msgsEndRef}/>
                </div>
              )}

              <div className="typing-indicator">
                {typingFrom && contacts[activeId]?.username===typingFrom
                  ? <span className="typing-pulse">✍ {typingFrom} is typing…</span>
                  : null}
              </div>

              <div className="input-area">
                <div className="input-row">
                  <textarea className="msg-input"
                    placeholder={`Message ${activeContact.username}…`}
                    value={input} onChange={handleInputChange}
                    onKeyDown={e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage();}}}
                    rows={1}/>
                  <button className="send-btn" onClick={sendMessage} disabled={!input.trim()||sending}>
                    {sending ? <span className="spinner" style={{width:14,height:14}}/> : '↑'}
                  </button>
                </div>
                <div className="input-hint">🔒 Encrypted before sending · Enter to send · Shift+Enter for new line</div>
              </div>
            </>
          )}
        </div>
      </div>

      {showKeyModal && activeContact && (
        <KeyModal myKeys={myKeys} myUser={user} contact={activeContact} onClose={()=>setShowKeyModal(false)}/>
      )}
    </>
  );
}
