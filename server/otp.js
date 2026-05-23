'use strict';

/**
 * otp.js — Email OTP for sign-up verification
 * Dev mode: code printed to console AND returned to client for display.
 */

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
require('dotenv').config();

const OTP_EXPIRY_MS    = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function getOtpSecret() {
  return process.env.OTP_SECRET || process.env.JWT_SECRET || 'fallback-otp-secret-change-in-prod';
}

// email → { codeHash, expiresAt, attempts, sentCount, windowStart }
const store = new Map();

function hashCode(code) {
  return crypto.createHash('sha256').update(String(code).trim()).digest('hex');
}

function generateOTP() {
  return String(crypto.randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, '0');
}

// ── Send OTP ──────────────────────────────────────────────────────────────
async function sendOTP(email) {
  const key = email.toLowerCase().trim();
  const now = Date.now();

  // Rate limit: 3 sends per 15 min per email
  const existing = store.get(key);
  if (existing) {
    const age = now - (existing.windowStart || 0);
    if (age < 15 * 60 * 1000 && (existing.sentCount || 0) >= 3) {
      throw new Error('Too many codes requested. Please wait 15 minutes.');
    }
  }

  const code      = generateOTP();
  const codeHash  = hashCode(code);
  const expiresAt = now + OTP_EXPIRY_MS;
  const sentCount = existing && (now - (existing.windowStart || 0)) < 15 * 60 * 1000
    ? (existing.sentCount || 0) + 1 : 1;

  store.set(key, {
    codeHash, expiresAt, attempts: 0, sentCount,
    windowStart: existing?.windowStart && sentCount > 1 ? existing.windowStart : now,
  });

  const provider = (process.env.EMAIL_PROVIDER || 'dev').toLowerCase();

  // ── DEV MODE ─────────────────────────────────────────────────────────────
  if (provider === 'dev' || !process.env.EMAIL_USER) {
    console.log('\n' + '═'.repeat(46));
    console.log('  vault.msg  │  OTP [DEV MODE - no email sent]');
    console.log('─'.repeat(46));
    console.log(`  Email : ${key}`);
    console.log(`  Code  : ${code}   ← enter this in the app`);
    console.log(`  Valid : 10 minutes`);
    console.log('═'.repeat(46) + '\n');
    // Return code so the UI can display it — great DX for dev/testing
    return { sent: true, isTest: true, code };
  }

  // ── PRODUCTION EMAIL ──────────────────────────────────────────────────────
  let nodemailer;
  try { nodemailer = require('nodemailer'); }
  catch { throw new Error('nodemailer not installed. Run: npm install in the server folder.'); }

  let transport;
  if (provider === 'gmail') {
    transport = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  } else if (provider === 'outlook') {
    transport = nodemailer.createTransport({
      service: 'hotmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  } else if (provider === 'smtp') {
    transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST, port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER || process.env.EMAIL_USER, pass: process.env.SMTP_PASS || process.env.EMAIL_PASS },
    });
  } else {
    throw new Error(`Unknown EMAIL_PROVIDER "${provider}". Use: dev, gmail, outlook, or smtp`);
  }

  await transport.sendMail({
    from:    `"vault.msg" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
    to:      key,
    subject: `${code} — Your vault.msg verification code`,
    html: `
      <div style="font-family:sans-serif;background:#0c0d11;color:#e4e5f0;padding:40px 20px;">
        <div style="max-width:400px;margin:0 auto;background:#13141a;border:1px solid #272833;border-radius:16px;padding:32px;">
          <div style="font-family:monospace;font-size:22px;color:#6c63ff;margin-bottom:16px;">vault.msg</div>
          <p style="font-size:15px;margin-bottom:20px;">Your sign-up verification code:</p>
          <div style="font-family:monospace;font-size:44px;font-weight:700;letter-spacing:14px;color:#4fd1c5;
            background:#1a1b23;border-radius:10px;padding:20px;text-align:center;margin-bottom:20px;">${code}</div>
          <p style="font-size:12px;color:#5a5d73;line-height:1.7;">
            Expires in <strong style="color:#e4e5f0;">10 minutes</strong>.<br>
            If you didn't request this, you can ignore this email.
          </p>
        </div>
      </div>`,
    text: `Your vault.msg verification code: ${code}\n\nExpires in 10 minutes.`,
  });

  return { sent: true, isTest: false };
}

// ── Verify OTP ────────────────────────────────────────────────────────────
function verifyOTP(email, code) {
  const key    = email.toLowerCase().trim();
  const record = store.get(key);

  if (!record)
    throw new Error('No code found for this email. Please request a new one.');
  if (Date.now() > record.expiresAt) {
    store.delete(key);
    throw new Error('Code has expired. Please request a new one.');
  }
  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    store.delete(key);
    throw new Error('Too many incorrect attempts. Please request a new code.');
  }

  const inputHash = hashCode(code);
  let match = false;
  try {
    match = crypto.timingSafeEqual(
      Buffer.from(inputHash, 'hex'),
      Buffer.from(record.codeHash, 'hex')
    );
  } catch { match = false; }

  if (!match) {
    record.attempts++;
    const left = OTP_MAX_ATTEMPTS - record.attempts;
    throw new Error(`Incorrect code. ${left} attempt${left === 1 ? '' : 's'} remaining.`);
  }

  store.delete(key);

  const token = jwt.sign(
    { email: key, purpose: 'otp_verified' },
    getOtpSecret(),
    { expiresIn: '15m', algorithm: 'HS256' }
  );
  return { verified: true, otp_token: token };
}

// ── Validate OTP token (called at /register) ──────────────────────────────
function validateOTPToken(token, email) {
  try {
    const p = jwt.verify(token, getOtpSecret(), { algorithms: ['HS256'] });
    return p.purpose === 'otp_verified' && p.email === email.toLowerCase().trim();
  } catch { return false; }
}

module.exports = { sendOTP, verifyOTP, validateOTPToken };
