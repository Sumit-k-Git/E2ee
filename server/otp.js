'use strict';

/**
 * otp.js — Email OTP for registration verification
 *
 * Flow:
 *  1. POST /api/auth/send-otp   { email }  → generates 6-digit code, emails it
 *  2. POST /api/auth/verify-otp { email, code } → returns verified: true
 *  3. POST /api/auth/register   { username, password, public_key, key_fingerprint, email, otp_token }
 *
 * OTP design:
 *  - 6-digit numeric code
 *  - 10-minute expiry
 *  - Max 3 attempts per code (brute-force protection)
 *  - Rate limited: 3 sends per email per 15 minutes
 *  - Stored in SQLite (same DB, separate table)
 *  - Verification issues a short-lived signed token so register endpoint
 *    can confirm OTP was verified without re-checking the code
 */

const crypto      = require('crypto');
const nodemailer  = require('nodemailer');
const jwt         = require('jsonwebtoken');
require('dotenv').config();

const OTP_EXPIRY_MS   = 10 * 60 * 1000;   // 10 minutes
const OTP_MAX_ATTEMPTS = 3;
const OTP_SECRET      = process.env.OTP_SECRET || process.env.JWT_SECRET;

// ── In-memory OTP store (SQLite preferred for multi-process, but this is
//    sufficient for single-process deployment — resets on restart which is fine
//    since OTPs are short-lived) ─────────────────────────────────────────────
// Map<email → { codeHash, expiresAt, attempts, sentCount, windowStart }>
const otpStore = new Map();

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function generateOTP() {
  // Cryptographically secure 6-digit code
  const bytes = crypto.randomBytes(4);
  const num   = bytes.readUInt32BE(0);
  return String(num % 1000000).padStart(6, '0');
}

// ── Email transport ──────────────────────────────────────────────────────────
function createTransport() {
  const provider = (process.env.EMAIL_PROVIDER || 'smtp').toLowerCase();

  // Gmail  ── set EMAIL_PROVIDER=gmail, EMAIL_USER, EMAIL_PASS
  if (provider === 'gmail') {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  }

  // Outlook / Hotmail
  if (provider === 'outlook') {
    return nodemailer.createTransport({
      service: 'hotmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  }

  // Generic SMTP  ── set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
  if (provider === 'smtp') {
    return nodemailer.createTransport({
      host:   process.env.SMTP_HOST   || 'smtp.ethereal.email',
      port:   parseInt(process.env.SMTP_PORT  || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER || process.env.EMAIL_USER,
        pass: process.env.SMTP_PASS || process.env.EMAIL_PASS,
      },
    });
  }

  // DEV MODE — Ethereal (fake SMTP, logs to console, no real email sent)
  // Automatically used when EMAIL_PROVIDER=dev or no EMAIL_USER is set
  return null; // handled below
}

async function getTransport() {
  if (process.env.EMAIL_PROVIDER === 'dev' || !process.env.EMAIL_USER) {
    // Create a disposable Ethereal test account — perfect for dev/testing
    const testAccount = await nodemailer.createTestAccount();
    const transport = nodemailer.createTransport({
      host: 'smtp.ethereal.email', port: 587, secure: false,
      auth: { user: testAccount.user, pass: testAccount.pass },
    });
    return { transport, isTest: true };
  }
  return { transport: createTransport(), isTest: false };
}

// ── Send OTP ──────────────────────────────────────────────────────────────────
async function sendOTP(email) {
  const normalised = email.toLowerCase().trim();

  // Rate limit: max 3 sends per email per 15 minutes
  const existing = otpStore.get(normalised);
  const now = Date.now();
  if (existing) {
    const windowAge = now - (existing.windowStart || 0);
    if (windowAge < 15 * 60 * 1000 && (existing.sentCount || 0) >= 3) {
      throw new Error('Too many OTP requests. Please wait 15 minutes before trying again.');
    }
  }

  const code      = generateOTP();
  const codeHash  = hashCode(code);
  const expiresAt = now + OTP_EXPIRY_MS;
  const sentCount = existing && (Date.now() - (existing.windowStart || 0)) < 15 * 60 * 1000
    ? (existing.sentCount || 0) + 1 : 1;

  otpStore.set(normalised, {
    codeHash,
    expiresAt,
    attempts:    0,
    sentCount,
    windowStart: existing?.windowStart && sentCount > 1 ? existing.windowStart : now,
  });

  const { transport, isTest } = await getTransport();

  const html = `
    <!DOCTYPE html>
    <html>
    <body style="font-family:sans-serif;background:#0c0d11;color:#e4e5f0;padding:40px 20px;">
      <div style="max-width:400px;margin:0 auto;background:#13141a;border:1px solid #272833;border-radius:16px;padding:32px;">
        <div style="font-family:monospace;font-size:20px;color:#6c63ff;letter-spacing:.06em;margin-bottom:8px;">vault.msg</div>
        <div style="font-size:13px;color:#5a5d73;margin-bottom:28px;">Zero-knowledge encrypted messenger</div>
        <div style="font-size:14px;margin-bottom:20px;">Your one-time verification code:</div>
        <div style="font-family:monospace;font-size:36px;font-weight:700;letter-spacing:10px;color:#4fd1c5;
          background:#1a1b23;border:1px solid #272833;border-radius:10px;
          padding:16px 24px;text-align:center;margin-bottom:20px;">
          ${code}
        </div>
        <div style="font-size:12px;color:#5a5d73;line-height:1.7;">
          This code expires in <strong style="color:#e4e5f0;">10 minutes</strong>.<br>
          If you didn't request this, ignore this email.<br>
          Never share this code with anyone.
        </div>
      </div>
    </body>
    </html>
  `;

  const info = await transport.sendMail({
    from:    `"vault.msg" <${process.env.EMAIL_FROM || process.env.EMAIL_USER || 'noreply@vault.msg'}>`,
    to:      normalised,
    subject: `${code} — Your vault.msg verification code`,
    html,
    text:    `Your vault.msg verification code is: ${code}\n\nExpires in 10 minutes. Never share this code.`,
  });

  // In dev/test mode, log the preview URL so you can see the email
  if (isTest) {
    console.log(`[otp] DEV MODE — OTP for ${normalised}: ${code}`);
    console.log(`[otp] Preview URL: ${nodemailer.getTestMessageUrl(info)}`);
  }

  return { sent: true, isTest, previewUrl: isTest ? nodemailer.getTestMessageUrl(info) : null };
}

// ── Verify OTP ─────────────────────────────────────────────────────────────────
function verifyOTP(email, code) {
  const normalised = email.toLowerCase().trim();
  const record     = otpStore.get(normalised);

  if (!record) throw new Error('No OTP found for this email. Please request a new code.');
  if (Date.now() > record.expiresAt) {
    otpStore.delete(normalised);
    throw new Error('OTP has expired. Please request a new code.');
  }
  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    otpStore.delete(normalised);
    throw new Error('Too many incorrect attempts. Please request a new code.');
  }

  // Constant-time comparison
  const inputHash   = hashCode(String(code).trim());
  const match = crypto.timingSafeEqual(
    Buffer.from(inputHash, 'hex'),
    Buffer.from(record.codeHash, 'hex')
  );

  if (!match) {
    record.attempts++;
    throw new Error(`Incorrect code. ${OTP_MAX_ATTEMPTS - record.attempts} attempt(s) remaining.`);
  }

  // Success — delete OTP and issue a short-lived verification token
  otpStore.delete(normalised);

  const token = jwt.sign(
    { email: normalised, purpose: 'otp_verified' },
    OTP_SECRET,
    { expiresIn: '15m', algorithm: 'HS256' }
  );

  return { verified: true, otp_token: token };
}

// ── Validate OTP token (called during register) ────────────────────────────────
function validateOTPToken(token, email) {
  try {
    const payload = jwt.verify(token, OTP_SECRET, { algorithms: ['HS256'] });
    if (payload.purpose !== 'otp_verified') return false;
    if (payload.email !== email.toLowerCase().trim()) return false;
    return true;
  } catch {
    return false;
  }
}

module.exports = { sendOTP, verifyOTP, validateOTPToken };
