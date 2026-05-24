'use strict';

/**
 * otp.js — Email OTP for sign-up verification
 *
 * Supported providers (set EMAIL_PROVIDER in Railway env):
 *   dev      → code shown on website UI (default, no email setup)
 *   gmail    → Gmail with App Password
 *   brevo    → Brevo SMTP (free, 300/day, recommended for production)
 *   outlook  → Outlook/Hotmail
 *   smtp     → Any custom SMTP server
 */

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
require('dotenv').config();

const OTP_EXPIRY_MS    = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function getOtpSecret() {
  return process.env.OTP_SECRET || process.env.JWT_SECRET || 'fallback-change-in-prod';
}

// email → { codeHash, expiresAt, attempts, sentCount, windowStart }
const store = new Map();

function hashCode(code) {
  return crypto.createHash('sha256').update(String(code).trim()).digest('hex');
}

function generateOTP() {
  return String(crypto.randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, '0');
}

// ── Build nodemailer transport from env vars ───────────────────────────────
function buildTransport(nodemailer) {
  const provider = (process.env.EMAIL_PROVIDER || 'dev').toLowerCase();

  if (provider === 'gmail') {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      throw new Error('Gmail requires EMAIL_USER and EMAIL_PASS (App Password) in environment variables.');
    }
    return nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  }

  if (provider === 'brevo') {
    // Brevo (formerly Sendinblue) — free tier: 300 emails/day
    // Get SMTP key from: https://app.brevo.com/settings/keys/smtp
    if (!process.env.BREVO_SMTP_KEY) {
      throw new Error('Brevo requires BREVO_SMTP_KEY in environment variables. Get it from https://app.brevo.com/settings/keys/smtp');
    }
    return nodemailer.createTransport({
      host:   'smtp-relay.brevo.com',
      port:   587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER || process.env.BREVO_LOGIN,
        pass: process.env.BREVO_SMTP_KEY,
      },
    });
  }

  if (provider === 'outlook') {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      throw new Error('Outlook requires EMAIL_USER and EMAIL_PASS in environment variables.');
    }
    return nodemailer.createTransport({
      service: 'hotmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  }

  if (provider === 'smtp') {
    if (!process.env.SMTP_HOST) {
      throw new Error('SMTP provider requires SMTP_HOST in environment variables.');
    }
    return nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER || process.env.EMAIL_USER,
        pass: process.env.SMTP_PASS || process.env.EMAIL_PASS,
      },
    });
  }

  throw new Error(`Unknown EMAIL_PROVIDER "${provider}". Use: dev, gmail, brevo, outlook, or smtp`);
}

// ── Send OTP ──────────────────────────────────────────────────────────────
async function sendOTP(email) {
  const key = email.toLowerCase().trim();
  const now = Date.now();
  const provider = (process.env.EMAIL_PROVIDER || 'dev').toLowerCase();

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

  // ── DEV MODE — no email, show code in UI ──────────────────────────────
  if (provider === 'dev') {
    console.log('\n' + '═'.repeat(48));
    console.log('  vault.msg OTP  [DEV MODE — no email sent]');
    console.log('─'.repeat(48));
    console.log(`  Email : ${key}`);
    console.log(`  Code  : ${code}   ← shown on website`);
    console.log('═'.repeat(48) + '\n');
    // Return the code so UI can display it
    return { sent: true, isTest: true, code };
  }

  // ── PRODUCTION EMAIL ──────────────────────────────────────────────────
  let nodemailer;
  try {
    nodemailer = require('nodemailer');
  } catch {
    throw new Error('nodemailer package missing. Run: cd server && npm install');
  }

  let transport;
  try {
    transport = buildTransport(nodemailer);
  } catch (e) {
    // Config error — log clearly and fall back to dev mode so signup doesn't break
    console.error('\n[otp] EMAIL CONFIG ERROR:', e.message);
    console.error('[otp] Falling back to dev mode — code shown on website');
    console.error('[otp] Fix your email environment variables in Railway to send real emails\n');
    console.log(`[otp] DEV FALLBACK — Code for ${key}: ${code}`);
    return { sent: true, isTest: true, code };
  }

  // Send the email
  try {
    await transport.sendMail({
      from:    `"vault.msg" <${process.env.EMAIL_FROM || process.env.EMAIL_USER || 'noreply@vault.msg'}>`,
      to:      key,
      subject: `${code} — Your vault.msg verification code`,
      html: `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0c0d11;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0c0d11;padding:40px 20px;">
    <tr><td align="center">
      <table width="400" cellpadding="0" cellspacing="0" style="background:#13141a;border:1px solid #272833;border-radius:16px;padding:32px;">
        <tr><td>
          <p style="font-family:monospace;font-size:22px;color:#6c63ff;margin:0 0 8px;">vault.msg</p>
          <p style="font-size:13px;color:#5a5d73;margin:0 0 24px;">Zero-knowledge encrypted messenger</p>
          <p style="font-size:15px;color:#e4e5f0;margin:0 0 16px;">Your sign-up verification code:</p>
          <div style="background:#1a1b23;border:2px solid #272833;border-radius:12px;padding:24px;text-align:center;margin:0 0 20px;">
            <span style="font-family:monospace;font-size:42px;font-weight:bold;letter-spacing:16px;color:#4fd1c5;">${code}</span>
          </div>
          <p style="font-size:12px;color:#5a5d73;line-height:1.8;margin:0;">
            This code expires in <strong style="color:#e4e5f0;">10 minutes</strong>.<br>
            Enter it on vault.msg to complete your sign-up.<br>
            If you didn't request this, you can ignore this email.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
      text: `Your vault.msg sign-up code: ${code}\n\nExpires in 10 minutes.\nIf you didn't request this, ignore this email.`,
    });
    console.log(`[otp] Email sent to ${key} via ${provider}`);
    return { sent: true, isTest: false };
  } catch (e) {
    console.error(`[otp] Failed to send email to ${key}:`, e.message);
    // Don't expose email errors to the client — just say it was sent
    // The code is still valid so the user can try entering it from Railway logs
    throw new Error('Failed to send verification email. Please check your email address and try again.');
  }
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
      Buffer.from(inputHash,       'hex'),
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

function validateOTPToken(token, email) {
  try {
    const p = jwt.verify(token, getOtpSecret(), { algorithms: ['HS256'] });
    return p.purpose === 'otp_verified' && p.email === email.toLowerCase().trim();
  } catch { return false; }
}

module.exports = { sendOTP, verifyOTP, validateOTPToken };
