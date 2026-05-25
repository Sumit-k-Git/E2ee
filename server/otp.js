'use strict';

/**
 * otp.js — OTP email delivery
 *
 * Brevo connection timeout fix:
 * Railway blocks outbound port 587. Use port 465 (SSL) instead.
 * Or use Brevo's HTTP API (no SMTP needed, always works).
 */

const crypto  = require('crypto');
const jwt     = require('jsonwebtoken');
const https   = require('https');
require('dotenv').config();

const OTP_EXPIRY_MS    = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function getOtpSecret() {
  return process.env.OTP_SECRET || process.env.JWT_SECRET || 'fallback-change-in-prod';
}

const store = new Map(); // email → { codeHash, expiresAt, attempts, sentCount, windowStart }

function hashCode(code) {
  return crypto.createHash('sha256').update(String(code).trim()).digest('hex');
}
function generateOTP() {
  return String(crypto.randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, '0');
}

// ── Brevo HTTP API (no SMTP — works on Railway) ───────────────────────────
function sendViaBrevoAPI(to, code) {
  return new Promise((resolve, reject) => {
    const apiKey = process.env.BREVO_API_KEY;
    if (!apiKey) {
      reject(new Error('BREVO_API_KEY not set. Get it from https://app.brevo.com/settings/keys/api'));
      return;
    }

    // EMAIL_FROM must be set to a verified sender in your Brevo account.
    // e.g. EMAIL_FROM=noreply@yourdomain.com
    // DO NOT leave this as the default — Brevo will reject unverified sender addresses.
    const from = process.env.EMAIL_FROM || process.env.EMAIL_USER;
    if (!from) {
      reject(new Error(
        'EMAIL_FROM is not set. In Railway, add EMAIL_FROM=noreply@yourdomain.com ' +
        '(must be a verified sender in your Brevo account at https://app.brevo.com/senders)'
      ));
      return;
    }
    const fromName = 'vault.msg';

    const body = JSON.stringify({
      sender:  { name: fromName, email: from },
      to:      [{ email: to }],
      subject: `${code} — Your vault.msg verification code`,
      htmlContent: buildEmailHtml(code),
      textContent: `Your vault.msg verification code: ${code}\n\nExpires in 10 minutes.`,
    });

    const options = {
      hostname: 'api.brevo.com',
      path:     '/v3/smtp/email',
      method:   'POST',
      headers: {
        'Content-Type':  'application/json',
        'api-key':       apiKey,
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ ok: true });
        } else {
          reject(new Error(`Brevo API error ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Brevo API request timed out')); });
    req.write(body);
    req.end();
  });
}

// ── Gmail / SMTP via nodemailer ────────────────────────────────────────────
async function sendViaSMTP(to, code, provider) {
  let nodemailer;
  try { nodemailer = require('nodemailer'); }
  catch { throw new Error('nodemailer not installed. Run: npm install in server/'); }

  let transport;

  if (provider === 'gmail') {
    transport = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  } else if (provider === 'brevo_smtp') {
    // Brevo SMTP — use port 465 (SSL) since Railway blocks 587
    transport = nodemailer.createTransport({
      host:   'smtp-relay.brevo.com',
      port:   465,
      secure: true, // SSL on 465
      auth: {
        user: process.env.EMAIL_USER || process.env.BREVO_LOGIN,
        pass: process.env.BREVO_SMTP_KEY,
      },
    });
  } else if (provider === 'outlook') {
    transport = nodemailer.createTransport({
      service: 'hotmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  } else {
    // Generic SMTP
    transport = nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || '465'),
      secure: process.env.SMTP_SECURE !== 'false',
      auth: {
        user: process.env.SMTP_USER || process.env.EMAIL_USER,
        pass: process.env.SMTP_PASS || process.env.EMAIL_PASS,
      },
    });
  }

  await transport.sendMail({
    from:    `"vault.msg" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
    to,
    subject: `${code} — Your vault.msg verification code`,
    html:    buildEmailHtml(code),
    text:    `Your vault.msg verification code: ${code}\n\nExpires in 10 minutes.`,
  });
}

// ── Email HTML template ────────────────────────────────────────────────────
function buildEmailHtml(code) {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0c0d11;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0c0d11;padding:40px 20px;">
    <tr><td align="center">
      <table width="400" cellpadding="0" cellspacing="0"
        style="background:#13141a;border:1px solid #272833;border-radius:16px;padding:32px;max-width:400px;width:100%;">
        <tr><td>
          <p style="font-family:monospace;font-size:22px;color:#6c63ff;margin:0 0 6px;">vault.msg</p>
          <p style="font-size:12px;color:#5a5d73;margin:0 0 24px;">Zero-knowledge encrypted messenger</p>
          <p style="font-size:15px;color:#e4e5f0;margin:0 0 16px;">Your sign-up verification code:</p>
          <div style="background:#1a1b23;border:2px solid #272833;border-radius:12px;
            padding:24px;text-align:center;margin:0 0 20px;">
            <span style="font-family:monospace;font-size:42px;font-weight:bold;
              letter-spacing:16px;color:#4fd1c5;">${code}</span>
          </div>
          <p style="font-size:12px;color:#5a5d73;line-height:1.8;margin:0;">
            Expires in <strong style="color:#e4e5f0;">10 minutes</strong>.<br>
            If you didn't request this, ignore this email.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

// ── Main sendOTP ───────────────────────────────────────────────────────────
async function sendOTP(email) {
  const key      = email.toLowerCase().trim();
  const now      = Date.now();
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

  // ── DEV MODE ─────────────────────────────────────────────────────────────
  if (provider === 'dev') {
    console.log('\n' + '═'.repeat(50));
    console.log('  vault.msg  │  OTP CODE [DEV MODE]');
    console.log('─'.repeat(50));
    console.log(`  Email : ${key}`);
    console.log(`  Code  : ${code}   ← shown on website`);
    console.log('═'.repeat(50) + '\n');
    return { sent: true, isTest: true, code };
  }

  // ── BREVO HTTP API (recommended — works on Railway) ───────────────────────
  if (provider === 'brevo') {
    try {
      await sendViaBrevoAPI(key, code);
      console.log(`[otp] Email sent to ${key} via Brevo API`);
      return { sent: true, isTest: false };
    } catch (e) {
      console.error('[otp] Brevo API error:', e.message);
      if (e.message.includes('valid sender') || e.message.includes('invalid_parameter')) {
        throw new Error('Email delivery failed: sender address not verified in Brevo. Visit https://app.brevo.com/senders and verify your EMAIL_FROM address.');
      }
      throw new Error('Could not send verification email. Please try again shortly.');
    }
  }

  // ── GMAIL / SMTP ──────────────────────────────────────────────────────────
  try {
    await sendViaSMTP(key, code, provider);
    console.log(`[otp] Email sent to ${key} via ${provider}`);
    return { sent: true, isTest: false };
  } catch (e) {
    console.error(`[otp] ${provider} send failed:`, e.message);
    throw new Error(`Failed to send verification email (${e.message}). Check email settings in Railway.`);
  }
}

// ── Verify OTP ────────────────────────────────────────────────────────────
function verifyOTP(email, code) {
  const key    = email.toLowerCase().trim();
  const record = store.get(key);

  if (!record) throw new Error('No code found for this email. Please request a new one.');
  if (Date.now() > record.expiresAt) {
    store.delete(key);
    throw new Error('Code has expired. Please request a new one.');
  }
  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    store.delete(key);
    throw new Error('Too many incorrect attempts. Please request a new code.');
  }

  let match = false;
  try {
    match = crypto.timingSafeEqual(
      Buffer.from(hashCode(code), 'hex'),
      Buffer.from(record.codeHash,  'hex')
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
