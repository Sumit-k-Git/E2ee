'use strict';

/**
 * otp.js — Email OTP for sign-up verification
 */

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
require('dotenv').config();

const OTP_EXPIRY_MS    = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function getOtpSecret() {
  return process.env.OTP_SECRET || process.env.JWT_SECRET || 'fallback-change-in-prod';
}

const store = new Map();

function hashCode(code) {
  return crypto.createHash('sha256').update(String(code).trim()).digest('hex');
}

function generateOTP() {
  return String(crypto.randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, '0');
}

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
    if (!process.env.BREVO_SMTP_KEY) {
      throw new Error('Brevo requires BREVO_SMTP_KEY in environment variables.');
    }
    const brevoPort = parseInt(process.env.BREVO_PORT || '587');
    const brevoSecure = process.env.BREVO_SECURE === 'true' || brevoPort === 465;
    return nodemailer.createTransport({
      host:   process.env.BREVO_HOST || 'smtp-relay.brevo.com',
      port:   brevoPort,
      secure: brevoSecure,
      auth: {
        user: process.env.EMAIL_USER || process.env.BREVO_LOGIN,
        pass: process.env.BREVO_SMTP_KEY,
      },
      tls: {
        rejectUnauthorized: false
      }
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

async function sendOTP(email) {
  const key = email.toLowerCase().trim();
  const now = Date.now();
  const provider = (process.env.EMAIL_PROVIDER || 'dev').toLowerCase();

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

  if (provider === 'dev') {
    console.log('\n' + '═'.repeat(48));
    console.log('  vault.msg OTP  [DEV MODE]');
    console.log(`  Email : ${key}`);
    console.log(`  Code  : ${code}`);
    console.log('═'.repeat(48) + '\n');
    return { sent: true, isTest: true, code };
  }

  let nodemailer;
  try {
    nodemailer = require('nodemailer');
  } catch {
    throw new Error('nodemailer package missing.');
  }

  let transport;
  try {
    transport = buildTransport(nodemailer);
  } catch (e) {
    console.error('\n[otp] EMAIL CONFIG ERROR:', e.message);
    return { sent: true, isTest: true, code };
  }

  // Auto-resolve validated from address matching Brevo authenticated user
  let fromAddress;
  const loginUser = process.env.EMAIL_USER || process.env.BREVO_LOGIN || '';
  if (process.env.EMAIL_FROM) {
    if (process.env.EMAIL_FROM.includes('<')) {
      fromAddress = process.env.EMAIL_FROM;
    } else {
      fromAddress = `"vault.msg" <${process.env.EMAIL_FROM}>`;
    }
  } else if (loginUser) {
    fromAddress = `"vault.msg" <${loginUser}>`;
  } else {
    fromAddress = '"vault.msg" <noreply@vault.msg>';
  }

  try {
    await transport.sendMail({
      from:    fromAddress,
      to:      key,
      subject: `${code} — Your vault.msg verification code`,
      html: `<!DOCTYPE html>
<html>
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
      text: `Your vault.msg sign-up code: ${code}\n\nExpires in 10 minutes.`,
    });
    console.log(`[otp] Email sent to ${key} via ${provider}`);
    return { sent: true, isTest: false };
  } catch (e) {
    console.error(`[otp] Failed to send email to ${key}:`, e.message);
    throw new Error('Failed to send verification email. Please check configuration.');
  }
}

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