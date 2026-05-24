/**
 * crypto.js — All cryptographic operations for vault.msg
 *
 * Primitives: X25519 key agreement + XSalsa20-Poly1305 (NaCl box)
 * Forward secrecy: fresh ephemeral keypair per message
 * Key storage: IndexedDB (private key never leaves the browser)
 */

import nacl from 'tweetnacl';
import { encodeBase64, encodeUTF8, decodeUTF8 } from 'tweetnacl-util';

// ── Robust base64 decoder ─────────────────────────────────────────────────
// tweetnacl-util's decodeBase64 rejects some valid base64 strings.
// This function handles standard base64, URL-safe base64, and padding variants.
function robustDecodeBase64(str) {
  if (!str || typeof str !== 'string') {
    throw new Error(`base64 decode: expected string, got ${typeof str}`);
  }
  // Normalize: URL-safe → standard, strip whitespace
  const normalized = str.trim()
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  // Re-add missing padding
  const padded = normalized + '=='.slice(0, (4 - normalized.length % 4) % 4);

  try {
    const binary = atob(padded);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch (e) {
    throw new Error(`base64 decode failed for "${str.slice(0, 20)}…": ${e.message}`);
  }
}

// ── IndexedDB key store ───────────────────────────────────────────────────
const DB_NAME    = 'vault_keys';
const STORE_NAME = 'keypairs';
const DB_VERSION = 1;

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => e.target.result.createObjectStore(STORE_NAME);
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = ()  => reject(req.error);
  });
}

function storeKey(name, value) {
  return openKeyDb().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(value, name);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  }));
}

function loadKey(name) {
  return openKeyDb().then(db => new Promise((resolve, reject) => {
    const tx  = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(name);
    req.onsuccess = () => resolve(req.result !== undefined ? req.result : null);
    req.onerror   = () => reject(req.error);
  }));
}

function deleteKey(name) {
  return openKeyDb().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(name);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  }));
}

// ── Ensure value is a 32-byte Uint8Array ─────────────────────────────────
function toUint8Array32(value, label) {
  let arr;
  if (value instanceof Uint8Array) {
    arr = value;
  } else if (value instanceof ArrayBuffer) {
    arr = new Uint8Array(value);
  } else if (typeof value === 'string') {
    // It's a base64 string — decode it
    arr = robustDecodeBase64(value);
  } else {
    throw new Error(`${label}: expected Uint8Array, ArrayBuffer, or base64 string`);
  }
  if (arr.length !== 32) {
    throw new Error(`${label}: expected 32 bytes, got ${arr.length}. Value: "${String(value).slice(0, 30)}"`);
  }
  return arr;
}

// ── Identity keypair ──────────────────────────────────────────────────────

export async function generateIdentityKeypair() {
  const kp = nacl.box.keyPair();
  await storeKey('identity_public', kp.publicKey);
  await storeKey('identity_secret', kp.secretKey);
  return kp;
}

export async function loadIdentityKeypair() {
  const pub = await loadKey('identity_public');
  const sec = await loadKey('identity_secret');
  if (!pub || !sec) return null;
  try {
    const publicKey = pub instanceof Uint8Array ? pub : new Uint8Array(pub);
    const secretKey = sec instanceof Uint8Array ? sec : new Uint8Array(sec);
    if (publicKey.length !== 32 || secretKey.length !== 32) return null;
    return { publicKey, secretKey };
  } catch {
    return null;
  }
}

export async function wipeIdentityKeypair() {
  await deleteKey('identity_public');
  await deleteKey('identity_secret');
}

// ── Key fingerprint ───────────────────────────────────────────────────────

export async function computeFingerprint(publicKeyBytes) {
  const bytes = publicKeyBytes instanceof Uint8Array
    ? publicKeyBytes : new Uint8Array(publicKeyBytes);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function formatFingerprint(hex) {
  return (hex || '').match(/.{1,4}/g)?.join(' ') || hex || '';
}

// ── Encrypt (with forward secrecy) ────────────────────────────────────────

export function encryptMessage(plaintext, recipientPublicKey) {
  // FIX: handle string (base64), Uint8Array, or ArrayBuffer
  let recipientKey;
  if (typeof recipientPublicKey === 'string') {
    recipientKey = robustDecodeBase64(recipientPublicKey);
  } else if (recipientPublicKey instanceof Uint8Array) {
    recipientKey = recipientPublicKey;
  } else if (recipientPublicKey instanceof ArrayBuffer) {
    recipientKey = new Uint8Array(recipientPublicKey);
  } else {
    throw new Error('encryptMessage: recipientPublicKey must be a base64 string or Uint8Array');
  }

  if (recipientKey.length !== 32) {
    throw new Error(`encryptMessage: recipient key must be 32 bytes, got ${recipientKey.length}. Did the key decode correctly?`);
  }

  const ephemeral  = nacl.box.keyPair();
  const nonce      = nacl.randomBytes(nacl.box.nonceLength);
  const ciphertext = nacl.box(encodeUTF8(plaintext), nonce, recipientKey, ephemeral.secretKey);

  if (!ciphertext) throw new Error('Encryption failed');

  return {
    ciphertext:    encodeBase64(ciphertext),
    nonce:         encodeBase64(nonce),
    ephemeral_pub: encodeBase64(ephemeral.publicKey),
  };
}

// ── Decrypt ───────────────────────────────────────────────────────────────

export function decryptMessage(ciphertext, nonce, ephemeralPub, mySecretKey) {
  if (!ciphertext || !nonce || !ephemeralPub || !mySecretKey) return null;
  if (ciphertext === 'deleted') return null;
  try {
    const secretKey = mySecretKey instanceof Uint8Array
      ? mySecretKey : new Uint8Array(mySecretKey);

    const decrypted = nacl.box.open(
      robustDecodeBase64(ciphertext),
      robustDecodeBase64(nonce),
      robustDecodeBase64(ephemeralPub),
      secretKey
    );
    if (!decrypted) return null;
    return decodeUTF8(decrypted);
  } catch (e) {
    console.warn('[crypto] decryptMessage failed:', e.message);
    return null;
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────

export function publicKeyToBase64(keypairOrBytes) {
  const bytes = keypairOrBytes?.publicKey ?? keypairOrBytes;
  return encodeBase64(bytes);
}

// FIX: export robustDecodeBase64 as base64ToBytes so App.jsx uses the safe version
export function base64ToBytes(b64) {
  if (!b64) return new Uint8Array(0);
  return robustDecodeBase64(b64);
}
