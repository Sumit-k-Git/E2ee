/**
 * crypto.js — All E2EE operations for vault.msg
 * X25519 key agreement + XSalsa20-Poly1305 encryption (NaCl box)
 * Forward secrecy: fresh ephemeral keypair per message
 */

// FIX: tweetnacl is a CommonJS module. When Vite bundles it as ESM,
// the default import might be the module wrapper, not nacl itself.
// This handles both cases safely.
import * as _naclImport from 'tweetnacl';
const nacl = _naclImport.default || _naclImport;

import * as _naclUtilImport from 'tweetnacl-util';
const naclUtil = _naclUtilImport.default || _naclUtilImport;

const { encodeBase64, encodeUTF8, decodeUTF8 } = naclUtil;

// ── Robust base64 decoder ─────────────────────────────────────────────────
// Handles standard base64 (+/), URL-safe base64 (-_), and missing padding.
// Uses native atob() which is universal in all modern browsers.
function robustDecodeBase64(str) {
  if (!str || typeof str !== 'string') {
    throw new Error(`base64 decode: expected string, got ${typeof str} (value: ${str})`);
  }
  const normalized = str.trim().replace(/-/g, '+').replace(/_/g, '/');
  const padded     = normalized + '=='.slice(0, (4 - normalized.length % 4) % 4);
  try {
    const binary = atob(padded);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch (e) {
    throw new Error(`base64 decode failed: "${str.slice(0, 30)}" — ${e.message}`);
  }
}

// ── IndexedDB key store ───────────────────────────────────────────────────
const DB_NAME    = 'vault_keys';
const STORE_NAME = 'keypairs';

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
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
  } catch { return null; }
}

export async function wipeIdentityKeypair() {
  await deleteKey('identity_public');
  await deleteKey('identity_secret');
}

// ── Fingerprint ───────────────────────────────────────────────────────────

export async function computeFingerprint(publicKeyBytes) {
  const bytes = publicKeyBytes instanceof Uint8Array
    ? publicKeyBytes : new Uint8Array(publicKeyBytes);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

export function formatFingerprint(hex) {
  return (hex || '').match(/.{1,4}/g)?.join(' ') || hex || '';
}

// ── Encrypt ───────────────────────────────────────────────────────────────

export function encryptMessage(plaintext, recipientPublicKey) {
  // Accept base64 string, Uint8Array, or ArrayBuffer
  let recipientKey;
  if (typeof recipientPublicKey === 'string') {
    recipientKey = robustDecodeBase64(recipientPublicKey);
  } else if (recipientPublicKey instanceof Uint8Array) {
    recipientKey = recipientPublicKey;
  } else if (recipientPublicKey instanceof ArrayBuffer) {
    recipientKey = new Uint8Array(recipientPublicKey);
  } else {
    throw new Error(`encryptMessage: invalid key type "${typeof recipientPublicKey}"`);
  }

  if (recipientKey.length !== 32) {
    throw new Error(`encryptMessage: key must be 32 bytes, got ${recipientKey.length}`);
  }

  const ephemeral  = nacl.box.keyPair();
  const nonce      = nacl.randomBytes(nacl.box.nonceLength);
  const msgBytes   = encodeUTF8(plaintext);

  const ciphertext = nacl.box(msgBytes, nonce, recipientKey, ephemeral.secretKey);
  if (!ciphertext) throw new Error('nacl.box encryption failed');

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
    if (secretKey.length !== 32) return null;

    const decrypted = nacl.box.open(
      robustDecodeBase64(ciphertext),
      robustDecodeBase64(nonce),
      robustDecodeBase64(ephemeralPub),
      secretKey
    );
    if (!decrypted) return null;
    return decodeUTF8(decrypted);
  } catch (e) {
    console.warn('[crypto] decryptMessage error:', e.message);
    return null;
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────

export function publicKeyToBase64(keypairOrBytes) {
  const bytes = keypairOrBytes?.publicKey ?? keypairOrBytes;
  return encodeBase64(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}

export function base64ToBytes(b64) {
  if (!b64) return new Uint8Array(0);
  return robustDecodeBase64(b64);
}
