/**
 * crypto.js — All cryptographic operations for vault.msg
 *
 * Primitives: X25519 key agreement + XSalsa20-Poly1305 encryption (NaCl box)
 * Forward secrecy: fresh ephemeral keypair generated per message
 * Key storage: IndexedDB (private key never leaves the browser)
 */

import nacl from 'tweetnacl';
import { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } from 'tweetnacl-util';

// ── IndexedDB key store ───────────────────────────────────────────────────
const DB_NAME    = 'vault_keys';
const STORE_NAME = 'keypairs';
const DB_VERSION = 1;

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      e.target.result.createObjectStore(STORE_NAME);
    };
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
    // FIX: explicitly return null (not undefined) when key not found
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

// FIX: returns null (not a truthy object with undefined fields) when no key stored
export async function loadIdentityKeypair() {
  const pub = await loadKey('identity_public');
  const sec = await loadKey('identity_secret');
  if (!pub || !sec) return null;
  // FIX: ensure they are proper Uint8Arrays (IndexedDB may return ArrayBuffer on some browsers)
  const publicKey  = pub instanceof Uint8Array ? pub : new Uint8Array(pub);
  const secretKey  = sec instanceof Uint8Array ? sec : new Uint8Array(sec);
  if (publicKey.length !== 32 || secretKey.length !== 32) return null;
  return { publicKey, secretKey };
}

export async function wipeIdentityKeypair() {
  await deleteKey('identity_public');
  await deleteKey('identity_secret');
}

// ── Key fingerprint ───────────────────────────────────────────────────────

export async function computeFingerprint(publicKeyBytes) {
  const bytes = publicKeyBytes instanceof Uint8Array
    ? publicKeyBytes
    : new Uint8Array(publicKeyBytes);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function formatFingerprint(hex) {
  return (hex || '').match(/.{1,4}/g)?.join(' ') || hex || '';
}

// ── Encrypt (with forward secrecy) ───────────────────────────────────────

export function encryptMessage(plaintext, recipientPublicKey) {
  // Ensure recipientPublicKey is a proper Uint8Array
  const recipientKey = recipientPublicKey instanceof Uint8Array
    ? recipientPublicKey
    : new Uint8Array(recipientPublicKey);

  const ephemeral  = nacl.box.keyPair();                      // fresh per message
  const nonce      = nacl.randomBytes(nacl.box.nonceLength);
  const ciphertext = nacl.box(encodeUTF8(plaintext), nonce, recipientKey, ephemeral.secretKey);

  if (!ciphertext) throw new Error('Encryption failed — check recipient key');

  return {
    ciphertext:   encodeBase64(ciphertext),
    nonce:        encodeBase64(nonce),
    ephemeral_pub: encodeBase64(ephemeral.publicKey),
    // ephemeral.secretKey is discarded here — forward secrecy
  };
}

// ── Decrypt ───────────────────────────────────────────────────────────────

export function decryptMessage(ciphertext, nonce, ephemeralPub, mySecretKey) {
  // Guard: all fields must be present and non-empty
  if (!ciphertext || !nonce || !ephemeralPub || !mySecretKey) return null;
  // Guard: skip soft-deleted messages
  if (ciphertext === 'deleted') return null;
  try {
    const secretKey = mySecretKey instanceof Uint8Array
      ? mySecretKey : new Uint8Array(mySecretKey);

    const decrypted = nacl.box.open(
      decodeBase64(ciphertext),
      decodeBase64(nonce),
      decodeBase64(ephemeralPub),
      secretKey
    );
    if (!decrypted) return null;
    return decodeUTF8(decrypted);
  } catch {
    return null;
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────

// Takes a keypair { publicKey: Uint8Array } OR a raw Uint8Array
export function publicKeyToBase64(keypairOrBytes) {
  const bytes = keypairOrBytes?.publicKey ?? keypairOrBytes;
  return encodeBase64(bytes);
}

export function base64ToBytes(b64) {
  if (!b64) return new Uint8Array(0);
  return decodeBase64(b64);
}
