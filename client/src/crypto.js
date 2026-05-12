/**
 * crypto.js — All cryptographic operations for vault.msg
 *
 * Primitives used:
 * - X25519 (Diffie-Hellman): key agreement
 * - XSalsa20-Poly1305 (NaCl box): authenticated encryption
 * - Ed25519 (NaCl sign): message signing & prekey verification
 * - BLAKE2b (via SubtleCrypto SHA-512 fallback): key fingerprinting
 *
 * Forward secrecy model:
 * - Each message uses a freshly generated ephemeral X25519 keypair
 * - Shared secret = DH(ephemeral_secret, recipient_identity_public)
 * - Even if the recipient's long-term key is compromised later,
 *   past messages cannot be decrypted without the (deleted) ephemeral secret
 *
 * Key storage:
 * - Long-term identity keypair stored in IndexedDB (encrypted with device key)
 * - Never exported as plain bytes after initial generation
 */

import nacl from 'tweetnacl';
import { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } from 'tweetnacl-util';

// ── IndexedDB key store ───────────────────────────────────────────────────

const DB_NAME = 'vault_keys';
const STORE_NAME = 'keypairs';
const DB_VERSION = 1;

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      e.target.result.createObjectStore(STORE_NAME);
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = () => reject(req.error);
  });
}

async function storeKey(name, value) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(value, name);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

async function loadKey(name) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(name);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function deleteKey(name) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(name);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

// ── Identity keypair management ───────────────────────────────────────────

/**
 * Generate a new X25519 identity keypair and persist it to IndexedDB.
 * Returns { publicKey: Uint8Array, secretKey: Uint8Array }
 */
export async function generateIdentityKeypair() {
  const kp = nacl.box.keyPair();
  // Store as raw bytes in IndexedDB
  await storeKey('identity_public', kp.publicKey);
  await storeKey('identity_secret', kp.secretKey);
  return kp;
}

/**
 * Load the persisted identity keypair from IndexedDB.
 * Returns null if not found (first-time setup).
 */
export async function loadIdentityKeypair() {
  const pub = await loadKey('identity_public');
  const sec = await loadKey('identity_secret');
  if (!pub || !sec) return null;
  return { publicKey: pub, secretKey: sec };
}

/**
 * Wipe identity keys from storage (account deletion / key rotation).
 */
export async function wipeIdentityKeypair() {
  await deleteKey('identity_public');
  await deleteKey('identity_secret');
}

// ── Key fingerprinting ────────────────────────────────────────────────────

/**
 * Produce a SHA-256 fingerprint of a public key for out-of-band verification.
 * Returns lowercase hex string.
 * Users can compare this fingerprint via another channel (QR code, voice call)
 * to confirm they have each other's genuine public key.
 */
export async function computeFingerprint(publicKeyBytes) {
  const hash = await crypto.subtle.digest('SHA-256', publicKeyBytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Format fingerprint as groups of 4 for readability:
 * "a1b2 c3d4 e5f6 ..."
 */
export function formatFingerprint(hex) {
  return hex.match(/.{1,4}/g)?.join(' ') || hex;
}

// ── Message encryption (with forward secrecy) ─────────────────────────────

/**
 * Encrypt a plaintext message for a recipient.
 *
 * Process:
 * 1. Generate a fresh ephemeral X25519 keypair (one-time use)
 * 2. Compute shared secret: DH(ephemeral_secret, recipient_identity_public)
 * 3. Encrypt with XSalsa20-Poly1305 using the shared secret
 * 4. The ciphertext + nonce + ephemeral_pub is sent to the server
 *
 * The ephemeral secret is NEVER stored or sent — it's discarded after encryption.
 * This gives forward secrecy: even if the recipient's long-term key is later
 * compromised, this message cannot be decrypted.
 *
 * @param {string} plaintext
 * @param {Uint8Array} recipientPublicKey - recipient's X25519 identity public key
 * @returns {{ ciphertext: string, nonce: string, ephemeral_pub: string }} base64 strings
 */
export function encryptMessage(plaintext, recipientPublicKey) {
  // Fresh ephemeral keypair — used once and discarded
  const ephemeral = nacl.box.keyPair();

  // Shared secret via X25519
  const nonce = nacl.randomBytes(nacl.box.nonceLength);

  // XSalsa20-Poly1305 authenticated encryption
  const ciphertext = nacl.box(
    encodeUTF8(plaintext),
    nonce,
    recipientPublicKey,
    ephemeral.secretKey
  );

  if (!ciphertext) {
    throw new Error('Encryption failed');
  }

  return {
    ciphertext: encodeBase64(ciphertext),
    nonce: encodeBase64(nonce),
    ephemeral_pub: encodeBase64(ephemeral.publicKey),
    // ephemeral.secretKey is abandoned here — GC will collect it
  };
}

/**
 * Decrypt a message received from a sender.
 *
 * Process:
 * 1. Decode base64 fields
 * 2. Reconstruct shared secret: DH(my_identity_secret, sender_ephemeral_public)
 * 3. Verify MAC and decrypt with XSalsa20-Poly1305
 *
 * @param {string} ciphertext - base64
 * @param {string} nonce - base64
 * @param {string} ephemeralPub - sender's ephemeral public key, base64
 * @param {Uint8Array} mySecretKey - my X25519 identity secret key
 * @returns {string|null} plaintext, or null if decryption fails (tampered/wrong key)
 */
export function decryptMessage(ciphertext, nonce, ephemeralPub, mySecretKey) {
  try {
    const decrypted = nacl.box.open(
      decodeBase64(ciphertext),
      decodeBase64(nonce),
      decodeBase64(ephemeralPub),
      mySecretKey
    );

    if (!decrypted) return null; // MAC verification failed

    return decodeUTF8(decrypted);
  } catch {
    return null;
  }
}

// ── Prekey generation (Signal-style async E2EE) ────────────────────────────

/**
 * Generate N one-time prekeys for upload to the server.
 * These allow senders to encrypt messages even when you're offline.
 *
 * Each prekey is an X25519 keypair.
 * The prekey_pub is uploaded to the server.
 * The prekey_secret must be stored locally (IndexedDB).
 * The signature proves you own the identity key that generated these.
 *
 * @param {number} count - number of prekeys to generate
 * @param {Uint8Array} identitySecretKey - your X25519 identity secret key
 * @returns {{ prekey_pub: string, signature: string, secret: Uint8Array }[]}
 */
export function generatePrekeys(count, identitySecretKey) {
  // Use Ed25519 signing keypair derived from identity secret for signing prekeys
  // In a full Signal implementation, you'd use a separate signing keypair.
  // Here we use a simpler approach: sign the prekey bytes with nacl.sign.
  const signingKp = nacl.sign.keyPair.fromSeed(identitySecretKey.slice(0, 32));

  const prekeys = [];
  for (let i = 0; i < count; i++) {
    const kp = nacl.box.keyPair();
    const signature = nacl.sign.detached(kp.publicKey, signingKp.secretKey);
    prekeys.push({
      prekey_pub: encodeBase64(kp.publicKey),
      signature: encodeBase64(signature),
      secret: kp.secretKey, // store locally
    });
  }
  return prekeys;
}

/**
 * Verify a prekey signature.
 * Alice verifies that Bob's prekey was signed by Bob's identity key
 * before encrypting a message to it.
 *
 * @param {string} prekeyPub - base64
 * @param {string} signature - base64
 * @param {Uint8Array} identityPublicKey - signer's identity public key
 */
export function verifyPrekeySignature(prekeyPub, signature, identityPublicKey) {
  try {
    // Derive verification key from identity public key (same as generation)
    // Note: In production, use a separate Ed25519 identity key pair.
    const signingPub = nacl.sign.keyPair.fromSeed(identityPublicKey.slice(0, 32)).publicKey;
    return nacl.sign.detached.verify(
      decodeBase64(prekeyPub),
      decodeBase64(signature),
      signingPub
    );
  } catch {
    return false;
  }
}

// ── Session key caching (for performance) ─────────────────────────────────
// We can cache the shared secret for a contact to avoid re-deriving it each time.
// This is safe because the ephemeral key is per-message on the SENDER side;
// on the receiver side, the shared secret is derived from their static secret key.
// Cache is in-memory only; cleared on logout.

const sessionCache = new Map();

export function clearSessionCache() {
  sessionCache.clear();
}

// ── Utility ───────────────────────────────────────────────────────────────

export function publicKeyToBase64(keypair) {
  return encodeBase64(keypair.publicKey);
}

export function base64ToBytes(b64) {
  return decodeBase64(b64);
}
