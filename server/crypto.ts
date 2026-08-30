import argon2 from 'argon2';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import sodium from 'libsodium-wrappers-sumo';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const argonOptions = {
  type: argon2.argon2id,
  memoryCost: 65_536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
} as const;

export async function cryptoReady() {
  await sodium.ready;
}

export async function hashPassword(password: string) {
  return argon2.hash(password, argonOptions);
}

export async function verifyPassword(hash: string, password: string) {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export function randomBase64Url(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function sha256(value: string | Uint8Array) {
  return createHash('sha256').update(value).digest('hex');
}

export async function deriveKey(password: string, saltBase64: string) {
  return argon2.hash(password, {
    ...argonOptions,
    salt: Buffer.from(saltBase64, 'base64'),
    raw: true,
  });
}

export function newSalt() {
  return randomBytes(16).toString('base64');
}

export function newVaultKey() {
  return new Uint8Array(randomBytes(32));
}

export function encryptBytes(plaintext: Uint8Array, key: Uint8Array, aad: string) {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    encoder.encode(aad),
    null,
    nonce,
    key,
  );
  return {
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL),
  };
}

export function decryptBytes(
  nonceBase64: string,
  ciphertextBase64: string,
  key: Uint8Array,
  aad: string,
) {
  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    sodium.from_base64(ciphertextBase64, sodium.base64_variants.ORIGINAL),
    encoder.encode(aad),
    sodium.from_base64(nonceBase64, sodium.base64_variants.ORIGINAL),
    key,
  );
  return new Uint8Array(plaintext);
}

export function encryptText(plaintext: string, key: Uint8Array, aad: string) {
  return encryptBytes(encoder.encode(plaintext), key, aad);
}

export function decryptText(nonce: string, ciphertext: string, key: Uint8Array, aad: string) {
  return decoder.decode(decryptBytes(nonce, ciphertext, key, aad));
}

export function encryptJson(value: unknown, key: Uint8Array, aad: string) {
  return encryptText(JSON.stringify(value), key, aad);
}

export function decryptJson<T>(nonce: string, ciphertext: string, key: Uint8Array, aad: string): T {
  return JSON.parse(decryptText(nonce, ciphertext, key, aad)) as T;
}

export function secureEqual(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function makeRecoveryCodes(count = 10) {
  return Array.from({ length: count }, () => {
    const raw = randomBytes(9).toString('base64url').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
  });
}

export function normalizeRecoveryCode(code: string) {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
}
