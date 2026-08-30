const encoder = new TextEncoder();
const decoder = new TextDecoder();

function arrayBuffer(bytes: Uint8Array) {
  return Uint8Array.from(bytes).buffer;
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function base64Url(bytes: Uint8Array) {
  return bytesToBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function fromBase64Url(value: string) {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4);
  return base64ToBytes(padded);
}

export function randomBytes(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function randomToken(length = 32) {
  return base64Url(randomBytes(length));
}

export async function sha256(value: string) {
  return base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
}

export async function safeEqual(left: string, right: string) {
  const [leftHash, rightHash] = await Promise.all([sha256(left), sha256(right)]);
  let difference = 0;
  for (let index = 0; index < leftHash.length; index += 1) difference |= leftHash.charCodeAt(index) ^ rightHash.charCodeAt(index);
  return difference === 0;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: arrayBuffer(salt), iterations }, key, 256);
  return new Uint8Array(bits);
}

export async function derivePasswordKey(password: string, saltValue: string) {
  return pbkdf2(password, fromBase64Url(saltValue), 600_000);
}

export async function hashPassword(password: string) {
  const salt = randomBytes(16);
  const digest = await pbkdf2(password, salt, 600_000);
  return `pbkdf2-sha256$600000$${base64Url(salt)}$${base64Url(digest)}`;
}

export async function verifyPassword(password: string, encoded: string) {
  const [algorithm, iterationsValue, salt, expected] = encoded.split('$');
  if (algorithm !== 'pbkdf2-sha256' || !salt || !expected) return false;
  const iterations = Number(iterationsValue);
  if (!Number.isSafeInteger(iterations) || iterations < 100_000 || iterations > 1_000_000) return false;
  const digest = await pbkdf2(password, fromBase64Url(salt), iterations);
  return safeEqual(base64Url(digest), expected);
}

async function aesKey(keyBytes: Uint8Array) {
  return crypto.subtle.importKey('raw', arrayBuffer(keyBytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function encryptBytes(plaintext: Uint8Array, keyBytes: Uint8Array, additionalData: string) {
  const nonce = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: arrayBuffer(nonce), additionalData: encoder.encode(additionalData), tagLength: 128 },
    await aesKey(keyBytes),
    arrayBuffer(plaintext),
  );
  return { nonce: base64Url(nonce), ciphertext: base64Url(new Uint8Array(ciphertext)) };
}

export async function decryptBytes(nonce: string, ciphertext: string, keyBytes: Uint8Array, additionalData: string) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: arrayBuffer(fromBase64Url(nonce)), additionalData: encoder.encode(additionalData), tagLength: 128 },
    await aesKey(keyBytes),
    arrayBuffer(fromBase64Url(ciphertext)),
  );
  return new Uint8Array(plaintext);
}

export async function encryptText(value: string, keyBytes: Uint8Array, additionalData: string) {
  return encryptBytes(encoder.encode(value), keyBytes, additionalData);
}

export async function decryptText(nonce: string, ciphertext: string, keyBytes: Uint8Array, additionalData: string) {
  return decoder.decode(await decryptBytes(nonce, ciphertext, keyBytes, additionalData));
}

export async function encryptJson(value: unknown, keyBytes: Uint8Array, additionalData: string) {
  return encryptText(JSON.stringify(value), keyBytes, additionalData);
}

export async function decryptJson<T>(nonce: string, ciphertext: string, keyBytes: Uint8Array, additionalData: string) {
  return JSON.parse(await decryptText(nonce, ciphertext, keyBytes, additionalData)) as T;
}

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += base32Alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += base32Alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(value: string) {
  let bits = 0;
  let buffer = 0;
  const output: number[] = [];
  for (const character of value.toUpperCase().replace(/[^A-Z2-7]/gu, '')) {
    const index = base32Alphabet.indexOf(character);
    if (index < 0) continue;
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(output);
}

async function totpCode(secret: string, epoch: number) {
  const counter = Math.floor(epoch / 30_000);
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey('raw', arrayBuffer(base32Decode(secret)), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, arrayBuffer(counterBytes)));
  const offset = signature[signature.length - 1] & 15;
  const code = (((signature[offset] & 127) << 24) | (signature[offset + 1] << 16) | (signature[offset + 2] << 8) | signature[offset + 3]) % 1_000_000;
  return code.toString().padStart(6, '0');
}

export async function verifyTotp(secret: string, token: string) {
  if (!/^\d{6}$/u.test(token)) return false;
  const now = Date.now();
  for (const drift of [-30_000, 0, 30_000]) {
    if (await safeEqual(await totpCode(secret, now + drift), token)) return true;
  }
  return false;
}

export function makeTotpSecret() {
  return base32Encode(randomBytes(20));
}

export function makeRecoveryCodes() {
  return Array.from({ length: 10 }, () => {
    const value = base32Encode(randomBytes(5)).slice(0, 8);
    return `${value.slice(0, 4)}-${value.slice(4)}`;
  });
}

export function normalizeRecoveryCode(value: string) {
  return value.toUpperCase().replace(/[^A-Z2-7]/gu, '');
}
