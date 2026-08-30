import type { NextFunction, Request, Response } from 'express';
import QRCode from 'qrcode';
import { generateSecret, generateURI, verify as verifyTotpToken } from 'otplib';

import { audit } from './audit.js';
import { config } from './config.js';
import {
  decryptText,
  deriveKey,
  encryptText,
  hashPassword,
  makeRecoveryCodes,
  newSalt,
  newVaultKey,
  normalizeRecoveryCode,
  randomBase64Url,
  sha256,
  verifyPassword,
} from './crypto.js';
import { countUsers, db, newId, nowIso } from './db.js';
import type { AuthenticatedRequest, SessionRow, UserRow } from './types.js';

type LoginChallenge = {
  id: string;
  kind: 'login' | 'enrollment';
  userId: string;
  vaultKey: Uint8Array;
  expiresAt: number;
};

const challenges = new Map<string, LoginChallenge>();
const unlockedSessionKeys = new Map<string, Uint8Array>();
const dummyHashPromise = hashPassword(`not-a-user-${randomBase64Url(16)}`);

const userSelect = `
  SELECT id, name, email, role, password_hash, kdf_salt, wrapped_key_nonce,
    wrapped_key_ciphertext, mfa_secret_nonce, mfa_secret_ciphertext,
    mfa_enabled, failed_login_count, locked_until, last_login_at, created_at, updated_at
  FROM users
`;

function pruneChallenges() {
  const now = Date.now();
  for (const [id, challenge] of challenges) {
    if (challenge.expiresAt <= now) challenges.delete(id);
  }
}

function getUserByEmail(email: string) {
  return db.prepare(`${userSelect} WHERE email = ? COLLATE NOCASE`).get(email) as UserRow | undefined;
}

export function getUserById(id: string) {
  return db.prepare(`${userSelect} WHERE id = ?`).get(id) as UserRow | undefined;
}

function wrapVaultKey(userId: string, vaultKey: Uint8Array, derivedKey: Uint8Array) {
  return encryptText(Buffer.from(vaultKey).toString('base64'), derivedKey, `user:${userId}:vault-key:v1`);
}

async function unwrapVaultKey(user: UserRow, password: string) {
  const keyEncryptionKey = await deriveKey(password, user.kdf_salt);
  const encoded = decryptText(
    user.wrapped_key_nonce,
    user.wrapped_key_ciphertext,
    keyEncryptionKey,
    `user:${user.id}:vault-key:v1`,
  );
  return new Uint8Array(Buffer.from(encoded, 'base64'));
}

function decryptTotpSecret(user: UserRow, vaultKey: Uint8Array) {
  return decryptText(
    user.mfa_secret_nonce,
    user.mfa_secret_ciphertext,
    vaultKey,
    `user:${user.id}:totp:v1`,
  );
}

async function totpValid(secret: string, token: string) {
  if (!/^\d{6}$/.test(token)) return false;
  const result = await verifyTotpToken({ secret, token, epochTolerance: 30 });
  return result.valid;
}

function requestIpHash(request: Request) {
  return sha256(request.ip || request.socket.remoteAddress || 'local');
}

function cookieValue(request: Request, name: string) {
  const cookies = request.headers.cookie?.split(';') ?? [];
  for (const cookie of cookies) {
    const [key, ...rest] = cookie.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

function setSessionCookie(response: Response, token: string) {
  const secure = process.env.INNASC_HTTPS === '1';
  const parts = [
    `innasc_session=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${config.sessionHours * 60 * 60}`,
  ];
  if (secure) parts.push('Secure');
  response.append('Set-Cookie', parts.join('; '));
}

export function clearSessionCookie(response: Response) {
  response.append('Set-Cookie', 'innasc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
}

function issueChallenge(user: UserRow, vaultKey: Uint8Array) {
  pruneChallenges();
  const challenge: LoginChallenge = {
    id: randomBase64Url(24),
    kind: user.mfa_enabled ? 'login' : 'enrollment',
    userId: user.id,
    vaultKey,
    expiresAt: Date.now() + config.challengeMinutes * 60_000,
  };
  challenges.set(challenge.id, challenge);
  return challenge;
}

async function challengePayload(challenge: LoginChallenge, user: UserRow) {
  const passkeyCount = (db.prepare('SELECT COUNT(*) AS count FROM passkeys WHERE user_id = ?').get(user.id) as { count: number }).count;
  if (challenge.kind === 'login') {
    return { challengeId: challenge.id, kind: challenge.kind, passkeyAvailable: passkeyCount > 0 };
  }
  const secret = decryptTotpSecret(user, challenge.vaultKey);
  const uri = generateURI({ issuer: config.rpName, label: user.email, secret });
  return {
    challengeId: challenge.id,
    kind: challenge.kind,
    qrCodeDataUrl: await QRCode.toDataURL(uri, { margin: 1, width: 240 }),
    manualKey: secret,
    passkeyAvailable: false,
  };
}

function createRecoveryCodes(userId: string) {
  const codes = makeRecoveryCodes();
  const createdAt = nowIso();
  const save = db.transaction(() => {
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
    const insert = db.prepare('INSERT INTO recovery_codes(id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)');
    for (const code of codes) {
      insert.run(newId(), userId, sha256(normalizeRecoveryCode(code)), createdAt);
    }
  });
  save();
  return codes;
}

function consumeRecoveryCode(userId: string, code: string) {
  const codeHash = sha256(normalizeRecoveryCode(code));
  const row = db.prepare('SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL').get(userId, codeHash) as { id: string } | undefined;
  if (!row) return false;
  db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL').run(nowIso(), row.id);
  return true;
}

function createSession(request: Request, response: Response, user: UserRow, vaultKey: Uint8Array) {
  const rawToken = randomBase64Url(32);
  const idHash = sha256(rawToken);
  const csrfToken = randomBase64Url(24);
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + config.sessionHours * 60 * 60_000).toISOString();
  db.prepare(`
    INSERT INTO sessions(id_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip_hash, user_agent)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    idHash,
    user.id,
    csrfToken,
    createdAt,
    createdAt,
    expiresAt,
    requestIpHash(request),
    request.get('user-agent')?.slice(0, 500) ?? null,
  );
  unlockedSessionKeys.set(idHash, vaultKey);
  setSessionCookie(response, rawToken);
  return { csrfToken, expiresAt };
}

export function publicUser(user: UserRow) {
  const recoveryRemaining = (db.prepare('SELECT COUNT(*) AS count FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').get(user.id) as { count: number }).count;
  const passkeyCount = (db.prepare('SELECT COUNT(*) AS count FROM passkeys WHERE user_id = ?').get(user.id) as { count: number }).count;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    mfaEnabled: Boolean(user.mfa_enabled),
    recoveryCodesRemaining: recoveryRemaining,
    passkeyCount,
    lastLoginAt: user.last_login_at,
  };
}

export async function createManagedUser(
  request: AuthenticatedRequest,
  input: { name: string; email: string; password: string; role: UserRow['role'] },
) {
  if (getUserByEmail(input.email)) throw Object.assign(new Error('A user with that email already exists.'), { status: 409 });
  const userId = newId();
  const kdfSalt = newSalt();
  const derivedKey = await deriveKey(input.password, kdfSalt);
  const wrappedKey = wrapVaultKey(userId, request.auth.vaultKey, derivedKey);
  const passwordHash = await hashPassword(input.password);
  const totpSecret = generateSecret();
  const encryptedTotp = encryptText(totpSecret, request.auth.vaultKey, `user:${userId}:totp:v1`);
  const createdAt = nowIso();
  db.prepare(`
    INSERT INTO users (
      id, name, email, role, password_hash, kdf_salt, wrapped_key_nonce,
      wrapped_key_ciphertext, mfa_secret_nonce, mfa_secret_ciphertext,
      mfa_enabled, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `).run(
    userId,
    input.name,
    input.email.toLowerCase(),
    input.role,
    passwordHash,
    kdfSalt,
    wrappedKey.nonce,
    wrappedKey.ciphertext,
    encryptedTotp.nonce,
    encryptedTotp.ciphertext,
    createdAt,
    createdAt,
  );
  audit({ request, actorUserId: request.auth.user.id, eventType: 'user.create', targetType: 'user', targetId: userId, detail: { role: input.role } });
  return publicUser(getUserById(userId)!);
}

export function setupStatus() {
  return { setupRequired: countUsers() === 0 };
}

export async function beginInitialSetup(request: Request, name: string, email: string, password: string) {
  if (countUsers() !== 0) throw Object.assign(new Error('Initial setup has already been completed.'), { status: 409 });

  const userId = newId();
  const vaultKey = newVaultKey();
  const kdfSalt = newSalt();
  const derivedKey = await deriveKey(password, kdfSalt);
  const wrappedKey = wrapVaultKey(userId, vaultKey, derivedKey);
  const passwordHash = await hashPassword(password);
  const totpSecret = generateSecret();
  const encryptedTotp = encryptText(totpSecret, vaultKey, `user:${userId}:totp:v1`);
  const createdAt = nowIso();

  db.prepare(`
    INSERT INTO users (
      id, name, email, role, password_hash, kdf_salt, wrapped_key_nonce,
      wrapped_key_ciphertext, mfa_secret_nonce, mfa_secret_ciphertext,
      mfa_enabled, created_at, updated_at
    ) VALUES (?, ?, ?, 'workspace_owner', ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `).run(
    userId,
    name,
    email.toLowerCase(),
    passwordHash,
    kdfSalt,
    wrappedKey.nonce,
    wrappedKey.ciphertext,
    encryptedTotp.nonce,
    encryptedTotp.ciphertext,
    createdAt,
    createdAt,
  );

  const user = getUserById(userId)!;
  const challenge = issueChallenge(user, vaultKey);
  audit({ request, actorUserId: userId, eventType: 'account.initial_setup_started', targetType: 'user', targetId: userId });
  return challengePayload(challenge, user);
}

function recordLoginFailure(request: Request, user?: UserRow) {
  if (user) {
    const failures = user.failed_login_count + 1;
    const lockedUntil = failures >= 5 ? new Date(Date.now() + Math.min(30, 2 ** (failures - 5) * 5) * 60_000).toISOString() : null;
    db.prepare('UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?').run(failures, lockedUntil, nowIso(), user.id);
  }
  audit({
    request,
    actorUserId: user?.id ?? null,
    eventType: 'auth.sign_in',
    targetType: 'user',
    targetId: user?.id ?? null,
    outcome: 'failure',
    detail: { reason: 'invalid_credentials' },
  });
}

export async function beginLogin(request: Request, email: string, password: string) {
  const user = getUserByEmail(email);
  const hash = user?.password_hash ?? await dummyHashPromise;
  const passwordOk = await verifyPassword(hash, password);

  if (!user || !passwordOk) {
    recordLoginFailure(request, user);
    throw Object.assign(new Error('Email, password, or MFA code was not accepted.'), { status: 401 });
  }

  if (user.locked_until && Date.parse(user.locked_until) > Date.now()) {
    audit({ request, actorUserId: user.id, eventType: 'auth.sign_in', targetType: 'user', targetId: user.id, outcome: 'blocked', detail: { reason: 'rate_limited' } });
    throw Object.assign(new Error('This account is temporarily locked. Try again later.'), { status: 429 });
  }

  let vaultKey: Uint8Array;
  try {
    vaultKey = await unwrapVaultKey(user, password);
  } catch {
    recordLoginFailure(request, user);
    throw Object.assign(new Error('Email, password, or MFA code was not accepted.'), { status: 401 });
  }

  db.prepare('UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?').run(nowIso(), user.id);
  const freshUser = getUserById(user.id)!;
  const challenge = issueChallenge(freshUser, vaultKey);
  audit({ request, actorUserId: user.id, eventType: 'auth.password_verified', targetType: 'user', targetId: user.id });
  return challengePayload(challenge, freshUser);
}

export function getLoginChallenge(id: string) {
  pruneChallenges();
  return challenges.get(id);
}

export async function completeLoginChallenge(
  request: Request,
  response: Response,
  challengeId: string,
  code: string,
) {
  pruneChallenges();
  const challenge = challenges.get(challengeId);
  if (!challenge) throw Object.assign(new Error('The MFA challenge expired. Please sign in again.'), { status: 401 });
  const user = getUserById(challenge.userId);
  if (!user) throw Object.assign(new Error('Account not found.'), { status: 404 });

  const secret = decryptTotpSecret(user, challenge.vaultKey);
  let valid = await totpValid(secret, code);
  let method = 'totp';
  if (!valid && challenge.kind === 'login' && code.length >= 8) {
    valid = consumeRecoveryCode(user.id, code);
    method = 'recovery_code';
  }

  if (!valid) {
    audit({ request, actorUserId: user.id, eventType: 'auth.mfa_challenge', targetType: 'user', targetId: user.id, outcome: 'failure', detail: { method } });
    throw Object.assign(new Error('Email, password, or MFA code was not accepted.'), { status: 401 });
  }

  let recoveryCodes: string[] | undefined;
  if (challenge.kind === 'enrollment') {
    db.prepare('UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?').run(nowIso(), user.id);
    recoveryCodes = createRecoveryCodes(user.id);
    audit({ request, actorUserId: user.id, eventType: 'auth.mfa_enrolled', targetType: 'user', targetId: user.id, detail: { method: 'totp' } });
  }

  challenges.delete(challenge.id);
  const session = createSession(request, response, getUserById(user.id)!, challenge.vaultKey);
  const signedInAt = nowIso();
  db.prepare('UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?').run(signedInAt, signedInAt, user.id);
  audit({ request, actorUserId: user.id, eventType: 'auth.sign_in', targetType: 'user', targetId: user.id, detail: { method } });

  return { user: publicUser(getUserById(user.id)!), ...session, recoveryCodes };
}

export function requireAuth(request: Request, response: Response, next: NextFunction) {
  const rawToken = cookieValue(request, 'innasc_session');
  if (!rawToken) return response.status(401).json({ error: 'Sign in required.', code: 'AUTH_REQUIRED' });
  const idHash = sha256(rawToken);
  const session = db.prepare('SELECT * FROM sessions WHERE id_hash = ?').get(idHash) as SessionRow | undefined;
  const vaultKey = unlockedSessionKeys.get(idHash);
  if (!session || !vaultKey || Date.parse(session.expires_at) <= Date.now()) {
    if (session) db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
    unlockedSessionKeys.delete(idHash);
    clearSessionCookie(response);
    return response.status(401).json({ error: 'Your secure session ended. Sign in again.', code: 'AUTH_REQUIRED' });
  }
  const user = getUserById(session.user_id);
  if (!user) return response.status(401).json({ error: 'Sign in required.', code: 'AUTH_REQUIRED' });
  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(nowIso(), idHash);
  (request as AuthenticatedRequest).auth = { session, user, vaultKey };
  return next();
}

export function requireCsrf(request: Request, response: Response, next: NextFunction) {
  const auth = (request as AuthenticatedRequest).auth;
  if (!auth || request.get('x-csrf-token') !== auth.session.csrf_token) {
    return response.status(403).json({ error: 'The request could not be verified.', code: 'CSRF_FAILED' });
  }
  return next();
}

export function requireStepUp(request: Request, response: Response, next: NextFunction) {
  const auth = (request as AuthenticatedRequest).auth;
  if (!auth.session.step_up_until || Date.parse(auth.session.step_up_until) <= Date.now()) {
    return response.status(428).json({ error: 'Confirm your identity to continue.', code: 'STEP_UP_REQUIRED' });
  }
  return next();
}

export async function performStepUp(request: AuthenticatedRequest, code: string) {
  const secret = decryptTotpSecret(request.auth.user, request.auth.vaultKey);
  let valid = await totpValid(secret, code);
  let method = 'totp';
  if (!valid && code.length >= 8) {
    valid = consumeRecoveryCode(request.auth.user.id, code);
    method = 'recovery_code';
  }
  if (!valid) {
    audit({ request, actorUserId: request.auth.user.id, eventType: 'auth.step_up', targetType: 'user', targetId: request.auth.user.id, outcome: 'failure', detail: { method } });
    throw Object.assign(new Error('The verification code was not accepted.'), { status: 401 });
  }
  const until = new Date(Date.now() + config.stepUpMinutes * 60_000).toISOString();
  db.prepare('UPDATE sessions SET step_up_until = ? WHERE id_hash = ?').run(until, request.auth.session.id_hash);
  request.auth.session.step_up_until = until;
  audit({ request, actorUserId: request.auth.user.id, eventType: 'auth.step_up', targetType: 'user', targetId: request.auth.user.id, detail: { method } });
  return { stepUpUntil: until };
}

export function currentSession(request: AuthenticatedRequest) {
  return {
    user: publicUser(request.auth.user),
    csrfToken: request.auth.session.csrf_token,
    expiresAt: request.auth.session.expires_at,
    stepUpUntil: request.auth.session.step_up_until,
  };
}

export function logout(request: AuthenticatedRequest, response: Response) {
  db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(request.auth.session.id_hash);
  unlockedSessionKeys.delete(request.auth.session.id_hash);
  clearSessionCookie(response);
  audit({ request, actorUserId: request.auth.user.id, eventType: 'auth.sign_out', targetType: 'user', targetId: request.auth.user.id });
}

export function resetUserMfa(targetUser: UserRow, vaultKey: Uint8Array) {
  const totpSecret = generateSecret();
  const encrypted = encryptText(totpSecret, vaultKey, `user:${targetUser.id}:totp:v1`);
  const reset = db.transaction(() => {
    db.prepare(`UPDATE users SET mfa_secret_nonce = ?, mfa_secret_ciphertext = ?, mfa_enabled = 0, updated_at = ? WHERE id = ?`).run(encrypted.nonce, encrypted.ciphertext, nowIso(), targetUser.id);
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(targetUser.id);
    db.prepare('DELETE FROM passkeys WHERE user_id = ?').run(targetUser.id);
    const sessions = db.prepare('SELECT id_hash FROM sessions WHERE user_id = ?').all(targetUser.id) as Array<{ id_hash: string }>;
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(targetUser.id);
    for (const session of sessions) unlockedSessionKeys.delete(session.id_hash);
  });
  reset();
}

export function storeUnlockedSessionKey(sessionHash: string, vaultKey: Uint8Array) {
  unlockedSessionKeys.set(sessionHash, vaultKey);
}

export function sessionKey(sessionHash: string) {
  return unlockedSessionKeys.get(sessionHash);
}

export function createSessionFromChallenge(request: Request, response: Response, challengeId: string, method: string) {
  const challenge = getLoginChallenge(challengeId);
  if (!challenge) throw Object.assign(new Error('The MFA challenge expired. Please sign in again.'), { status: 401 });
  const user = getUserById(challenge.userId);
  if (!user || challenge.kind !== 'login') throw Object.assign(new Error('Invalid passkey challenge.'), { status: 401 });
  challenges.delete(challenge.id);
  const session = createSession(request, response, user, challenge.vaultKey);
  const signedInAt = nowIso();
  db.prepare('UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?').run(signedInAt, signedInAt, user.id);
  audit({ request, actorUserId: user.id, eventType: 'auth.sign_in', targetType: 'user', targetId: user.id, detail: { method } });
  return { user: publicUser(getUserById(user.id)!), ...session };
}
