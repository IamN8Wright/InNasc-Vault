import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  Base64URLString,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { Request, Response } from 'express';

import { audit } from './audit.js';
import { createSessionFromChallenge, getLoginChallenge } from './auth.js';
import { config } from './config.js';
import { randomBase64Url } from './crypto.js';
import { db, newId, nowIso } from './db.js';
import type { AuthenticatedRequest } from './types.js';

type PasskeyRow = {
  id: string;
  user_id: string;
  credential_id: Base64URLString;
  public_key: Buffer;
  counter: number;
  transports: string;
  device_type: string | null;
  backed_up: number;
  name: string;
};

type WebChallenge = {
  id: string;
  challenge: string;
  kind: 'register' | 'login' | 'step_up';
  userId: string;
  sessionHash?: string;
  loginChallengeId?: string;
  expiresAt: number;
};

const webChallenges = new Map<string, WebChallenge>();

function prune() {
  for (const [id, value] of webChallenges) {
    if (value.expiresAt <= Date.now()) webChallenges.delete(id);
  }
}

function passkeysForUser(userId: string) {
  return db.prepare('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at').all(userId) as PasskeyRow[];
}

function transports(value: string) {
  try {
    return JSON.parse(value) as AuthenticatorTransportFuture[];
  } catch {
    return [];
  }
}

function saveChallenge(input: Omit<WebChallenge, 'id' | 'expiresAt'>) {
  prune();
  const value: WebChallenge = {
    ...input,
    id: randomBase64Url(18),
    expiresAt: Date.now() + config.challengeMinutes * 60_000,
  };
  webChallenges.set(value.id, value);
  return value;
}

export async function registrationOptions(request: AuthenticatedRequest) {
  const existing = passkeysForUser(request.auth.user.id);
  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userName: request.auth.user.email,
    userDisplayName: request.auth.user.name,
    userID: new TextEncoder().encode(request.auth.user.id),
    attestationType: 'none',
    excludeCredentials: existing.map((item) => ({ id: item.credential_id, transports: transports(item.transports) })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
  });
  const saved = saveChallenge({
    challenge: options.challenge,
    kind: 'register',
    userId: request.auth.user.id,
    sessionHash: request.auth.session.id_hash,
  });
  return { challengeId: saved.id, options };
}

export async function verifyRegistration(
  request: AuthenticatedRequest,
  challengeId: string,
  response: RegistrationResponseJSON,
  name?: string,
) {
  prune();
  const challenge = webChallenges.get(challengeId);
  if (!challenge || challenge.kind !== 'register' || challenge.userId !== request.auth.user.id || challenge.sessionHash !== request.auth.session.id_hash) {
    throw Object.assign(new Error('The passkey registration challenge expired.'), { status: 401 });
  }

  const result = await verifyRegistrationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpID,
    requireUserVerification: true,
  });
  if (!result.verified) throw Object.assign(new Error('The passkey could not be verified.'), { status: 401 });

  const info = result.registrationInfo;
  db.prepare(`
    INSERT INTO passkeys (
      id, user_id, credential_id, public_key, counter, transports,
      device_type, backed_up, name, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    newId(),
    request.auth.user.id,
    info.credential.id,
    Buffer.from(info.credential.publicKey),
    info.credential.counter,
    JSON.stringify(info.credential.transports ?? []),
    info.credentialDeviceType,
    info.credentialBackedUp ? 1 : 0,
    (name || 'Windows passkey').slice(0, 120),
    nowIso(),
  );
  webChallenges.delete(challenge.id);
  audit({ request, actorUserId: request.auth.user.id, eventType: 'auth.passkey_enrolled', targetType: 'user', targetId: request.auth.user.id });
  return { verified: true };
}

export async function loginOptions(loginChallengeId: string) {
  const loginChallenge = getLoginChallenge(loginChallengeId);
  if (!loginChallenge || loginChallenge.kind !== 'login') throw Object.assign(new Error('The sign-in challenge expired.'), { status: 401 });
  const keys = passkeysForUser(loginChallenge.userId);
  if (!keys.length) throw Object.assign(new Error('No passkey is enrolled for this account.'), { status: 409 });
  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    userVerification: 'required',
    allowCredentials: keys.map((item) => ({ id: item.credential_id, transports: transports(item.transports) })),
  });
  const saved = saveChallenge({
    challenge: options.challenge,
    kind: 'login',
    userId: loginChallenge.userId,
    loginChallengeId,
  });
  return { challengeId: saved.id, options };
}

export async function stepUpOptions(request: AuthenticatedRequest) {
  const keys = passkeysForUser(request.auth.user.id);
  if (!keys.length) throw Object.assign(new Error('No passkey is enrolled for this account.'), { status: 409 });
  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    userVerification: 'required',
    allowCredentials: keys.map((item) => ({ id: item.credential_id, transports: transports(item.transports) })),
  });
  const saved = saveChallenge({
    challenge: options.challenge,
    kind: 'step_up',
    userId: request.auth.user.id,
    sessionHash: request.auth.session.id_hash,
  });
  return { challengeId: saved.id, options };
}

export async function verifyAuthentication(
  request: Request,
  response: Response,
  challengeId: string,
  credentialResponse: AuthenticationResponseJSON,
) {
  prune();
  const challenge = webChallenges.get(challengeId);
  if (!challenge || challenge.kind === 'register') throw Object.assign(new Error('The passkey challenge expired.'), { status: 401 });
  const row = db.prepare('SELECT * FROM passkeys WHERE user_id = ? AND credential_id = ?').get(challenge.userId, credentialResponse.id) as PasskeyRow | undefined;
  if (!row) throw Object.assign(new Error('This passkey is not registered.'), { status: 401 });

  const result = await verifyAuthenticationResponse({
    response: credentialResponse,
    expectedChallenge: challenge.challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpID,
    credential: {
      id: row.credential_id,
      publicKey: new Uint8Array(row.public_key),
      counter: row.counter,
      transports: transports(row.transports),
    },
    requireUserVerification: true,
  });
  if (!result.verified) throw Object.assign(new Error('The passkey could not be verified.'), { status: 401 });

  db.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?').run(result.authenticationInfo.newCounter, nowIso(), row.id);
  webChallenges.delete(challenge.id);

  if (challenge.kind === 'login') {
    return createSessionFromChallenge(request, response, challenge.loginChallengeId!, 'passkey');
  }

  const authRequest = request as AuthenticatedRequest;
  if (!authRequest.auth || authRequest.auth.user.id !== challenge.userId || authRequest.auth.session.id_hash !== challenge.sessionHash) {
    throw Object.assign(new Error('The passkey challenge does not match this session.'), { status: 401 });
  }
  const until = new Date(Date.now() + config.stepUpMinutes * 60_000).toISOString();
  db.prepare('UPDATE sessions SET step_up_until = ? WHERE id_hash = ?').run(until, authRequest.auth.session.id_hash);
  audit({ request: authRequest, actorUserId: authRequest.auth.user.id, eventType: 'auth.step_up', targetType: 'user', targetId: authRequest.auth.user.id, detail: { method: 'passkey' } });
  return { stepUpUntil: until };
}

export function listPasskeys(userId: string) {
  return passkeysForUser(userId).map((key) => ({
    id: key.id,
    name: key.name,
    deviceType: key.device_type,
    backedUp: Boolean(key.backed_up),
  }));
}
