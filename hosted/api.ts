import QRCode from 'qrcode';
import { z, ZodError } from 'zod';

import {
  base64Url,
  decryptBytes,
  decryptJson,
  decryptText,
  derivePasswordKey,
  encryptBytes,
  encryptJson,
  encryptText,
  hashPassword,
  makeRecoveryCodes,
  makeTotpSecret,
  normalizeRecoveryCode,
  randomBytes,
  randomToken,
  safeEqual,
  sha256,
  verifyPassword,
  verifyTotp,
} from '@/hosted/crypto';
import { all, ApiProblem, ensureHostedSchema, first, hostedEnv, newId, nowIso, run, serverKey } from '@/hosted/db';

const roles = ['workspace_owner', 'admin', 'technician', 'client_admin', 'client_user', 'read_only'] as const;
const collections = ['network', 'av_systems', 'voip', 'access_control', 'remote_access', 'software', 'websites_accounts', 'general'] as const;
type Role = (typeof roles)[number];
type Collection = (typeof collections)[number];
type PermissionAction = 'view' | 'manage' | 'reveal' | 'export';

type UserRow = {
  id: string;
  name: string;
  email: string;
  role: Role;
  password_hash: string;
  kdf_salt: string;
  wrapped_key_nonce: string;
  wrapped_key_ciphertext: string;
  mfa_secret_nonce: string;
  mfa_secret_ciphertext: string;
  mfa_enabled: number;
  failed_login_count: number;
  locked_until: string | null;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
};

type AuthContext = {
  sessionIdHash: string;
  csrfToken: string;
  expiresAt: string;
  stepUpUntil: string | null;
  user: UserRow;
  vaultKey: Uint8Array;
};

type PermissionRow = {
  can_view: number;
  can_manage: number;
  can_reveal: number;
  can_export: number;
  client_id: string | null;
  location_id: string | null;
  collection: Collection | null;
};

const strongPassword = z.string().min(14).max(256).refine(
  (value) => /[a-z]/u.test(value) && /[A-Z]/u.test(value) && /\d/u.test(value) && /[^A-Za-z0-9]/u.test(value),
  'Use at least one uppercase letter, lowercase letter, number, and symbol.',
);
const setupSchema = z.object({
  name: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(254),
  password: strongPassword,
  setupToken: z.string().min(16).max(512),
});
const loginSchema = z.object({ email: z.string().trim().email().max(254), password: z.string().min(1).max(256) });
const mfaSchema = z.object({ challengeId: z.string().min(16).max(200), code: z.string().trim().min(6).max(32) });
const entityName = z.string().trim().min(1).max(180);
const clientSchema = z.object({ name: entityName, code: z.string().trim().max(50).default(''), notes: z.string().trim().max(10_000).default('') });
const locationSchema = z.object({ clientId: z.string().uuid(), name: entityName, address: z.string().trim().max(500).default(''), notes: z.string().trim().max(10_000).default('') });
const systemSchema = z.object({
  clientId: z.string().uuid(),
  locationId: z.string().uuid(),
  name: entityName,
  collection: z.enum(collections),
  manufacturer: z.string().trim().max(180).default(''),
  model: z.string().trim().max(180).default(''),
  networkAddress: z.string().trim().max(500).default(''),
  notes: z.string().trim().max(10_000).default(''),
});
const assetSchema = z.object({
  clientId: z.string().uuid(),
  locationId: z.string().uuid(),
  systemId: z.string().uuid().nullable().optional(),
  assetType: z.enum(['device', 'software', 'website_account']),
  name: entityName,
  vendor: z.string().trim().max(180).default(''),
  versionOrModel: z.string().trim().max(180).default(''),
  identifier: z.string().trim().max(500).default(''),
  url: z.string().trim().max(2_000).default(''),
  notes: z.string().trim().max(10_000).default(''),
});
const secretSchema = z.object({
  username: z.string().max(1_000).default(''),
  password: z.string().max(10_000).default(''),
  pin: z.string().max(500).default(''),
  apiToken: z.string().max(20_000).default(''),
  licenseKey: z.string().max(10_000).default(''),
  notes: z.string().max(20_000).default(''),
});
const credentialSchema = z.object({
  clientId: z.string().uuid(),
  locationId: z.string().uuid(),
  systemId: z.string().uuid().nullable().optional(),
  collection: z.enum(collections),
  name: entityName,
  url: z.string().trim().max(2_000).default(''),
  lastVerifiedAt: z.string().datetime().nullable().optional(),
  expiresAt: z.string().datetime().nullable().optional(),
  secret: secretSchema,
});
const userSchema = z.object({ name: z.string().trim().min(2).max(120), email: z.string().trim().email().max(254), password: strongPassword, role: z.enum(roles).refine((role) => role !== 'workspace_owner') });
const permissionSchema = z.object({
  userId: z.string().uuid(),
  clientId: z.string().uuid().nullable(),
  locationId: z.string().uuid().nullable().optional(),
  collection: z.enum(collections).nullable().optional(),
  canView: z.boolean(), canManage: z.boolean(), canReveal: z.boolean(), canExport: z.boolean(),
});

function json(data: unknown, status = 200, headers?: HeadersInit) {
  return Response.json(data, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}

function noContent(headers?: HeadersInit) {
  return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store', ...headers } });
}

function downloadJson(data: unknown, filename: string) {
  return new Response(JSON.stringify(data, null, 2), {
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
    },
  });
}

async function body(request: Request) {
  try {
    return await request.json();
  } catch {
    throw new ApiProblem('A valid JSON request body is required.', 400, 'INVALID_JSON');
  }
}

function cookie(request: Request, name: string) {
  for (const item of request.headers.get('cookie')?.split(';') ?? []) {
    const [key, ...rest] = item.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

function sessionCookie(token: string) {
  return `innasc_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${8 * 60 * 60}`;
}

function clearSessionCookie() {
  return 'innasc_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';
}

async function requestIpHash(request: Request) {
  return sha256(request.headers.get('cf-connecting-ip') ?? 'hosted');
}

async function getUserById(id: string) {
  return first<UserRow>('SELECT * FROM users WHERE id = ?', id);
}

async function publicUser(user: UserRow) {
  const recovery = await first<{ count: number }>('SELECT COUNT(*) AS count FROM recovery_codes WHERE user_id = ? AND used_at IS NULL', user.id);
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    mfaEnabled: Boolean(user.mfa_enabled),
    recoveryCodesRemaining: recovery?.count ?? 0,
    passkeyCount: 0,
    lastLoginAt: user.last_login_at,
  };
}

async function audit(request: Request, input: {
  actorUserId?: string | null;
  eventType: string;
  targetType?: string | null;
  targetId?: string | null;
  clientId?: string | null;
  outcome?: 'success' | 'failure' | 'blocked';
  detail?: Record<string, unknown>;
}) {
  const occurredAt = nowIso();
  const id = newId();
  const previous = await first<{ entry_hash: string }>('SELECT entry_hash FROM audit_log ORDER BY occurred_at DESC, id DESC LIMIT 1');
  const previousHash = previous?.entry_hash ?? 'GENESIS';
  const detailJson = JSON.stringify(input.detail ?? {});
  const outcome = input.outcome ?? 'success';
  const entryHash = await sha256(JSON.stringify({ id, occurredAt, actorUserId: input.actorUserId ?? null, eventType: input.eventType, targetType: input.targetType ?? null, targetId: input.targetId ?? null, clientId: input.clientId ?? null, outcome, detailJson, previousHash }));
  await run(`INSERT INTO audit_log(id,occurred_at,actor_user_id,event_type,target_type,target_id,client_id,outcome,ip_hash,user_agent,detail_json,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    id, occurredAt, input.actorUserId ?? null, input.eventType, input.targetType ?? null, input.targetId ?? null,
    input.clientId ?? null, outcome, await requestIpHash(request), request.headers.get('user-agent')?.slice(0, 500) ?? null,
    detailJson, previousHash, entryHash);
}

async function requireAuth(request: Request) {
  const rawToken = cookie(request, 'innasc_session');
  if (!rawToken) throw new ApiProblem('Sign in is required.', 401, 'AUTH_REQUIRED');
  const idHash = await sha256(rawToken);
  const row = await first<UserRow & {
    csrf_token: string;
    vault_key_nonce: string;
    vault_key_ciphertext: string;
    expires_at: string;
    step_up_until: string | null;
  }>(`SELECT u.*,s.csrf_token,s.vault_key_nonce,s.vault_key_ciphertext,s.expires_at,s.step_up_until FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=?`, idHash);
  if (!row || Date.parse(row.expires_at) <= Date.now()) {
    if (row) await run('DELETE FROM sessions WHERE id_hash=?', idHash);
    throw new ApiProblem('Your session expired. Sign in again.', 401, 'AUTH_REQUIRED');
  }
  const vaultKey = await decryptBytes(row.vault_key_nonce, row.vault_key_ciphertext, serverKey(), `session:${idHash}:vault-key:v1`);
  await run('UPDATE sessions SET last_seen_at=? WHERE id_hash=?', nowIso(), idHash);
  return { sessionIdHash: idHash, csrfToken: row.csrf_token, expiresAt: row.expires_at, stepUpUntil: row.step_up_until, user: row, vaultKey } satisfies AuthContext;
}

async function requireCsrf(request: Request, auth: AuthContext) {
  const supplied = request.headers.get('x-csrf-token') ?? '';
  if (!supplied || !(await safeEqual(supplied, auth.csrfToken))) throw new ApiProblem('The request could not be verified.', 403, 'CSRF_INVALID');
}

function requireStepUp(auth: AuthContext) {
  if (!auth.stepUpUntil || Date.parse(auth.stepUpUntil) <= Date.now()) throw new ApiProblem('Fresh MFA verification is required.', 428, 'STEP_UP_REQUIRED');
}

function assertWorkspaceAdmin(auth: AuthContext) {
  if (auth.user.role !== 'workspace_owner' && auth.user.role !== 'admin') throw new ApiProblem('Workspace administration permission is required.', 403, 'PERMISSION_DENIED');
}

async function visibleClientIds(user: UserRow) {
  if (user.role === 'workspace_owner' || user.role === 'admin') return null;
  if (await first('SELECT id FROM permissions WHERE user_id=? AND can_view=1 AND client_id IS NULL LIMIT 1', user.id)) return null;
  const rows = await all<{ client_id: string }>('SELECT DISTINCT client_id FROM permissions WHERE user_id=? AND can_view=1 AND client_id IS NOT NULL', user.id);
  return rows.map((row) => row.client_id);
}

async function canViewLocation(user: UserRow, clientId: string, locationId: string) {
  if (user.role === 'workspace_owner' || user.role === 'admin') return true;
  return Boolean(await first(
    'SELECT id FROM permissions WHERE user_id=? AND can_view=1 AND (client_id IS NULL OR client_id=?) AND (location_id IS NULL OR location_id=?) LIMIT 1',
    user.id,
    clientId,
    locationId,
  ));
}

async function hasPermission(user: UserRow, scope: { clientId: string; locationId?: string | null; collection?: Collection | null }, action: PermissionAction) {
  if (user.role === 'workspace_owner' || user.role === 'admin') return true;
  const rows = await all<PermissionRow>(`SELECT can_view,can_manage,can_reveal,can_export,client_id,location_id,collection FROM permissions WHERE user_id=? AND (client_id IS NULL OR client_id=?) AND (location_id IS NULL OR location_id=?) AND (collection IS NULL OR collection=?) ORDER BY (client_id IS NOT NULL)+(location_id IS NOT NULL)+(collection IS NOT NULL) DESC,updated_at DESC`, user.id, scope.clientId, scope.locationId ?? null, scope.collection ?? null);
  const best = rows[0];
  if (!best) return false;
  const column = { view: 'can_view', manage: 'can_manage', reveal: 'can_reveal', export: 'can_export' } as const;
  return Boolean(best[column[action]]);
}

async function assertPermission(auth: AuthContext, scope: { clientId: string; locationId?: string | null; collection?: Collection | null }, action: PermissionAction) {
  if (!(await hasPermission(auth.user, scope, action))) throw new ApiProblem('You do not have permission for this client record.', 403, 'PERMISSION_DENIED');
}

async function assertLocation(clientId: string, locationId: string) {
  if (!(await first('SELECT id FROM locations WHERE id=? AND client_id=?', locationId, clientId))) throw new ApiProblem('The selected location does not belong to this client.');
}

async function assertSystem(clientId: string, locationId: string, systemId?: string | null) {
  if (systemId && !(await first('SELECT id FROM systems WHERE id=? AND client_id=? AND location_id=?', systemId, clientId, locationId))) throw new ApiProblem('The selected system does not belong to this location.');
}

async function credentialById(id: string) {
  return first<Record<string, unknown>>(`SELECT c.*,cl.name AS client_name,l.name AS location_name,s.name AS system_name FROM credentials c JOIN clients cl ON cl.id=c.client_id JOIN locations l ON l.id=c.location_id LEFT JOIN systems s ON s.id=c.system_id WHERE c.id=?`, id);
}

async function issueChallenge(user: UserRow, vaultKey: Uint8Array) {
  const id = randomToken(24);
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  const kind = user.mfa_enabled ? 'login' : 'enrollment';
  const encrypted = await encryptBytes(vaultKey, serverKey(), `challenge:${id}:vault-key:v1`);
  await run('DELETE FROM login_challenges WHERE expires_at<=?', createdAt);
  await run('INSERT INTO login_challenges(id,kind,user_id,vault_key_nonce,vault_key_ciphertext,expires_at,created_at) VALUES(?,?,?,?,?,?,?)', id, kind, user.id, encrypted.nonce, encrypted.ciphertext, expiresAt, createdAt);
  if (kind === 'login') return { challengeId: id, kind, passkeyAvailable: false };
  const secret = await decryptText(user.mfa_secret_nonce, user.mfa_secret_ciphertext, vaultKey, `user:${user.id}:totp:v1`);
  const uri = `otpauth://totp/${encodeURIComponent(`InNasc Vault:${user.email}`)}?secret=${secret}&issuer=${encodeURIComponent('InNasc Vault')}&algorithm=SHA1&digits=6&period=30`;
  return { challengeId: id, kind, passkeyAvailable: false, manualKey: secret, qrCodeDataUrl: await QRCode.toDataURL(uri, { margin: 1, width: 240 }) };
}

async function consumeRecoveryCode(userId: string, code: string) {
  const codeHash = await sha256(normalizeRecoveryCode(code));
  const row = await first<{ id: string }>('SELECT id FROM recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL', userId, codeHash);
  if (!row) return false;
  const result = await run('UPDATE recovery_codes SET used_at=? WHERE id=? AND used_at IS NULL', nowIso(), row.id);
  return Number(result.meta.changes ?? 0) === 1;
}

async function createSession(request: Request, user: UserRow, vaultKey: Uint8Array) {
  const rawToken = randomToken(32);
  const idHash = await sha256(rawToken);
  const csrfToken = randomToken(24);
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + 8 * 60 * 60_000).toISOString();
  const encrypted = await encryptBytes(vaultKey, serverKey(), `session:${idHash}:vault-key:v1`);
  await run(`INSERT INTO sessions(id_hash,user_id,csrf_token,vault_key_nonce,vault_key_ciphertext,created_at,last_seen_at,expires_at,ip_hash,user_agent) VALUES(?,?,?,?,?,?,?,?,?,?)`,
    idHash, user.id, csrfToken, encrypted.nonce, encrypted.ciphertext, createdAt, createdAt, expiresAt,
    await requestIpHash(request), request.headers.get('user-agent')?.slice(0, 500) ?? null);
  return { rawToken, csrfToken, expiresAt };
}

async function beginSetup(request: Request) {
  const input = setupSchema.parse(await body(request));
  const configuredToken = hostedEnv().INNASC_SETUP_TOKEN;
  if (!configuredToken || !(await safeEqual(input.setupToken, configuredToken))) {
    await audit(request, { eventType: 'auth.setup', targetType: 'workspace', outcome: 'failure', detail: { reason: 'invalid_setup_token' } });
    throw new ApiProblem('The deployment setup key is not valid.', 403, 'SETUP_TOKEN_INVALID');
  }
  // Fail before inserting the owner if the deployment key cannot protect login challenges.
  serverKey();
  const userId = newId();
  const vaultKey = randomBytes(32);
  const salt = base64Url(randomBytes(16));
  const derivedKey = await derivePasswordKey(input.password, salt);
  const wrapped = await encryptBytes(vaultKey, derivedKey, `user:${userId}:vault-key:v1`);
  const totpSecret = makeTotpSecret();
  const encryptedTotp = await encryptText(totpSecret, vaultKey, `user:${userId}:totp:v1`);
  const timestamp = nowIso();
  const insert = await run(`INSERT INTO users(id,name,email,role,password_hash,kdf_salt,wrapped_key_nonce,wrapped_key_ciphertext,mfa_secret_nonce,mfa_secret_ciphertext,mfa_enabled,created_at,updated_at) SELECT ?,?,?,?,?,?,?,?,?,?,0,?,? WHERE NOT EXISTS (SELECT 1 FROM users)`,
    userId, input.name, input.email.toLowerCase(), 'workspace_owner', await hashPassword(input.password), salt,
    wrapped.nonce, wrapped.ciphertext, encryptedTotp.nonce, encryptedTotp.ciphertext, timestamp, timestamp);
  if (Number(insert.meta.changes ?? 0) !== 1) throw new ApiProblem('Workspace setup has already been completed.', 409, 'SETUP_COMPLETE');
  const user = (await getUserById(userId))!;
  await audit(request, { actorUserId: userId, eventType: 'auth.setup', targetType: 'workspace' });
  return json(await issueChallenge(user, vaultKey), 201);
}

async function beginLogin(request: Request) {
  const input = loginSchema.parse(await body(request));
  const user = await first<UserRow>('SELECT * FROM users WHERE email=? COLLATE NOCASE', input.email);
  if (!user) {
    await derivePasswordKey(input.password, base64Url(new Uint8Array(16)));
    await audit(request, { eventType: 'auth.sign_in', targetType: 'user', outcome: 'failure', detail: { reason: 'invalid_credentials' } });
    throw new ApiProblem('Email or password is incorrect.', 401, 'INVALID_CREDENTIALS');
  }
  if (user.locked_until && Date.parse(user.locked_until) > Date.now()) throw new ApiProblem('This account is temporarily locked. Try again later.', 423, 'ACCOUNT_LOCKED');
  if (!(await verifyPassword(input.password, user.password_hash))) {
    const failures = user.failed_login_count + 1;
    const lockedUntil = failures >= 5 ? new Date(Date.now() + 15 * 60_000).toISOString() : null;
    await run('UPDATE users SET failed_login_count=?,locked_until=?,updated_at=? WHERE id=?', failures >= 5 ? 0 : failures, lockedUntil, nowIso(), user.id);
    await audit(request, { actorUserId: user.id, eventType: 'auth.sign_in', targetType: 'user', targetId: user.id, outcome: 'failure', detail: { reason: lockedUntil ? 'locked' : 'invalid_credentials' } });
    throw new ApiProblem('Email or password is incorrect.', 401, 'INVALID_CREDENTIALS');
  }
  const derivedKey = await derivePasswordKey(input.password, user.kdf_salt);
  const vaultKey = await decryptBytes(user.wrapped_key_nonce, user.wrapped_key_ciphertext, derivedKey, `user:${user.id}:vault-key:v1`);
  await run('UPDATE users SET failed_login_count=0,locked_until=NULL,updated_at=? WHERE id=?', nowIso(), user.id);
  return json(await issueChallenge(user, vaultKey));
}

async function completeMfa(request: Request) {
  const input = mfaSchema.parse(await body(request));
  const challenge = await first<{ id: string; kind: 'login' | 'enrollment'; user_id: string; vault_key_nonce: string; vault_key_ciphertext: string; expires_at: string; attempt_count: number }>('SELECT * FROM login_challenges WHERE id=?', input.challengeId);
  if (!challenge || Date.parse(challenge.expires_at) <= Date.now()) throw new ApiProblem('The MFA challenge expired. Sign in again.', 401, 'CHALLENGE_EXPIRED');
  const user = await getUserById(challenge.user_id);
  if (!user) throw new ApiProblem('Account not found.', 401, 'AUTH_REQUIRED');
  const vaultKey = await decryptBytes(challenge.vault_key_nonce, challenge.vault_key_ciphertext, serverKey(), `challenge:${challenge.id}:vault-key:v1`);
  const secret = await decryptText(user.mfa_secret_nonce, user.mfa_secret_ciphertext, vaultKey, `user:${user.id}:totp:v1`);
  const valid = await verifyTotp(secret, input.code) || (challenge.kind === 'login' && await consumeRecoveryCode(user.id, input.code));
  if (!valid) {
    if (challenge.attempt_count >= 4) await run('DELETE FROM login_challenges WHERE id=?', challenge.id);
    else await run('UPDATE login_challenges SET attempt_count=attempt_count+1 WHERE id=?', challenge.id);
    await audit(request, { actorUserId: user.id, eventType: 'auth.mfa', targetType: 'user', targetId: user.id, outcome: 'failure' });
    throw new ApiProblem(challenge.attempt_count >= 4 ? 'Too many MFA attempts. Sign in again.' : 'The authenticator or recovery code is not valid.', 401, challenge.attempt_count >= 4 ? 'CHALLENGE_EXPIRED' : 'MFA_INVALID');
  }
  let recoveryCodes: string[] | undefined;
  if (challenge.kind === 'enrollment') {
    recoveryCodes = makeRecoveryCodes();
    await run('DELETE FROM recovery_codes WHERE user_id=?', user.id);
    for (const code of recoveryCodes) await run('INSERT INTO recovery_codes(id,user_id,code_hash,created_at) VALUES(?,?,?,?)', newId(), user.id, await sha256(normalizeRecoveryCode(code)), nowIso());
    await run('UPDATE users SET mfa_enabled=1,updated_at=? WHERE id=?', nowIso(), user.id);
    user.mfa_enabled = 1;
  }
  const session = await createSession(request, user, vaultKey);
  await run('DELETE FROM login_challenges WHERE id=?', challenge.id);
  await run('UPDATE users SET last_login_at=?,updated_at=? WHERE id=?', nowIso(), nowIso(), user.id);
  user.last_login_at = nowIso();
  await audit(request, { actorUserId: user.id, eventType: 'auth.sign_in', targetType: 'user', targetId: user.id });
  return json({ user: await publicUser(user), csrfToken: session.csrfToken, expiresAt: session.expiresAt, stepUpUntil: null, recoveryCodes, capabilities: { passkeys: false, sqliteBackup: false } }, 200, { 'Set-Cookie': sessionCookie(session.rawToken) });
}

async function currentSession(auth: AuthContext) {
  return { user: await publicUser(auth.user), csrfToken: auth.csrfToken, expiresAt: auth.expiresAt, stepUpUntil: auth.stepUpUntil, capabilities: { passkeys: false, sqliteBackup: false } };
}

async function handleProtected(request: Request, path: string, method: string, auth: AuthContext) {
  if (method !== 'GET') await requireCsrf(request, auth);

  if (path === 'session' && method === 'GET') return json(await currentSession(auth));
  if (path === 'auth/logout' && method === 'POST') {
    await run('DELETE FROM sessions WHERE id_hash=?', auth.sessionIdHash);
    await audit(request, { actorUserId: auth.user.id, eventType: 'auth.sign_out', targetType: 'user', targetId: auth.user.id });
    return noContent({ 'Set-Cookie': clearSessionCookie() });
  }
  if (path === 'auth/step-up' && method === 'POST') {
    const input = z.object({ code: z.string().trim().min(6).max(32) }).parse(await body(request));
    const secret = await decryptText(auth.user.mfa_secret_nonce, auth.user.mfa_secret_ciphertext, auth.vaultKey, `user:${auth.user.id}:totp:v1`);
    if (!(await verifyTotp(secret, input.code)) && !(await consumeRecoveryCode(auth.user.id, input.code))) {
      const session = await first<{ step_up_failed_count: number }>('SELECT step_up_failed_count FROM sessions WHERE id_hash=?', auth.sessionIdHash);
      if ((session?.step_up_failed_count ?? 0) >= 4) await run('DELETE FROM sessions WHERE id_hash=?', auth.sessionIdHash);
      else await run('UPDATE sessions SET step_up_failed_count=step_up_failed_count+1 WHERE id_hash=?', auth.sessionIdHash);
      await audit(request, { actorUserId: auth.user.id, eventType: 'auth.step_up', targetType: 'user', targetId: auth.user.id, outcome: 'failure' });
      throw new ApiProblem((session?.step_up_failed_count ?? 0) >= 4 ? 'Too many MFA attempts. Sign in again.' : 'The authenticator or recovery code is not valid.', 401, (session?.step_up_failed_count ?? 0) >= 4 ? 'AUTH_REQUIRED' : 'MFA_INVALID');
    }
    const stepUpUntil = new Date(Date.now() + 5 * 60_000).toISOString();
    await run('UPDATE sessions SET step_up_until=?,step_up_failed_count=0 WHERE id_hash=?', stepUpUntil, auth.sessionIdHash);
    await audit(request, { actorUserId: auth.user.id, eventType: 'auth.step_up', targetType: 'user', targetId: auth.user.id });
    return json({ stepUpUntil });
  }
  if (path.startsWith('auth/passkey/') || path.startsWith('passkeys/register/')) throw new ApiProblem('Hosted passkey enrollment is not enabled in this beta.', 501, 'HOSTED_PASSKEYS_PENDING');
  if (path === 'passkeys' && method === 'GET') return json([]);

  if (path === 'dashboard' && method === 'GET') {
    const ids = await visibleClientIds(auth.user);
    if (ids !== null && ids.length === 0) return json({ clients: 0, locations: 0, systems: 0, credentials: 0, recentClients: [] });
    const where = ids === null ? '' : ` WHERE id IN (${ids.map(() => '?').join(',')})`;
    const childWhere = ids === null ? '' : ` WHERE client_id IN (${ids.map(() => '?').join(',')})`;
    const params = ids ?? [];
    const [clientRows, locationRows, systemRows, credentialRows] = await Promise.all([
      all<Record<string, unknown>>(`SELECT id,name,code,updated_at FROM clients${where} ORDER BY updated_at DESC`, ...params),
      all<Record<string, unknown>>(`SELECT id,client_id FROM locations${childWhere}`, ...params),
      all<Record<string, unknown>>(`SELECT id,client_id,location_id,collection FROM systems${childWhere}`, ...params),
      all<Record<string, unknown>>(`SELECT id,client_id,location_id,collection FROM credentials${childWhere}`, ...params),
    ]);
    const locations = (await Promise.all(locationRows.map(async (row) => await canViewLocation(auth.user, String(row.client_id), String(row.id)) ? row : null))).filter(Boolean);
    const systems = (await Promise.all(systemRows.map(async (row) => await hasPermission(auth.user, { clientId: String(row.client_id), locationId: String(row.location_id), collection: row.collection as Collection }, 'view') ? row : null))).filter(Boolean);
    const credentials = (await Promise.all(credentialRows.map(async (row) => await hasPermission(auth.user, { clientId: String(row.client_id), locationId: String(row.location_id), collection: row.collection as Collection }, 'view') ? row : null))).filter(Boolean);
    return json({ clients: clientRows.length, locations: locations.length, systems: systems.length, credentials: credentials.length, recentClients: clientRows.slice(0, 5) });
  }

  if (path === 'clients' && method === 'GET') {
    const ids = await visibleClientIds(auth.user);
    if (ids !== null && !ids.length) return json([]);
    const where = ids === null ? '' : ` WHERE id IN (${ids.map(() => '?').join(',')})`;
    return json(await all(`SELECT id,name,code,notes,created_at,updated_at FROM clients${where} ORDER BY name`, ...(ids ?? [])));
  }
  if (path === 'clients' && method === 'POST') {
    assertWorkspaceAdmin(auth);
    const input = clientSchema.parse(await body(request));
    const id = newId(); const timestamp = nowIso();
    await run('INSERT INTO clients(id,name,code,notes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)', id, input.name, input.code, input.notes, auth.user.id, timestamp, timestamp);
    await audit(request, { actorUserId: auth.user.id, eventType: 'client.create', targetType: 'client', targetId: id, clientId: id });
    return json({ id, ...input, createdAt: timestamp, updatedAt: timestamp }, 201);
  }

  if (path === 'locations' && method === 'GET') {
    const ids = await visibleClientIds(auth.user);
    if (ids !== null && !ids.length) return json([]);
    const where = ids === null ? '' : ` WHERE client_id IN (${ids.map(() => '?').join(',')})`;
    const rows = await all<Record<string, unknown>>(`SELECT id,client_id,name,address,notes,created_at,updated_at FROM locations${where} ORDER BY name`, ...(ids ?? []));
    const allowed = await Promise.all(rows.map(async (row) => await canViewLocation(auth.user, String(row.client_id), String(row.id)) ? row : null));
    return json(allowed.filter(Boolean));
  }
  if (path === 'locations' && method === 'POST') {
    const input = locationSchema.parse(await body(request));
    await assertPermission(auth, { clientId: input.clientId }, 'manage');
    const id = newId(); const timestamp = nowIso();
    await run('INSERT INTO locations(id,client_id,name,address,notes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)', id, input.clientId, input.name, input.address, input.notes, auth.user.id, timestamp, timestamp);
    await audit(request, { actorUserId: auth.user.id, eventType: 'location.create', targetType: 'location', targetId: id, clientId: input.clientId });
    return json({ id, ...input, createdAt: timestamp, updatedAt: timestamp }, 201);
  }

  if (path === 'systems' && method === 'GET') {
    const ids = await visibleClientIds(auth.user);
    if (ids !== null && !ids.length) return json([]);
    const where = ids === null ? '' : ` WHERE client_id IN (${ids.map(() => '?').join(',')})`;
    const rows = await all<Record<string, unknown>>(`SELECT id,client_id,location_id,name,collection,manufacturer,model,network_address,notes,created_at,updated_at FROM systems${where} ORDER BY name`, ...(ids ?? []));
    const allowed = await Promise.all(rows.map(async (row) => await hasPermission(auth.user, { clientId: String(row.client_id), locationId: String(row.location_id), collection: row.collection as Collection }, 'view') ? row : null));
    return json(allowed.filter(Boolean));
  }
  if (path === 'systems' && method === 'POST') {
    const input = systemSchema.parse(await body(request));
    await assertLocation(input.clientId, input.locationId);
    await assertPermission(auth, { clientId: input.clientId, locationId: input.locationId, collection: input.collection }, 'manage');
    const id = newId(); const timestamp = nowIso();
    await run('INSERT INTO systems(id,client_id,location_id,name,collection,manufacturer,model,network_address,notes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', id, input.clientId, input.locationId, input.name, input.collection, input.manufacturer, input.model, input.networkAddress, input.notes, auth.user.id, timestamp, timestamp);
    await audit(request, { actorUserId: auth.user.id, eventType: 'system.create', targetType: 'system', targetId: id, clientId: input.clientId, detail: { collection: input.collection } });
    return json({ id, ...input, createdAt: timestamp, updatedAt: timestamp }, 201);
  }

  if (path === 'assets' && method === 'GET') {
    const ids = await visibleClientIds(auth.user);
    if (ids !== null && !ids.length) return json([]);
    const where = ids === null ? '' : ` WHERE a.client_id IN (${ids.map(() => '?').join(',')})`;
    const rows = await all<Record<string, unknown>>(`SELECT a.*,cl.name AS client_name,l.name AS location_name,s.name AS system_name FROM assets a JOIN clients cl ON cl.id=a.client_id JOIN locations l ON l.id=a.location_id LEFT JOIN systems s ON s.id=a.system_id${where} ORDER BY a.name`, ...(ids ?? []));
    const allowed = await Promise.all(rows.map(async (row) => await hasPermission(auth.user, { clientId: String(row.client_id), locationId: String(row.location_id) }, 'view') ? row : null));
    return json(allowed.filter(Boolean));
  }
  if (path === 'assets' && method === 'POST') {
    const input = assetSchema.parse(await body(request));
    await assertLocation(input.clientId, input.locationId); await assertSystem(input.clientId, input.locationId, input.systemId);
    await assertPermission(auth, { clientId: input.clientId, locationId: input.locationId }, 'manage');
    const id = newId(); const timestamp = nowIso();
    await run('INSERT INTO assets(id,client_id,location_id,system_id,asset_type,name,vendor,version_or_model,identifier,url,notes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, input.clientId, input.locationId, input.systemId ?? null, input.assetType, input.name, input.vendor, input.versionOrModel, input.identifier, input.url, input.notes, auth.user.id, timestamp, timestamp);
    await audit(request, { actorUserId: auth.user.id, eventType: 'asset.create', targetType: input.assetType, targetId: id, clientId: input.clientId });
    return json({ id, ...input, createdAt: timestamp, updatedAt: timestamp }, 201);
  }

  if (path === 'credentials' && method === 'GET') {
    const ids = await visibleClientIds(auth.user);
    if (ids !== null && !ids.length) return json([]);
    const where = ids === null ? '' : ` WHERE c.client_id IN (${ids.map(() => '?').join(',')})`;
    const rows = await all<Record<string, unknown>>(`SELECT c.id,c.client_id,c.location_id,c.system_id,c.collection,c.name,c.url,c.last_verified_at,c.expires_at,c.created_at,c.updated_at,cl.name AS client_name,l.name AS location_name,s.name AS system_name FROM credentials c JOIN clients cl ON cl.id=c.client_id JOIN locations l ON l.id=c.location_id LEFT JOIN systems s ON s.id=c.system_id${where} ORDER BY c.updated_at DESC`, ...(ids ?? []));
    const allowed = await Promise.all(rows.map(async (row) => await hasPermission(auth.user, { clientId: String(row.client_id), locationId: String(row.location_id), collection: row.collection as Collection }, 'view') ? row : null));
    return json(allowed.filter(Boolean));
  }
  if (path === 'credentials' && method === 'POST') {
    const input = credentialSchema.parse(await body(request));
    await assertLocation(input.clientId, input.locationId); await assertSystem(input.clientId, input.locationId, input.systemId);
    await assertPermission(auth, { clientId: input.clientId, locationId: input.locationId, collection: input.collection }, 'manage');
    const id = newId(); const timestamp = nowIso();
    const encrypted = await encryptJson(input.secret, auth.vaultKey, `credential:${id}:v1`);
    await run('INSERT INTO credentials(id,client_id,location_id,system_id,collection,name,url,secret_nonce,secret_ciphertext,last_verified_at,expires_at,created_by,updated_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, input.clientId, input.locationId, input.systemId ?? null, input.collection, input.name, input.url, encrypted.nonce, encrypted.ciphertext, input.lastVerifiedAt ?? null, input.expiresAt ?? null, auth.user.id, auth.user.id, timestamp, timestamp);
    await audit(request, { actorUserId: auth.user.id, eventType: 'credential.create', targetType: 'credential', targetId: id, clientId: input.clientId, detail: { collection: input.collection } });
    return json({ id, name: input.name, clientId: input.clientId, locationId: input.locationId, collection: input.collection }, 201);
  }

  const credentialMatch = path.match(/^credentials\/([0-9a-f-]+)$/u);
  if (credentialMatch && method === 'PUT') {
    const credentialId = credentialMatch[1];
    const current = await credentialById(credentialId);
    if (!current) throw new ApiProblem('Credential not found.', 404);
    const input = credentialSchema.parse(await body(request));
    await assertPermission(auth, { clientId: String(current.client_id), locationId: String(current.location_id), collection: current.collection as Collection }, 'manage');
    await assertLocation(input.clientId, input.locationId); await assertSystem(input.clientId, input.locationId, input.systemId);
    await assertPermission(auth, { clientId: input.clientId, locationId: input.locationId, collection: input.collection }, 'manage');
    const encrypted = await encryptJson(input.secret, auth.vaultKey, `credential:${credentialId}:v1`); const timestamp = nowIso();
    await run('UPDATE credentials SET client_id=?,location_id=?,system_id=?,collection=?,name=?,url=?,secret_nonce=?,secret_ciphertext=?,last_verified_at=?,expires_at=?,updated_by=?,updated_at=? WHERE id=?', input.clientId, input.locationId, input.systemId ?? null, input.collection, input.name, input.url, encrypted.nonce, encrypted.ciphertext, input.lastVerifiedAt ?? null, input.expiresAt ?? null, auth.user.id, timestamp, credentialId);
    await audit(request, { actorUserId: auth.user.id, eventType: 'credential.update', targetType: 'credential', targetId: credentialId, clientId: input.clientId });
    return json({ id: credentialId, updatedAt: timestamp });
  }
  if (credentialMatch && method === 'DELETE') {
    requireStepUp(auth);
    const credential = await credentialById(credentialMatch[1]);
    if (!credential) throw new ApiProblem('Credential not found.', 404);
    await assertPermission(auth, { clientId: String(credential.client_id), locationId: String(credential.location_id), collection: credential.collection as Collection }, 'manage');
    await run('DELETE FROM credentials WHERE id=?', credentialMatch[1]);
    await audit(request, { actorUserId: auth.user.id, eventType: 'credential.delete', targetType: 'credential', targetId: credentialMatch[1], clientId: String(credential.client_id) });
    return noContent();
  }
  const secretMatch = path.match(/^credentials\/([0-9a-f-]+)\/secret$/u);
  if (secretMatch && method === 'POST') {
    requireStepUp(auth);
    const input = z.object({ purpose: z.enum(['reveal', 'copy']) }).parse(await body(request));
    const credential = await credentialById(secretMatch[1]);
    if (!credential) throw new ApiProblem('Credential not found.', 404);
    await assertPermission(auth, { clientId: String(credential.client_id), locationId: String(credential.location_id), collection: credential.collection as Collection }, 'reveal');
    const secret = await decryptJson(credential.secret_nonce as string, credential.secret_ciphertext as string, auth.vaultKey, `credential:${secretMatch[1]}:v1`);
    await audit(request, { actorUserId: auth.user.id, eventType: `credential.${input.purpose}`, targetType: 'credential', targetId: secretMatch[1], clientId: String(credential.client_id) });
    return json({ credential: { id: secretMatch[1], name: credential.name, client_name: credential.client_name, location_name: credential.location_name }, secret });
  }

  if (path === 'users' && method === 'GET') {
    assertWorkspaceAdmin(auth);
    const users = await all<UserRow>('SELECT * FROM users ORDER BY name');
    return json(await Promise.all(users.map(publicUser)));
  }
  if (path === 'users' && method === 'POST') {
    assertWorkspaceAdmin(auth);
    const input = userSchema.parse(await body(request));
    if (await first('SELECT id FROM users WHERE email=? COLLATE NOCASE', input.email)) throw new ApiProblem('A user with that email already exists.', 409);
    const userId = newId(); const timestamp = nowIso(); const salt = base64Url(randomBytes(16));
    const wrapped = await encryptBytes(auth.vaultKey, await derivePasswordKey(input.password, salt), `user:${userId}:vault-key:v1`);
    const encryptedTotp = await encryptText(makeTotpSecret(), auth.vaultKey, `user:${userId}:totp:v1`);
    await run('INSERT INTO users(id,name,email,role,password_hash,kdf_salt,wrapped_key_nonce,wrapped_key_ciphertext,mfa_secret_nonce,mfa_secret_ciphertext,mfa_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?)', userId, input.name, input.email.toLowerCase(), input.role, await hashPassword(input.password), salt, wrapped.nonce, wrapped.ciphertext, encryptedTotp.nonce, encryptedTotp.ciphertext, timestamp, timestamp);
    await audit(request, { actorUserId: auth.user.id, eventType: 'user.create', targetType: 'user', targetId: userId, detail: { role: input.role } });
    return json(await publicUser((await getUserById(userId))!), 201);
  }
  const userMatch = path.match(/^users\/([0-9a-f-]+)$/u);
  if (userMatch && method === 'PATCH') {
    requireStepUp(auth); assertWorkspaceAdmin(auth);
    const target = await getUserById(userMatch[1]); if (!target) throw new ApiProblem('User not found.', 404);
    const input = z.object({ name: z.string().trim().min(2).max(120) }).parse(await body(request));
    await run('UPDATE users SET name=?,updated_at=? WHERE id=?', input.name, nowIso(), target.id);
    await audit(request, { actorUserId: auth.user.id, eventType: 'user.update', targetType: 'user', targetId: target.id, detail: { field: 'name' } });
    target.name = input.name; return json(await publicUser(target));
  }
  const resetMatch = path.match(/^users\/([0-9a-f-]+)\/reset-mfa$/u);
  if (resetMatch && method === 'POST') {
    requireStepUp(auth); assertWorkspaceAdmin(auth);
    const target = await getUserById(resetMatch[1]); if (!target) throw new ApiProblem('User not found.', 404);
    if (target.role === 'workspace_owner' && target.id !== auth.user.id) throw new ApiProblem('Another administrator cannot reset the workspace owner.', 403);
    const encryptedTotp = await encryptText(makeTotpSecret(), auth.vaultKey, `user:${target.id}:totp:v1`);
    await run('UPDATE users SET mfa_secret_nonce=?,mfa_secret_ciphertext=?,mfa_enabled=0,updated_at=? WHERE id=?', encryptedTotp.nonce, encryptedTotp.ciphertext, nowIso(), target.id);
    await run('DELETE FROM recovery_codes WHERE user_id=?', target.id); await run('DELETE FROM sessions WHERE user_id=?', target.id);
    await audit(request, { actorUserId: auth.user.id, eventType: 'auth.mfa_reset', targetType: 'user', targetId: target.id });
    return json({ reset: true });
  }

  if (path === 'permissions' && method === 'GET') {
    assertWorkspaceAdmin(auth);
    return json(await all('SELECT id,user_id,client_id,location_id,collection,can_view,can_manage,can_reveal,can_export,updated_at FROM permissions ORDER BY updated_at DESC'));
  }
  if (path === 'permissions' && method === 'POST') {
    requireStepUp(auth); assertWorkspaceAdmin(auth);
    const input = permissionSchema.parse(await body(request));
    if (!(await getUserById(input.userId))) throw new ApiProblem('User not found.', 404);
    if (input.locationId && !input.clientId) throw new ApiProblem('A location permission must include its client.');
    if (input.clientId && !(await first('SELECT id FROM clients WHERE id=?', input.clientId))) throw new ApiProblem('Client not found.');
    if (input.locationId) await assertLocation(input.clientId!, input.locationId);
    const scopeKey = `${input.clientId ?? '*'}|${input.locationId ?? '*'}|${input.collection ?? '*'}`; const timestamp = nowIso();
    await run(`INSERT INTO permissions(id,user_id,scope_key,client_id,location_id,collection,can_view,can_manage,can_reveal,can_export,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,scope_key) DO UPDATE SET can_view=excluded.can_view,can_manage=excluded.can_manage,can_reveal=excluded.can_reveal,can_export=excluded.can_export,updated_at=excluded.updated_at`, newId(), input.userId, scopeKey, input.clientId, input.locationId ?? null, input.collection ?? null, input.canView ? 1 : 0, input.canManage ? 1 : 0, input.canReveal ? 1 : 0, input.canExport ? 1 : 0, auth.user.id, timestamp, timestamp);
    await audit(request, { actorUserId: auth.user.id, eventType: 'permission.change', targetType: 'user', targetId: input.userId, clientId: input.clientId, detail: { scopeKey, canView: input.canView, canManage: input.canManage, canReveal: input.canReveal, canExport: input.canExport } });
    return json({ saved: true, scopeKey });
  }

  if (path === 'audit' && method === 'GET') {
    const limit = Math.min(Number(new URL(request.url).searchParams.get('limit') ?? 100) || 100, 500);
    const rows = auth.user.role === 'workspace_owner' || auth.user.role === 'admin'
      ? await all('SELECT a.*,u.name AS actor_name FROM audit_log a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.occurred_at DESC LIMIT ?', limit)
      : await all('SELECT a.*,u.name AS actor_name FROM audit_log a LEFT JOIN users u ON u.id=a.actor_user_id WHERE a.actor_user_id=? ORDER BY a.occurred_at DESC LIMIT ?', auth.user.id, limit);
    return json(rows);
  }

  if (path === 'exports/documentation' && method === 'POST') {
    requireStepUp(auth);
    const input = z.object({ clientId: z.string().uuid().nullable().optional() }).parse(await body(request));
    const ids = input.clientId ? [input.clientId] : await visibleClientIds(auth.user);
    const clients = ids === null ? await all<Record<string, unknown>>('SELECT id,name,code,notes FROM clients ORDER BY name') : ids.length ? await all<Record<string, unknown>>(`SELECT id,name,code,notes FROM clients WHERE id IN (${ids.map(() => '?').join(',')}) ORDER BY name`, ...ids) : [];
    const exported: unknown[] = [];
    for (const client of clients) {
      if (!(await hasPermission(auth.user, { clientId: String(client.id) }, 'export'))) continue;
      const locations = await all<Record<string, unknown>>('SELECT id,name,address,notes FROM locations WHERE client_id=? ORDER BY name', client.id);
      const nested = [];
      for (const location of locations) nested.push({ ...location,
        systems: await all('SELECT id,name,collection,manufacturer,model,network_address,notes FROM systems WHERE location_id=? ORDER BY name', location.id),
        assets: await all('SELECT id,system_id,asset_type,name,vendor,version_or_model,identifier,url,notes FROM assets WHERE location_id=? ORDER BY name', location.id),
        credentials: await all(`SELECT id,system_id,collection,name,url,last_verified_at,expires_at,'[OMITTED]' AS secret FROM credentials WHERE location_id=? ORDER BY name`, location.id),
      });
      exported.push({ ...client, locations: nested });
    }
    await audit(request, { actorUserId: auth.user.id, eventType: 'export.documentation', targetType: 'workspace', detail: { clientCount: exported.length, secretsIncluded: false } });
    return downloadJson({ format: 'InNasc Documentation Export v1', exportedAt: nowIso(), secretsIncluded: false, clients: exported }, `InNasc_Documentation_${nowIso().slice(0, 10)}.json`);
  }

  if (path === 'exports/backup' && method === 'POST') {
    requireStepUp(auth); assertWorkspaceAdmin(auth);
    const tables = ['users', 'recovery_codes', 'clients', 'locations', 'systems', 'assets', 'credentials', 'permissions', 'audit_log'] as const;
    const backup: Record<string, unknown> = { format: 'InNasc Hosted Encrypted Backup v1', exportedAt: nowIso(), encryptedSecrets: true };
    for (const table of tables) backup[table] = await all(`SELECT * FROM ${table}`);
    await audit(request, { actorUserId: auth.user.id, eventType: 'export.backup', targetType: 'workspace', detail: { encryptedSecrets: true, format: 'hosted_json_v1' } });
    return downloadJson(backup, `InNasc_Vault_Encrypted_Backup_${nowIso().slice(0, 10)}.json`);
  }

  if (path === 'shares/status' && method === 'GET') return json({ enabled: false, localOnly: false, message: 'Temporary public sharing is disabled while the hosted beta completes its independent security review.' });
  if (path === 'shares' && method === 'POST') {
    requireStepUp(auth);
    await audit(request, { actorUserId: auth.user.id, eventType: 'share.create', targetType: 'share', outcome: 'blocked', detail: { reason: 'hosted_beta_disabled' } });
    throw new ApiProblem('Temporary sharing is disabled in the hosted beta.', 501, 'SHARING_DISABLED');
  }

  throw new ApiProblem('Not found.', 404, 'NOT_FOUND');
}

export async function handleHostedApi(request: Request) {
  try {
    await ensureHostedSchema();
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api\/?/u, '').replace(/\/$/u, '');
    const method = request.method.toUpperCase();
    if (path === 'health' && method === 'GET') return json({ status: 'ok', service: 'InNasc Vault hosted API' });
    if (path === 'setup/status' && method === 'GET') {
      const count = await first<{ count: number }>('SELECT COUNT(*) AS count FROM users');
      return json({ setupRequired: (count?.count ?? 0) === 0, setupTokenRequired: true });
    }
    if (path === 'setup/start' && method === 'POST') return await beginSetup(request);
    if (path === 'auth/login' && method === 'POST') return await beginLogin(request);
    if (path === 'auth/mfa/verify' && method === 'POST') return await completeMfa(request);
    if ((path === 'auth/passkey/options' || path === 'auth/passkey/verify') && method === 'POST') throw new ApiProblem('Hosted passkey sign-in is not enabled in this beta.', 501, 'HOSTED_PASSKEYS_PENDING');
    const auth = await requireAuth(request);
    return await handleProtected(request, path, method, auth);
  } catch (error) {
    if (error instanceof ZodError) return json({ error: error.issues[0]?.message ?? 'Please check the information you entered.', code: 'VALIDATION_ERROR', fields: error.flatten().fieldErrors }, 400);
    if (error instanceof ApiProblem) return json({ error: error.message, code: error.code }, error.status);
    console.error('Hosted API failure', error);
    return json({ error: 'The hosted vault encountered an unexpected error.', code: 'HOSTED_API_ERROR' }, 500);
  }
}
