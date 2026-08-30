import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { Router, type NextFunction, type Request, type Response } from 'express';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';

import { audit } from './audit.js';
import {
  beginInitialSetup,
  beginLogin,
  completeLoginChallenge,
  createManagedUser,
  currentSession,
  getUserById,
  logout,
  performStepUp,
  publicUser,
  requireAuth,
  requireCsrf,
  requireStepUp,
  resetUserMfa,
  setupStatus,
} from './auth.js';
import { collections, roles, type Collection } from './config.js';
import { decryptJson, encryptJson } from './crypto.js';
import { db, newId, nowIso } from './db.js';
import {
  assertPermission,
  assertWorkspaceAdmin,
  hasPermission,
  visibleClientIds,
} from './permissions.js';
import type { AuthenticatedRequest, UserRow, VaultSecret } from './types.js';
import {
  listPasskeys,
  loginOptions,
  registrationOptions,
  stepUpOptions,
  verifyAuthentication,
  verifyRegistration,
} from './webauthn.js';

const router = Router();

const asyncRoute = (handler: (request: Request, response: Response, next: NextFunction) => Promise<unknown>) =>
  (request: Request, response: Response, next: NextFunction) => {
    void handler(request, response, next).catch(next);
  };

const strongPassword = z.string().min(14).max(256).refine(
  (value) => /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value) && /[^A-Za-z0-9]/.test(value),
  'Use at least one uppercase letter, lowercase letter, number, and symbol.',
);

const setupSchema = z.object({
  name: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(254),
  password: strongPassword,
});

const loginSchema = z.object({ email: z.string().trim().email().max(254), password: z.string().min(1).max(256) });
const mfaSchema = z.object({ challengeId: z.string().min(16).max(200), code: z.string().trim().min(6).max(32) });
const stepUpSchema = z.object({ code: z.string().trim().min(6).max(32) });
const entityName = z.string().trim().min(1).max(180);

const clientSchema = z.object({
  name: entityName,
  code: z.string().trim().max(50).default(''),
  notes: z.string().trim().max(10_000).default(''),
});

const locationSchema = z.object({
  clientId: z.string().uuid(),
  name: entityName,
  address: z.string().trim().max(500).default(''),
  notes: z.string().trim().max(10_000).default(''),
});

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

const userSchema = z.object({
  name: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(254),
  password: strongPassword,
  role: z.enum(roles).refine((role) => role !== 'workspace_owner', 'Only one workspace owner is supported in the local build.'),
});

const userNameSchema = z.object({
  name: z.string().trim().min(2).max(120),
});

const permissionSchema = z.object({
  userId: z.string().uuid(),
  clientId: z.string().uuid().nullable(),
  locationId: z.string().uuid().nullable().optional(),
  collection: z.enum(collections).nullable().optional(),
  canView: z.boolean(),
  canManage: z.boolean(),
  canReveal: z.boolean(),
  canExport: z.boolean(),
});

function authRequest(request: Request) {
  return request as AuthenticatedRequest;
}

function clientIdsFor(user: UserRow) {
  return visibleClientIds(user);
}

function visibleWhere(user: UserRow, column = 'client_id') {
  const ids = clientIdsFor(user);
  if (ids === null) return { clause: '', params: [] as string[] };
  if (!ids.length) return { clause: ' WHERE 1 = 0', params: [] as string[] };
  return { clause: ` WHERE ${column} IN (${ids.map(() => '?').join(',')})`, params: ids };
}

function assertLocation(clientId: string, locationId: string) {
  const row = db.prepare('SELECT id FROM locations WHERE id = ? AND client_id = ?').get(locationId, clientId);
  if (!row) throw Object.assign(new Error('The selected location does not belong to this client.'), { status: 400 });
}

function assertSystem(clientId: string, locationId: string, systemId?: string | null) {
  if (!systemId) return;
  const row = db.prepare('SELECT id FROM systems WHERE id = ? AND client_id = ? AND location_id = ?').get(systemId, clientId, locationId);
  if (!row) throw Object.assign(new Error('The selected system does not belong to this location.'), { status: 400 });
}

function credentialById(id: string) {
  return db.prepare(`
    SELECT c.*, cl.name AS client_name, l.name AS location_name, s.name AS system_name
    FROM credentials c
    JOIN clients cl ON cl.id = c.client_id
    JOIN locations l ON l.id = c.location_id
    LEFT JOIN systems s ON s.id = c.system_id
    WHERE c.id = ?
  `).get(id) as Record<string, unknown> | undefined;
}

router.get('/health', (_request, response) => response.json({ status: 'ok', service: 'InNasc Vault local API' }));
router.get('/setup/status', (_request, response) => response.json(setupStatus()));

router.post('/setup/start', asyncRoute(async (request, response) => {
  const input = setupSchema.parse(request.body);
  response.status(201).json(await beginInitialSetup(request, input.name, input.email, input.password));
}));

router.post('/auth/login', asyncRoute(async (request, response) => {
  const input = loginSchema.parse(request.body);
  response.json(await beginLogin(request, input.email, input.password));
}));

router.post('/auth/mfa/verify', asyncRoute(async (request, response) => {
  const input = mfaSchema.parse(request.body);
  response.json(await completeLoginChallenge(request, response, input.challengeId, input.code));
}));

router.post('/auth/passkey/options', asyncRoute(async (request, response) => {
  const input = z.object({ loginChallengeId: z.string().min(16).max(200) }).parse(request.body);
  response.json(await loginOptions(input.loginChallengeId));
}));

router.post('/auth/passkey/verify', asyncRoute(async (request, response) => {
  const input = z.object({ challengeId: z.string(), response: z.any() }).parse(request.body);
  response.json(await verifyAuthentication(request, response, input.challengeId, input.response as AuthenticationResponseJSON));
}));

router.use(requireAuth);

router.get('/session', (request, response) => response.json(currentSession(authRequest(request))));

router.post('/auth/logout', requireCsrf, (request, response) => {
  logout(authRequest(request), response);
  response.status(204).end();
});

router.post('/auth/step-up', requireCsrf, asyncRoute(async (request, response) => {
  const input = stepUpSchema.parse(request.body);
  response.json(await performStepUp(authRequest(request), input.code));
}));

router.post('/auth/passkey/step-up/options', requireCsrf, asyncRoute(async (request, response) => {
  response.json(await stepUpOptions(authRequest(request)));
}));

router.post('/auth/passkey/step-up/verify', requireCsrf, asyncRoute(async (request, response) => {
  const input = z.object({ challengeId: z.string(), response: z.any() }).parse(request.body);
  response.json(await verifyAuthentication(request, response, input.challengeId, input.response as AuthenticationResponseJSON));
}));

router.get('/passkeys', (request, response) => response.json(listPasskeys(authRequest(request).auth.user.id)));

router.post('/passkeys/register/options', requireCsrf, requireStepUp, asyncRoute(async (request, response) => {
  response.json(await registrationOptions(authRequest(request)));
}));

router.post('/passkeys/register/verify', requireCsrf, requireStepUp, asyncRoute(async (request, response) => {
  const input = z.object({ challengeId: z.string(), response: z.any(), name: z.string().trim().max(120).optional() }).parse(request.body);
  response.json(await verifyRegistration(authRequest(request), input.challengeId, input.response as RegistrationResponseJSON, input.name));
}));

router.get('/dashboard', (request, response) => {
  const auth = authRequest(request);
  const ids = clientIdsFor(auth.auth.user);
  if (ids !== null && ids.length === 0) {
    return response.json({ clients: 0, locations: 0, systems: 0, credentials: 0, recentClients: [] });
  }
  const where = ids === null ? '' : ` WHERE id IN (${ids.map(() => '?').join(',')})`;
  const childWhere = ids === null ? '' : ` WHERE client_id IN (${ids.map(() => '?').join(',')})`;
  const count = (table: string, filter: string, params: string[]) =>
    (db.prepare(`SELECT COUNT(*) AS count FROM ${table}${filter}`).get(...params) as { count: number }).count;
  const recent = db.prepare(`SELECT id, name, code, updated_at FROM clients${where} ORDER BY updated_at DESC LIMIT 5`).all(...(ids ?? []));
  return response.json({
    clients: count('clients', where, ids ?? []),
    locations: count('locations', childWhere, ids ?? []),
    systems: count('systems', childWhere, ids ?? []),
    credentials: count('credentials', childWhere, ids ?? []),
    recentClients: recent,
  });
});

router.get('/clients', (request, response) => {
  const auth = authRequest(request);
  const where = visibleWhere(auth.auth.user, 'id');
  const rows = db.prepare(`SELECT id, name, code, notes, created_at, updated_at FROM clients${where.clause} ORDER BY name`).all(...where.params);
  response.json(rows);
});

router.post('/clients', requireCsrf, (request, response) => {
  const auth = authRequest(request);
  assertWorkspaceAdmin(auth);
  const input = clientSchema.parse(request.body);
  const id = newId();
  const timestamp = nowIso();
  db.prepare('INSERT INTO clients(id, name, code, notes, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, input.name, input.code, input.notes, auth.auth.user.id, timestamp, timestamp);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'client.create', targetType: 'client', targetId: id, clientId: id });
  response.status(201).json({ id, ...input, createdAt: timestamp, updatedAt: timestamp });
});

router.get('/locations', (request, response) => {
  const auth = authRequest(request);
  const where = visibleWhere(auth.auth.user);
  response.json(db.prepare(`SELECT id, client_id, name, address, notes, created_at, updated_at FROM locations${where.clause} ORDER BY name`).all(...where.params));
});

router.post('/locations', requireCsrf, (request, response) => {
  const auth = authRequest(request);
  const input = locationSchema.parse(request.body);
  assertPermission(auth, { clientId: input.clientId }, 'manage');
  const id = newId();
  const timestamp = nowIso();
  db.prepare('INSERT INTO locations(id, client_id, name, address, notes, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, input.clientId, input.name, input.address, input.notes, auth.auth.user.id, timestamp, timestamp);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'location.create', targetType: 'location', targetId: id, clientId: input.clientId });
  response.status(201).json({ id, ...input, createdAt: timestamp, updatedAt: timestamp });
});

router.get('/systems', (request, response) => {
  const auth = authRequest(request);
  const where = visibleWhere(auth.auth.user);
  const rows = db.prepare(`SELECT id, client_id, location_id, name, collection, manufacturer, model, network_address, notes, created_at, updated_at FROM systems${where.clause} ORDER BY name`).all(...where.params) as Array<Record<string, unknown>>;
  response.json(rows.filter((row) => hasPermission(auth.auth.user, { clientId: String(row.client_id), locationId: String(row.location_id), collection: row.collection as Collection }, 'view')));
});

router.post('/systems', requireCsrf, (request, response) => {
  const auth = authRequest(request);
  const input = systemSchema.parse(request.body);
  assertLocation(input.clientId, input.locationId);
  assertPermission(auth, { clientId: input.clientId, locationId: input.locationId, collection: input.collection }, 'manage');
  const id = newId();
  const timestamp = nowIso();
  db.prepare(`INSERT INTO systems(id, client_id, location_id, name, collection, manufacturer, model, network_address, notes, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, input.clientId, input.locationId, input.name, input.collection, input.manufacturer, input.model, input.networkAddress, input.notes, auth.auth.user.id, timestamp, timestamp);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'system.create', targetType: 'system', targetId: id, clientId: input.clientId, detail: { collection: input.collection } });
  response.status(201).json({ id, ...input, createdAt: timestamp, updatedAt: timestamp });
});

router.get('/assets', (request, response) => {
  const auth = authRequest(request);
  const where = visibleWhere(auth.auth.user, 'a.client_id');
  const rows = db.prepare(`
    SELECT a.*, cl.name AS client_name, l.name AS location_name, s.name AS system_name
    FROM assets a JOIN clients cl ON cl.id = a.client_id JOIN locations l ON l.id = a.location_id
    LEFT JOIN systems s ON s.id = a.system_id${where.clause} ORDER BY a.name
  `).all(...where.params) as Array<Record<string, unknown>>;
  response.json(rows.filter((row) => hasPermission(auth.auth.user, { clientId: String(row.client_id), locationId: String(row.location_id) }, 'view')));
});

router.post('/assets', requireCsrf, (request, response) => {
  const auth = authRequest(request);
  const input = assetSchema.parse(request.body);
  assertLocation(input.clientId, input.locationId);
  assertSystem(input.clientId, input.locationId, input.systemId);
  assertPermission(auth, { clientId: input.clientId, locationId: input.locationId }, 'manage');
  const id = newId();
  const timestamp = nowIso();
  db.prepare(`INSERT INTO assets(id, client_id, location_id, system_id, asset_type, name, vendor, version_or_model, identifier, url, notes, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, input.clientId, input.locationId, input.systemId ?? null, input.assetType, input.name, input.vendor, input.versionOrModel, input.identifier, input.url, input.notes, auth.auth.user.id, timestamp, timestamp);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'asset.create', targetType: input.assetType, targetId: id, clientId: input.clientId });
  response.status(201).json({ id, ...input, createdAt: timestamp, updatedAt: timestamp });
});

router.get('/credentials', (request, response) => {
  const auth = authRequest(request);
  const where = visibleWhere(auth.auth.user, 'c.client_id');
  const rows = db.prepare(`
    SELECT c.id, c.client_id, c.location_id, c.system_id, c.collection, c.name, c.url,
      c.last_verified_at, c.expires_at, c.created_at, c.updated_at,
      cl.name AS client_name, l.name AS location_name, s.name AS system_name
    FROM credentials c JOIN clients cl ON cl.id = c.client_id JOIN locations l ON l.id = c.location_id
    LEFT JOIN systems s ON s.id = c.system_id${where.clause} ORDER BY c.updated_at DESC
  `).all(...where.params) as Array<Record<string, unknown>>;
  response.json(rows.filter((row) => hasPermission(auth.auth.user, { clientId: String(row.client_id), locationId: String(row.location_id), collection: row.collection as Collection }, 'view')));
});

router.post('/credentials', requireCsrf, (request, response) => {
  const auth = authRequest(request);
  const input = credentialSchema.parse(request.body);
  assertLocation(input.clientId, input.locationId);
  assertSystem(input.clientId, input.locationId, input.systemId);
  assertPermission(auth, { clientId: input.clientId, locationId: input.locationId, collection: input.collection }, 'manage');
  const id = newId();
  const encrypted = encryptJson(input.secret, auth.auth.vaultKey, `credential:${id}:v1`);
  const timestamp = nowIso();
  db.prepare(`
    INSERT INTO credentials(id, client_id, location_id, system_id, collection, name, url,
      secret_nonce, secret_ciphertext, last_verified_at, expires_at, created_by, updated_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, input.clientId, input.locationId, input.systemId ?? null, input.collection, input.name, input.url, encrypted.nonce, encrypted.ciphertext, input.lastVerifiedAt ?? null, input.expiresAt ?? null, auth.auth.user.id, auth.auth.user.id, timestamp, timestamp);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'credential.create', targetType: 'credential', targetId: id, clientId: input.clientId, detail: { collection: input.collection } });
  response.status(201).json({ id, name: input.name, clientId: input.clientId, locationId: input.locationId, collection: input.collection });
});

router.put('/credentials/:id', requireCsrf, (request, response) => {
  const auth = authRequest(request);
  const credentialId = String(request.params.id);
  const current = credentialById(credentialId);
  if (!current) return response.status(404).json({ error: 'Credential not found.' });
  const input = credentialSchema.parse(request.body);
  assertPermission(auth, { clientId: String(current.client_id), locationId: String(current.location_id), collection: current.collection as Collection }, 'manage');
  assertLocation(input.clientId, input.locationId);
  assertSystem(input.clientId, input.locationId, input.systemId);
  const encrypted = encryptJson(input.secret, auth.auth.vaultKey, `credential:${credentialId}:v1`);
  const timestamp = nowIso();
  db.prepare(`UPDATE credentials SET client_id=?, location_id=?, system_id=?, collection=?, name=?, url=?, secret_nonce=?, secret_ciphertext=?, last_verified_at=?, expires_at=?, updated_by=?, updated_at=? WHERE id=?`).run(input.clientId, input.locationId, input.systemId ?? null, input.collection, input.name, input.url, encrypted.nonce, encrypted.ciphertext, input.lastVerifiedAt ?? null, input.expiresAt ?? null, auth.auth.user.id, timestamp, credentialId);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'credential.update', targetType: 'credential', targetId: credentialId, clientId: input.clientId });
  return response.json({ id: credentialId, updatedAt: timestamp });
});

router.post('/credentials/:id/secret', requireCsrf, requireStepUp, (request, response) => {
  const auth = authRequest(request);
  const input = z.object({ purpose: z.enum(['reveal', 'copy']) }).parse(request.body);
  const credentialId = String(request.params.id);
  const credential = credentialById(credentialId);
  if (!credential) return response.status(404).json({ error: 'Credential not found.' });
  assertPermission(auth, { clientId: String(credential.client_id), locationId: String(credential.location_id), collection: credential.collection as Collection }, 'reveal');
  const secret = decryptJson<VaultSecret>(String(credential.secret_nonce), String(credential.secret_ciphertext), auth.auth.vaultKey, `credential:${credentialId}:v1`);
  audit({ request, actorUserId: auth.auth.user.id, eventType: `credential.${input.purpose}`, targetType: 'credential', targetId: credentialId, clientId: String(credential.client_id) });
  return response.json({ secret });
});

router.delete('/credentials/:id', requireCsrf, requireStepUp, (request, response) => {
  const auth = authRequest(request);
  const credentialId = String(request.params.id);
  const credential = credentialById(credentialId);
  if (!credential) return response.status(404).json({ error: 'Credential not found.' });
  assertPermission(auth, { clientId: String(credential.client_id), locationId: String(credential.location_id), collection: credential.collection as Collection }, 'manage');
  db.prepare('DELETE FROM credentials WHERE id = ?').run(credentialId);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'credential.delete', targetType: 'credential', targetId: credentialId, clientId: String(credential.client_id) });
  return response.status(204).end();
});

router.get('/users', (request, response) => {
  const auth = authRequest(request);
  assertWorkspaceAdmin(auth);
  const users = db.prepare('SELECT id FROM users ORDER BY name').all() as Array<{ id: string }>;
  response.json(users.map((item) => publicUser(getUserById(item.id)!)));
});

router.post('/users', requireCsrf, asyncRoute(async (request, response) => {
  const auth = authRequest(request);
  assertWorkspaceAdmin(auth);
  const input = userSchema.parse(request.body);
  response.status(201).json(await createManagedUser(auth, input));
}));

router.patch('/users/:id', requireCsrf, requireStepUp, (request, response) => {
  const auth = authRequest(request);
  assertWorkspaceAdmin(auth);
  const target = getUserById(String(request.params.id));
  if (!target) return response.status(404).json({ error: 'User not found.' });
  const input = userNameSchema.parse(request.body);
  const previousName = target.name;
  db.prepare('UPDATE users SET name = ?, updated_at = ? WHERE id = ?').run(input.name, nowIso(), target.id);
  audit({
    request,
    actorUserId: auth.auth.user.id,
    eventType: 'user.update',
    targetType: 'user',
    targetId: target.id,
    detail: { field: 'name', previousName, name: input.name },
  });
  return response.json(publicUser(getUserById(target.id)!));
});

router.post('/users/:id/reset-mfa', requireCsrf, requireStepUp, (request, response) => {
  const auth = authRequest(request);
  assertWorkspaceAdmin(auth);
  const target = getUserById(String(request.params.id));
  if (!target) return response.status(404).json({ error: 'User not found.' });
  if (target.role === 'workspace_owner' && target.id !== auth.auth.user.id) return response.status(403).json({ error: 'Another administrator cannot reset the workspace owner.' });
  resetUserMfa(target, auth.auth.vaultKey);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'auth.mfa_reset', targetType: 'user', targetId: target.id });
  return response.json({ reset: true });
});

router.get('/permissions', (request, response) => {
  const auth = authRequest(request);
  assertWorkspaceAdmin(auth);
  response.json(db.prepare(`SELECT id, user_id, client_id, location_id, collection, can_view, can_manage, can_reveal, can_export, updated_at FROM permissions ORDER BY updated_at DESC`).all());
});

router.post('/permissions', requireCsrf, requireStepUp, (request, response) => {
  const auth = authRequest(request);
  assertWorkspaceAdmin(auth);
  const input = permissionSchema.parse(request.body);
  const target = getUserById(input.userId);
  if (!target) return response.status(404).json({ error: 'User not found.' });
  if (input.locationId && !input.clientId) return response.status(400).json({ error: 'A location permission must include its client.' });
  if (input.clientId && !db.prepare('SELECT id FROM clients WHERE id = ?').get(input.clientId)) return response.status(400).json({ error: 'Client not found.' });
  if (input.locationId) assertLocation(input.clientId!, input.locationId);
  const scopeKey = `${input.clientId ?? '*'}|${input.locationId ?? '*'}|${input.collection ?? '*'}`;
  const timestamp = nowIso();
  db.prepare(`
    INSERT INTO permissions(id, user_id, scope_key, client_id, location_id, collection, can_view, can_manage, can_reveal, can_export, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, scope_key) DO UPDATE SET
      can_view=excluded.can_view, can_manage=excluded.can_manage, can_reveal=excluded.can_reveal,
      can_export=excluded.can_export, updated_at=excluded.updated_at
  `).run(newId(), input.userId, scopeKey, input.clientId, input.locationId ?? null, input.collection ?? null, input.canView ? 1 : 0, input.canManage ? 1 : 0, input.canReveal ? 1 : 0, input.canExport ? 1 : 0, auth.auth.user.id, timestamp, timestamp);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'permission.change', targetType: 'user', targetId: input.userId, clientId: input.clientId, detail: { scopeKey, canView: input.canView, canManage: input.canManage, canReveal: input.canReveal, canExport: input.canExport } });
  return response.json({ saved: true, scopeKey });
});

router.get('/audit', (request, response) => {
  const auth = authRequest(request);
  const limit = Math.min(Number(request.query.limit ?? 100) || 100, 500);
  const admin = auth.auth.user.role === 'workspace_owner' || auth.auth.user.role === 'admin';
  const rows = admin
    ? db.prepare(`SELECT a.*, u.name AS actor_name FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id ORDER BY a.occurred_at DESC LIMIT ?`).all(limit)
    : db.prepare(`SELECT a.*, u.name AS actor_name FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id WHERE a.actor_user_id = ? ORDER BY a.occurred_at DESC LIMIT ?`).all(auth.auth.user.id, limit);
  response.json(rows);
});

router.post('/exports/documentation', requireCsrf, requireStepUp, (request, response) => {
  const auth = authRequest(request);
  const input = z.object({ clientId: z.string().uuid().nullable().optional() }).parse(request.body);
  const ids = input.clientId ? [input.clientId] : clientIdsFor(auth.auth.user);
  const clients = (ids === null
    ? db.prepare('SELECT id, name, code, notes FROM clients ORDER BY name').all()
    : ids.length
      ? db.prepare(`SELECT id, name, code, notes FROM clients WHERE id IN (${ids.map(() => '?').join(',')}) ORDER BY name`).all(...ids)
      : []) as Array<Record<string, unknown>>;
  const exported = clients.filter((client) => hasPermission(auth.auth.user, { clientId: String(client.id) }, 'export')).map((client) => {
    const locations = db.prepare('SELECT id, name, address, notes FROM locations WHERE client_id = ? ORDER BY name').all(client.id) as Array<Record<string, unknown>>;
    return {
      ...client,
      locations: locations.map((location) => ({
        ...location,
        systems: db.prepare('SELECT id, name, collection, manufacturer, model, network_address, notes FROM systems WHERE location_id = ? ORDER BY name').all(location.id),
        assets: db.prepare('SELECT id, system_id, asset_type, name, vendor, version_or_model, identifier, url, notes FROM assets WHERE location_id = ? ORDER BY name').all(location.id),
        credentials: db.prepare(`SELECT id, system_id, collection, name, url, last_verified_at, expires_at, '[OMITTED]' AS secret FROM credentials WHERE location_id = ? ORDER BY name`).all(location.id),
      })),
    };
  });
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'export.documentation', targetType: 'workspace', detail: { clientCount: exported.length, secretsIncluded: false } });
  response.setHeader('Content-Disposition', `attachment; filename="InNasc_Documentation_${new Date().toISOString().slice(0, 10)}.json"`);
  response.json({ format: 'InNasc Documentation Export v1', exportedAt: nowIso(), secretsIncluded: false, clients: exported });
});

router.post('/exports/backup', requireCsrf, requireStepUp, asyncRoute(async (request, response) => {
  const auth = authRequest(request);
  assertWorkspaceAdmin(auth);
  const backupPath = path.join(os.tmpdir(), `InNasc_Vault_Backup_${Date.now()}_${newId()}.sqlite3`);
  await db.backup(backupPath);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'export.backup', targetType: 'workspace', detail: { encryptedSecrets: true } });
  response.download(backupPath, `InNasc_Vault_Backup_${new Date().toISOString().slice(0, 10)}.sqlite3`, (error) => {
    fs.rm(backupPath, { force: true }, () => undefined);
    if (error && !response.headersSent) response.status(500).json({ error: 'Backup download failed.' });
  });
}));

router.get('/shares/status', (_request, response) => {
  response.json({ enabled: false, localOnly: true, message: 'Temporary sharing is disabled in the local build because localhost links cannot be shared safely.' });
});

router.post('/shares', requireCsrf, requireStepUp, (request, response) => {
  const auth = authRequest(request);
  audit({ request, actorUserId: auth.auth.user.id, eventType: 'share.create', targetType: 'share', outcome: 'blocked', detail: { reason: 'local_build_disabled' } });
  response.status(501).json({ error: 'Temporary sharing is disabled in this local build.', code: 'LOCAL_ONLY_DISABLED' });
});

export { router };
