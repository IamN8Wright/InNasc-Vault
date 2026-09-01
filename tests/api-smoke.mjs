import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import Database from 'better-sqlite3';
import { generate } from 'otplib';
import { PDFDocument } from 'pdf-lib';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'innasc-vault-test-'));
const databasePath = path.join(tempDir, 'vault.sqlite3');
const port = 3888;
const base = `http://localhost:${port}/api`;
const origin = 'http://localhost:3000';
const password = `A!a1${crypto.randomBytes(18).toString('base64url')}`;
const testSecret = `synthetic-${crypto.randomBytes(18).toString('base64url')}`;
let cookie = '';
let csrfToken = '';

const server = spawn(process.execPath, ['dist/local-server/index.js'], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    INNASC_API_PORT: String(port),
    INNASC_UI_PORT: '3000',
    INNASC_DATA_DIR: tempDir,
    INNASC_DB_PATH: databasePath,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let serverOutput = '';
server.stdout.on('data', (chunk) => { serverOutput += chunk.toString(); });
server.stderr.on('data', (chunk) => { serverOutput += chunk.toString(); });

async function request(pathname, options = {}) {
  const headers = new Headers(options.headers);
  headers.set('Origin', origin);
  if (options.body) headers.set('Content-Type', 'application/json');
  if (cookie) headers.set('Cookie', cookie);
  const response = await fetch(`${base}${pathname}`, { ...options, headers });
  const setCookie = response.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json') ? await response.json() : await response.arrayBuffer();
  return { response, body };
}

async function waitForServer() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const result = await request('/health');
      if (result.response.ok) return;
    } catch {
      // Server is still starting.
    }
    await delay(250);
  }
  throw new Error(`Local API did not start.\n${serverOutput}`);
}

try {
  await waitForServer();

  const setup = await request('/setup/start', {
    method: 'POST',
    body: JSON.stringify({ name: 'Automated Test Owner', email: 'owner@example.invalid', password }),
  });
  assert.equal(setup.response.status, 201);
  assert.equal(setup.body.kind, 'enrollment');
  assert.ok(setup.body.manualKey);

  const token = await generate({ secret: setup.body.manualKey });
  const verified = await request('/auth/mfa/verify', {
    method: 'POST',
    body: JSON.stringify({ challengeId: setup.body.challengeId, code: token }),
  });
  assert.equal(verified.response.status, 200);
  assert.equal(verified.body.user.role, 'workspace_owner');
  assert.equal(verified.body.recoveryCodes.length, 10);
  csrfToken = verified.body.csrfToken;

  const secured = (body) => ({
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body: JSON.stringify(body),
  });

  const client = await request('/clients', secured({ name: 'Automated Test Client', code: 'TEST', notes: '' }));
  assert.equal(client.response.status, 201);

  const userAdminStepUpToken = await generate({ secret: setup.body.manualKey });
  const userAdminStepUp = await request('/auth/step-up', secured({ code: userAdminStepUpToken }));
  assert.equal(userAdminStepUp.response.status, 200);

  const ownerCookie = cookie;
  const ownerCsrfToken = csrfToken;
  const clientAdminPassword = `A!a1${crypto.randomBytes(18).toString('base64url')}`;
  const clientAdmin = await request('/users', secured({
    name: 'Automated Client Admin',
    email: 'client-admin@example.invalid',
    password: clientAdminPassword,
    role: 'client_admin',
    clientId: client.body.id,
    canView: true,
    canManage: true,
    canReveal: true,
    canExport: true,
  }));
  assert.equal(clientAdmin.response.status, 201);
  assert.deepEqual(clientAdmin.body.clientIds, [client.body.id]);
  assert.equal(clientAdmin.body.mustChangePassword, true);
  assert.deepEqual(clientAdmin.body.welcomeEmail, { configured: false, sent: false });

  cookie = '';
  const clientAdminLogin = await request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email: 'client-admin@example.invalid', password: clientAdminPassword }),
  });
  assert.equal(clientAdminLogin.response.status, 200);
  assert.equal(clientAdminLogin.body.kind, 'enrollment');
  const clientAdminEnrollmentCode = await generate({ secret: clientAdminLogin.body.manualKey });
  const clientAdminVerified = await request('/auth/mfa/verify', {
    method: 'POST',
    body: JSON.stringify({ challengeId: clientAdminLogin.body.challengeId, code: clientAdminEnrollmentCode }),
  });
  assert.equal(clientAdminVerified.response.status, 200);
  csrfToken = clientAdminVerified.body.csrfToken;
  assert.equal(clientAdminVerified.body.user.mustChangePassword, true);
  const blockedBeforePasswordChange = await request('/dashboard');
  assert.equal(blockedBeforePasswordChange.response.status, 428);
  assert.equal(blockedBeforePasswordChange.body.code, 'PASSWORD_CHANGE_REQUIRED');
  const clientAdminPrivatePassword = `P!v4${crypto.randomBytes(18).toString('base64url')}`;
  const changedClientAdminPassword = await request('/auth/change-temporary-password', secured({ password: clientAdminPrivatePassword }));
  assert.equal(changedClientAdminPassword.response.status, 200);
  assert.equal(changedClientAdminPassword.body.user.mustChangePassword, false);
  const clientAdminStepUpCode = await generate({ secret: clientAdminLogin.body.manualKey });
  const clientAdminStepUp = await request('/auth/step-up', secured({ code: clientAdminStepUpCode }));
  assert.equal(clientAdminStepUp.response.status, 200);

  const forbiddenAdmin = await request('/users', secured({
    name: 'Forbidden Admin',
    email: 'forbidden-admin@example.invalid',
    password: clientAdminPassword,
    role: 'admin',
    clientId: null,
    canView: false,
    canManage: false,
    canReveal: false,
    canExport: false,
  }));
  assert.equal(forbiddenAdmin.response.status, 403);

  const clientUserPassword = `A!a1${crypto.randomBytes(18).toString('base64url')}`;
  const clientUser = await request('/users', secured({
    name: 'Automated Client User',
    email: 'client-user@example.invalid',
    password: clientUserPassword,
    role: 'client_user',
    clientId: client.body.id,
    canView: true,
    canManage: false,
    canReveal: true,
    canExport: false,
  }));
  assert.equal(clientUser.response.status, 201);
  assert.equal(clientUser.body.role, 'client_user');
  assert.deepEqual(clientUser.body.clientIds, [client.body.id]);
  assert.equal(clientUser.body.mustChangePassword, true);

  const updatedClientUser = await request(`/users/${clientUser.body.id}`, {
    ...secured({ name: 'Updated Client User', email: 'updated-client-user@example.invalid' }),
    method: 'PATCH',
  });
  assert.equal(updatedClientUser.response.status, 200);
  assert.equal(updatedClientUser.body.email, 'updated-client-user@example.invalid');

  const removedClientUser = await request(`/users/${clientUser.body.id}`, { ...secured({}), method: 'DELETE' });
  assert.equal(removedClientUser.response.status, 200);
  const removedUsers = await request('/users');
  assert.ok(removedUsers.body.find((user) => user.id === clientUser.body.id)?.disabledAt);

  const restoredClientUser = await request(`/users/${clientUser.body.id}/restore`, secured({}));
  assert.equal(restoredClientUser.response.status, 200);
  assert.equal(restoredClientUser.body.disabledAt, null);
  assert.equal(restoredClientUser.body.mfaEnabled, false);

  cookie = ownerCookie;
  csrfToken = ownerCsrfToken;
  const sessionDatabase = new Database(databasePath);
  sessionDatabase.prepare('UPDATE sessions SET step_up_until = NULL WHERE user_id = ?').run(verified.body.user.id);
  sessionDatabase.close();

  const location = await request('/locations', secured({ clientId: client.body.id, name: 'Test Location', address: '', notes: '' }));
  assert.equal(location.response.status, 201);

  const system = await request('/systems', secured({
    clientId: client.body.id,
    locationId: location.body.id,
    name: 'Test Network System',
    collection: 'network',
    manufacturer: '',
    model: '',
    networkAddress: '192.0.2.10',
    notes: '',
  }));
  assert.equal(system.response.status, 201);

  const credential = await request('/credentials', secured({
    clientId: client.body.id,
    locationId: location.body.id,
    systemId: system.body.id,
    collection: 'network',
    name: 'Synthetic Test Credential',
    url: 'https://192.0.2.10',
    lastVerifiedAt: null,
    expiresAt: null,
    secret: { username: 'test-user', password: testSecret, pin: '', apiToken: '', licenseKey: '', notes: 'synthetic only' },
  }));
  assert.equal(credential.response.status, 201);

  const blockedReveal = await request(`/credentials/${credential.body.id}/secret`, secured({ purpose: 'reveal' }));
  assert.equal(blockedReveal.response.status, 428);
  assert.equal(blockedReveal.body.code, 'STEP_UP_REQUIRED');

  const stepUpToken = await generate({ secret: setup.body.manualKey });
  const stepUp = await request('/auth/step-up', secured({ code: stepUpToken }));
  assert.equal(stepUp.response.status, 200);

  const demotedAdmin = await request(`/users/${clientAdmin.body.id}`, {
    ...secured({ name: 'Automated Client Admin', email: 'client-admin@example.invalid', role: 'client_user', clientId: client.body.id }),
    method: 'PATCH',
  });
  assert.equal(demotedAdmin.response.status, 200);
  assert.equal(demotedAdmin.body.role, 'client_user');
  assert.deepEqual(demotedAdmin.body.clientIds, [client.body.id]);

  const removedMistake = await request(`/users/${clientUser.body.id}`, { ...secured({}), method: 'DELETE' });
  assert.equal(removedMistake.response.status, 200);
  const rejectedPermanentDelete = await request(`/users/${clientUser.body.id}/permanent`, { ...secured({ confirmation: 'wrong@example.invalid' }), method: 'DELETE' });
  assert.equal(rejectedPermanentDelete.response.status, 400);
  const permanentlyDeleted = await request(`/users/${clientUser.body.id}/permanent`, { ...secured({ confirmation: 'updated-client-user@example.invalid' }), method: 'DELETE' });
  assert.equal(permanentlyDeleted.response.status, 200);
  assert.equal(permanentlyDeleted.body.deleted, true);
  const usersAfterPermanentDelete = await request('/users');
  assert.equal(usersAfterPermanentDelete.body.some((user) => user.id === clientUser.body.id), false);
  const tombstoneDatabase = new Database(databasePath, { readonly: true });
  const tombstone = tombstoneDatabase.prepare('SELECT name,email,permanently_deleted_at FROM users WHERE id=?').get(clientUser.body.id);
  assert.equal(tombstone.name, 'Deleted user');
  assert.ok(tombstone.email.endsWith('@innasc.invalid'));
  assert.ok(tombstone.permanently_deleted_at);
  tombstoneDatabase.close();

  const existingUserWelcome = await request(`/users/${clientAdmin.body.id}/resend-welcome`, secured({}));
  assert.equal(existingUserWelcome.response.status, 503);
  assert.equal(existingUserWelcome.body.code, 'EMAIL_NOT_CONFIGURED');

  const renamedOwner = await request(`/users/${verified.body.user.id}`, {
    ...secured({ name: 'Renamed Automated Owner', email: 'renamed-owner@example.invalid' }),
    method: 'PATCH',
  });
  assert.equal(renamedOwner.response.status, 200);
  assert.equal(renamedOwner.body.name, 'Renamed Automated Owner');
  assert.equal(renamedOwner.body.email, 'renamed-owner@example.invalid');

  const reveal = await request(`/credentials/${credential.body.id}/secret`, secured({ purpose: 'reveal' }));
  assert.equal(reveal.response.status, 200);
  assert.equal(reveal.body.secret.password, testSecret);

  const documentation = await request('/exports/documentation', secured({ clientId: client.body.id }));
  assert.equal(documentation.response.status, 200);
  const exportText = JSON.stringify(documentation.body);
  assert.equal(exportText.includes(testSecret), false);
  assert.equal(documentation.body.secretsIncluded, false);

  const rejectedOffboarding = await request('/exports/offboarding', secured({ clientId: client.body.id, acknowledged: false }));
  assert.equal(rejectedOffboarding.response.status, 400);
  const offboarding = await request('/exports/offboarding', secured({ clientId: client.body.id, acknowledged: true }));
  assert.equal(offboarding.response.status, 200);
  assert.match(offboarding.response.headers.get('content-type') ?? '', /^application\/pdf/u);
  assert.match(offboarding.response.headers.get('content-disposition') ?? '', /InNasc_Offboarding_.*\.pdf/u);
  const offboardingBytes = new Uint8Array(offboarding.body);
  assert.equal(new TextDecoder().decode(offboardingBytes.slice(0, 5)), '%PDF-');
  const offboardingPdf = await PDFDocument.load(offboardingBytes);
  assert.ok(offboardingPdf.getPageCount() > 0);
  assert.equal(offboardingPdf.getTitle(), 'InNasc Vault Offboarding Export');

  const audit = await request('/audit');
  assert.equal(audit.response.status, 200);
  assert.ok(audit.body.some((entry) => entry.event_type === 'credential.reveal'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'export.documentation'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'export.offboarding'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.update'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.remove'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.restore'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.permanent_delete'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.welcome_email'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'auth.temporary_password_changed'));
  assert.equal(JSON.stringify(audit.body).includes(testSecret), false);

  const sqlite = new Database(databasePath, { readonly: true });
  const stored = sqlite.prepare('SELECT secret_ciphertext FROM credentials WHERE id = ?').get(credential.body.id);
  assert.ok(stored.secret_ciphertext);
  assert.equal(stored.secret_ciphertext.includes(testSecret), false);
  sqlite.close();

  console.log('PASS: encryption, MFA, forced password onboarding, scoped Client Admin users, user editing/removal, safe/offboarding exports, and audit smoke test');
} finally {
  server.kill('SIGTERM');
  await Promise.race([new Promise((resolve) => server.once('exit', resolve)), delay(3000)]);
  fs.rmSync(tempDir, { recursive: true, force: true });
}
