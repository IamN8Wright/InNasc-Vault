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

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'innasc-vault-railway-test-'));
const port = 3999;
const base = `http://127.0.0.1:${port}/api`;
const password = `A!a1${crypto.randomBytes(18).toString('base64url')}`;
const setupToken = `setup-${crypto.randomBytes(24).toString('base64url')}`;
const testSecret = `synthetic-${crypto.randomBytes(18).toString('base64url')}`;
let cookie = '';
let csrfToken = '';

const server = spawn(process.execPath, ['node_modules/vinext/dist/cli.js', 'start', '--port', String(port)], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    PORT: String(port),
    RAILWAY_VOLUME_MOUNT_PATH: tempDir,
    INNASC_SERVER_KEY: crypto.randomBytes(32).toString('base64url'),
    INNASC_SETUP_TOKEN: setupToken,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let serverOutput = '';
server.stdout.on('data', (chunk) => { serverOutput += chunk.toString(); });
server.stderr.on('data', (chunk) => { serverOutput += chunk.toString(); });

async function request(pathname, options = {}) {
  const headers = new Headers();
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  if (cookie) headers.set('Cookie', cookie);
  if (options.csrf) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(`${base}${pathname}`, {
    method: options.method ?? 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const setCookie = response.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json')
    ? await response.json()
    : contentType.includes('application/pdf')
      ? await response.arrayBuffer()
      : await response.text();
  return { response, body };
}

async function waitForServer() {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const result = await request('/health');
      if (result.response.ok) return;
    } catch {
      // Production server is still starting.
    }
    await delay(250);
  }
  throw new Error(`Railway-style server did not start.\n${serverOutput}`);
}

try {
  await waitForServer();

  const status = await request('/setup/status');
  assert.equal(status.body.setupRequired, true);
  assert.equal(status.body.setupTokenRequired, true);

  const rejectedSetup = await request('/setup/start', {
    method: 'POST',
    body: { name: 'Rejected Owner', email: 'rejected-owner@example.invalid', password, setupToken: 'invalid-setup-token' },
  });
  assert.equal(rejectedSetup.response.status, 403);
  assert.equal(rejectedSetup.body.code, 'SETUP_TOKEN_INVALID');
  const statusAfterRejectedSetup = await request('/setup/status');
  assert.equal(statusAfterRejectedSetup.body.setupRequired, true);

  const setup = await request('/setup/start', {
    method: 'POST',
    body: { name: 'Automated Railway Owner', email: 'railway-owner@example.invalid', password, setupToken },
  });
  assert.equal(setup.response.status, 201);
  assert.equal(setup.body.kind, 'enrollment');
  assert.ok(setup.body.manualKey);

  const interruptedStatus = await request('/setup/status');
  assert.equal(interruptedStatus.body.setupRequired, true);
  assert.equal(interruptedStatus.body.setupIncomplete, true);
  const resumedSetup = await request('/setup/start', {
    method: 'POST',
    body: { name: 'Resumed Railway Owner', email: 'resumed-owner@example.invalid', password, setupToken },
  });
  assert.equal(resumedSetup.response.status, 201);
  assert.equal(resumedSetup.body.kind, 'enrollment');
  assert.ok(resumedSetup.body.manualKey);

  const enrollmentCode = await generate({ secret: resumedSetup.body.manualKey });
  const verified = await request('/auth/mfa/verify', {
    method: 'POST',
    body: { challengeId: resumedSetup.body.challengeId, code: enrollmentCode },
  });
  assert.equal(verified.response.status, 200);
  assert.equal(verified.body.user.role, 'workspace_owner');
  csrfToken = verified.body.csrfToken;
  assert.ok(cookie.startsWith('innasc_session='));

  const completedStatus = await request('/setup/status');
  assert.equal(completedStatus.body.setupRequired, false);
  assert.equal(completedStatus.body.setupIncomplete, false);

  const stepUpCode = await generate({ secret: resumedSetup.body.manualKey });
  const stepUp = await request('/auth/step-up', { method: 'POST', body: { code: stepUpCode }, csrf: true });
  assert.equal(stepUp.response.status, 200);

  const client = await request('/clients', {
    method: 'POST',
    body: { name: 'Synthetic Test Client', code: 'TEST', notes: 'No real client data.' },
    csrf: true,
  });
  assert.equal(client.response.status, 201);

  const hostedClientUserPassword = `A!a1${crypto.randomBytes(18).toString('base64url')}`;
  const hostedClientUser = await request('/users', {
    method: 'POST',
    body: {
      name: 'Hosted Client User',
      email: 'hosted-client-user@example.invalid',
      password: hostedClientUserPassword,
      role: 'client_user',
      clientId: client.body.id,
      canView: true,
      canManage: false,
      canReveal: true,
      canExport: false,
    },
    csrf: true,
  });
  assert.equal(hostedClientUser.response.status, 201);
  assert.deepEqual(hostedClientUser.body.clientIds, [client.body.id]);
  assert.equal(hostedClientUser.body.mustChangePassword, true);
  assert.deepEqual(hostedClientUser.body.welcomeEmail, { configured: false, sent: false });

  const missingEmailConfiguration = await request(`/users/${hostedClientUser.body.id}/resend-welcome`, { method: 'POST', body: {}, csrf: true });
  assert.equal(missingEmailConfiguration.response.status, 503);
  assert.equal(missingEmailConfiguration.body.code, 'EMAIL_NOT_CONFIGURED');

  const ownerCookie = cookie;
  const ownerCsrfToken = csrfToken;
  cookie = '';
  const hostedClientUserLogin = await request('/auth/login', {
    method: 'POST',
    body: { email: 'hosted-client-user@example.invalid', password: hostedClientUserPassword },
  });
  assert.equal(hostedClientUserLogin.response.status, 200);
  assert.equal(hostedClientUserLogin.body.kind, 'enrollment');
  const hostedClientUserMfa = await generate({ secret: hostedClientUserLogin.body.manualKey });
  const hostedClientUserVerified = await request('/auth/mfa/verify', {
    method: 'POST',
    body: { challengeId: hostedClientUserLogin.body.challengeId, code: hostedClientUserMfa },
  });
  assert.equal(hostedClientUserVerified.response.status, 200);
  csrfToken = hostedClientUserVerified.body.csrfToken;
  const hostedBlockedBeforePasswordChange = await request('/dashboard');
  assert.equal(hostedBlockedBeforePasswordChange.response.status, 428);
  assert.equal(hostedBlockedBeforePasswordChange.body.code, 'PASSWORD_CHANGE_REQUIRED');
  const hostedPrivatePassword = `P!v4${crypto.randomBytes(18).toString('base64url')}`;
  const hostedPasswordChanged = await request('/auth/change-temporary-password', { method: 'POST', body: { password: hostedPrivatePassword }, csrf: true });
  assert.equal(hostedPasswordChanged.response.status, 200);
  assert.equal(hostedPasswordChanged.body.user.mustChangePassword, false);
  cookie = ownerCookie;
  csrfToken = ownerCsrfToken;

  const hostedAdminPassword = `A!a1${crypto.randomBytes(18).toString('base64url')}`;
  const hostedAdmin = await request('/users', {
    method: 'POST',
    body: { name: 'Mistaken Hosted Admin', email: 'mistaken-hosted-admin@example.invalid', password: hostedAdminPassword, role: 'admin', clientId: null, canView: false, canManage: false, canReveal: false, canExport: false },
    csrf: true,
  });
  assert.equal(hostedAdmin.response.status, 201);
  const demotedHostedAdmin = await request(`/users/${hostedAdmin.body.id}`, {
    method: 'PATCH',
    body: { name: hostedAdmin.body.name, email: hostedAdmin.body.email, role: 'client_user', clientId: client.body.id },
    csrf: true,
  });
  assert.equal(demotedHostedAdmin.response.status, 200);
  assert.equal(demotedHostedAdmin.body.role, 'client_user');
  assert.deepEqual(demotedHostedAdmin.body.clientIds, [client.body.id]);
  const removedHostedMistake = await request(`/users/${hostedAdmin.body.id}`, { method: 'DELETE', body: {}, csrf: true });
  assert.equal(removedHostedMistake.response.status, 200);
  const deletedHostedMistake = await request(`/users/${hostedAdmin.body.id}/permanent`, { method: 'DELETE', body: { confirmation: hostedAdmin.body.email }, csrf: true });
  assert.equal(deletedHostedMistake.response.status, 200);
  assert.equal(deletedHostedMistake.body.deleted, true);

  const existingHostedUserWelcome = await request(`/users/${hostedClientUser.body.id}/resend-welcome`, { method: 'POST', body: {}, csrf: true });
  assert.equal(existingHostedUserWelcome.response.status, 503);
  assert.equal(existingHostedUserWelcome.body.code, 'EMAIL_NOT_CONFIGURED');

  const updatedHostedClientUser = await request(`/users/${hostedClientUser.body.id}`, {
    method: 'PATCH',
    body: { name: 'Updated Hosted Client User', email: 'updated-hosted-client-user@example.invalid' },
    csrf: true,
  });
  assert.equal(updatedHostedClientUser.response.status, 200);
  assert.equal(updatedHostedClientUser.body.email, 'updated-hosted-client-user@example.invalid');

  const removedHostedClientUser = await request(`/users/${hostedClientUser.body.id}`, { method: 'DELETE', body: {}, csrf: true });
  assert.equal(removedHostedClientUser.response.status, 200);
  assert.ok(removedHostedClientUser.body.disabledAt);

  const restoredHostedClientUser = await request(`/users/${hostedClientUser.body.id}/restore`, { method: 'POST', body: {}, csrf: true });
  assert.equal(restoredHostedClientUser.response.status, 200);
  assert.equal(restoredHostedClientUser.body.disabledAt, null);
  assert.equal(restoredHostedClientUser.body.mfaEnabled, false);

  const location = await request('/locations', {
    method: 'POST',
    body: { clientId: client.body.id, name: 'Synthetic Location', address: '', notes: '' },
    csrf: true,
  });
  assert.equal(location.response.status, 201);

  const system = await request('/systems', {
    method: 'POST',
    body: {
      clientId: client.body.id,
      locationId: location.body.id,
      name: 'Synthetic Firewall',
      collection: 'network',
      manufacturer: '',
      model: '',
      networkAddress: '',
      notes: '',
    },
    csrf: true,
  });
  assert.equal(system.response.status, 201);

  const credential = await request('/credentials', {
    method: 'POST',
    body: {
      clientId: client.body.id,
      locationId: location.body.id,
      systemId: system.body.id,
      collection: 'network',
      name: 'Synthetic Admin',
      url: '',
      lastVerifiedAt: null,
      expiresAt: null,
      secret: { username: 'synthetic-user', password: testSecret, pin: '', apiToken: '', licenseKey: '', notes: '' },
    },
    csrf: true,
  });
  assert.equal(credential.response.status, 201);

  const database = new Database(path.join(tempDir, 'innasc-vault-hosted.sqlite3'), { readonly: true });
  const stored = database.prepare('SELECT secret_ciphertext FROM credentials WHERE id=?').get(credential.body.id);
  assert.ok(stored.secret_ciphertext);
  assert.equal(stored.secret_ciphertext.includes(testSecret), false);
  database.close();

  const revealed = await request(`/credentials/${credential.body.id}/secret`, {
    method: 'POST',
    body: { purpose: 'reveal' },
    csrf: true,
  });
  assert.equal(revealed.response.status, 200);
  assert.equal(revealed.body.secret.password, testSecret);

  const renamed = await request(`/users/${verified.body.user.id}`, {
    method: 'PATCH',
    body: { name: 'Renamed Railway Owner', email: 'renamed-railway-owner@example.invalid' },
    csrf: true,
  });
  assert.equal(renamed.response.status, 200);
  assert.equal(renamed.body.name, 'Renamed Railway Owner');
  assert.equal(renamed.body.email, 'renamed-railway-owner@example.invalid');

  const documentation = await request('/exports/documentation', {
    method: 'POST',
    body: { clientId: client.body.id },
    csrf: true,
  });
  assert.equal(documentation.response.status, 200);
  const documentationJson = JSON.stringify(documentation.body);
  assert.equal(documentationJson.includes(testSecret), false);
  assert.ok(documentationJson.includes('[OMITTED]'));

  const rejectedOffboarding = await request('/exports/offboarding', {
    method: 'POST',
    body: { clientId: client.body.id, acknowledged: false },
    csrf: true,
  });
  assert.equal(rejectedOffboarding.response.status, 400);
  const offboarding = await request('/exports/offboarding', {
    method: 'POST',
    body: { clientId: client.body.id, acknowledged: true },
    csrf: true,
  });
  assert.equal(offboarding.response.status, 200);
  assert.match(offboarding.response.headers.get('content-type') ?? '', /^application\/pdf/u);
  assert.match(offboarding.response.headers.get('content-disposition') ?? '', /InNasc_Offboarding_.*\.pdf/u);
  const offboardingBytes = new Uint8Array(offboarding.body);
  assert.equal(new TextDecoder().decode(offboardingBytes.slice(0, 5)), '%PDF-');
  const offboardingPdf = await PDFDocument.load(offboardingBytes);
  assert.ok(offboardingPdf.getPageCount() > 0);
  assert.equal(offboardingPdf.getTitle(), 'InNasc Vault Offboarding Export');

  const backup = await request('/exports/backup', { method: 'POST', body: {}, csrf: true });
  assert.equal(backup.response.status, 200);
  const backupJson = JSON.stringify(backup.body);
  assert.equal(backupJson.includes(testSecret), false);
  assert.ok(backupJson.includes(stored.secret_ciphertext));

  const sharing = await request('/shares/status');
  assert.equal(sharing.body.enabled, false);

  const audit = await request('/audit?limit=100');
  assert.equal(audit.response.status, 200);
  assert.ok(Array.isArray(audit.body));
  assert.ok(audit.body.some((entry) => entry.event_type === 'credential.reveal'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'export.offboarding'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.update'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.remove'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.restore'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.permanent_delete'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.welcome_email'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'auth.temporary_password_changed'));
  assert.equal(JSON.stringify(audit.body).includes(testSecret), false);

  console.log('PASS: Railway hosted MFA, onboarding email safeguards, user editing/removal, encryption, safe/offboarding exports, backup, and audit smoke test');
} finally {
  server.kill();
  await delay(500);
  fs.rmSync(tempDir, { recursive: true, force: true });
}
