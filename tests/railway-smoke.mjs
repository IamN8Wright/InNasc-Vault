import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import Database from 'better-sqlite3';
import { generate } from 'otplib';

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
  const body = contentType.includes('application/json') ? await response.json() : await response.text();
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

  const setup = await request('/setup/start', {
    method: 'POST',
    body: { name: 'Automated Railway Owner', email: 'railway-owner@example.invalid', password, setupToken },
  });
  assert.equal(setup.response.status, 201);
  assert.equal(setup.body.kind, 'enrollment');
  assert.ok(setup.body.manualKey);

  const enrollmentCode = await generate({ secret: setup.body.manualKey });
  const verified = await request('/auth/mfa/verify', {
    method: 'POST',
    body: { challengeId: setup.body.challengeId, code: enrollmentCode },
  });
  assert.equal(verified.response.status, 200);
  assert.equal(verified.body.user.role, 'workspace_owner');
  csrfToken = verified.body.csrfToken;
  assert.ok(cookie.startsWith('innasc_session='));

  const stepUpCode = await generate({ secret: setup.body.manualKey });
  const stepUp = await request('/auth/step-up', { method: 'POST', body: { code: stepUpCode }, csrf: true });
  assert.equal(stepUp.response.status, 200);

  const client = await request('/clients', {
    method: 'POST',
    body: { name: 'Synthetic Test Client', code: 'TEST', notes: 'No real client data.' },
    csrf: true,
  });
  assert.equal(client.response.status, 201);

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
    body: { name: 'Renamed Railway Owner' },
    csrf: true,
  });
  assert.equal(renamed.response.status, 200);
  assert.equal(renamed.body.name, 'Renamed Railway Owner');

  const documentation = await request('/exports/documentation', {
    method: 'POST',
    body: { clientId: client.body.id },
    csrf: true,
  });
  assert.equal(documentation.response.status, 200);
  const documentationJson = JSON.stringify(documentation.body);
  assert.equal(documentationJson.includes(testSecret), false);
  assert.ok(documentationJson.includes('[OMITTED]'));

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
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.update'));

  console.log('PASS: Railway hosted MFA, encryption, step-up, rename, exports, backup, and audit smoke test');
} finally {
  server.kill();
  await delay(500);
  fs.rmSync(tempDir, { recursive: true, force: true });
}
