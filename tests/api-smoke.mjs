import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import Database from 'better-sqlite3';
import { generate } from 'otplib';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'innasc-vault-test-'));
const databasePath = path.join(tempDir, 'vault.sqlite3');
const port = 3888;
const base = `http://localhost:${port}/api`;
const origin = 'http://localhost:3000';
const password = `A!a1${crypto.randomBytes(18).toString('base64url')}`;
const testSecret = `synthetic-${crypto.randomBytes(18).toString('base64url')}`;
let cookie = '';

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
  const csrfToken = verified.body.csrfToken;

  const secured = (body) => ({
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body: JSON.stringify(body),
  });

  const client = await request('/clients', secured({ name: 'Automated Test Client', code: 'TEST', notes: '' }));
  assert.equal(client.response.status, 201);

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

  const renamedOwner = await request(`/users/${verified.body.user.id}`, {
    ...secured({ name: 'Renamed Automated Owner' }),
    method: 'PATCH',
  });
  assert.equal(renamedOwner.response.status, 200);
  assert.equal(renamedOwner.body.name, 'Renamed Automated Owner');

  const reveal = await request(`/credentials/${credential.body.id}/secret`, secured({ purpose: 'reveal' }));
  assert.equal(reveal.response.status, 200);
  assert.equal(reveal.body.secret.password, testSecret);

  const documentation = await request('/exports/documentation', secured({ clientId: client.body.id }));
  assert.equal(documentation.response.status, 200);
  const exportText = JSON.stringify(documentation.body);
  assert.equal(exportText.includes(testSecret), false);
  assert.equal(documentation.body.secretsIncluded, false);

  const audit = await request('/audit');
  assert.equal(audit.response.status, 200);
  assert.ok(audit.body.some((entry) => entry.event_type === 'credential.reveal'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'export.documentation'));
  assert.ok(audit.body.some((entry) => entry.event_type === 'user.update'));

  const sqlite = new Database(databasePath, { readonly: true });
  const stored = sqlite.prepare('SELECT secret_ciphertext FROM credentials WHERE id = ?').get(credential.body.id);
  assert.ok(stored.secret_ciphertext);
  assert.equal(stored.secret_ciphertext.includes(testSecret), false);
  sqlite.close();

  console.log('PASS: encrypted credential, MFA, step-up, user rename, safe export, and audit smoke test');
} finally {
  server.kill('SIGTERM');
  await Promise.race([new Promise((resolve) => server.once('exit', resolve)), delay(3000)]);
  fs.rmSync(tempDir, { recursive: true, force: true });
}
