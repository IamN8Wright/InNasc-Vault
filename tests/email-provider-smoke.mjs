import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.INNASC_RESEND_API_KEY = `re_test_${crypto.randomBytes(12).toString('hex')}`;
process.env.INNASC_EMAIL_FROM = 'InNasc Vault <welcome@innasc.com>';
process.env.INNASC_APP_URL = 'https://vault.innasc.com';

const originalFetch = globalThis.fetch;
let captured;
globalThis.fetch = async (url, options) => {
  captured = { url, options };
  return new Response(JSON.stringify({ id: crypto.randomUUID() }), { status: 200, headers: { 'Content-Type': 'application/json' } });
};

try {
  const { sendWelcomeEmail, welcomeEmailConfigured } = await import('../dist/local-server/email.js');
  const temporaryPassword = `T!m9${crypto.randomBytes(16).toString('base64url')}`;
  assert.equal(welcomeEmailConfigured(), true);
  const result = await sendWelcomeEmail({
    name: 'Synthetic User',
    email: 'recipient@example.invalid',
    temporaryPassword,
    mfaAlreadyEnrolled: false,
  });
  assert.deepEqual(result, { configured: true, sent: true });
  assert.equal(captured.url, 'https://api.resend.com/emails');
  assert.equal(captured.options.method, 'POST');
  assert.equal(captured.options.headers.Authorization, `Bearer ${process.env.INNASC_RESEND_API_KEY}`);
  assert.ok(captured.options.headers['Idempotency-Key'].startsWith('innasc-welcome-'));
  const message = JSON.parse(captured.options.body);
  assert.equal(message.from, process.env.INNASC_EMAIL_FROM);
  assert.deepEqual(message.to, ['recipient@example.invalid']);
  assert.ok(message.text.includes(temporaryPassword));
  assert.ok(message.text.includes('This email address is not monitored. Please do not reply.'));
  assert.ok(message.html.includes('https://vault.innasc.com'));
  assert.ok(message.html.includes('src="cid:innasc-vault-logo"'));
  assert.ok(message.html.includes('Welcome to your secure InNasc workspace.'));
  assert.ok(message.html.includes('Complete your secure setup'));
  assert.ok(message.html.indexOf('Complete your secure setup') < message.html.indexOf('Temporary password:'));
  assert.deepEqual(message.attachments, [
    {
      path: 'https://vault.innasc.com/innasc-vault-mark.png',
      filename: 'innasc-vault-mark.png',
      content_id: 'innasc-vault-logo',
      content_type: 'image/png',
    },
  ]);
  console.log('PASS: Resend HTTPS welcome-email provider and secure configuration smoke test');
} finally {
  globalThis.fetch = originalFetch;
  delete process.env.INNASC_RESEND_API_KEY;
  delete process.env.INNASC_EMAIL_FROM;
  delete process.env.INNASC_APP_URL;
}
