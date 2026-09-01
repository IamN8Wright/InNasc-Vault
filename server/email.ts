import nodemailer from 'nodemailer';

type WelcomeMessage = {
  name: string;
  email: string;
  temporaryPassword: string;
  mfaAlreadyEnrolled: boolean;
};

export type WelcomeEmailResult = {
  configured: boolean;
  sent: boolean;
};

function smtpSettings() {
  const host = process.env.INNASC_SMTP_HOST?.trim();
  const port = Number(process.env.INNASC_SMTP_PORT ?? '587');
  const user = process.env.INNASC_SMTP_USER?.trim();
  const password = process.env.INNASC_SMTP_PASSWORD;
  const from = process.env.INNASC_SMTP_FROM?.trim() || user;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65_535 || !from) return null;
  if (Boolean(user) !== Boolean(password)) return null;
  return {
    host,
    port,
    secure: process.env.INNASC_SMTP_SECURE === '1' || process.env.INNASC_SMTP_SECURE === 'true' || port === 465,
    user,
    password,
    from,
    appUrl: process.env.INNASC_APP_URL?.trim() || 'http://localhost:3000',
  };
}

function escapeHtml(value: string) {
  return value.replace(/[&<>'"]/gu, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]!);
}

export function welcomeEmailConfigured() {
  return Boolean(smtpSettings());
}

export async function sendWelcomeEmail(message: WelcomeMessage): Promise<WelcomeEmailResult> {
  const settings = smtpSettings();
  if (!settings) return { configured: false, sent: false };

  const transporter = nodemailer.createTransport({
    host: settings.host,
    port: settings.port,
    secure: settings.secure,
    requireTLS: !settings.secure,
    auth: settings.user ? { user: settings.user, pass: settings.password! } : undefined,
    tls: { minVersion: 'TLSv1.2' },
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
  });
  const mfaStep = message.mfaAlreadyEnrolled
    ? 'Confirm sign-in with your existing authenticator code.'
    : 'Enroll an authenticator app when prompted and save the recovery codes.';
  const text = [
    `Welcome to InNasc Vault, ${message.name}.`,
    '',
    `Sign in: ${settings.appUrl}`,
    `Email: ${message.email}`,
    `Temporary password: ${message.temporaryPassword}`,
    '',
    'Your onboarding steps:',
    '1. Sign in with the email and temporary password above.',
    `2. ${mfaStep}`,
    '3. Create a new private password before the vault opens.',
    '',
    'This temporary password stops working when an administrator resends this welcome email. Do not forward this message.',
  ].join('\n');
  const html = `<div style="font-family:Arial,sans-serif;line-height:1.55;color:#102033;max-width:620px"><h1 style="color:#1557d6">Welcome to InNasc Vault</h1><p>Hello ${escapeHtml(message.name)},</p><p>Your secure workspace account is ready.</p><div style="background:#f3f7ff;border:1px solid #c8d8f4;border-radius:10px;padding:18px"><p><strong>Sign in:</strong> <a href="${escapeHtml(settings.appUrl)}">${escapeHtml(settings.appUrl)}</a><br><strong>Email:</strong> ${escapeHtml(message.email)}<br><strong>Temporary password:</strong> <code style="font-size:15px">${escapeHtml(message.temporaryPassword)}</code></p></div><h2 style="font-size:18px">Complete your secure setup</h2><ol><li>Sign in with the email and temporary password above.</li><li>${escapeHtml(mfaStep)}</li><li>Create a new private password before the vault opens.</li></ol><p style="color:#5d6673;font-size:13px">This temporary password stops working when an administrator resends this welcome email. Do not forward this message.</p></div>`;

  try {
    await transporter.sendMail({ from: settings.from, to: message.email, subject: 'Welcome to InNasc Vault', text, html });
    return { configured: true, sent: true };
  } catch {
    return { configured: true, sent: false };
  }
}
