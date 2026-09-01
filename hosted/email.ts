import nodemailer from 'nodemailer';

import { hostedEnv } from '@/hosted/db';

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
  const environment = hostedEnv();
  const host = environment.INNASC_SMTP_HOST?.trim();
  const port = Number(environment.INNASC_SMTP_PORT ?? '587');
  const user = environment.INNASC_SMTP_USER?.trim();
  const password = environment.INNASC_SMTP_PASSWORD;
  const from = environment.INNASC_SMTP_FROM?.trim() || user;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65_535 || !from) return null;
  if (Boolean(user) !== Boolean(password)) return null;
  return {
    host,
    port,
    secure: environment.INNASC_SMTP_SECURE === '1' || environment.INNASC_SMTP_SECURE === 'true' || port === 465,
    user,
    password,
    from,
    appUrl: environment.INNASC_APP_URL?.trim() || 'https://vault.innasc.com',
  };
}

function resendSettings() {
  const environment = hostedEnv();
  const apiKey = environment.INNASC_RESEND_API_KEY?.trim();
  const from = environment.INNASC_EMAIL_FROM?.trim();
  if (!apiKey || !from) return null;
  return { apiKey, from, appUrl: environment.INNASC_APP_URL?.trim() || 'https://vault.innasc.com' };
}

function escapeHtml(value: string) {
  return value.replace(/[&<>'"]/gu, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]!);
}

export function welcomeEmailConfigured() {
  return Boolean(resendSettings() || smtpSettings());
}

export async function sendWelcomeEmail(message: WelcomeMessage): Promise<WelcomeEmailResult> {
  const resend = resendSettings();
  const smtp = smtpSettings();
  if (!resend && !smtp) return { configured: false, sent: false };
  const appUrl = resend?.appUrl ?? smtp!.appUrl;
  const logoContentId = 'innasc-vault-logo';
  const logoUrl = new URL('/innasc-vault-mark.png', appUrl).toString();
  const sentAt = new Date().toISOString();
  const mfaStep = message.mfaAlreadyEnrolled
    ? 'Confirm sign-in with your existing authenticator code.'
    : 'Enroll an authenticator app when prompted and save the recovery codes.';
  const text = [
    `Welcome to InNasc Vault, ${message.name}.`,
    '',
    'Welcome to your secure InNasc workspace. InNasc Vault gives you one protected place to access the usernames, passwords, device records, and system documentation that have been shared with you.',
    'Please complete the three steps below to protect your account before entering the vault.',
    '',
    'Your onboarding steps:',
    '1. Sign in with the email and temporary password shown below.',
    `2. ${mfaStep}`,
    '3. Create a new private password before the vault opens.',
    '',
    `Sign in: ${appUrl}`,
    `Email: ${message.email}`,
    `Temporary password: ${message.temporaryPassword}`,
    '',
    'This temporary password stops working when an administrator resends this welcome email. Do not forward this message.',
    '',
    'This is an automated message from InNasc Vault. This email address is not monitored. Please do not reply.',
  ].join('\n');
  const html = `<div style="font-family:Arial,sans-serif;line-height:1.55;color:#102033;max-width:620px"><div style="text-align:center;margin:0 0 20px"><img src="cid:${logoContentId}" alt="InNasc Vault" width="96" height="96" style="display:inline-block;width:96px;height:96px;border:0"></div><h1 style="color:#1557d6;text-align:center">Welcome to InNasc Vault</h1><p>Hello ${escapeHtml(message.name)},</p><p>Welcome to your secure InNasc workspace. InNasc Vault gives you one protected place to access the usernames, passwords, device records, and system documentation that have been shared with you.</p><p>Please complete the three steps below to protect your account before entering the vault.</p><h2 style="font-size:18px">Complete your secure setup</h2><ol style="padding-left:24px"><li style="margin-bottom:8px">Sign in with the email and temporary password shown below.</li><li style="margin-bottom:8px">${escapeHtml(mfaStep)}</li><li style="margin-bottom:8px">Create a new private password before the vault opens.</li></ol><div style="background:#f3f7ff;border:1px solid #c8d8f4;border-radius:10px;padding:18px;margin:20px 0"><p style="margin:0"><strong>Sign in:</strong> <a href="${escapeHtml(appUrl)}">${escapeHtml(appUrl)}</a><br><strong>Email:</strong> ${escapeHtml(message.email)}<br><strong>Temporary password:</strong> <code style="font-size:15px">${escapeHtml(message.temporaryPassword)}</code></p></div><p style="color:#5d6673;font-size:13px">For your security, this temporary password stops working when an administrator resends this welcome email. Do not forward or share this message.</p><p style="color:#5d6673;font-size:13px">After you finish MFA enrollment and choose your private password, the vault will open with the information your administrator has made available to you.</p><hr style="border:0;border-top:1px solid #d8e0eb;margin:24px 0 14px"><p style="color:#6b7280;font-size:12px;text-align:center">This is an automated message from InNasc Vault. This email address is not monitored. Please do not reply.<br>Generated for ${escapeHtml(message.email)} at ${escapeHtml(sentAt)}.</p></div>`;
  const logoAttachment = { path: logoUrl, filename: 'innasc-vault-mark.png' };

  try {
    if (resend) {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${resend.apiKey}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `innasc-welcome-${crypto.randomUUID()}`,
        },
        body: JSON.stringify({
          from: resend.from,
          to: [message.email],
          subject: 'Welcome to InNasc Vault',
          text,
          html,
          attachments: [{ ...logoAttachment, content_id: logoContentId, content_type: 'image/png' }],
        }),
        signal: AbortSignal.timeout(20_000),
      });
      return { configured: true, sent: response.ok };
    }
    const transporter = nodemailer.createTransport({
      host: smtp!.host,
      port: smtp!.port,
      secure: smtp!.secure,
      requireTLS: !smtp!.secure,
      auth: smtp!.user ? { user: smtp!.user, pass: smtp!.password! } : undefined,
      tls: { minVersion: 'TLSv1.2' },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 20_000,
    });
    await transporter.sendMail({
      from: smtp!.from,
      to: message.email,
      subject: 'Welcome to InNasc Vault',
      text,
      html,
      attachments: [{ filename: logoAttachment.filename, path: logoAttachment.path, cid: logoContentId }],
    });
    return { configured: true, sent: true };
  } catch {
    return { configured: true, sent: false };
  }
}
