# Security status

## Read this first

InNasc Vault is an **evaluation alpha / hosted beta**, not a security-audited commercial password manager. The local build is intended for workflow testing on one controlled Windows PC. The hosted build is suitable for carefully limited beta evaluation, but it has not completed the independent work required before accepting high-impact production credentials or paid customers.

Use unique test credentials first. Before storing irreplaceable client secrets, obtain an independent threat model, cryptographic review, code review, and penetration test; establish tested backups; and accept the limits below.

## Protections shared by both builds

- A random 256-bit workspace key encrypts credential payloads with authenticated encryption and unique nonces.
- Each user password derives a separate key-encryption key that wraps the workspace key. The password is not stored.
- TOTP enrollment secrets are encrypted with the workspace key.
- Recovery codes are random, shown once, stored only as hashes, and consumed after one use.
- Administrator-created accounts are marked for onboarding. After MFA enrollment, every protected vault route remains blocked until the temporary password is replaced and the workspace key is rewrapped with the new password-derived key.
- A welcome-email resend creates a new cryptographically random temporary password, revokes that user’s sessions and login challenges, and invalidates the earlier temporary password. Plaintext temporary passwords are not stored in the database or audit log.
- Session tokens are random; only their SHA-256 hashes are stored. Session cookies are HttpOnly and SameSite=Strict.
- Mutating authenticated requests require a session-bound CSRF token.
- Sensitive credential actions require a recent TOTP, recovery-code, or supported passkey step-up.
- Login and MFA failures are attempt-limited; repeated failures lock the account, expire the challenge, or end the session.
- Access decisions are enforced by the API, including client, location, and collection scope.
- Audit entries omit secret values, are application-immutable through database triggers, and form a SHA-256 hash chain.
- Documentation export substitutes `[OMITTED]` for secret content.
- The separate offboarding export requires a recent MFA step-up, explicit plaintext-risk acknowledgment, and both reveal and export permission for every included credential. Its audit event records counts, never secret values.
- Temporary public sharing is disabled.

## Local Windows build

- The API binds to `127.0.0.1` and accepts browser requests only from `http://localhost:3000`.
- Account passwords and wrapping keys use Argon2id (64 MiB, three iterations, one lane, and per-user random salt).
- Credential encryption uses libsodium XChaCha20-Poly1305.
- The unwrapped workspace key is kept only in server memory for an active session; sessions end when the backend restarts.
- Optional passkeys support Windows Hello and compatible security keys on localhost.
- The SQLite database reveals non-secret metadata such as client names, locations, user email addresses, record names, URLs, timestamps, and audit events.

## Hosted beta

- The hosted API and interface are served from one HTTPS origin. Cookies add the `Secure` attribute.
- Account passwords and wrapping keys use WebCrypto PBKDF2-HMAC-SHA-256 with 600,000 iterations and per-user random salts.
- Credential encryption uses WebCrypto AES-256-GCM with per-record random 96-bit nonces and record-bound additional authenticated data.
- A persistent Railway volume stores the SQLite database containing encrypted credential payloads, wrapped keys, password hashes, and metadata. The database does not store credential secrets in plaintext.
- A protected deployment key encrypts the temporary workspace-key copy used by active login challenges and sessions. The one-time setup key prevents an unknown visitor from claiming a new deployment.
- Hosted passkeys are disabled until WebAuthn origin, RP ID, attestation, recovery, and browser behavior receive a dedicated review.
- Hosted backup export is JSON containing the encrypted blobs and wrapped keys; self-service restore is not implemented yet.

The hosted design is **not zero knowledge**. The deployed server processes password-derived key unwrapping and decrypted values for authorized requests. A compromised deployment, malicious code release, server-key compromise combined with active session records, browser compromise, or privileged platform operator could expose secrets. A paid-service launch should use a separately reviewed client-side encryption and key-sharing protocol if zero-knowledge claims are intended.

## Important limits

- Neither build nor its dependencies has undergone an independent penetration test or cryptographic implementation audit.
- An administrator, malware process, debugger, browser extension, or keylogger controlling a user device may capture passwords, decrypted secrets, clipboard contents, or an in-memory workspace key.
- Clipboard clearing is not reliable across browsers or clipboard-history/sync features. Copy only when necessary.
- Offboarding HTML exports intentionally contain readable usernames, passwords, PINs, tokens, license keys, and secret notes. The downloaded file has no encryption of its own; browser history, Downloads folders, backups, sync tools, endpoint monitoring, and anyone with file access may expose it. Move it to encrypted storage or import it into a trusted password manager immediately, do not email it, and securely delete every copy when finished.
- Metadata is not encrypted. Client names, locations, record titles, URLs, users, timestamps, and audit details may be visible to the database/platform operator.
- The audit hash chain detects simple editing but is not equivalent to a separately controlled, signed append-only audit service. Concurrent hosted writes and privileged database replacement remain outside this guarantee.
- Welcome email uses the configured Resend HTTPS API or SMTP fallback, but delivery is not verified identity proof. There is no email-address verification, expiring invitation link, security notification system, device approval, remote session management, automatic update channel, breach monitoring, or audited account-recovery workflow.
- The user-requested welcome message contains a temporary password. This exposes that one-time secret to the recipient’s mailbox, email provider, mail retention, forwarding, and compromised email accounts. MFA and the forced replacement reduce but do not eliminate that risk; a paid production service should replace emailed passwords with short-lived, single-use setup links.
- The hosted beta is a single workspace. Billing, subscription enforcement, tenant isolation, organization lifecycle, and customer-support controls are not implemented.
- The Railway SQLite service must remain at one replica. Multi-replica writes require a tested PostgreSQL migration and concurrency controls.
- Passkeys are MFA/step-up factors only in the local build, not passwordless vault unlock.
- Backups are not protected by a separate backup password. They retain encrypted blobs but also include sensitive metadata and password hashes.
- Hosted key rotation, self-service restore, Railway volume-backup drills, point-in-time recovery, regional data controls, and PostgreSQL migration are not complete.
- Local HTTP is acceptable only for the browser secure-context exception on `localhost`. Never tunnel or port-forward the local API.

## Required work before a paid production service

1. Commission an independent threat model, source review, cryptographic review, dependency review, and penetration test.
2. Decide and document the hosted key model. Build and review client-side encryption, per-collection key wrapping, user removal, rotation, and recovery before making zero-knowledge claims.
3. Implement and test tenant isolation, billing/subscription state, short-lived single-use invitation links, email verification, delivery/bounce handling, organization deletion/export, rate limiting, abuse protection, and operator access controls.
4. Move to a production database design with versioned migrations, transaction/concurrency testing, encrypted backups, point-in-time recovery, restore drills, rollback, and disaster recovery.
5. Put deployment keys in a reviewed KMS/HSM-backed process with rotation, dual control, access logs, and an emergency revocation plan.
6. Add fixed WebAuthn RP ID/origin handling, security notifications, remote session/device management, verified recovery, and passkey recovery testing.
7. Send audit events to a separately controlled append-only service with retention, alerting, and customer-visible evidence.
8. Establish SAST, secret scanning, dependency vulnerability policy, signed/reproducible builds, update provenance, incident response, vulnerability reporting, and service monitoring.
9. Review TLS, HSTS, CSP, clickjacking protection, cache controls, content-type protections, proxy headers, DNS, and custom-domain ownership after deployment.
10. Implement temporary sharing only after a dedicated design review covering recipient authentication, expiry, revocation, single use, key distribution, abuse handling, and audit evidence.

## Reporting a security issue

Do not publish exploitable details or real client data. Record the issue without credentials, stop using the affected build for sensitive data, preserve relevant logs, and arrange a private review with the InNasc maintainer.
