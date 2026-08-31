# InNasc Vault

InNasc Vault is a local-first client technology and credential workspace organized as:

**Client → Location → System → Credential**

The repository contains two evaluation targets that share the same responsive HTML5/TypeScript interface:

- a Windows local build with an Express API and SQLite at `http://localhost:3000`; and
- a Railway-hosted beta with same-origin API routes, encrypted SQLite storage on a persistent Railway volume, secure cookies, and mandatory MFA.

No sample passwords, accounts, API keys, or client records are included.

## Start the local Windows build

1. Install the current **Node.js 22 LTS** release from [nodejs.org](https://nodejs.org) if it is not already installed.
2. Extract the entire `InNasc_Vault` folder. Do not run the launcher from inside the ZIP preview.
3. Double-click **`Start-InNasc-Vault.cmd`**.
4. The first run downloads the exact packages recorded in `package-lock.json` and builds the local app. This can take several minutes.
5. Your browser opens to `http://localhost:3000`.
6. Keep the launcher window open while using the vault. Press **Enter** in that window when finished so both local services close cleanly.

Windows Firewall should not need a public-network rule: the API listens only on this computer. Do not change the bind address to `0.0.0.0` for a client trial.

## First owner setup

1. Enter the workspace owner’s name, email, and a unique password of at least 14 characters. The hosted beta also asks for the one-time deployment setup key supplied by the operator.
2. Scan the QR code with Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden, or another standards-based TOTP app.
3. Enter the current six-digit code.
4. Save the ten recovery codes somewhere separate from the vault. Each works once.
5. Add the client, their location, a system, and then any encrypted credentials.

The password unlocks the wrapped workspace key. There is no password-reset backdoor. MFA recovery codes do not replace the password.

## What is included

- Clients, locations, and systems in a strict hierarchy
- Collections for network, AV systems, VoIP, access control, remote access, software, websites/accounts, and general records
- Encrypted credential records plus separate device, software, and website/account inventory
- Workspace Owner, Admin, Technician, Client Admin, Client User, and Read Only roles
- Client/location/collection permission grants enforced by the API
- Mandatory authenticator MFA during first sign-in, one-time recovery codes, attempt limits, and account lockout
- Optional Windows Hello/security-key passkeys in the local build; hosted passkeys are intentionally disabled pending a dedicated WebAuthn review
- Five-minute step-up MFA for reveal, copy, delete, exports, backup, MFA reset, and permission changes
- Cryptographically secure password generator in the browser
- Editable user display names with step-up MFA and audit history
- Auditing for sign-in, MFA, reveal, copy, create, update, delete, permissions, blocked shares, and exports
- Documentation export that always omits secret fields
- Encrypted SQLite backup locally and encrypted-data JSON export in the hosted beta
- Temporary sharing disabled in both evaluation builds

## Everyday use

- **Clients:** create client, location, and system records.
- **Credential vault:** add, reveal, copy, edit, or delete encrypted secrets. Reveal and copy require a fresh MFA check.
- **Devices & software:** track non-secret inventory. Put passwords and tokens in the vault instead of notes.
- **Users & permissions:** Workspace Owners/Admins can create users, edit names and sign-in emails, grant scoped access, reset MFA, and safely remove or restore accounts. Client Admins can create and manage Client Users only inside their assigned client-wide management scopes. New and restored users must enroll MFA on first sign-in.
- **Security & backup:** enroll a local passkey, export password-free documentation, or download an encrypted-data backup.

## Local data location

The live local database is created at:

`data\innasc-vault.sqlite3`

SQLite may also create `-wal` and `-shm` companion files while the app is running. Never copy only one of these files while the app is open; use the in-app backup button or stop the app first.

Read [BACKUP-RESTORE.md](BACKUP-RESTORE.md) before relying on either backup format, and read [SECURITY.md](SECURITY.md) before putting production client credentials into the app.

## Developer commands

```powershell
npm ci
npm run dev
npm test
npm run check
npm run build
npm start
```

## Railway deployment

Deploy the repository as a single Node 22 web service. Railway installs the locked dependencies automatically; use `npm run build` as the build command and `npm run start:railway` as the start command. Before using the hosted beta:

1. Attach a persistent Railway volume to the service. The application uses Railway's `RAILWAY_VOLUME_MOUNT_PATH` automatically and creates `innasc-vault-hosted.sqlite3` there.
2. Set `INNASC_SERVER_KEY` to a random 32-byte base64url value and `INNASC_SETUP_TOKEN` to a separate high-entropy one-time setup value. Keep both secret and never commit them.
3. Keep the service at one replica while it uses SQLite.
4. Configure `/api/health` as the health check, attach the custom domain, and verify Railway volume backups before storing important data.

The SQLite schema uses UUID text identifiers and a repository boundary intended to ease a later PostgreSQL migration. The Railway beta is not the final paid-service architecture.
