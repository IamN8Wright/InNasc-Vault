# Backup and restore

## Local Windows backup

1. Sign in as Workspace Owner or Admin.
2. Open **Security & backup**.
3. Select **Download encrypted backup**.
4. Complete the step-up MFA prompt.
5. Store the downloaded `.sqlite3` file in a protected, backed-up location separate from this PC.

The database backup contains encrypted credential and MFA blobs, but it also contains client metadata, user email addresses, audit history, and password hashes. Treat the whole file as confidential.

Use a rotation such as daily/weekly/monthly, and perform a restore drill before trusting the process. A backup is not proven until it has been restored and opened successfully.

## Offline file backup

If the app cannot open, stop InNasc Vault completely and copy the entire `data` folder. Do not copy the live database while the launcher is running because SQLite may have active WAL files.

## Restore an in-app backup

1. Stop InNasc Vault.
2. Open the `data` folder beside `Start-InNasc-Vault.cmd`.
3. Rename the existing `innasc-vault.sqlite3` to a dated name such as `innasc-vault-before-restore-2026-08-30.sqlite3`. This preserves a recovery path.
4. Copy the chosen backup into the `data` folder.
5. Rename the copied file to exactly `innasc-vault.sqlite3`.
6. Remove stale `innasc-vault.sqlite3-wal` or `innasc-vault.sqlite3-shm` files only if the app is fully stopped and they belong to the database being replaced.
7. Start InNasc Vault and sign in with the password that was valid when the backup was created.

Recovery codes solve a lost authenticator, not a lost password. The workspace key is wrapped by the user password, so losing every valid password can make credential recovery impossible.

## Hosted beta backup

1. Sign in as Workspace Owner or Admin.
2. Open **Security & backup** and download the encrypted-data JSON backup after completing step-up MFA.
3. Store it in an encrypted, access-controlled backup location separate from the service.

The hosted JSON contains encrypted credential and MFA blobs, wrapped workspace keys, password hashes, client metadata, user records, permissions, and audit history. It does not contain active session or login-challenge records. Treat the entire file as highly confidential.

Self-service hosted restore is not implemented. Restoring requires a controlled operator procedure against an empty compatible database, migration validation, audit-chain verification, and a login test using a password valid when the backup was created. Do not overwrite a live hosted database with an unverified backup. Maintain at least one separate recovery copy and run an operator-assisted restore drill before relying on the hosted beta for important data.

## Moving to another Windows PC

Copy the complete extracted application folder and a recent in-app database backup. Install Node.js 22 LTS on the new PC, restore the database as above, and run `Start-InNasc-Vault.cmd`. Passkeys normally stay with their original Windows account/device; TOTP and recovery codes remain available.
