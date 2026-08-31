import Database from 'better-sqlite3';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import { config } from './config.js';

fs.mkdirSync(config.dataDir, { recursive: true });

export const db = new Database(config.databasePath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');
db.pragma('synchronous = FULL');

const initialMigrationPath = fileURLToPath(new URL('./migrations/001_initial.sql', import.meta.url));
db.exec(fs.readFileSync(initialMigrationPath, 'utf8'));
db.prepare('INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)').run(1, new Date().toISOString());

const userColumns = db.pragma('table_info(users)') as Array<{ name: string }>;
if (!userColumns.some((column) => column.name === 'disabled_at')) {
  const migrationPath = fileURLToPath(new URL('./migrations/002_user_deactivation.sql', import.meta.url));
  db.exec(fs.readFileSync(migrationPath, 'utf8'));
}
db.prepare('INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)').run(2, new Date().toISOString());
db.pragma('optimize');

// Vault keys live only in process memory. Restarting the app intentionally invalidates sessions.
db.prepare('DELETE FROM sessions').run();

export function nowIso() {
  return new Date().toISOString();
}

export function newId() {
  return crypto.randomUUID();
}

export function countUsers() {
  return (db.prepare('SELECT COUNT(*) AS count FROM users').get() as { count: number }).count;
}

export function closeDatabase() {
  db.close();
}
