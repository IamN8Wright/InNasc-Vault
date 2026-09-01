import fs from 'node:fs';
import path from 'node:path';

import Database from 'better-sqlite3';

import { hostedSchemaStatements } from '@/db/schema';
import { fromBase64Url } from '@/hosted/crypto';

export class ApiProblem extends Error {
  constructor(
    message: string,
    public readonly status = 400,
    public readonly code?: string,
  ) {
    super(message);
    this.name = 'ApiProblem';
  }
}

type HostedEnvironment = {
  INNASC_SERVER_KEY?: string;
  INNASC_SETUP_TOKEN?: string;
  INNASC_SMTP_HOST?: string;
  INNASC_SMTP_PORT?: string;
  INNASC_SMTP_SECURE?: string;
  INNASC_SMTP_USER?: string;
  INNASC_SMTP_PASSWORD?: string;
  INNASC_SMTP_FROM?: string;
  INNASC_RESEND_API_KEY?: string;
  INNASC_EMAIL_FROM?: string;
  INNASC_APP_URL?: string;
};

let database: Database.Database | null = null;
let schemaReady = false;

export function hostedEnv(): HostedEnvironment {
  return {
    INNASC_SERVER_KEY: process.env.INNASC_SERVER_KEY,
    INNASC_SETUP_TOKEN: process.env.INNASC_SETUP_TOKEN,
    INNASC_SMTP_HOST: process.env.INNASC_SMTP_HOST,
    INNASC_SMTP_PORT: process.env.INNASC_SMTP_PORT,
    INNASC_SMTP_SECURE: process.env.INNASC_SMTP_SECURE,
    INNASC_SMTP_USER: process.env.INNASC_SMTP_USER,
    INNASC_SMTP_PASSWORD: process.env.INNASC_SMTP_PASSWORD,
    INNASC_SMTP_FROM: process.env.INNASC_SMTP_FROM,
    INNASC_RESEND_API_KEY: process.env.INNASC_RESEND_API_KEY,
    INNASC_EMAIL_FROM: process.env.INNASC_EMAIL_FROM,
    INNASC_APP_URL: process.env.INNASC_APP_URL,
  };
}

function databaseDirectory() {
  const configured = process.env.RAILWAY_VOLUME_MOUNT_PATH?.trim()
    || process.env.VAULT_DATA_DIR?.trim()
    || path.resolve(process.cwd(), 'data');
  return path.isAbsolute(configured) ? configured : path.resolve(process.cwd(), configured);
}

function hostedDatabase() {
  if (!database) {
    const directory = databaseDirectory();
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const filename = path.join(directory, 'innasc-vault-hosted.sqlite3');
    database = new Database(filename);
    database.pragma('journal_mode = WAL');
    database.pragma('foreign_keys = ON');
    database.pragma('busy_timeout = 5000');
    database.pragma('synchronous = FULL');
  }
  return database;
}

export async function ensureHostedSchema() {
  if (schemaReady) return;
  const activeDatabase = hostedDatabase();
  activeDatabase.transaction(() => {
    for (const statement of hostedSchemaStatements) activeDatabase.exec(statement);
    const userColumns = activeDatabase.pragma('table_info(users)') as Array<{ name: string }>;
    if (!userColumns.some((column) => column.name === 'disabled_at')) {
      activeDatabase.exec('ALTER TABLE users ADD COLUMN disabled_at TEXT');
    }
    if (!userColumns.some((column) => column.name === 'must_change_password')) {
      activeDatabase.exec('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0,1))');
    }
    if (!userColumns.some((column) => column.name === 'welcome_sent_at')) {
      activeDatabase.exec('ALTER TABLE users ADD COLUMN welcome_sent_at TEXT');
    }
    if (!userColumns.some((column) => column.name === 'welcome_send_count')) {
      activeDatabase.exec('ALTER TABLE users ADD COLUMN welcome_send_count INTEGER NOT NULL DEFAULT 0');
    }
    if (!userColumns.some((column) => column.name === 'permanently_deleted_at')) {
      activeDatabase.exec('ALTER TABLE users ADD COLUMN permanently_deleted_at TEXT');
    }
  })();
  schemaReady = true;
}

export function serverKey() {
  const encoded = hostedEnv().INNASC_SERVER_KEY;
  if (!encoded) throw new ApiProblem('Hosted encryption key is not configured.', 503, 'HOSTED_KEY_MISSING');
  const key = fromBase64Url(encoded);
  if (key.length !== 32) throw new ApiProblem('Hosted encryption key is invalid.', 503, 'HOSTED_KEY_INVALID');
  return key;
}

export function newId() {
  return crypto.randomUUID();
}

export function nowIso() {
  return new Date().toISOString();
}

function bindings(values: unknown[]) {
  return values.map((value) => value === undefined ? null : value);
}

export async function first<T>(statement: string, ...values: unknown[]) {
  return hostedDatabase().prepare<unknown[], T>(statement).get(...bindings(values));
}

export async function all<T>(statement: string, ...values: unknown[]) {
  return hostedDatabase().prepare<unknown[], T>(statement).all(...bindings(values));
}

export async function run(statement: string, ...values: unknown[]) {
  const result = hostedDatabase().prepare<unknown[]>(statement).run(...bindings(values));
  return { meta: { changes: result.changes } };
}
