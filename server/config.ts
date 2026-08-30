import path from 'node:path';

const port = Number(process.env.INNASC_API_PORT ?? 3778);
const uiPort = Number(process.env.INNASC_UI_PORT ?? 3000);
const appRoot = process.cwd();

export const config = {
  port,
  uiPort,
  host: '127.0.0.1',
  origin: `http://localhost:${uiPort}`,
  rpID: 'localhost',
  rpName: 'InNasc Vault',
  dataDir: path.resolve(process.env.INNASC_DATA_DIR ?? path.join(appRoot, 'data')),
  databasePath: path.resolve(process.env.INNASC_DB_PATH ?? path.join(appRoot, 'data', 'innasc-vault.sqlite3')),
  sessionHours: 8,
  stepUpMinutes: 5,
  challengeMinutes: 10,
} as const;

export const roles = [
  'workspace_owner',
  'admin',
  'technician',
  'client_admin',
  'client_user',
  'read_only',
] as const;

export type Role = (typeof roles)[number];

export const collections = [
  'network',
  'av_systems',
  'voip',
  'access_control',
  'remote_access',
  'software',
  'websites_accounts',
  'general',
] as const;

export type Collection = (typeof collections)[number];
