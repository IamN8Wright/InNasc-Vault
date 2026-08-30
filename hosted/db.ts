import { env } from 'cloudflare:workers';

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

let schemaPromise: Promise<void> | null = null;

export function hostedEnv() {
  const bindings = env as Cloudflare.Env;
  if (!bindings.DB) throw new ApiProblem('Hosted database is not configured.', 503, 'HOSTED_DATABASE_MISSING');
  return bindings;
}

export async function ensureHostedSchema() {
  if (!schemaPromise) {
    const database = hostedEnv().DB;
    schemaPromise = (async () => {
      for (const statement of hostedSchemaStatements) await database.prepare(statement).run();
    })().catch((error) => {
      schemaPromise = null;
      throw error;
    });
  }
  await schemaPromise;
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

export async function first<T>(statement: string, ...values: unknown[]) {
  return hostedEnv().DB.prepare(statement).bind(...values).first<T>();
}

export async function all<T>(statement: string, ...values: unknown[]) {
  const result = await hostedEnv().DB.prepare(statement).bind(...values).all<T>();
  return result.results;
}

export async function run(statement: string, ...values: unknown[]) {
  return hostedEnv().DB.prepare(statement).bind(...values).run();
}
