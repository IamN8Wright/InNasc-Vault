import type { Request } from 'express';

import { db, newId, nowIso } from './db.js';
import { sha256 } from './crypto.js';

type AuditInput = {
  request?: Request;
  actorUserId?: string | null;
  eventType: string;
  targetType?: string | null;
  targetId?: string | null;
  clientId?: string | null;
  outcome?: 'success' | 'failure' | 'blocked';
  detail?: Record<string, unknown>;
};

function requestIpHash(request?: Request) {
  if (!request) return null;
  return sha256(request.ip || request.socket.remoteAddress || 'local');
}

export function audit(input: AuditInput) {
  const occurredAt = nowIso();
  const id = newId();
  const previous = db.prepare('SELECT entry_hash FROM audit_log ORDER BY occurred_at DESC, id DESC LIMIT 1').get() as { entry_hash: string } | undefined;
  const previousHash = previous?.entry_hash ?? 'GENESIS';
  const detailJson = JSON.stringify(input.detail ?? {});
  const canonical = JSON.stringify({
    id,
    occurredAt,
    actorUserId: input.actorUserId ?? null,
    eventType: input.eventType,
    targetType: input.targetType ?? null,
    targetId: input.targetId ?? null,
    clientId: input.clientId ?? null,
    outcome: input.outcome ?? 'success',
    detailJson,
    previousHash,
  });
  const entryHash = sha256(canonical);

  db.prepare(`
    INSERT INTO audit_log (
      id, occurred_at, actor_user_id, event_type, target_type, target_id,
      client_id, outcome, ip_hash, user_agent, detail_json, previous_hash, entry_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    occurredAt,
    input.actorUserId ?? null,
    input.eventType,
    input.targetType ?? null,
    input.targetId ?? null,
    input.clientId ?? null,
    input.outcome ?? 'success',
    requestIpHash(input.request),
    input.request?.get('user-agent')?.slice(0, 500) ?? null,
    detailJson,
    previousHash,
    entryHash,
  );
}
