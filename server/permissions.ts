import { db } from './db.js';
import type { AuthenticatedRequest, UserRow } from './types.js';
import type { Collection } from './config.js';

export type PermissionAction = 'view' | 'manage' | 'reveal' | 'export';

export type ResourceScope = {
  clientId: string;
  locationId?: string | null;
  collection?: Collection | null;
};

type PermissionRow = {
  can_view: number;
  can_manage: number;
  can_reveal: number;
  can_export: number;
  client_id: string | null;
  location_id: string | null;
  collection: Collection | null;
};

const actionColumn: Record<PermissionAction, keyof PermissionRow> = {
  view: 'can_view',
  manage: 'can_manage',
  reveal: 'can_reveal',
  export: 'can_export',
};

export function hasPermission(user: UserRow, scope: ResourceScope, action: PermissionAction) {
  if (user.role === 'workspace_owner' || user.role === 'admin') return true;

  const rows = db.prepare(`
    SELECT can_view, can_manage, can_reveal, can_export, client_id, location_id, collection
    FROM permissions
    WHERE user_id = ?
      AND (client_id IS NULL OR client_id = ?)
      AND (location_id IS NULL OR location_id = ?)
      AND (collection IS NULL OR collection = ?)
    ORDER BY
      (client_id IS NOT NULL) + (location_id IS NOT NULL) + (collection IS NOT NULL) DESC,
      updated_at DESC
  `).all(user.id, scope.clientId, scope.locationId ?? null, scope.collection ?? null) as PermissionRow[];

  const best = rows[0];
  if (!best) return false;
  const column = actionColumn[action];
  return Boolean(best[column]);
}

export function assertPermission(request: AuthenticatedRequest, scope: ResourceScope, action: PermissionAction) {
  if (!hasPermission(request.auth.user, scope, action)) {
    throw Object.assign(new Error('You do not have permission for this client record.'), { status: 403, code: 'PERMISSION_DENIED' });
  }
}

export function canManageWorkspace(user: UserRow) {
  return user.role === 'workspace_owner' || user.role === 'admin';
}

export function assertWorkspaceAdmin(request: AuthenticatedRequest) {
  if (!canManageWorkspace(request.auth.user)) {
    throw Object.assign(new Error('Workspace administration permission is required.'), { status: 403, code: 'PERMISSION_DENIED' });
  }
}

export function visibleClientIds(user: UserRow) {
  if (user.role === 'workspace_owner' || user.role === 'admin') return null;
  return (db.prepare('SELECT DISTINCT client_id FROM permissions WHERE user_id = ? AND can_view = 1 AND client_id IS NOT NULL').all(user.id) as Array<{ client_id: string }>).map((row) => row.client_id);
}

export function assignedClientIds(userId: string) {
  return (db.prepare('SELECT DISTINCT client_id FROM permissions WHERE user_id = ? AND client_id IS NOT NULL ORDER BY client_id').all(userId) as Array<{ client_id: string }>).map((row) => row.client_id);
}

export function manageableClientIds(user: UserRow) {
  if (user.role === 'workspace_owner' || user.role === 'admin') return null;
  if (user.role !== 'client_admin') return [];
  return (db.prepare(`
    SELECT DISTINCT client_id
    FROM permissions
    WHERE user_id = ? AND can_manage = 1 AND client_id IS NOT NULL
      AND location_id IS NULL AND collection IS NULL
    ORDER BY client_id
  `).all(user.id) as Array<{ client_id: string }>).map((row) => row.client_id);
}
