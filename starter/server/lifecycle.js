// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// Roles are ordered only for modification authority.
// Permission checks must NEVER use roles.rank.

import { randomUUID } from 'node:crypto';

export function roleRanks(db) {
  const rows = db
    .prepare(`
      SELECT key, rank
      FROM roles
      ORDER BY rank DESC, key ASC
    `)
    .all();

  return Object.fromEntries(rows.map((row) => [row.key, row.rank]));
}

export function assertRoleExists(db, role) {
  const row = db
    .prepare(`
      SELECT key
      FROM roles
      WHERE key = ?
      LIMIT 1
    `)
    .get(role);

  if (!row) {
    const error = new Error(`unknown role: ${role}`);
    error.code = 'UNKNOWN_ROLE';
    throw error;
  }

  return row.key;
}

export function assertCanModify(db, callerRole, targetRole) {
  assertRoleExists(db, callerRole);
  assertRoleExists(db, targetRole);

  const caller = db
    .prepare(`
      SELECT rank
      FROM roles
      WHERE key = ?
      LIMIT 1
    `)
    .get(callerRole);

  const target = db
    .prepare(`
      SELECT rank
      FROM roles
      WHERE key = ?
      LIMIT 1
    `)
    .get(targetRole);

  if (caller.rank <= target.rank) {
    const error = new Error('caller cannot modify target role');
    error.code = 'FORBIDDEN';
    throw error;
  }

  return true;
}

export function assertNotLastOwner(db, orgId, userId) {
  const owners = db
    .prepare(`
      SELECT user_id
      FROM memberships
      WHERE org_id = ?
        AND role = 'owner'
        AND status = 'active'
    `)
    .all(orgId);

  const isOwner = owners.some((owner) => owner.user_id === userId);

  if (!isOwner) {
    return true;
  }

  if (owners.length <= 1) {
    const error = new Error('cannot remove or demote the last owner');
    error.code = 'LAST_OWNER';
    throw error;
  }

  return true;
}

export function endActiveSessions(
  db,
  { orgId, userId, deviceId, reason, exceptSessionId }
) {
  const conditions = [
    'org_id = ?',
    "state = 'active'",
  ];

  const params = [orgId];

  if (userId !== undefined && userId !== null) {
    conditions.push('user_id = ?');
    params.push(userId);
  }

  if (deviceId !== undefined && deviceId !== null) {
    conditions.push('device_id = ?');
    params.push(deviceId);
  }

  if (exceptSessionId !== undefined && exceptSessionId !== null) {
    conditions.push('id <> ?');
    params.push(exceptSessionId);
  }

  const now = new Date().toISOString();

  const result = db
    .prepare(`
      UPDATE sessions
      SET state = 'ended',
          end_reason = ?,
          expires_at = ?
      WHERE ${conditions.join(' AND ')}
    `)
    .run(reason, now, ...params);

  return result.changes;
}

export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const membership = db
    .prepare(`
      SELECT role, perm_version
      FROM memberships
      WHERE user_id = ?
        AND org_id = ?
        AND status = 'active'
      LIMIT 1
    `)
    .get(userId, orgId);

  if (!membership) {
    const error = new Error('active membership not found');
    error.code = 'NOT_A_MEMBER';
    throw error;
  }

  const rolePermissions = db
    .prepare(`
      SELECT rp.permission
      FROM role_permissions rp
      WHERE rp.role = ?
    `)
    .all(membership.role)
    .map((row) => row.permission);

  return {
    role: membership.role,
    permVersion: membership.perm_version,
    deviceId: deviceId ?? null,
    permissions: rolePermissions,
  };
}

export function sessionExpiry(db, orgId) {
  const organization = db
    .prepare(`
      SELECT max_session_minutes
      FROM organizations
      WHERE id = ?
        AND deleted_at IS NULL
      LIMIT 1
    `)
    .get(orgId);

  if (!organization) {
    const error = new Error('organization not found');
    error.code = 'NOT_FOUND';
    throw error;
  }

  const minutes = Number(organization.max_session_minutes);

  if (!Number.isFinite(minutes) || minutes <= 0) {
    const error = new Error('invalid session duration');
    error.code = 'INVALID_SESSION_DURATION';
    throw error;
  }

  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}