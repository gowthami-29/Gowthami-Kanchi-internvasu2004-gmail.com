// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/permissions.js — ${name}() is yours to write (BRIEF.md §3).`),
    { code: 'NOT_IMPLEMENTED' }
  );

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const permissions = db
    .prepare(`SELECT key FROM permissions ORDER BY key`)
    .all();

  const membership = db
    .prepare(`
      SELECT role, status
      FROM memberships
      WHERE org_id = ? AND user_id = ?
      LIMIT 1
    `)
    .get(orgId, userId);

  // Not a member: everything is denied.
  if (!membership) {
    const result = {};

    for (const permission of permissions) {
      result[permission.key] = {
        effect: 'deny',
        source: null,
        reason: 'not_a_member'
      };
    }

    return {
      role: null,
      permissions: result
    };
  }

  // Suspended membership: everything is denied.
  if (membership.status === 'suspended') {
    const result = {};

    for (const permission of permissions) {
      result[permission.key] = {
        effect: 'deny',
        source: null,
        reason: 'suspended'
      };
    }

    return {
      role: membership.role,
      permissions: result
    };
  }

  // Role baseline.
  const baselineRows = db
    .prepare(`
      SELECT permission
      FROM role_permissions
      WHERE role = ?
    `)
    .all(membership.role);

  const baseline = new Set(
    baselineRows.map(row => row.permission)
  );

  // Grants that are active right now and applicable to this scope.
  const grantRows = db
    .prepare(`
      SELECT
        g.id,
        g.effect,
        g.device_id,
        gp.permission
      FROM grants g
      JOIN grant_permissions gp
        ON gp.grant_id = g.id
      WHERE g.org_id = ?
        AND g.user_id = ?
        AND g.revoked_at IS NULL
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR ? < g.expires_at)
        AND (
          g.device_id IS NULL
          OR g.device_id = ?
        )
    `)
    .all(
      orgId,
      userId,
      now.toISOString(),
      now.toISOString(),
      deviceId
    );

  function patternMatches(pattern, permission) {
    if (pattern === '*') return true;

    if (pattern.endsWith(':*')) {
      const resource = pattern.slice(0, -2);
      return permission.startsWith(`${resource}:`);
    }

    return pattern === permission;
  }

  const result = {};

  for (const { key } of permissions) {
    const applicable = grantRows.filter(row =>
      patternMatches(row.permission, key)
    );

    // Explicit deny always wins.
    const deny = applicable.find(row => row.effect === 'deny');

    if (deny) {
      result[key] = {
        effect: 'deny',
        source: `grant:${deny.id}`,
        reason: 'explicit_deny',
        grantId: deny.id
      };
      continue;
    }

    // An explicit allow grant can add a permission to the role baseline.
    const allow = applicable.find(row => row.effect === 'allow');

    if (allow) {
      result[key] = {
        effect: 'allow',
        source: `grant:${allow.id}`,
        reason: 'grant',
        grantId: allow.id
      };
      continue;
    }

    // Otherwise use the role baseline.
    if (baseline.has(key)) {
      result[key] = {
        effect: 'allow',
        source: 'role',
        reason: 'role_baseline'
      };
      continue;
    }

    // Default deny.
    result[key] = {
      effect: 'deny',
      source: null,
      reason: 'implicit'
    };
  }

  return {
    role: membership.role,
    permissions: result
  };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(
  db,
  { userId, orgId, deviceIds, now = new Date() }
) {
  const ids = Array.isArray(deviceIds) ? deviceIds : [];

  const byDevice = {};

  for (const deviceId of ids) {
    const resolved = resolve(db, {
      userId,
      orgId,
      deviceId,
      now,
    });

    byDevice[deviceId] = resolved.permissions;
  }

  const orgResolved = resolve(db, {
    userId,
    orgId,
    deviceId: null,
    now,
  });

  return {
    role: orgResolved.role,
    byDevice,
  };
}

export function can(db, ctx, permission, deviceId) {
  const resolved = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId: deviceId ?? null,
  });

  return resolved.permissions[permission]?.effect === 'allow';
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  const resolved = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId: deviceId ?? null,
  });

  const entry = resolved.permissions[permission];

  if (entry?.effect !== 'allow') {
    const error = new Error(`Missing ${permission} permission`);
    error.reason = entry?.reason || 'missing_permission';
    error.code = 'FORBIDDEN';
    error.status = 403;
    throw error;
  }

  return true;
}

// No privilege laundering: you may only grant authority you hold at that scope.
export function assertMayGrant(
  db,
  ctx,
  targetUserId,
  patterns,
  deviceId = null
) {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    const error = new Error('At least one permission is required');
    error.reason = 'invalid_permissions';
    throw error;
  }

  if (patterns.some((permission) => typeof permission !== 'string' || !permission)) {
    const error = new Error('Invalid permission');
    error.reason = 'invalid_permissions';
    throw error;
  }

  // A user may never grant authority to themselves.
  if (ctx.userId === targetUserId) {
    const error = new Error('You cannot grant permissions to yourself');
    error.code = 'FORBIDDEN';
    error.reason = 'self_grant';
    throw error;
  }

  const resolved = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  });

  for (const permission of patterns) {
    const effective = resolved.permissions[permission];

    if (effective?.effect !== 'allow') {
      const error = new Error(
        `You cannot grant permission you do not hold: ${permission}`
      );
      error.code = 'FORBIDDEN';
      error.reason = 'missing_permission';
      throw error;
    }
  }

  return true;
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const requiredPermission = MODE_PERMISSION[mode];

  if (!requiredPermission) {
    const error = new Error(`Unknown session mode: ${mode}`);
    error.reason = 'missing_permission';
    throw error;
  }

  const resolved = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  });

  // The user must have session:start.
  if (resolved.permissions['session:start']?.effect !== 'allow') {
    const error = new Error('Missing session:start permission');
    error.reason = 'missing_permission';
    throw error;
  }

  // The user must also have the permission for the requested mode
  // on this exact device.
  if (resolved.permissions[requiredPermission]?.effect !== 'allow') {
    const error = new Error(`Missing ${requiredPermission} permission`);
    error.reason = 'missing_device_permission';
    throw error;
  }

  return undefined;
}