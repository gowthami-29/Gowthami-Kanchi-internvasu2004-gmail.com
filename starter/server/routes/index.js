import { randomUUID } from 'node:crypto';
import {
  issueAccessToken,
  verifyPassword,
  hashPassword,
  newInviteToken,
  hashInviteToken,
} from '../auth.js';
import {
  resolveDevices,
  assertCanStartSession,
  assertMayGrant,
  assertCan,
} from '../permissions.js';

import {
  selfRoleChange,
} from '../http.js';
import {
  unauthenticated,
  badRequest,
  send,
  notFound,
  forbidden,
  deviceBusy,
  lastOwner,conflict
} from '../http.js';
import {
  sessionExpiry,
  snapshotAuthority,
} from '../lifecycle.js';
import { audit } from '../audit.js';
import {
  assertCanModify,
  assertNotLastOwner,
  endActiveSessions,
} from '../lifecycle.js';
export function registerRoutes(router, deps) {
  const { db, secret } = deps;

  // -------------------------------------------------------------------------
  // POST /v1/auth/login
  // -------------------------------------------------------------------------
  router.post('/v1/auth/login', async (ctx, params, res) => {
    const { email, password, orgId } = ctx.body;

    if (
      typeof email !== 'string' ||
      typeof password !== 'string'
    ) {
      throw badRequest('email and password are required');
    }

    const user = db
      .prepare(`
        SELECT id, email, name, password_hash
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .get(email.toLowerCase());

    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid email or password');
    }

    const memberships = db
      .prepare(`
        SELECT
          m.org_id,
          m.role,
          m.perm_version,
          o.name,
          o.theme
        FROM memberships m
        JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ?
          AND m.status = 'active'
          AND o.deleted_at IS NULL
        ORDER BY m.created_at
      `)
      .all(user.id);

    if (memberships.length === 0) {
      throw unauthenticated(
        'user is not a member of an active organization'
      );
    }

    const selected = orgId
      ? memberships.find((m) => m.org_id === orgId)
      : memberships[0];

    if (!selected) {
      throw unauthenticated(
        'not a member of this organization'
      );
    }

    const token = issueAccessToken(
      {
        userId: user.id,
        orgId: selected.org_id,
        role: selected.role,
        permVersion: selected.perm_version,
      },
      secret
    );

    send(res, 200, {
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      orgId: selected.org_id,
      role: selected.role,
      orgs: memberships.map((m) => ({
        id: m.org_id,
        name: m.name,
        theme: m.theme,
      })),
    });
  });

  // -------------------------------------------------------------------------
  // POST /v1/auth/token
  // Switch the authenticated user to another organization
  // -------------------------------------------------------------------------
  router.post('/v1/auth/token', async (ctx, params, res) => {
    const { orgId } = ctx.body;

    if (typeof orgId !== 'string' || !orgId) {
      throw badRequest('orgId is required');
    }

    const membership = db
      .prepare(`
        SELECT
          m.org_id,
          m.role,
          m.perm_version,
          o.name,
          o.theme
        FROM memberships m
        JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ?
          AND m.org_id = ?
          AND m.status = 'active'
          AND o.deleted_at IS NULL
        LIMIT 1
      `)
      .get(ctx.userId, orgId);

    if (!membership) {
      throw notFound('organization not found');
    }

    const token = issueAccessToken(
      {
        userId: ctx.userId,
        orgId: membership.org_id,
        role: membership.role,
        permVersion: membership.perm_version,
      },
      secret
    );

    send(res, 200, {
      token,
      orgId: membership.org_id,
      role: membership.role,
    });
  });


  // -------------------------------------------------------------------------
  // GET /v1/orgs/:orgId/devices
  // -------------------------------------------------------------------------
  router.get('/v1/orgs/:orgId/devices', async (ctx, params, res) => {
    const devices = db
      .prepare(`
        SELECT
          id,
          name,
          kind,
          online,
          created_at
        FROM devices
        WHERE org_id = ?
          AND deleted_at IS NULL
        ORDER BY name, id
      `)
      .all(ctx.orgId);

    const resolved = resolveDevices(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceIds: devices.map((device) => device.id),
    });

    const result = [];

    for (const device of devices) {
      const permissions = resolved.byDevice[device.id];

      // device:list controls whether the endpoint can be used.
      // device:view controls whether a particular row is visible.
      if (permissions?.['device:view']?.effect !== 'allow') {
        continue;
      }

      result.push({
        id: device.id,
        name: device.name,
        kind: device.kind,
        online: Boolean(device.online),
        created_at: device.created_at,
        permissions,
      });
    }

    send(res, 200, {
      role: resolved.role,
      devices: result,
    });
  });





    // -------------------------------------------------------------------------
  // POST /v1/orgs/:orgId/sessions
  // -------------------------------------------------------------------------
  router.post('/v1/orgs/:orgId/sessions', async (ctx, params, res) => {
    const { deviceId, mode } = ctx.body;

    if (typeof deviceId !== 'string' || !deviceId) {
      throw badRequest('deviceId is required');
    }

    if (!['view', 'control', 'terminal'].includes(mode)) {
      throw badRequest('mode must be view, control, or terminal');
    }

    // Structural org isolation: a device from another org is invisible.
    const device = db
      .prepare(`
        SELECT id, org_id, name, kind, online, created_at
        FROM devices
        WHERE id = ?
          AND org_id = ?
          AND deleted_at IS NULL
        LIMIT 1
      `)
      .get(deviceId, ctx.orgId);

    if (!device) {
      throw notFound('device not found');
    }

    // Compound permission check:
    // session:start + device permission for requested mode.
    try {
      assertCanStartSession(db, ctx, mode, deviceId);
    } catch (error) {
      throw forbidden(
        error.message,
        error.reason || 'missing_permission'
      );
    }

    const authorizedBy = snapshotAuthority(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceId,
    });

    const sessionId = randomUUID();
    const expiresAt = sessionExpiry(db, ctx.orgId);

    try {
      db.prepare(`
        INSERT INTO sessions (
          id,
          org_id,
          user_id,
          device_id,
          mode,
          state,
          end_reason,
          authorized_by,
          expires_at
        )
        VALUES (?, ?, ?, ?, ?, 'active', NULL, ?, ?)
      `).run(
        sessionId,
        ctx.orgId,
        ctx.userId,
        deviceId,
        mode,
        JSON.stringify(authorizedBy),
        expiresAt
      );
    } catch (error) {
      // SQLite's partial unique index enforces D10.
      if (
        error?.code === 'SQLITE_CONSTRAINT_UNIQUE' ||
        String(error?.message || '').includes(
          'one_exclusive_session_per_device'
        )
      ) {
        throw deviceBusy();
      }

      throw error;
    }

    const session = db
      .prepare(`
        SELECT
          id,
          org_id,
          user_id,
          device_id,
          mode,
          state,
          end_reason,
          authorized_by,
          started_at,
          expires_at,
          ended_at
        FROM sessions
        WHERE id = ?
      `)
      .get(sessionId);

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'session.start',
      targetType: 'session',
      targetId: sessionId,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 201, session);
  });

  // -------------------------------------------------------------------------
  // GET /v1/orgs/:orgId/sessions
  // -------------------------------------------------------------------------
  router.get('/v1/orgs/:orgId/sessions', async (ctx, params, res) => {
    const sessions = db
      .prepare(`
        SELECT
          id,
          org_id,
          user_id,
          device_id,
          mode,
          state,
          end_reason,
          authorized_by,
          started_at,
          expires_at,
          ended_at
        FROM sessions
        WHERE org_id = ?
        ORDER BY started_at DESC
      `)
      .all(ctx.orgId);

    send(res, 200, { sessions });
  });

  // -------------------------------------------------------------------------
  // GET /v1/sessions/:sessionId
  // -------------------------------------------------------------------------
  router.get('/v1/sessions/:sessionId', async (ctx, params, res) => {
    const session = db
      .prepare(`
        SELECT
          id,
          org_id,
          user_id,
          device_id,
          mode,
          state,
          end_reason,
          authorized_by,
          started_at,
          expires_at,
          ended_at
        FROM sessions
        WHERE id = ?
          AND org_id = ?
        LIMIT 1
      `)
      .get(params.sessionId, ctx.orgId);

    if (!session) {
      throw notFound('session not found');
    }

    send(res, 200, session);
  });

    // -------------------------------------------------------------------------
  // GET /v1/orgs/:orgId/audit
  // -------------------------------------------------------------------------
  router.get('/v1/orgs/:orgId/audit', async (ctx, params, res) => {
    // Permission is deliberately checked here.
    // operator does not inherit auditor permissions.
    try {
      assertCan(db, ctx, 'audit:read', null);
    } catch (error) {
      throw forbidden(
        error.message,
        error.reason || 'missing_permission'
      );
    }

    const limitRaw = ctx.query.get('limit');
    const offsetRaw = ctx.query.get('offset');

    const limit = limitRaw === null ? 50 : Number(limitRaw);
    const offset = offsetRaw === null ? 0 : Number(offsetRaw);

    if (
      !Number.isInteger(limit) ||
      limit <= 0 ||
      limit > 1000
    ) {
      throw badRequest('limit must be between 1 and 1000');
    }

    if (!Number.isInteger(offset) || offset < 0) {
      throw badRequest('offset must be 0 or greater');
    }

    const events = db
      .prepare(`
        SELECT
          id,
          org_id,
          actor_id,
          action,
          target_type,
          target_id,
          result,
          reason_code,
          request_id,
          at
        FROM audit_events
        WHERE org_id = ?
        ORDER BY at DESC
        LIMIT ? OFFSET ?
      `)
      .all(ctx.orgId, limit, offset);

    send(res, 200, {
      events,
      limit,
      offset,
    });
  });


    // -------------------------------------------------------------------------
  // PATCH /v1/orgs/:orgId/members/:userId
  // -------------------------------------------------------------------------
  router.patch('/v1/orgs/:orgId/members/:userId', async (ctx, params, res) => {
    const { role } = ctx.body;

    if (typeof role !== 'string' || !role) {
      throw badRequest('role is required');
    }

    // Never allow a caller to change their own role.
    if (params.userId === ctx.userId) {
      throw selfRoleChange();
    }

    // Target must belong to this exact organization.
    const target = db
      .prepare(`
        SELECT
          id,
          user_id,
          org_id,
          role,
          status,
          perm_version
        FROM memberships
        WHERE user_id = ?
          AND org_id = ?
        LIMIT 1
      `)
      .get(params.userId, ctx.orgId);

    if (!target) {
      throw notFound('member not found');
    }

    // Validate the requested role exists.
    try {
      assertCanModify(db, ctx.role, role);
    } catch (error) {
      if (error.code === 'UNKNOWN_ROLE') {
        throw badRequest('unknown role');
      }

      throw forbidden(
        error.message,
        error.reason || 'missing_permission'
      );
    }

    // Demoting/removing the final active owner is forbidden.
    if (target.role === 'owner' && role !== 'owner') {
      try {
        assertNotLastOwner(db, ctx.orgId, target.user_id);
      } catch (error) {
        if (error.code === 'LAST_OWNER') {
          throw error;
        }
        throw error;
      }
    }

    const updated = db
      .prepare(`
        UPDATE memberships
        SET role = ?,
            perm_version = perm_version + 1
        WHERE user_id = ?
          AND org_id = ?
      `)
      .run(role, target.user_id, ctx.orgId);

    if (updated.changes !== 1) {
      throw notFound('member not found');
    }

    const membership = db
      .prepare(`
        SELECT
          id,
          user_id,
          org_id,
          role,
          status,
          perm_version,
          joined_at,
          created_at
        FROM memberships
        WHERE user_id = ?
          AND org_id = ?
        LIMIT 1
      `)
      .get(target.user_id, ctx.orgId);

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'member.role_change',
      targetType: 'membership',
      targetId: membership.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 200, membership);
  });
    // -------------------------------------------------------------------------
  // POST /v1/orgs/:orgId/members/:userId/suspend
  // -------------------------------------------------------------------------
  router.post('/v1/orgs/:orgId/members/:userId/suspend', async (ctx, params, res) => {
    const target = db
      .prepare(`
        SELECT
          id,
          user_id,
          org_id,
          role,
          status,
          perm_version
        FROM memberships
        WHERE user_id = ?
          AND org_id = ?
        LIMIT 1
      `)
      .get(params.userId, ctx.orgId);

    if (!target) {
      throw notFound('member not found');
    }

    if (target.user_id === ctx.userId) {
      throw selfRoleChange();
    }

    // Suspension is an authority-changing membership action.
    try {
      assertCanModify(db, ctx.role, target.role);
    } catch (error) {
      if (error.code === 'UNKNOWN_ROLE') {
        throw badRequest('unknown role');
      }

      throw forbidden(
        error.message,
        error.reason || 'missing_permission'
      );
    }

    if (target.status !== 'suspended') {
      db.prepare(`
        UPDATE memberships
        SET status = 'suspended',
            perm_version = perm_version + 1
        WHERE user_id = ?
          AND org_id = ?
      `).run(target.user_id, ctx.orgId);

      endActiveSessions(db, {
        orgId: ctx.orgId,
        userId: target.user_id,
        reason: 'user_suspended',
      });
    }

    const membership = db
      .prepare(`
        SELECT
          id,
          user_id,
          org_id,
          role,
          status,
          perm_version,
          joined_at,
          created_at
        FROM memberships
        WHERE user_id = ?
          AND org_id = ?
        LIMIT 1
      `)
      .get(target.user_id, ctx.orgId);

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'member.suspend',
      targetType: 'membership',
      targetId: membership.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 200, membership);
  });

  // -------------------------------------------------------------------------
  // DELETE /v1/orgs/:orgId/members/:userId/suspend
  // -------------------------------------------------------------------------
  router.delete('/v1/orgs/:orgId/members/:userId/suspend', async (ctx, params, res) => {
    const target = db
      .prepare(`
        SELECT
          id,
          user_id,
          org_id,
          role,
          status,
          perm_version
        FROM memberships
        WHERE user_id = ?
          AND org_id = ?
        LIMIT 1
      `)
      .get(params.userId, ctx.orgId);

    if (!target) {
      throw notFound('member not found');
    }

    try {
      assertCanModify(db, ctx.role, target.role);
    } catch (error) {
      if (error.code === 'UNKNOWN_ROLE') {
        throw badRequest('unknown role');
      }

      throw forbidden(
        error.message,
        error.reason || 'missing_permission'
      );
    }

    db.prepare(`
      UPDATE memberships
      SET status = 'active',
          perm_version = perm_version + 1
      WHERE user_id = ?
        AND org_id = ?
    `).run(target.user_id, ctx.orgId);

    const membership = db
      .prepare(`
        SELECT
          id,
          user_id,
          org_id,
          role,
          status,
          perm_version,
          joined_at,
          created_at
        FROM memberships
        WHERE user_id = ?
          AND org_id = ?
        LIMIT 1
      `)
      .get(target.user_id, ctx.orgId);

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'member.reinstate',
      targetType: 'membership',
      targetId: membership.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 200, membership);
  });

    // -------------------------------------------------------------------------
  // POST /v1/orgs
  // -------------------------------------------------------------------------
  router.post('/v1/orgs', async (ctx, params, res) => {
    const { name } = ctx.body;

    if (typeof name !== 'string' || !name.trim()) {
      throw badRequest('organization name is required');
    }

    

    const orgId = `org_${randomUUID()}`;
    const membershipId = randomUUID();

    db.prepare(`
      INSERT INTO organizations (
        id,
        name,
        theme
      )
      VALUES (?, ?, ?)
    `).run(
      orgId,
      name.trim(),
      'default'
    );

    db.prepare(`
      INSERT INTO memberships (
        id,
        org_id,
        user_id,
        role,
        status,
        perm_version,
        joined_at
      )
      VALUES (?, ?, ?, 'owner', 'active', 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    `).run(
      membershipId,
      
      orgId,
      ctx.userId,
    );

    audit(db, {
      orgId,
      actorId: ctx.userId,
      action: 'org.create',
      targetType: 'organization',
      targetId: orgId,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 201, {
      id: orgId,
      name: name.trim(),
      role: 'owner',
    });
  });

    // -------------------------------------------------------------------------
  // DELETE /v1/orgs/:orgId/members/me
  // -------------------------------------------------------------------------
  router.delete('/v1/orgs/:orgId/members/me', async (ctx, params, res) => {
    const membership = db
      .prepare(`
        SELECT
          id,
          user_id,
          org_id,
          role,
          status
        FROM memberships
        WHERE user_id = ?
          AND org_id = ?
          AND status = 'active'
        LIMIT 1
      `)
      .get(ctx.userId, ctx.orgId);

    if (!membership) {
      throw notFound('member not found');
    }

    if (membership.role === 'owner') {
  try {
    assertNotLastOwner(db, ctx.orgId, ctx.userId);
  } catch (error) {
    if (error.code === 'LAST_OWNER') {
      throw lastOwner();
    }

    throw error;
  }
}

    db.prepare(`
      UPDATE memberships
      SET status = 'removed',
          perm_version = perm_version + 1
      WHERE user_id = ?
        AND org_id = ?
    `).run(ctx.userId, ctx.orgId);

    endActiveSessions(db, {
      orgId: ctx.orgId,
      userId: ctx.userId,
      reason: 'user_removed',
    });

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'member.leave',
      targetType: 'membership',
      targetId: membership.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 200, {
      ...membership,
      status: 'removed',
    });
  });

    // -------------------------------------------------------------------------
  // POST /v1/orgs/:orgId/grants
  // -------------------------------------------------------------------------
  router.post('/v1/orgs/:orgId/grants', async (ctx, params, res) => {
    const {
      userId,
      effect,
      permissions,
      deviceId = null,
      startsAt = null,
      expiresAt = null,
    } = ctx.body;

    if (typeof userId !== 'string' || !userId) {
      throw badRequest('userId is required');
    }

    if (effect !== 'allow' && effect !== 'deny') {
      throw badRequest('effect must be allow or deny');
    }

    if (!Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('permissions must contain at least one permission');
    }

    if (
      permissions.some(
        (permission) =>
          typeof permission !== 'string' || !permission.trim()
      )
    ) {
      throw badRequest('permissions must contain valid permission names');
    }

    // Target must belong to this exact organization.
    const target = db
      .prepare(`
        SELECT id, user_id, org_id, role, status
        FROM memberships
        WHERE user_id = ?
          AND org_id = ?
          AND status = 'active'
        LIMIT 1
      `)
      .get(userId, ctx.orgId);

    if (!target) {
      throw notFound('member not found');
    }

    // A user cannot grant permissions to themselves.
    
      
    // Every permission must exist in the permission catalog.
    const placeholders = permissions.map(() => '?').join(', ');

    const knownPermissions = db
      .prepare(`
        SELECT pattern
        FROM permission_patterns
        WHERE pattern IN (${placeholders})
      `)
      .all(...permissions)
      .map((row) => row.pattern);

    const unknownPermission = permissions.find(
      (permission) => !knownPermissions.includes(permission)
    );

    if (unknownPermission) {
      const error = badRequest(
        `unknown permission: ${unknownPermission}`
      );
      error.reason = 'unknown_permission';
      throw error;
    }

    // A user cannot grant permissions to themselves,
    // and cannot grant authority they do not hold.
    try {
      assertMayGrant(db, ctx, userId, permissions, deviceId);
    } catch (error) {
      if (error.reason === 'self_grant') {
        throw forbidden(error.message, 'self_grant');
      }

      throw forbidden(
        error.message,
        error.reason || 'missing_permission'
      );
    }

    // If a device is supplied, it must belong to this organization.
    if (deviceId !== null) {
      const device = db
        .prepare(`
          SELECT id
          FROM devices
          WHERE id = ?
            AND org_id = ?
            AND deleted_at IS NULL
          LIMIT 1
        `)
        .get(deviceId, ctx.orgId);

      if (!device) {
        throw notFound('device not found');
      }
    }

    if (
      startsAt !== null &&
      typeof startsAt !== 'string'
    ) {
      throw badRequest('startsAt must be a timestamp or null');
    }

    if (
      expiresAt !== null &&
      typeof expiresAt !== 'string'
    ) {
      throw badRequest('expiresAt must be a timestamp or null');
    }

    if (startsAt && expiresAt && expiresAt <= startsAt) {
      throw badRequest('expiresAt must be after startsAt');
    }

    const grantId = randomUUID();

    db.exec('BEGIN');

    try {
      db.prepare(`
        INSERT INTO grants (
          id,
          org_id,
          user_id,
          device_id,
          effect,
          starts_at,
          expires_at,
          created_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        grantId,
        ctx.orgId,
        userId,
        deviceId,
        effect,
        startsAt,
        expiresAt,
        ctx.userId
      );

      const insertPermission = db.prepare(`
        INSERT INTO grant_permissions (
          grant_id,
          permission
        )
        VALUES (?, ?)
      `);

      for (const permission of permissions) {
        insertPermission.run(grantId, permission);
      }

      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'grant.create',
      targetType: 'grant',
      targetId: grantId,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 201, {
      id: grantId,
      orgId: ctx.orgId,
      userId,
      deviceId,
      effect,
      permissions,
      startsAt,
      expiresAt,
    });
  });

    // -------------------------------------------------------------------------
  // POST /v1/orgs/:orgId/invites
  // -------------------------------------------------------------------------
  router.post('/v1/orgs/:orgId/invites', async (ctx, params, res) => {
    const { email, role } = ctx.body;

    if (typeof email !== 'string' || !email.trim()) {
      throw badRequest('email is required');
    }

    if (typeof role !== 'string' || !role) {
      throw badRequest('role is required');
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Validate the requested role.
    const roleRow = db
      .prepare(`
        SELECT key
        FROM roles
        WHERE key = ?
        LIMIT 1
      `)
      .get(role);

    if (!roleRow) {
      throw badRequest('unknown role');
    }

    // The inviter must have authority to modify this role.
    try {
      assertCanModify(db, ctx.role, role);
    } catch (error) {
      if (error.code === 'UNKNOWN_ROLE') {
        throw badRequest('unknown role');
      }

      throw forbidden(
        error.message,
        error.reason || 'missing_permission'
      );
    }

    const existingUser = db
      .prepare(`
        SELECT id
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .get(normalizedEmail);

    if (existingUser) {
      const existingMembership = db
        .prepare(`
          SELECT id
          FROM memberships
          WHERE user_id = ?
            AND org_id = ?
            AND status = 'active'
          LIMIT 1
        `)
        .get(existingUser.id, ctx.orgId);

      if (existingMembership) {
        throw badRequest('user is already a member');
      }
    }

    const rawToken = newInviteToken();
    const tokenHash = hashInviteToken(rawToken);
    const inviteId = randomUUID();

    // Invites are short-lived bearer credentials.
    const expiresAt = new Date(
      Date.now() + 24 * 60 * 60 * 1000
    ).toISOString();

    try {
      db.prepare(`
        INSERT INTO invites (
          id,
          org_id,
          email,
          role,
          token_hash,
          invited_by,
          expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        inviteId,
        ctx.orgId,
        normalizedEmail,
        role,
        tokenHash,
        ctx.userId,
        expiresAt
      );
    } catch (error) {
      if (
        error?.code === 'SQLITE_CONSTRAINT_UNIQUE' ||
        String(error?.message || '').includes(
          'one_live_invite_per_email'
        )
      ) {
        throw conflict('an active invite already exists for this email');
      }

      throw error;
    }

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'invite.create',
      targetType: 'invite',
      targetId: inviteId,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 201, {
      id: inviteId,
      email: normalizedEmail,
      role,
      expiresAt,
      inviteToken: rawToken,
    });
  });

    // -------------------------------------------------------------------------
  // GET /v1/invites/:token
  // Public invite preview — never exposes org ID or devices.
  // -------------------------------------------------------------------------
  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const token = params.token;

    if (typeof token !== 'string' || !token) {
      throw notFound('invite not found');
    }

    const tokenHash = hashInviteToken(token);

    const invite = db
      .prepare(`
        SELECT
          i.id,
          i.email,
          i.role,
          i.expires_at,
          i.accepted_at,
          i.revoked_at,
          o.name AS org_name
        FROM invites i
        JOIN organizations o ON o.id = i.org_id
        WHERE i.token_hash = ?
          AND o.deleted_at IS NULL
        LIMIT 1
      `)
      .get(tokenHash);

    if (!invite) {
      throw notFound('invite not found');
    }

    if (invite.accepted_at || invite.revoked_at) {
      throw notFound('invite not found');
    }

    if (new Date(invite.expires_at).getTime() <= Date.now()) {
      throw notFound('invite not found');
    }

    send(res, 200, {
      email: invite.email,
      role: invite.role,
      orgName: invite.org_name,
      expiresAt: invite.expires_at,
    });
  });


    // -------------------------------------------------------------------------
  // POST /v1/invites/:token/accept
  // -------------------------------------------------------------------------
  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    const token = params.token;
    const { name, password } = ctx.body;

    if (typeof name !== 'string' || !name.trim()) {
      throw badRequest('name is required');
    }

    if (typeof password !== 'string' || password.length < 8) {
      throw badRequest('password must be at least 8 characters');
    }

    if (typeof token !== 'string' || !token) {
      throw notFound('invite not found');
    }

    const tokenHash = hashInviteToken(token);

    const invite = db
      .prepare(`
        SELECT
          i.id,
          i.org_id,
          i.email,
          i.role,
          i.expires_at,
          i.accepted_at,
          i.revoked_at,
          o.name AS org_name
        FROM invites i
        JOIN organizations o ON o.id = i.org_id
        WHERE i.token_hash = ?
          AND o.deleted_at IS NULL
        LIMIT 1
      `)
      .get(tokenHash);

    if (!invite) {
      throw notFound('invite not found');
    }

    if (invite.accepted_at || invite.revoked_at) {
      throw conflict('invite has already been used');
    }

    if (new Date(invite.expires_at).getTime() <= Date.now()) {
      throw conflict('invite has expired');
    }

    const existingUser = db
      .prepare(`
        SELECT id
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .get(invite.email);

    if (existingUser) {
      throw conflict('a user with this email already exists');
    }

    const userId = randomUUID();
    const membershipId = randomUUID();
    const passwordHash = hashPassword(password);

    db.exec('BEGIN');

    try {
      db.prepare(`
        INSERT INTO users (
          id,
          email,
          name,
          password_hash
        )
        VALUES (?, ?, ?, ?)
      `).run(
        userId,
        invite.email,
        name.trim(),
        passwordHash
      );

      db.prepare(`
        INSERT INTO memberships (
          id,
          org_id,
          user_id,
          role,
          status,
          perm_version,
          invited_by,
          joined_at
        )
        VALUES (?, ?, ?, ?, 'active', 1, NULL, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
      `).run(
        membershipId,
        invite.org_id,
        userId,
        invite.role
      );

      const updated = db
        .prepare(`
          UPDATE invites
          SET accepted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
              accepted_by = ?
          WHERE id = ?
            AND accepted_at IS NULL
            AND revoked_at IS NULL
        `)
        .run(userId, invite.id);

      if (updated.changes !== 1) {
        throw conflict('invite has already been used');
      }

      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }

    audit(db, {
      orgId: invite.org_id,
      actorId: userId,
      action: 'invite.accept',
      targetType: 'invite',
      targetId: invite.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 200, {
      id: userId,
      email: invite.email,
      name: name.trim(),
      role: invite.role,
      orgId: invite.org_id,
    });
  });
}