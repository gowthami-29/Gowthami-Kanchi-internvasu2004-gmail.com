// Per-request context: turn a bearer token into an authenticated caller.

import { verifyAccessToken, assertFresh } from './auth.js';
import {
  unauthenticated,
  notFound,
} from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // -----------------------------------------------------------------------
    // 1. Read bearer token
    // -----------------------------------------------------------------------
    const header = req.headers.authorization;

    if (typeof header !== 'string') {
      throw unauthenticated('access token required');
    }

    if (!header.startsWith('Bearer ')) {
      throw unauthenticated('access token required');
    }

    const token = header.slice('Bearer '.length).trim();

    if (!token) {
      throw unauthenticated('access token required');
    }

    // -----------------------------------------------------------------------
    // 2. Verify JWT
    // -----------------------------------------------------------------------
    const claims = verifyAccessToken(token, secret);

    const userId = claims.sub;
    const orgId = claims.org;

    if (
      typeof userId !== 'string' ||
      !userId ||
      typeof orgId !== 'string' ||
      !orgId
    ) {
      throw unauthenticated('invalid access token');
    }

    // -----------------------------------------------------------------------
    // 3. Token org is the only org this caller can address.
    // Different org => invisible 404.
    // -----------------------------------------------------------------------
    if (
      params &&
      typeof params.orgId === 'string' &&
      params.orgId !== orgId
    ) {
      throw notFound('not found');
    }

    // -----------------------------------------------------------------------
    // 4. Find the caller's membership in the token's organization.
    // -----------------------------------------------------------------------
    const membership = db
      .prepare(`
        SELECT
          m.id,
          m.user_id,
          m.org_id,
          m.role,
          m.status,
          m.perm_version,
          m.created_at,

          o.name AS org_name,
          o.theme AS org_theme
        FROM memberships m
        JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ?
          AND m.org_id = ?
          AND o.deleted_at IS NULL
        LIMIT 1
      `)
      .get(userId, orgId);

    if (!membership) {
      throw notFound('not found');
    }

    // -----------------------------------------------------------------------
    // 5. Membership must still be active.
    // -----------------------------------------------------------------------
    if (membership.status !== 'active') {
      throw unauthenticated('membership is not active');
    }

    // -----------------------------------------------------------------------
    // 6. Permission-version freshness.
    // -----------------------------------------------------------------------
    assertFresh(claims, membership);

    // -----------------------------------------------------------------------
    // 7. Return authenticated caller context.
    // -----------------------------------------------------------------------
    return {
      userId,
      orgId,
      role: membership.role,
      membership,
      claims,
    };
  };
}