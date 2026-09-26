import { randomUUID } from 'node:crypto';

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/audit.js — ${name}() is yours to write.`),
    { code: 'NOT_IMPLEMENTED' }
  );

/**
 * Append one audit event.
 *
 * Audit is append-only. The database triggers prevent UPDATE/DELETE,
 * so this function only ever INSERTs.
 */
export function audit(
  db,
  {
    orgId,
    actorId,
    action,
    targetType = null,
    targetId = null,
    result,
    reasonCode = null,
    requestId = null,
  }
) {
  if (!orgId) {
    throw new Error('audit requires orgId');
  }

  if (!actorId) {
    throw new Error('audit requires actorId');
  }

  if (!action) {
    throw new Error('audit requires action');
  }

  if (result !== 'allow' && result !== 'deny') {
    throw new Error('audit result must be allow or deny');
  }

  const id = randomUUID();

  db.prepare(`
    INSERT INTO audit_events (
      id,
      org_id,
      actor_id,
      action,
      target_type,
      target_id,
      result,
      reason_code,
      request_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    orgId,
    actorId,
    action,
    targetType,
    targetId,
    result,
    reasonCode,
    requestId
  );

  return db
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
      WHERE id = ?
    `)
    .get(id);
}

/**
 * Run an operation and record denied permission attempts.
 *
 * Successful operations are responsible for recording their own
 * success audit row inside the same transaction as the mutation.
 */
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (error) {
    const permissionError =
      error?.status === 403 ||
      error?.statusCode === 403 ||
      error?.code === 'FORBIDDEN' ||
      error?.code === 'PERMISSION_DENIED';

    if (permissionError) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: error.reason ?? error.reasonCode ?? 'forbidden',
        requestId: ctx.requestId ?? null,
      });
    }

    throw error;
  }
}