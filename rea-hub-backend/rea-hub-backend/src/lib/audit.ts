import { Request } from 'express';

type Q = { query: (text: string, params?: unknown[]) => Promise<unknown> };
export interface AuditEntry { action: string; target?: string; targetId?: string; oldValue?: unknown; newValue?: unknown }

/** Append-only. Pass a transaction client so the audit row commits/rolls back with the change itself. */
export async function audit(q: Q, req: Request, e: AuditEntry): Promise<void> {
  const j = (v: unknown) => (v === undefined ? null : JSON.stringify(v));
  await q.query(
    `insert into audit_logs (actor_id, actor_role, action_type, target_entity, target_id, old_value, new_value, ip_address)
     values ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8)`,
    [req.user?.id ?? null, req.user?.role ?? null, e.action, e.target ?? null, e.targetId ?? null, j(e.oldValue), j(e.newValue), req.ip ?? null],
  );
}
