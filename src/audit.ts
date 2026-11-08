import type { Env } from './env';

/**
 * One line per event. Never put secrets, tokens, request bodies or upstream responses in here:
 * only who, what, and how it went.
 */
export interface AuditEvent {
  type: 'tool_call' | 'consent' | 'revoke' | 'policy' | 'login_failed' | 'redaction' | 'approval';
  outcome: 'ok' | 'error' | 'denied' | 'pending';
  client_id?: string;
  client_name?: string;
  agent?: string;
  tool?: string;
  /** Short machine-readable reason, e.g. "upstream_401". Never free text from upstream. */
  code?: string;
  /** Per-call approval this event belongs to. */
  approval_id?: string;
  ms?: number;
}

export interface AuditLine extends AuditEvent {
  ts: string;
}

const AUDIT_TTL_SECONDS = 30 * 24 * 3600;
// Keys sort newest first: KV lists keys in ascending order, so store a reversed timestamp.
const REVERSE_BASE = 9_000_000_000_000_000;

export function audit(env: Env, ctx: ExecutionContext, event: AuditEvent): AuditLine {
  const line: AuditLine = { ts: new Date().toISOString(), ...event };
  console.log(JSON.stringify({ audit: line }));
  const key = `audit:${String(REVERSE_BASE - Date.now()).padStart(16, '0')}:${crypto.randomUUID().slice(0, 8)}`;
  ctx.waitUntil(env.BROKER_KV.put(key, JSON.stringify(line), { expirationTtl: AUDIT_TTL_SECONDS }));
  return line;
}

export async function readAudit(env: Env, limit = 100): Promise<AuditLine[]> {
  const list = await env.BROKER_KV.list({ prefix: 'audit:', limit: Math.min(Math.max(limit, 1), 1000) });
  const values = await Promise.all(list.keys.map((k) => env.BROKER_KV.get(k.name)));
  return values.filter((v): v is string => !!v).map((v) => JSON.parse(v) as AuditLine);
}
