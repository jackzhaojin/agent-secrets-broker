import { DurableObject } from 'cloudflare:workers';
import type { Env } from './env';

/**
 * Per-call approval for sensitive tools. A call that needs approval first comes back "pending";
 * the owner approves or denies it on the admin page (owner password session only, never the admin
 * API token or an agent's OAuth token); the agent then repeats the exact same call, which runs once.
 *
 * An approval is bound to the client, the agent, the tool and a hash of the exact arguments, and
 * it is single use. It lives in one Durable Object so "approve, then run once" is atomic and takes
 * effect at once (KV could serve a stale "pending" for up to a minute and can't do single use).
 */

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'used';

export interface ApprovalRecord {
  id: string;
  key: string;
  status: ApprovalStatus;
  agent: string;
  client_id: string;
  client_name: string;
  tool: string;
  /** What the owner sees on the approval page: short, allow-listed, never a secret. */
  summary: Record<string, string>;
  created_at: number;
  /** Pending: when the request lapses. Approved: when the approval lapses unused. Denied: when a new request may be made. */
  expires_at: number;
  decided_at?: number;
  used_at?: number;
}

export interface GateInput {
  key: string;
  agent: string;
  client_id: string;
  client_name: string;
  tool: string;
  summary: Record<string, string>;
}

export type GateResult =
  | { state: 'run'; record: ApprovalRecord }
  | { state: 'pending'; record: ApprovalRecord; created: boolean }
  | { state: 'denied'; record: ApprovalRecord };

export const APPROVAL_WINDOW_MS = 15 * 60 * 1000;
const KEEP_MS = 7 * 24 * 3600 * 1000;

export class ApprovalStore extends DurableObject<Env> {
  /** Called on every gated tool call. Runs inside the object's input gate, so it is atomic. */
  async gate(input: GateInput): Promise<GateResult> {
    const now = Date.now();
    const id = await this.ctx.storage.get<string>(`k:${input.key}`);
    const existing = id ? await this.ctx.storage.get<ApprovalRecord>(`a:${id}`) : undefined;
    if (existing && existing.expires_at > now) {
      if (existing.status === 'approved') {
        const used: ApprovalRecord = { ...existing, status: 'used', used_at: now };
        await this.ctx.storage.put(`a:${used.id}`, used);
        await this.ctx.storage.delete(`k:${input.key}`);
        return { state: 'run', record: used };
      }
      if (existing.status === 'pending') return { state: 'pending', record: existing, created: false };
      if (existing.status === 'denied') return { state: 'denied', record: existing };
    }
    const record: ApprovalRecord = {
      id: crypto.randomUUID().replace(/-/g, '').slice(0, 12),
      key: input.key,
      status: 'pending',
      agent: input.agent,
      client_id: input.client_id,
      client_name: input.client_name,
      tool: input.tool,
      summary: input.summary,
      created_at: now,
      expires_at: now + APPROVAL_WINDOW_MS,
    };
    await this.ctx.storage.put(`a:${record.id}`, record);
    await this.ctx.storage.put(`k:${input.key}`, record.id);
    return { state: 'pending', record, created: true };
  }

  async get(id: string): Promise<ApprovalRecord | null> {
    return (await this.ctx.storage.get<ApprovalRecord>(`a:${id}`)) ?? null;
  }

  /** Newest first. Also drops records older than a week. */
  async list(limit = 50): Promise<ApprovalRecord[]> {
    const now = Date.now();
    const all = [...(await this.ctx.storage.list<ApprovalRecord>({ prefix: 'a:' })).values()];
    const stale = all.filter((r) => r.created_at < now - KEEP_MS);
    for (const r of stale) {
      await this.ctx.storage.delete(`a:${r.id}`);
      if ((await this.ctx.storage.get<string>(`k:${r.key}`)) === r.id) await this.ctx.storage.delete(`k:${r.key}`);
    }
    return all
      .filter((r) => r.created_at >= now - KEEP_MS)
      .sort((a, b) => b.created_at - a.created_at)
      .slice(0, limit);
  }

  /** Only a pending, unexpired request can be decided. */
  async decide(id: string, decision: 'approved' | 'denied'): Promise<{ ok: boolean; record: ApprovalRecord | null; reason?: string }> {
    const now = Date.now();
    const record = await this.ctx.storage.get<ApprovalRecord>(`a:${id}`);
    if (!record) return { ok: false, record: null, reason: 'not_found' };
    if (record.status !== 'pending') return { ok: false, record, reason: `already_${record.status}` };
    if (record.expires_at <= now) return { ok: false, record, reason: 'expired' };
    const decided: ApprovalRecord = { ...record, status: decision, decided_at: now, expires_at: now + APPROVAL_WINDOW_MS };
    await this.ctx.storage.put(`a:${id}`, decided);
    return { ok: true, record: decided };
  }
}

export function approvals(env: Env) {
  return env.APPROVALS.get(env.APPROVALS.idFromName('owner'));
}

/** Pending, approved, denied and used are stored; "expired" is derived for display. */
export function displayStatus(r: ApprovalRecord, now = Date.now()): string {
  if ((r.status === 'pending' || r.status === 'approved') && r.expires_at <= now) return `${r.status}, expired`;
  return r.status;
}

/** Stable hash of a tool call's exact arguments (keys sorted at every level). */
export async function argsHash(tool: string, args: Record<string, unknown>): Promise<string> {
  const canon = (v: unknown): unknown =>
    Array.isArray(v) ? v.map(canon) : v && typeof v === 'object'
      ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, canon((v as Record<string, unknown>)[k])]))
      : v;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify([tool, canon(args)])));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
