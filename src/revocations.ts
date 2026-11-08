import { DurableObject } from 'cloudflare:workers';
import type { Env } from './env';

/**
 * Revocation that takes effect at once, everywhere.
 *
 * The OAuth library revokes by listing a grant's tokens in KV and deleting them, and it validates
 * an access token by reading only that token's record. KV listings lag (up to about a minute), so
 * a grant or token created just before a revoke can be missed and keep working: an access token
 * until it expires, a refresh token until the next revoke finds it. Measured on the deployed
 * sandbox: a revoke seconds after a connection revoked 0 grants.
 *
 * So the broker also keeps its own list in one Durable Object (strongly consistent) and checks it
 * on every MCP call and every refresh: a grant id, or a client id with the time of the revoke
 * (grants approved at or before it are dead; a later consent works, which matters for CIMD client
 * IDs such as claude.ai's, shared by every user of the app).
 */

const KEEP_MS = 31 * 24 * 3600 * 1000; // longer than a refresh token lives

export class RevocationList extends DurableObject<Env> {
  async revokeGrant(grantId: string): Promise<number> {
    const at = Date.now();
    await this.ctx.storage.put(`g:${grantId}`, at);
    return at;
  }

  async revokeClient(clientId: string): Promise<number> {
    const at = Date.now();
    await this.ctx.storage.put(`c:${clientId}`, at);
    return at;
  }

  /** approvedAtMs: when the owner approved the grant (consent time). */
  async isRevoked(q: { grantId?: string; clientId: string; approvedAtMs: number }): Promise<boolean> {
    if (q.grantId && (await this.ctx.storage.get<number>(`g:${q.grantId}`)) !== undefined) return true;
    const clientAt = await this.ctx.storage.get<number>(`c:${q.clientId}`);
    return clientAt !== undefined && (!Number.isFinite(q.approvedAtMs) || q.approvedAtMs <= clientAt);
  }

  async prune(): Promise<number> {
    const cutoff = Date.now() - KEEP_MS;
    let n = 0;
    for (const [key, at] of await this.ctx.storage.list<number>()) {
      if (at < cutoff) {
        await this.ctx.storage.delete(key);
        n++;
      }
    }
    return n;
  }
}

export function revocations(env: Env) {
  return env.REVOCATIONS.get(env.REVOCATIONS.idFromName('owner'));
}

/** Grant id from one of the library's tokens (`<userId>:<grantId>:<secret>`), if it has that shape. */
export function grantIdOf(token: string): string | undefined {
  const parts = token.split(':');
  return parts.length === 3 && parts[1] ? parts[1] : undefined;
}
