import { deployment } from '../deployment';
import type { Env } from '../env';

/**
 * Where secrets live. The broker asks for a secret by reference at call time and never hands it
 * to an agent. Two implementations:
 *   - KvVault (sandbox): a separate KV namespace holding dummy test secrets
 *   - OnePasswordStore (live, src/secrets/onepassword.ts): the Broker vault, read-only service account
 */
export interface SecretStore {
  /** Returns the secret for a reference such as "mockgit/api_key", or null if it doesn't exist. */
  get(ref: string): Promise<string | null>;
}

export class KvVault implements SecretStore {
  constructor(private readonly kv: KVNamespace) {}
  async get(ref: string): Promise<string | null> {
    // cacheTtl 30s (the minimum) so a rotation in the vault reaches every edge location quickly.
    return this.kv.get(ref, { cacheTtl: 30 });
  }
}

interface CacheEntry {
  value: string;
  expiresAt: number;
}

/**
 * Every secret value this isolate has handled. The redactor uses it as a last line of defense:
 * nothing that leaves the broker may contain one of these, even an old rotated value.
 */
export const handledSecretValues = new Set<string>();

const cache = new Map<string, CacheEntry>();

/** Reads through a short in-memory cache, so a burst of tool calls doesn't hit the vault each time. */
export class CachedSecrets {
  constructor(
    private readonly store: SecretStore,
    private readonly ttlMs: number,
  ) {}

  async get(ref: string): Promise<string | null> {
    const hit = cache.get(ref);
    if (hit && hit.expiresAt > Date.now()) return hit.value;
    const value = await this.store.get(ref);
    if (value) {
      handledSecretValues.add(value);
      cache.set(ref, { value, expiresAt: Date.now() + this.ttlMs });
    } else {
      cache.delete(ref);
    }
    return value;
  }

  /** Drop a cached value, e.g. after the upstream rejected it (the key was probably rotated). */
  invalidate(ref: string): void {
    cache.delete(ref);
  }
}

export function secretsFor(env: Env): CachedSecrets {
  const ttlSeconds = Number(env.SECRET_CACHE_TTL_SECONDS ?? '300');
  return new CachedSecrets(deployment().secretStore(env), (Number.isFinite(ttlSeconds) ? ttlSeconds : 300) * 1000);
}
