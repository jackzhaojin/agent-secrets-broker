import type { Env } from '../env';
import type { SecretStore } from './store';

/**
 * Secrets held as Cloudflare Worker secrets, set by Jack with `wrangler secret put`. A reference
 * such as "adobe-oauth/client_secret" maps to the Worker secret ADOBE_OAUTH_CLIENT_SECRET
 * (upper case, anything that isn't a letter or digit becomes "_").
 *
 * The live broker uses this for now instead of 1Password (Jack, 2026-11-12). Trade-offs: no vault,
 * service account or SDK (the bundle drops from 4.4 MB to about 320 KB gzipped); a key is rotated
 * with `wrangler secret put`, which takes effect without a code change; but there is nowhere for
 * per-key notes (purpose, expiry), and whether the 1Password SDK works on Workers with a real
 * service account stays untested. The 1Password entry point is src/live-1password.ts.
 */
export function workerSecretName(ref: string): string {
  return ref.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

export class WorkerSecretStore implements SecretStore {
  constructor(private readonly env: Env) {}

  async get(ref: string): Promise<string | null> {
    const value = (this.env as unknown as Record<string, unknown>)[workerSecretName(ref)];
    return typeof value === 'string' && value ? value : null;
  }
}
