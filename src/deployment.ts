import type { Env } from './env';
import type { SecretStore } from './secrets/store';
import type { ToolDef } from './tools/types';

/**
 * What differs between the sandbox Worker (dummy secrets, Mock Git) and the live Worker (real
 * accounts). Each entry point registers one at module load; the shared code reads it. The live
 * bundle never contains the mock tools, and only the 1Password entry point contains its SDK.
 */
export interface Deployment {
  name: 'sandbox' | 'live';
  tools: Record<string, ToolDef>;
  /** The reviewed policy bundled with this deployment (a KV override can replace it). */
  policy: unknown;
  /** Where this deployment's secrets live. */
  secretStore(env: Env): SecretStore;
  /** Short name of the secret store, for status output: "kv-vault", "worker-secrets", "1password". */
  secretStoreName?: string;
  /** What the owner should check when a secret can't be read (shown on owner-only pages). */
  secretStoreHint?: string;
  /** Extra routes (for example /connect/adobe), tried before the app's own. */
  routes?(request: Request, env: Env, ctx: ExecutionContext): Promise<Response | null>;
  /** Extra sections on the admin page (HTML), for example upstream connection status. */
  adminSections?(env: Env): Promise<string>;
  /** Readiness for GET /admin/api/status: names, booleans and timestamps, never a secret value. */
  status?(env: Env): Promise<Record<string, unknown>>;
}

let current: Deployment | undefined;

export function useDeployment(d: Deployment): void {
  current = d;
}

export function deployment(): Deployment {
  if (!current) throw new Error('no deployment registered (import an entry point: src/index.ts or src/live.ts)');
  return current;
}
