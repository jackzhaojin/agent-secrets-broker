import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';
import type { ApprovalStore } from './approvals';
import type { RevocationList } from './revocations';

export interface Env {
  OAUTH_KV: KVNamespace;
  BROKER_KV: KVNamespace;
  VAULT: KVNamespace;
  MOCKGIT: Fetcher;
  APPROVALS: DurableObjectNamespace<ApprovalStore>;
  REVOCATIONS: DurableObjectNamespace<RevocationList>;
  CF_VERSION?: { id: string; tag?: string; timestamp?: string };
  OAUTH_PROVIDER: OAuthHelpers;

  PUBLIC_BASE_URL: string;
  ENVIRONMENT: string;
  SECRET_CACHE_TTL_SECONDS?: string;

  // Worker secrets
  OWNER_PASSWORD: string;
  ADMIN_TOKEN: string;
  COOKIE_SECRET: string;

  // Live deployment only (wrangler.live.jsonc)
  /** 1Password service account token, read access to one vault. Set by Jack with `wrangler secret put`. */
  OP_SERVICE_ACCOUNT_TOKEN?: string;
  /** The 1Password vault the broker reads (default "Broker"). */
  OP_VAULT?: string;
  /** 32 random bytes, base64: encrypts upstream OAuth tokens at rest in KV. */
  TOKEN_ENC_KEY?: string;
  /** The only da.live folder the DA tools may touch: "org/site/folder". */
  DA_SCRATCH?: string;
}

/** Stored (encrypted) with each grant; what the MCP handler sees as ctx.props. */
export interface GrantProps {
  agent: string;
  clientId: string;
  clientName: string;
  approvedAt: string;
}

/** The single owner of this broker. Every grant belongs to this user id. */
export const OWNER_USER_ID = 'owner';

export function baseUrl(env: Env): string {
  return env.PUBLIC_BASE_URL.replace(/\/+$/, '');
}
