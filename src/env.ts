import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';

export interface Env {
  OAUTH_KV: KVNamespace;
  BROKER_KV: KVNamespace;
  VAULT: KVNamespace;
  MOCKGIT: Fetcher;
  CF_VERSION?: { id: string; tag?: string; timestamp?: string };
  OAUTH_PROVIDER: OAuthHelpers;

  PUBLIC_BASE_URL: string;
  ENVIRONMENT: string;
  SECRET_CACHE_TTL_SECONDS?: string;

  // Worker secrets
  OWNER_PASSWORD: string;
  ADMIN_TOKEN: string;
  COOKIE_SECRET: string;
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
