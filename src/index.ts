import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { SCOPES_SUPPORTED, appHandler } from './app';
import { OWNER_USER_ID, baseUrl, type Env } from './env';
import { mcpApiHandler } from './mcp';
import { grantIdOf, revocations } from './revocations';

/**
 * One Worker that is both the OAuth 2.1 authorization server and the MCP resource server.
 *
 *   /mcp                                  MCP (Streamable HTTP), bearer token required
 *   /.well-known/oauth-protected-resource RFC 9728 metadata (served by the provider)
 *   /.well-known/oauth-authorization-server RFC 8414 metadata (served by the provider)
 *   /register                             Dynamic Client Registration (RFC 7591)
 *   /authorize                            owner sign-in and consent (src/app.ts)
 *   /token                                code and refresh exchange, revocation (provider)
 *   /admin, /admin/api/*                  connections, revoke, audit, policy
 */
let provider: OAuthProvider<Env> | undefined;
let providerBase: string | undefined;

function getProvider(env: Env): OAuthProvider<Env> {
  const base = baseUrl(env);
  if (!provider || providerBase !== base) {
    provider = new OAuthProvider<Env>({
      apiRoute: '/mcp',
      apiHandler: mcpApiHandler,
      defaultHandler: appHandler,
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/token',
      clientRegistrationEndpoint: '/register',
      scopesSupported: SCOPES_SUPPORTED,
      requiredScopes: ['broker'],
      resourceMetadata: {
        resource: `${base}/mcp`,
        authorization_servers: [base],
        bearer_methods_supported: ['header'],
        resource_name: 'Agent Secrets Broker',
      },
      clientIdMetadataDocumentEnabled: true,
      accessTokenTTL: 15 * 60,
      refreshTokenTTL: 30 * 24 * 3600,
      onError: ({ code, description, status, internal }) => {
        // Codes and reasons only: never request bodies, tokens or headers.
        console.warn(JSON.stringify({ oauth_error: { code, status, description, reason: (internal as { reason?: string } | undefined)?.reason } }));
      },
    });
    providerBase = base;
  }
  return provider;
}

export { ApprovalStore } from './approvals';
export { RevocationList } from './revocations';

/**
 * A refresh for a grant on the broker's revocation list is refused before the library sees it
 * (the library's own revoke can miss a grant created moments earlier; see src/revocations.ts).
 */
async function refusedRefresh(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== '/token' || request.method !== 'POST') return null;
  if (!(request.headers.get('content-type') ?? '').includes('application/x-www-form-urlencoded')) return null;
  const form = new URLSearchParams(await request.clone().text());
  if (form.get('grant_type') !== 'refresh_token') return null;
  const grantId = grantIdOf(form.get('refresh_token') ?? '');
  if (!grantId) return null;
  const grant = await env.OAUTH_KV.get<{ clientId?: string; createdAt?: number }>(`grant:${OWNER_USER_ID}:${grantId}`, { type: 'json' });
  if (!grant?.clientId) return null; // unknown grant: the library answers invalid_grant itself
  const revoked = await revocations(env).isRevoked({ grantId, clientId: grant.clientId, approvedAtMs: (grant.createdAt ?? NaN) * 1000 });
  if (!revoked) return null;
  console.warn(JSON.stringify({ oauth_error: { code: 'invalid_grant', status: 400, reason: 'grant_on_revocation_list' } }));
  return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'The grant was revoked.' }), {
    status: 400,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return (await refusedRefresh(request, env)) ?? getProvider(env).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
