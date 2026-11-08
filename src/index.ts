import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { SCOPES_SUPPORTED, appHandler } from './app';
import { baseUrl, type Env } from './env';
import { mcpApiHandler } from './mcp';

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

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return getProvider(env).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
