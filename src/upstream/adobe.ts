import { audit } from '../audit';
import { hasAdminSession, sameOrigin } from '../auth';
import { deployment } from '../deployment';
import { baseUrl, type Env } from '../env';
import { escape, htmlResponse } from '../html';
import { getSealed, putSealed } from '../sealed';
import { handledSecretValues, secretsFor } from '../secrets/store';

/**
 * Jack's Adobe account for da.live (Experience Workspace), user-delegated, through Adobe's own
 * hosted MCP server. Jack signs in on Adobe's page; the broker keeps the tokens (encrypted in KV),
 * refreshes them, and never hands one to an agent.
 *
 * Why this route: Adobe's Developer Console gives Jack's org only server-to-server credentials for
 * the APIs that fit, so a customer-registered app can't act as a user on da.live (findings A).
 * Adobe's MCP server (https://mcp.adobeaemcloud.com/adobe/mcp/da) signs users in through its own
 * authorization server, which registers clients dynamically but only for redirect URIs it knows:
 * the broker's own https callback was refused, a localhost one accepted. So:
 *
 *   GET  /connect/adobe             owner session required; redirects to Adobe (PKCE + state)
 *   (Adobe redirects the browser to ADOBE_REDIRECT_URI, http://localhost:8976/callback, where
 *    `npm run live -- adobe-connect` is listening on Jack's Mac and forwards the browser, with the
 *    one-time code, to the callback below. The code is useless without the PKCE verifier and the
 *    client secret, which stay in the Worker.)
 *   GET  /connect/adobe/callback    exchanges the code; tokens go from Adobe to the Worker only
 *   POST /connect/adobe/disconnect  revokes at Adobe (best effort) and forgets the tokens
 */

const AS = 'https://oauth.adobeaemcloud.com';
export const ADOBE_MCP_URL = 'https://mcp.adobeaemcloud.com/adobe/mcp/da';
/** Full Experience Workspace access is needed for da_put_draft; the broker narrows it to the scratch folder. */
export const ADOBE_SCOPES = ['aem.mcp.experience-workspace', 'openid', 'AdobeID'];
const TOKENS_KEY = 'upstream:adobe';
const STATE_PREFIX = 'upstream:adobe:state:';
const STATE_COOKIE = '__Host-adobe-connect';
const REFRESH_EARLY_MS = 5 * 60 * 1000;
/** The daily cron refreshes when the last refresh is older than this, keeping the refresh token in use. */
const KEEPALIVE_MS = 20 * 3600 * 1000;

function redirectUriFor(env: Env): string {
  return env.ADOBE_REDIRECT_URI || `${baseUrl(env)}/connect/adobe/callback`;
}

export interface AdobeTokens {
  access_token: string;
  refresh_token?: string;
  access_expires_at: number;
  refresh_obtained_at?: number;
  scope?: string;
  account: { email?: string; name?: string; user_id?: string };
  connected_at: number;
  last_refresh_at?: number;
  refresh_count: number;
  refresh_token_changes: number;
}

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function remember(t: AdobeTokens): AdobeTokens {
  // Everything the redactor and the credential-in-arguments check must catch.
  handledSecretValues.add(t.access_token);
  if (t.refresh_token) handledSecretValues.add(t.refresh_token);
  return t;
}

async function clientCredentials(env: Env): Promise<{ id: string; secret: string } | null> {
  const secrets = secretsFor(env);
  const [id, secret] = await Promise.all([secrets.get('adobe-oauth/client_id'), secrets.get('adobe-oauth/client_secret')]);
  return id && secret ? { id, secret } : null;
}

async function tokenRequest(creds: { id: string; secret: string }, params: Record<string, string>): Promise<{ ok: true; body: Record<string, unknown> } | { ok: false; status: number; error: string }> {
  // Adobe's authorization server takes the client secret in the form body (client_secret_post).
  const res = await fetch(`${AS}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({ ...params, client_id: creds.id, client_secret: creds.secret }),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok || typeof body.access_token !== 'string') {
    // The error code only: error descriptions can echo request details.
    return { ok: false, status: res.status, error: typeof body.error === 'string' ? body.error.slice(0, 60) : `http_${res.status}` };
  }
  return { ok: true, body };
}

function tokensFrom(body: Record<string, unknown>, prev?: AdobeTokens): Omit<AdobeTokens, 'account' | 'connected_at'> {
  const now = Date.now();
  const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 3600;
  const ms = expiresIn * 1000;
  const newRefresh = typeof body.refresh_token === 'string' ? body.refresh_token : undefined;
  return {
    access_token: String(body.access_token),
    refresh_token: newRefresh ?? prev?.refresh_token,
    access_expires_at: now + ms,
    refresh_obtained_at: newRefresh && newRefresh !== prev?.refresh_token ? now : prev?.refresh_obtained_at,
    scope: typeof body.scope === 'string' ? body.scope : prev?.scope,
    last_refresh_at: prev ? now : undefined,
    refresh_count: prev ? prev.refresh_count + 1 : 0,
    refresh_token_changes: prev ? prev.refresh_token_changes + (newRefresh && newRefresh !== prev.refresh_token ? 1 : 0) : 0,
  };
}

export async function loadAdobe(env: Env): Promise<AdobeTokens | null> {
  const t = await getSealed<AdobeTokens>(env, TOKENS_KEY);
  return t ? remember(t) : null;
}

async function refresh(env: Env, ctx: ExecutionContext | null, t: AdobeTokens, reason: string): Promise<AdobeTokens | { error: string }> {
  if (!t.refresh_token) return { error: 'adobe_no_refresh_token' };
  const creds = await clientCredentials(env);
  if (!creds) return { error: 'adobe_client_missing' };
  const r = await tokenRequest(creds, { grant_type: 'refresh_token', refresh_token: t.refresh_token });
  if (!r.ok) {
    if (ctx) audit(env, ctx, { type: 'upstream', outcome: 'error', tool: 'adobe', code: `refresh_${r.error}` });
    else console.warn(JSON.stringify({ upstream: 'adobe', msg: 'refresh failed', code: r.error }));
    return { error: r.status === 400 || r.status === 401 ? 'adobe_reconnect_needed' : 'adobe_refresh_failed' };
  }
  const next: AdobeTokens = { ...t, ...tokensFrom(r.body, t) };
  await putSealed(env, TOKENS_KEY, next);
  if (ctx) audit(env, ctx, { type: 'upstream', outcome: 'ok', tool: 'adobe', code: `refreshed_${reason}${next.refresh_token_changes > t.refresh_token_changes ? '_new_refresh_token' : ''}` });
  return remember(next);
}

/** A valid access token for Jack's Adobe account, refreshed if it's close to expiring. */
export async function adobeAccessToken(env: Env, ctx: ExecutionContext | null, opts: { forceRefresh?: boolean } = {}): Promise<{ token: string; account: AdobeTokens['account'] } | { error: string }> {
  const t = await loadAdobe(env);
  if (!t) return { error: 'adobe_not_connected' };
  if (!opts.forceRefresh && t.access_expires_at - Date.now() > REFRESH_EARLY_MS) return { token: t.access_token, account: t.account };
  const r = await refresh(env, ctx, t, opts.forceRefresh ? 'rejected' : 'expiring');
  return 'error' in r ? r : { token: r.access_token, account: r.account };
}

/** Daily cron: refresh about once a day, so the refresh token stays in use and its lifetime gets measured. */
export async function adobeKeepAlive(env: Env): Promise<string> {
  const t = await loadAdobe(env);
  if (!t) return 'not connected';
  const last = t.last_refresh_at ?? t.connected_at;
  if (Date.now() - last < KEEPALIVE_MS && t.access_expires_at - Date.now() > REFRESH_EARLY_MS) return 'fresh';
  const r = await refresh(env, null, t, 'keepalive');
  const outcome = 'error' in r ? r.error : 'refreshed';
  console.log(JSON.stringify({ upstream: 'adobe', msg: 'keepalive', outcome }));
  return outcome;
}

/** Claims of a JWT, unverified: used only to show the owner who signed in. It came from Adobe's token endpoint over TLS. */
function jwtClaims(token: unknown): Record<string, unknown> {
  if (typeof token !== 'string') return {};
  try {
    const part = token.split('.')[1] ?? '';
    const json = atob(part.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(part.length / 4) * 4, '='));
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(json, (c) => c.charCodeAt(0)))) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function page(title: string, body: string, status = 200): Response {
  return htmlResponse(status, title, `${body}<p><a href="/admin">Back to admin</a></p>`);
}

const fmt = (ms?: number) => (ms ? new Date(ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : 'unknown');

export async function adobeRoutes(request: Request, env: Env, ctx: ExecutionContext, signInPage: (returnTo: string) => Response): Promise<Response | null> {
  const url = new URL(request.url);
  const redirectUri = redirectUriFor(env);

  if (url.pathname === '/connect/adobe' && request.method === 'GET') {
    if (!(await hasAdminSession(env, request))) return signInPage('/connect/adobe');
    if (!env.TOKEN_ENC_KEY) return page('Not ready', '<h1>Not ready</h1><p>TOKEN_ENC_KEY is not set, so the broker has nowhere safe to keep the tokens.</p>', 503);
    const creds = await clientCredentials(env);
    if (!creds) {
      return page('Adobe client not configured', `<h1>Adobe client not configured</h1><p>The broker couldn't read the Adobe client ID and client secret (<code>adobe-oauth/client_id</code>, <code>adobe-oauth/client_secret</code>). ${escape(deployment().secretStoreHint ?? '')} See docs/live-setup.md.</p>`, 503);
    }
    const state = b64url(crypto.getRandomValues(new Uint8Array(24)));
    const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    await env.BROKER_KV.put(`${STATE_PREFIX}${state}`, verifier, { expirationTtl: 600 });
    const authorize = new URL(`${AS}/oauth/authorize`);
    authorize.search = new URLSearchParams({
      client_id: creds.id,
      redirect_uri: redirectUri,
      scope: ADOBE_SCOPES.join(' '),
      response_type: 'code',
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: ADOBE_MCP_URL,
    }).toString();
    audit(env, ctx, { type: 'upstream', outcome: 'ok', tool: 'adobe', code: 'connect_started' });
    return new Response(null, {
      status: 302,
      headers: {
        location: authorize.toString(),
        // Lax, not Strict: the callback is a top-level redirect from Adobe's site.
        'set-cookie': `${STATE_COOKIE}=${state}; Path=/connect/adobe; Secure; HttpOnly; SameSite=Lax; Max-Age=600`,
        'cache-control': 'no-store',
      },
    });
  }

  if (url.pathname === '/connect/adobe/callback' && request.method === 'GET') {
    const state = url.searchParams.get('state') ?? '';
    const cookieState = (request.headers.get('cookie') ?? '').split(/;\s*/).find((c) => c.startsWith(`${STATE_COOKIE}=`))?.slice(STATE_COOKIE.length + 1);
    const verifier = state ? await env.BROKER_KV.get(`${STATE_PREFIX}${state}`) : null;
    const clear = { 'set-cookie': `${STATE_COOKIE}=; Path=/connect/adobe; Secure; HttpOnly; SameSite=Lax; Max-Age=0` };
    if (!state || !verifier || cookieState !== state) {
      audit(env, ctx, { type: 'upstream', outcome: 'denied', tool: 'adobe', code: 'callback_bad_state' });
      return htmlResponse(400, 'Start again', '<h1>Start again</h1><p>This sign-in link expired, was already used, or was started in another browser. Open <a href="/connect/adobe">/connect/adobe</a> again.</p>', clear);
    }
    await env.BROKER_KV.delete(`${STATE_PREFIX}${state}`);
    const error = url.searchParams.get('error');
    const code = url.searchParams.get('code');
    if (error || !code) {
      audit(env, ctx, { type: 'upstream', outcome: 'denied', tool: 'adobe', code: `consent_${(error ?? 'no_code').slice(0, 40)}` });
      return htmlResponse(400, 'Adobe said no', `<h1>Adobe didn't connect</h1><p>Adobe returned <code>${escape(error ?? 'no code')}</code>.</p><p><a href="/admin">Back to admin</a></p>`, clear);
    }
    const creds = await clientCredentials(env);
    if (!creds) return page('Adobe client not configured', '<h1>Adobe client not configured</h1>', 503);
    const r = await tokenRequest(creds, { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri });
    if (!r.ok) {
      audit(env, ctx, { type: 'upstream', outcome: 'error', tool: 'adobe', code: `exchange_${r.error}` });
      return htmlResponse(502, 'Exchange failed', `<h1>Adobe refused the code exchange</h1><p>HTTP ${r.status}, <code>${escape(r.error)}</code>.</p><p><a href="/admin">Back to admin</a></p>`, clear);
    }
    const base = tokensFrom(r.body);
    handledSecretValues.add(base.access_token);
    if (base.refresh_token) handledSecretValues.add(base.refresh_token);
    // Who consented (shown to the owner; never the token): the id_token's claims, if one came.
    const who = jwtClaims(r.body.id_token);
    const tokens: AdobeTokens = {
      ...base,
      refresh_obtained_at: base.refresh_token ? Date.now() : undefined,
      account: {
        email: typeof who.email === 'string' ? who.email : undefined,
        name: typeof who.name === 'string' ? who.name : undefined,
        user_id: typeof who.sub === 'string' ? who.sub : undefined,
      },
      connected_at: Date.now(),
    };
    await putSealed(env, TOKENS_KEY, tokens);
    audit(env, ctx, { type: 'upstream', outcome: 'ok', tool: 'adobe', code: tokens.refresh_token ? 'connected' : 'connected_no_refresh_token' });
    return htmlResponse(
      200,
      'Adobe connected',
      `<h1>Adobe connected</h1><div class="card"><p>Signed in as <strong>${escape(tokens.account.email ?? tokens.account.name ?? 'unknown')}</strong>.</p>
<p class="muted">Scopes granted: ${escape(tokens.scope ?? '(not reported)')}<br>Access token valid until ${escape(fmt(tokens.access_expires_at))}<br>
Refresh token: ${tokens.refresh_token ? 'yes; the broker refreshes before the access token expires and about once a day' : '<strong>none</strong>: the connection ends when the access token expires'}</p></div>
<p><a href="/admin">Back to admin</a></p>`,
      clear,
    );
  }

  if (url.pathname === '/connect/adobe/disconnect' && request.method === 'POST') {
    if (!(await hasAdminSession(env, request)) || !sameOrigin(env, request)) return htmlResponse(403, 'Forbidden', '<h1>Forbidden</h1>');
    const t = await loadAdobe(env);
    const creds = await clientCredentials(env);
    let revoked = 'not attempted';
    if (t?.refresh_token && creds) {
      const res = await fetch(`${AS}/oauth/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: t.refresh_token, token_type_hint: 'refresh_token', client_id: creds.id, client_secret: creds.secret }),
      }).catch(() => null);
      await res?.body?.cancel();
      revoked = res ? `HTTP ${res.status}` : 'network error';
    }
    await env.BROKER_KV.delete(TOKENS_KEY);
    audit(env, ctx, { type: 'upstream', outcome: 'ok', tool: 'adobe', code: `disconnected_revoke_${revoked.replace(/\W+/g, '_')}` });
    return new Response(null, { status: 303, headers: { location: '/admin' } });
  }

  return null;
}

/** For GET /admin/api/status: is everything Jack set up readable? Booleans and metadata only. */
export async function liveStatus(env: Env): Promise<Record<string, unknown>> {
  const creds = await clientCredentials(env);
  const t = await loadAdobe(env);
  return {
    secret_store: deployment().secretStoreName ?? 'unknown',
    adobe_client_readable: !!creds,
    token_encryption_key_set: !!env.TOKEN_ENC_KEY,
    da_scratch: env.DA_SCRATCH || null,
    adobe_upstream: ADOBE_MCP_URL,
    adobe_redirect_uri: redirectUriFor(env),
    adobe: t
      ? {
          connected: true,
          account: t.account.email ?? t.account.name ?? null,
          connected_at: new Date(t.connected_at).toISOString(),
          scope: t.scope ?? null,
          access_expires_at: new Date(t.access_expires_at).toISOString(),
          has_refresh_token: !!t.refresh_token,
          refresh_count: t.refresh_count,
          refresh_token_changes: t.refresh_token_changes,
          last_refresh_at: t.last_refresh_at ? new Date(t.last_refresh_at).toISOString() : null,
        }
      : { connected: false },
  };
}

export async function adobeAdminSection(env: Env): Promise<string> {
  const t = await loadAdobe(env);
  if (!t) {
    return `<h2>Adobe (da.live)</h2><div class="card"><p>Not connected. On the Mac with the repo, run <code>npm run live -- adobe-connect</code> first (Adobe sends the sign-in back to localhost), then <a href="/connect/adobe">connect Adobe</a>. You sign in on Adobe's own page.</p>
<p class="muted">Scratch folder: <code>${escape(env.DA_SCRATCH || '(not set)')}</code></p></div>`;
  }
  return `<h2>Adobe (da.live)</h2><div class="card"><p>Connected as <strong>${escape(t.account.email ?? t.account.name ?? 'unknown')}</strong> since ${escape(fmt(t.connected_at))}.</p>
<p class="muted">Scopes: ${escape(t.scope ?? '(not reported)')}<br>Access token until ${escape(fmt(t.access_expires_at))} · refreshes: ${t.refresh_count} (refresh token replaced ${t.refresh_token_changes} times) · last refresh ${escape(fmt(t.last_refresh_at))}<br>
Refresh token: ${t.refresh_token ? `held since ${escape(fmt(t.refresh_obtained_at))}` : 'none'} · scratch folder <code>${escape(env.DA_SCRATCH || '(not set)')}</code></p>
<div class="row"><a href="/connect/adobe">Reconnect</a><form method="post" action="/connect/adobe/disconnect" style="display:inline"><button>Disconnect Adobe</button></form></div></div>`;
}
