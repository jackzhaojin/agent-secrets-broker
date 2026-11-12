import { audit } from '../audit';
import { hasAdminSession, sameOrigin } from '../auth';
import { deployment } from '../deployment';
import { baseUrl, type Env } from '../env';
import { escape, htmlResponse } from '../html';
import { getSealed, putSealed } from '../sealed';
import { handledSecretValues, secretsFor } from '../secrets/store';

/**
 * Jack's Adobe account (da.live), user-delegated: Jack consents once on Adobe's own page; the
 * broker keeps the tokens (encrypted in KV), refreshes them, and never hands one to an agent.
 *
 *   GET  /connect/adobe             owner session required; redirects to Adobe IMS (PKCE + state)
 *   GET  /connect/adobe/callback    exchanges the code with the client secret from the secret store
 *   POST /connect/adobe/disconnect  revokes at Adobe (best effort) and forgets the tokens
 *
 * Adobe IMS facts (developer.adobe.com/developer-console/docs/guides/authentication/UserAuthentication):
 * OAuth Web App credential (confidential, secret sent as HTTP Basic), access token 24 h, refresh
 * token 14 days, refresh only with the offline_access scope. admin.da.live accepts any valid IMS
 * user access token that can read the profile and organizations (adobe/da-admin src/utils/auth.js).
 */

const IMS = 'https://ims-na1.adobelogin.com';
export const ADOBE_SCOPES = ['openid', 'AdobeID', 'read_organizations', 'offline_access', 'additional_info.projectedProductContext'];
const TOKENS_KEY = 'upstream:adobe';
const STATE_PREFIX = 'upstream:adobe:state:';
const STATE_COOKIE = '__Host-adobe-connect';
const REFRESH_TOKEN_DAYS = 14; // Adobe's documented default; the response doesn't say
const REFRESH_EARLY_MS = 10 * 60 * 1000;
/** The daily cron refreshes when the last refresh is older than this, keeping the refresh token alive. */
const KEEPALIVE_MS = 3 * 24 * 3600 * 1000;

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
  const res = await fetch(`${IMS}/ims/token/v3`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${btoa(`${creds.id}:${creds.secret}`)}`,
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: new URLSearchParams(params),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok || typeof body.access_token !== 'string') {
    // The error code only: IMS error descriptions can echo request details.
    return { ok: false, status: res.status, error: typeof body.error === 'string' ? body.error.slice(0, 60) : `http_${res.status}` };
  }
  return { ok: true, body };
}

function tokensFrom(body: Record<string, unknown>, prev?: AdobeTokens): Omit<AdobeTokens, 'account' | 'connected_at'> {
  const now = Date.now();
  const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 86_400;
  // /ims/token/v3 returns expires_in in seconds; older endpoints used milliseconds.
  const ms = expiresIn > 10 * 86_400 ? expiresIn : expiresIn * 1000;
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
export async function adobeAccessToken(env: Env, ctx: ExecutionContext | null): Promise<{ token: string; account: AdobeTokens['account'] } | { error: string }> {
  const t = await loadAdobe(env);
  if (!t) return { error: 'adobe_not_connected' };
  if (t.access_expires_at - Date.now() > REFRESH_EARLY_MS) return { token: t.access_token, account: t.account };
  const r = await refresh(env, ctx, t, 'expiring');
  return 'error' in r ? r : { token: r.access_token, account: r.account };
}

/** Daily cron: keep the refresh token alive (Adobe expires it after 14 days without use). */
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

function page(title: string, body: string, status = 200): Response {
  return htmlResponse(status, title, `${body}<p><a href="/admin">Back to admin</a></p>`);
}

const fmt = (ms?: number) => (ms ? new Date(ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : 'unknown');

export async function adobeRoutes(request: Request, env: Env, ctx: ExecutionContext, signInPage: (returnTo: string) => Response): Promise<Response | null> {
  const url = new URL(request.url);
  const redirectUri = `${baseUrl(env)}/connect/adobe/callback`;

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
    const authorize = new URL(`${IMS}/ims/authorize/v2`);
    authorize.search = new URLSearchParams({
      client_id: creds.id,
      redirect_uri: redirectUri,
      scope: ADOBE_SCOPES.join(','),
      response_type: 'code',
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
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
    // Who consented (shown to the owner; never the token).
    const who = await fetch(`${IMS}/ims/userinfo/v2`, { headers: { authorization: `Bearer ${base.access_token}`, accept: 'application/json' } })
      .then(async (res) => (res.ok ? ((await res.json()) as Record<string, unknown>) : {}))
      .catch(() => ({}) as Record<string, unknown>);
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
Refresh token: ${tokens.refresh_token ? `yes, Adobe's default lifetime is ${REFRESH_TOKEN_DAYS} days without use; the broker refreshes daily` : '<strong>none</strong> (offline_access was not granted: the connection ends when the access token expires)'}</p></div>
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
      const res = await fetch(`${IMS}/ims/revoke`, {
        method: 'POST',
        headers: { authorization: `Basic ${btoa(`${creds.id}:${creds.secret}`)}`, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: t.refresh_token, token_type_hint: 'refresh_token' }),
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
    return `<h2>Adobe (da.live)</h2><div class="card"><p>Not connected. <a href="/connect/adobe">Connect Adobe</a> (you consent on Adobe's own page).</p>
<p class="muted">Scratch folder: <code>${escape(env.DA_SCRATCH || '(not set)')}</code></p></div>`;
  }
  return `<h2>Adobe (da.live)</h2><div class="card"><p>Connected as <strong>${escape(t.account.email ?? t.account.name ?? 'unknown')}</strong> since ${escape(fmt(t.connected_at))}.</p>
<p class="muted">Scopes: ${escape(t.scope ?? '(not reported)')}<br>Access token until ${escape(fmt(t.access_expires_at))} · refreshes: ${t.refresh_count} (refresh token replaced ${t.refresh_token_changes} times) · last refresh ${escape(fmt(t.last_refresh_at))}<br>
Refresh token: ${t.refresh_token ? `held since ${escape(fmt(t.refresh_obtained_at))}` : 'none'} · scratch folder <code>${escape(env.DA_SCRATCH || '(not set)')}</code></p>
<div class="row"><a href="/connect/adobe">Reconnect</a><form method="post" action="/connect/adobe/disconnect" style="display:inline"><button>Disconnect Adobe</button></form></div></div>`;
}
