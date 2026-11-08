import { AuthorizationError, CimdFetchError, type ConsentDescription, type GrantSummary } from '@cloudflare/workers-oauth-provider';
import { approvals, displayStatus, type ApprovalRecord } from './approvals';
import { audit, readAudit } from './audit';
import { deployment } from './deployment';
import { revocations } from './revocations';
import { adminSessionCookie, checkOwnerPassword, clearAdminSessionCookie, hasAdminSession, hasAdminToken, sameOrigin } from './auth';
import { OWNER_USER_ID, baseUrl, type Env, type GrantProps } from './env';
import { escape, htmlResponse, page } from './html';
import { clearPolicyOverride, loadPolicy, setPolicyOverride, suggestAgent, validatePolicy, type LoadedPolicy } from './policy';

export const SCOPES_SUPPORTED = ['broker', 'offline_access'];

const json = (status: number, body: unknown, headers?: HeadersInit) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });

// ---------------------------------------------------------------------------------------------
// Consent page
// ---------------------------------------------------------------------------------------------

function consentPage(d: ConsentDescription, handle: string, loaded: LoadedPolicy, returnTo: string): string {
  const name = escape(d.clientName);
  const suggested = suggestAgent(loaded.policy, d.clientName);
  const origin = d.clientDomain
    ? `Published by <strong>${escape(d.clientDomain)}</strong> (verified by its client ID URL).`
    : 'This app registered itself, so its name is not verified.';
  const agents = Object.entries(loaded.policy.agents)
    .map(
      ([id, a]) => `<label class="agent"><input type="radio" name="agent" value="${escape(id)}" required${id === suggested ? ' checked' : ''}>
 <strong>${escape(id)}</strong> <span class="muted">${escape(a.description ?? '')}</span><br>
 <span class="muted">Tools: ${a.tools.length ? a.tools.map((t) => `<code>${escape(t)}</code>`).join(', ') : 'none'}</span></label>`,
    )
    .join('');
  const scopes = d.scope.filter((s) => SCOPES_SUPPORTED.includes(s));
  return `
<h1>Approve ${name}?</h1>
<p><strong>${name}</strong> wants to call tools through your Agent Secrets Broker. It will never receive a secret: the broker makes the calls and returns trimmed results.</p>
<div class="card">
  <p>${origin}</p>
  <p>Access goes to <strong>${escape(d.redirectHost)}</strong>.</p>
  ${d.redirectIsLoopback ? '<p class="warn"><strong>This sends access to an app on a computer (localhost).</strong> Continue only if you just started connecting from it.</p>' : ''}
  <p class="muted">Client ID: <code>${escape(d.clientId)}</code><br>Scopes: ${scopes.length ? scopes.map((s) => `<code>${escape(s)}</code>`).join(' ') : '<code>broker</code>'}</p>
</div>
<form method="post" action="/authorize">
  <input type="hidden" name="handle" value="${escape(handle)}">
  <input type="hidden" name="return_to" value="${escape(returnTo)}">
  ${scopes.map((s) => `<input type="hidden" name="scope" value="${escape(s)}">`).join('')}
  <h2>Which agent is this?</h2>
  <p class="muted">The connection gets exactly the tools of the agent you pick.</p>
  ${agents}
  <h2>Owner password</h2>
  <input type="text" name="username" value="owner" autocomplete="username" hidden>
  <input type="password" name="password" autocomplete="current-password" required aria-label="Owner password">
  <div class="row">
    <button class="primary" name="decision" value="approve">Approve</button>
    <button name="decision" value="deny" formnovalidate>Deny</button>
  </div>
</form>`;
}

function safeReturnTo(value: unknown): string {
  const s = typeof value === 'string' ? value : '';
  return s.startsWith('/authorize?') ? s : '/';
}

function authErrorResponse(error: unknown): Response {
  if (error instanceof AuthorizationError && error.redirectTo) {
    return Response.redirect(error.redirectTo, 302);
  }
  if (error instanceof AuthorizationError || error instanceof CimdFetchError) {
    const message = error instanceof AuthorizationError ? error.description : 'This app could not be verified (its client metadata document could not be read).';
    return htmlResponse(400, 'Cannot authorize', `<h1>Cannot authorize</h1><p>${escape(message)}</p><p class="muted">Start connecting again from the app.</p>`);
  }
  throw error;
}

async function getAuthorize(request: Request, env: Env): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  try {
    const authRequest = await oauth.parseAuthRequest(request);
    const details = await oauth.describeConsent(authRequest);
    const consent = await oauth.beginConsent(authRequest);
    const loaded = await loadPolicy(env);
    const url = new URL(request.url);
    const headers = consent.headers;
    headers.set('content-type', 'text/html; charset=utf-8');
    headers.set('cache-control', 'no-store');
    headers.set('referrer-policy', 'no-referrer');
    // No inline script, no external loads, no framing. No form-action: browsers apply it to the
    // redirect after the post, which goes to the client's callback on another origin.
    headers.set('content-security-policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");
    // The library's other consent headers (X-Frame-Options, the consent cookie) are kept as they are.
    return new Response(page('Approve connection', consentPage(details, consent.handle, loaded, url.pathname + url.search)), {
      status: 200,
      headers,
    });
  } catch (error) {
    return authErrorResponse(error);
  }
}

async function postAuthorize(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  const form = await request.formData();
  const handle = String(form.get('handle') ?? '');
  const returnTo = safeReturnTo(form.get('return_to'));
  const retry = `<p><a href="${escape(returnTo)}">Try again</a></p>`;
  try {
    if (form.get('decision') !== 'approve') {
      const denied = await oauth.denyConsent(request, handle);
      audit(env, ctx, { type: 'consent', outcome: 'denied', code: 'owner_denied' });
      return new Response(null, { status: 302, headers: denied.headers });
    }

    const check = await checkOwnerPassword(env, request, String(form.get('password') ?? ''));
    if (check !== 'ok') {
      audit(env, ctx, { type: 'login_failed', outcome: 'denied', code: check === 'locked' ? 'locked_out' : 'bad_password' });
      return check === 'locked'
        ? htmlResponse(429, 'Locked out', '<h1>Too many attempts</h1><p>Wait 15 minutes, then try again.</p>')
        : htmlResponse(401, 'Wrong password', `<h1>Wrong password</h1><p>The owner password didn't match.</p>${retry}`);
    }

    const agent = String(form.get('agent') ?? '');
    const loaded = await loadPolicy(env);
    if (!loaded.policy.agents[agent]) {
      return htmlResponse(400, 'Pick an agent', `<h1>Pick an agent</h1><p>Choose which agent this connection is.</p>${retry}`);
    }

    const requested = form.getAll('scope').map(String).filter((s) => SCOPES_SUPPORTED.includes(s));
    const scope = requested.includes('broker') ? requested : ['broker', ...requested];
    const approved = await oauth.approveConsent(request, handle, { scope });
    const client = await oauth.lookupClient(approved.request.clientId);
    const clientName = (client?.clientName ?? approved.request.clientId).slice(0, 120);
    const props: GrantProps = { agent, clientId: approved.request.clientId, clientName, approvedAt: new Date().toISOString() };
    const { redirectTo } = await oauth.completeAuthorization({
      request: approved.request,
      userId: OWNER_USER_ID,
      metadata: { agent, clientName },
      scope: approved.request.scope,
      props,
    });
    audit(env, ctx, { type: 'consent', outcome: 'ok', client_id: props.clientId, client_name: clientName, agent });
    approved.headers.set('Location', redirectTo);
    return new Response(null, { status: 302, headers: approved.headers });
  } catch (error) {
    if (error instanceof AuthorizationError && !error.redirectTo) {
      return htmlResponse(400, 'Page expired', `<h1>This approval page expired or was already used</h1><p>${escape(error.description)}</p><p class="muted">Start connecting again from the app.</p>`);
    }
    return authErrorResponse(error);
  }
}

// ---------------------------------------------------------------------------------------------
// Admin: connections, revoke, audit, policy
// ---------------------------------------------------------------------------------------------

async function allOwnerGrants(env: Env): Promise<GrantSummary[]> {
  const grants: GrantSummary[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.OAUTH_PROVIDER.listUserGrants(OWNER_USER_ID, { limit: 100, cursor });
    grants.push(...page.items);
    cursor = page.cursor;
  } while (cursor);
  return grants;
}

interface Connection {
  client_id: string;
  client_name: string | null;
  kind: 'registered (DCR)' | 'metadata document (CIMD)' | 'unknown';
  redirect_hosts: string[];
  registered_at: string | null;
  grants: { id: string; agent: string | null; scope: string[]; created_at: string; expires_at: string | null }[];
}

async function listConnections(env: Env): Promise<Connection[]> {
  const oauth = env.OAUTH_PROVIDER;
  const [clients, grants] = await Promise.all([oauth.listClients({ limit: 100 }), allOwnerGrants(env)]);
  const byId = new Map<string, Connection>();
  for (const c of clients.items) {
    byId.set(c.clientId, {
      client_id: c.clientId,
      client_name: c.clientName ?? null,
      kind: 'registered (DCR)',
      redirect_hosts: c.redirectUris.map((u) => { try { return new URL(u).host; } catch { return u; } }),
      registered_at: c.registrationDate ? new Date(c.registrationDate * 1000).toISOString() : null,
      grants: [],
    });
  }
  for (const g of grants) {
    let conn = byId.get(g.clientId);
    if (!conn) {
      const meta = (g.metadata ?? {}) as { clientName?: string };
      conn = {
        client_id: g.clientId,
        client_name: meta.clientName ?? null,
        kind: g.clientId.startsWith('https://') ? 'metadata document (CIMD)' : 'unknown',
        redirect_hosts: g.redirectUri ? [new URL(g.redirectUri).host] : [],
        registered_at: null,
        grants: [],
      };
      byId.set(g.clientId, conn);
    }
    conn.grants.push({
      id: g.id,
      agent: ((g.metadata ?? {}) as { agent?: string }).agent ?? null,
      scope: g.scope,
      created_at: new Date(g.createdAt * 1000).toISOString(),
      expires_at: g.expiresAt ? new Date(g.expiresAt * 1000).toISOString() : null,
    });
  }
  return [...byId.values()];
}

/**
 * Revoke every grant (and so every access and refresh token) the owner gave this client, or just
 * one grant when grantId is given (a CIMD client ID is shared by every installation of that app).
 */
async function revokeClient(env: Env, ctx: ExecutionContext, clientId: string, deleteClient: boolean, grantId?: string) {
  // First the broker's own list: it cuts every token of the client (or grant) off at once, even
  // one the library's KV listing below doesn't see yet.
  const cutOffAt = grantId ? await revocations(env).revokeGrant(grantId) : await revocations(env).revokeClient(clientId);
  ctx.waitUntil(revocations(env).prune());
  const grants = (await allOwnerGrants(env)).filter((g) => g.clientId === clientId && (!grantId || g.id === grantId));
  for (const g of grants) await env.OAUTH_PROVIDER.revokeGrant(g.id, OWNER_USER_ID);
  let deleted = false;
  if (deleteClient && !clientId.startsWith('https://')) {
    await env.OAUTH_PROVIDER.deleteClient(clientId);
    deleted = true;
  }
  audit(env, ctx, { type: 'revoke', outcome: 'ok', client_id: clientId, code: `grants_${grants.length}${deleted ? '_client_deleted' : ''}` });
  return { client_id: clientId, cut_off_at: new Date(cutOffAt).toISOString(), revoked_grants: grants.length, client_deleted: deleted };
}

async function adminApi(request: Request, env: Env, ctx: ExecutionContext, path: string): Promise<Response> {
  if (!(await hasAdminToken(env, request))) {
    return json(401, { error: 'unauthorized' }, { 'www-authenticate': 'Bearer realm="admin"' });
  }
  if (path === '/admin/api/clients' && request.method === 'GET') {
    return json(200, { connections: await listConnections(env) });
  }
  if (path === '/admin/api/revoke' && request.method === 'POST') {
    const body = (await request.json().catch(() => ({}))) as { client_id?: string; grant_id?: string; delete_client?: boolean };
    if (!body.client_id) return json(400, { error: 'client_id is required' });
    return json(200, await revokeClient(env, ctx, body.client_id, !!body.delete_client && !body.grant_id, body.grant_id));
  }
  if (path === '/admin/api/audit' && request.method === 'GET') {
    const limit = Number(new URL(request.url).searchParams.get('limit') ?? '100');
    return json(200, { lines: await readAudit(env, limit) });
  }
  if (path === '/admin/api/status' && request.method === 'GET') {
    const loaded = await loadPolicy(env);
    return json(200, {
      environment: env.ENVIRONMENT,
      deployment: deployment().name,
      version: env.CF_VERSION?.id ?? 'local',
      policy: { source: loaded.source, hash: loaded.hash },
      owner_password_set: !!env.OWNER_PASSWORD,
      ...(await deployment().status?.(env)),
    });
  }
  // Read-only on purpose: approving needs the owner's password session (see adminPage), so
  // nothing that holds only the admin token (a script, an agent on the owner's machine) can approve.
  if (path === '/admin/api/approvals' && request.method === 'GET') {
    const now = Date.now();
    const list = await approvals(env).list(Number(new URL(request.url).searchParams.get('limit') ?? '50'));
    return json(200, { approvals: list.map((r) => ({ ...r, key: undefined, display_status: displayStatus(r, now) })) });
  }
  if (path === '/admin/api/policy') {
    if (request.method === 'GET') {
      const loaded = await loadPolicy(env);
      return json(200, { source: loaded.source, hash: loaded.hash, policy: loaded.policy });
    }
    if (request.method === 'PUT') {
      try {
        const policy = validatePolicy(await request.json());
        await setPolicyOverride(env, policy);
        const loaded = await loadPolicy(env);
        audit(env, ctx, { type: 'policy', outcome: 'ok', code: `override_set_${loaded.hash}` });
        return json(200, { source: loaded.source, hash: loaded.hash });
      } catch (err) {
        return json(400, { error: err instanceof Error ? err.message : 'invalid policy' });
      }
    }
    if (request.method === 'DELETE') {
      await clearPolicyOverride(env);
      const loaded = await loadPolicy(env);
      audit(env, ctx, { type: 'policy', outcome: 'ok', code: 'override_cleared' });
      return json(200, { source: loaded.source, hash: loaded.hash });
    }
  }
  return json(404, { error: 'not found' });
}

/** After sign-in, go back to the admin page that asked for it (an approval link), never elsewhere. */
export function adminReturnTo(value: unknown): string {
  const s = typeof value === 'string' ? value : '';
  return /^\/admin(\/approvals\/[a-f0-9]{12})?$|^\/connect\/[a-z]+$/.test(s) ? s : '/admin';
}

const APPROVAL_PATH = /^\/admin\/approvals\/([a-f0-9]{12})$/;

function fmt(ms: number | undefined): string {
  return ms ? new Date(ms).toISOString().slice(0, 19).replace('T', ' ') + ' UTC' : '';
}

function approvalRow(r: ApprovalRecord, now: number): string {
  const status = displayStatus(r, now);
  return `<tr><td><a href="/admin/approvals/${escape(r.id)}">${escape(r.id)}</a><br><span class="muted">${escape(fmt(r.created_at))}</span></td>
<td>${escape(r.agent)}<br><span class="muted">${escape(r.client_name)}</span></td><td><code>${escape(r.tool)}</code></td>
<td>${status === 'pending' ? `<strong>${escape(status)}</strong>` : escape(status)}</td></tr>`;
}

function approvalPage(r: ApprovalRecord, now: number): string {
  const status = displayStatus(r, now);
  const args = Object.entries(r.summary)
    .map(([k, v]) => `<tr><th>${escape(k)}</th><td><pre>${escape(v)}</pre></td></tr>`)
    .join('');
  const decide = status === 'pending'
    ? `<form method="post" action="/admin/approvals/${escape(r.id)}"><div class="row">
<button class="primary" name="decision" value="approved">Approve once</button><button name="decision" value="denied">Deny</button></div></form>
<p class="muted">Approving lets this agent run this exact call once, within 15 minutes. Any changed argument needs a new approval.</p>`
    : `<p class="muted">Decided ${escape(fmt(r.decided_at))}${r.used_at ? `, used ${escape(fmt(r.used_at))}` : ''}.</p>`;
  return `<h1>Approve a tool call?</h1><p><a href="/admin">Back to admin</a></p>
<div class="card"><p><strong>${escape(r.agent)}</strong> (${escape(r.client_name)}) wants to call <code>${escape(r.tool)}</code>.</p>
<p class="muted">Requested ${escape(fmt(r.created_at))} · status <strong>${escape(status)}</strong> · approval <code>${escape(r.id)}</code></p></div>
<p class="warn">Check the arguments yourself. An agent can be tricked by text it read (a web page, a README, an email) into asking for something you didn't intend.</p>
<div class="scroll"><table>${args || '<tr><td class="muted">no arguments</td></tr>'}</table></div>${decide}`;
}

/** Owner sign-in; afterwards the browser returns to returnTo (an admin page, an approval, a /connect page). */
export function signInPage(returnTo: string): Response {
  return htmlResponse(
    200,
    'Broker admin',
    `<h1>Broker admin</h1><form method="post" action="/admin/login"><p>Owner password</p>
<input type="hidden" name="return_to" value="${escape(adminReturnTo(returnTo))}">
<input type="text" name="username" value="owner" autocomplete="username" hidden>
<input type="password" name="password" autocomplete="current-password" required aria-label="Owner password">
<div class="row"><button class="primary">Sign in</button></div></form>`,
  );
}

async function adminPage(request: Request, env: Env, ctx: ExecutionContext, path: string): Promise<Response> {
  if (path === '/admin/login' && request.method === 'POST') {
    if (!sameOrigin(env, request)) return htmlResponse(403, 'Forbidden', '<h1>Forbidden</h1>');
    const form = await request.formData();
    const returnTo = adminReturnTo(form.get('return_to'));
    const check = await checkOwnerPassword(env, request, String(form.get('password') ?? ''));
    if (check !== 'ok') {
      audit(env, ctx, { type: 'login_failed', outcome: 'denied', code: check === 'locked' ? 'locked_out' : 'bad_password' });
      return htmlResponse(check === 'locked' ? 429 : 401, 'Sign in', `<h1>Sign in failed</h1><p><a href="${escape(returnTo)}">Try again</a></p>`);
    }
    return new Response(null, { status: 303, headers: { location: returnTo, 'set-cookie': await adminSessionCookie(env) } });
  }
  if (path === '/admin/logout' && request.method === 'POST') {
    return new Response(null, { status: 303, headers: { location: '/admin', 'set-cookie': clearAdminSessionCookie } });
  }

  const signedIn = await hasAdminSession(env, request);
  if (!signedIn) {
    // Posts (revoke, approve) need a session; a bearer token of any kind doesn't count.
    if (request.method !== 'GET') return htmlResponse(403, 'Forbidden', '<h1>Forbidden</h1><p>Sign in first.</p>');
    return signInPage(path);
  }

  const approvalMatch = path.match(APPROVAL_PATH);
  if (approvalMatch) {
    const id = approvalMatch[1];
    if (request.method === 'POST') {
      if (!sameOrigin(env, request)) return htmlResponse(403, 'Forbidden', '<h1>Forbidden</h1>');
      const decision = String((await request.formData()).get('decision') ?? '');
      if (decision !== 'approved' && decision !== 'denied') return htmlResponse(400, 'Bad request', '<h1>Pick approve or deny</h1>');
      const res = await approvals(env).decide(id, decision);
      if (res.record) {
        const r = res.record;
        audit(env, ctx, {
          type: 'approval',
          outcome: res.ok ? (decision === 'approved' ? 'ok' : 'denied') : 'error',
          tool: r.tool,
          agent: r.agent,
          client_id: r.client_id,
          client_name: r.client_name,
          approval_id: r.id,
          code: res.ok ? `owner_${decision}` : res.reason,
        });
      }
      return new Response(null, { status: 303, headers: { location: `/admin/approvals/${id}` } });
    }
    const record = await approvals(env).get(id);
    if (!record) return htmlResponse(404, 'Not found', '<h1>No such approval</h1><p><a href="/admin">Back to admin</a></p>');
    return htmlResponse(200, 'Approve a tool call', approvalPage(record, Date.now()));
  }

  if (path === '/admin/revoke' && request.method === 'POST') {
    if (!sameOrigin(env, request)) return htmlResponse(403, 'Forbidden', '<h1>Forbidden</h1>');
    const form = await request.formData();
    const clientId = String(form.get('client_id') ?? '');
    if (clientId) await revokeClient(env, ctx, clientId, form.get('delete_client') === '1');
    return new Response(null, { status: 303, headers: { location: '/admin' } });
  }

  const [connections, lines, loaded, approvalList, extra] = await Promise.all([
    listConnections(env),
    readAudit(env, 50),
    loadPolicy(env),
    approvals(env).list(20),
    deployment().adminSections?.(env) ?? Promise.resolve(''),
  ]);
  const now = Date.now();
  const pending = approvalList.filter((r) => displayStatus(r, now) === 'pending');
  const recent = approvalList.filter((r) => displayStatus(r, now) !== 'pending').slice(0, 10);
  const approvalTable = (rs: ApprovalRecord[], empty: string) =>
    `<div class="scroll"><table><tr><th>Approval</th><th>Agent</th><th>Tool</th><th>Status</th></tr>${rs.map((r) => approvalRow(r, now)).join('') || `<tr><td colspan="4" class="muted">${empty}</td></tr>`}</table></div>`;
  const rows = connections
    .map((c) => {
      const grants = c.grants.length
        ? c.grants.map((g) => `${escape(g.agent ?? '?')} · ${escape(g.scope.join(' '))} · since ${escape(g.created_at.slice(0, 16))}`).join('<br>')
        : '<span class="muted">no active grants</span>';
      const buttons = `<form method="post" action="/admin/revoke" style="display:inline"><input type="hidden" name="client_id" value="${escape(c.client_id)}"><button>Revoke</button></form>
${c.kind === 'registered (DCR)' ? `<form method="post" action="/admin/revoke" style="display:inline"><input type="hidden" name="client_id" value="${escape(c.client_id)}"><input type="hidden" name="delete_client" value="1"><button>Revoke and delete</button></form>` : ''}`;
      return `<tr><td><strong>${escape(c.client_name ?? '(unnamed)')}</strong><br><code>${escape(c.client_id)}</code><br><span class="muted">${escape(c.kind)} · ${escape(c.redirect_hosts.join(', '))}</span></td><td>${grants}</td><td>${buttons}</td></tr>`;
    })
    .join('');
  const audits = lines
    .map((l) => `<tr><td>${escape(l.ts.slice(0, 19))}</td><td>${escape(l.type)}</td><td>${escape(l.agent ?? '')}</td><td>${escape(l.tool ?? '')}</td><td>${escape(l.outcome)}</td><td>${escape(l.code ?? '')}${l.approval_id ? ` <a href="/admin/approvals/${escape(l.approval_id)}">${escape(l.approval_id)}</a>` : ''}</td></tr>`)
    .join('');
  return htmlResponse(
    200,
    'Broker admin',
    `<h1>Broker admin</h1><p class="muted">${escape(env.ENVIRONMENT)} · version ${escape(env.CF_VERSION?.id ?? 'local')}</p>
<form method="post" action="/admin/logout"><button>Sign out</button></form>
<h2>Waiting for your approval</h2>${approvalTable(pending, 'nothing pending')}
<h2>Recent approvals</h2>${approvalTable(recent, 'none yet')}
${extra}
<h2>Connections</h2><div class="scroll"><table><tr><th>Client</th><th>Grants</th><th></th></tr>${rows || '<tr><td colspan="3" class="muted">none</td></tr>'}</table></div>
<h2>Policy</h2><p class="muted">Source: ${escape(loaded.source)} · hash ${escape(loaded.hash)}</p><pre>${escape(JSON.stringify(loaded.policy.agents, null, 2))}</pre>
<h2>Audit (latest 50)</h2><div class="scroll"><table><tr><th>Time (UTC)</th><th>Type</th><th>Agent</th><th>Tool</th><th>Outcome</th><th>Code</th></tr>${audits}</table></div>`,
  );
}

// ---------------------------------------------------------------------------------------------

function landing(env: Env): Response {
  const mcp = `${baseUrl(env)}/mcp`;
  return htmlResponse(
    200,
    'Agent Secrets Broker',
    `<h1>Agent Secrets Broker</h1><p class="muted">${escape(env.ENVIRONMENT)}${env.ENVIRONMENT === 'sandbox' ? ' · dummy test secrets only' : ''}</p>
<p>Holds API keys and calls APIs on behalf of AI agents. Agents connect as a remote MCP server with OAuth and never see a key.</p>
<div class="card"><p>MCP server URL</p><pre>${escape(mcp)}</pre><p class="muted">In the Claude app: Settings, Connectors, Add custom connector, paste this URL.</p></div>
<p><a href="/admin">Admin</a> · <a href="https://github.com/jackzhaojin/agent-secrets-broker">Source</a></p>`,
  );
}

export const appHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    const extra = await deployment().routes?.(request, env, ctx);
    if (extra) return extra;
    if (path === '/' && request.method === 'GET') return landing(env);
    if (path === '/healthz') {
      const loaded = await loadPolicy(env);
      return json(200, { ok: true, environment: env.ENVIRONMENT, version: env.CF_VERSION?.id ?? 'local', policy: { source: loaded.source, hash: loaded.hash } });
    }
    if (path === '/authorize') {
      if (request.method === 'GET') return getAuthorize(request, env);
      if (request.method === 'POST') return postAuthorize(request, env, ctx);
    }
    if (path.startsWith('/admin/api/')) return adminApi(request, env, ctx, path);
    if (path === '/admin' || path.startsWith('/admin/')) return adminPage(request, env, ctx, path);
    if (path === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { 'content-type': 'text/plain' } });
    return new Response('Not Found', { status: 404 });
  },
};
