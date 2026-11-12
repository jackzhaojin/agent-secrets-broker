#!/usr/bin/env node
// End-to-end acceptance test for the Agent Secrets Broker.
//
//   node test/e2e.mjs --target remote            the deployed sandbox (default); writes docs/test-log.md
//   node test/e2e.mjs --target local             wrangler dev on :8787 (start it first: npm run dev)
//
// It plays the part of an agent's MCP client (as the Claude app does it: DCR, PKCE, consent, token,
// then MCP), and of the owner (the consent password, the admin API). Every value it can see coming
// back from the broker, plus the audit log and the Worker's own logs, is searched for every dummy
// secret (A-G). Values are never printed; the log shows labels and fingerprints.

import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js';
import { ROLES, ROOT, fingerprint, findSecrets, loadSandbox, seed, setUpstreamAccepted, setVault, startProcess, writeTestLog } from '../scripts/lib.mjs';

// ------------------------------------------------------------------------------------------------
// Setup
// ------------------------------------------------------------------------------------------------

const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : fallback;
};
const TARGET = arg('target', 'remote');
const BASE = (arg('base', TARGET === 'local' ? 'http://localhost:8787' : 'https://agent-secrets-broker-sandbox.jackzhaojin.workers.dev')).replace(/\/$/, '');
const MCP = `${BASE}/mcp`;
const CLAUDE_CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
const CLAUDE_CODE_CIMD = 'https://claude.ai/oauth/claude-code-client-metadata';
// The Claude app's own client metadata documents (claude.ai, desktop, mobile): a public client
// (token_endpoint_auth_method none) and a confidential one (private_key_jwt, ES256).
const CLAUDE_AI_CIMD = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const CLAUDE_AI_CIMD_CONFIDENTIAL = `${CLAUDE_AI_CIMD}/confidential_client`;
const DUET_TOOLS = ['whoami', 'mockgit_list_my_repos', 'mockgit_get_readme', 'mockgit_create_issue'];
const ANIMAMESH_TOOLS = ['whoami', 'mockgit_repo_stats'];
/** Text that exists only inside upstream README content: it may reach the agent, never a log. */
const UPSTREAM_MARKERS = ['README-MARKER-', 'INJECTION-MARKER-c7a1'];
const STARTED = new Date();
const STAMP = STARTED.toISOString().replace(/[:.]/g, '-');
const OUT_DIR = join(ROOT, 'test-output');
mkdirSync(OUT_DIR, { recursive: true });

const { values } = loadSandbox();
const OWNER_PASSWORD = values.D;
const ADMIN_TOKEN = values.E;

/** Every response the broker (or anything else) sent back during the run. */
const transcript = [];
const results = [];
let currentStep = 'setup';

let networkRetries = 0;

/**
 * fetch, with one retry when the connection drops before any response ("fetch failed", seen from
 * this Mac several times on 2026-11-12). Never retried: a code exchange (a second try would be a
 * replay and revoke the grant) and a consent post (single-use handle). Retries are counted in the report.
 */
async function fetchOnce(url, init) {
  try {
    return await fetch(url, init);
  } catch (err) {
    const path = new URL(String(url)).pathname;
    const body = typeof init.body === 'string' ? init.body : init.body instanceof URLSearchParams ? init.body.toString() : '';
    const unsafe = (path === '/token' && body.includes('grant_type=authorization_code')) || (path === '/authorize' && (init.method ?? 'GET') === 'POST');
    if (!(err instanceof TypeError) || unsafe || init.body instanceof ReadableStream) throw err;
    networkRetries++;
    await new Promise((r) => setTimeout(r, 1500));
    return fetch(url, init);
  }
}

async function tfetch(url, init = {}) {
  const res = await fetchOnce(url, init);
  const body = await res.clone().text().catch(() => '');
  transcript.push({
    step: currentStep,
    method: init.method ?? 'GET',
    url: String(url),
    status: res.status,
    headers: Object.fromEntries(res.headers),
    body,
  });
  return res;
}

function record(id, name, status, detail, extra = {}) {
  results.push({ id, name, status, detail, ...extra });
  const mark = ['PASS', 'FAIL', 'SKIP'].includes(status) ? status : 'INFO';
  console.log(`${mark.padEnd(4)}  ${id.padEnd(4)} ${name}${detail ? ` - ${detail}` : ''}`);
}

class CheckFailed extends Error {}
/** A check that stopped on purpose before a step that would disturb something real. */
class Skipped extends Error {}
const expect = (cond, message) => {
  if (!cond) throw new CheckFailed(message);
};

async function check(id, name, fn) {
  currentStep = id;
  const t0 = Date.now();
  try {
    const detail = await fn();
    record(id, name, 'PASS', detail ?? '', { ms: Date.now() - t0 });
    return true;
  } catch (err) {
    if (err instanceof Skipped) {
      record(id, name, 'SKIP', err.message, { ms: Date.now() - t0 });
      return true;
    }
    record(id, name, 'FAIL', err instanceof CheckFailed ? err.message : `${err?.name ?? 'Error'}: ${err?.message ?? err}`, { ms: Date.now() - t0 });
    return false;
  }
}

async function until(label, fn, { timeoutMs = 120_000, intervalMs = 3_000 } = {}) {
  const t0 = Date.now();
  let last;
  while (Date.now() - t0 < timeoutMs) {
    last = await fn();
    if (last?.done) return { ...last, waitedMs: Date.now() - t0 };
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new CheckFailed(`${label}: not reached within ${timeoutMs / 1000}s (last: ${JSON.stringify(last?.state ?? null)})`);
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
function pkce() {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash('sha256').update(verifier).digest()) };
}

// ------------------------------------------------------------------------------------------------
// OAuth helpers (what an MCP client does)
// ------------------------------------------------------------------------------------------------

async function register(metadata) {
  const res = await tfetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(metadata),
  });
  const body = await res.json();
  return { status: res.status, body };
}

function authorizeUrl({ clientId, redirectUri, challenge, state, scope = 'broker offline_access' }) {
  const url = new URL(`${BASE}/authorize`);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    scope,
    resource: MCP,
  }).toString();
  return url;
}

/** GET the consent page; returns the form fields and the consent cookie. */
async function openConsent(url) {
  const res = await tfetch(url, { redirect: 'manual' });
  const html = await res.text();
  const field = (name) => html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1];
  const scopes = [...html.matchAll(/name="scope" value="([^"]*)"/g)].map((m) => m[1]);
  const cookie = res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  return { status: res.status, html, handle: field('handle'), returnTo: field('return_to')?.replace(/&#38;/g, '&'), scopes, cookie };
}

async function submitConsent(consent, { decision = 'approve', agent, password }) {
  const form = new URLSearchParams({ handle: consent.handle, return_to: consent.returnTo ?? '', decision });
  if (agent) form.set('agent', agent);
  if (password !== undefined) form.set('password', password);
  for (const s of consent.scopes) form.append('scope', s);
  const res = await tfetch(`${BASE}/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: consent.cookie, origin: BASE },
    body: form,
    redirect: 'manual',
  });
  return { status: res.status, location: res.headers.get('location'), text: await res.text() };
}

async function token(params) {
  const res = await tfetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

/** Full authorization-code flow for a client: consent as the owner, then exchange the code. */
async function connect({ clientId, redirectUri, agent }) {
  const { verifier, challenge } = pkce();
  const state = b64url(randomBytes(12));
  const consent = await openConsent(authorizeUrl({ clientId, redirectUri, challenge, state }));
  expect(consent.status === 200 && consent.handle, `consent page: HTTP ${consent.status}`);
  const done = await submitConsent(consent, { agent, password: OWNER_PASSWORD });
  expect(done.status === 302 && done.location, `consent approve: HTTP ${done.status}`);
  const loc = new URL(done.location);
  expect(loc.searchParams.get('state') === state, 'state mismatch');
  const tok = await token({ grant_type: 'authorization_code', code: loc.searchParams.get('code'), redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier, resource: MCP });
  expect(tok.status === 200 && tok.body.access_token, `token: HTTP ${tok.status} ${tok.body.error ?? ''}`);
  return { consent, location: loc, tokens: tok.body, verifier, state };
}

// ------------------------------------------------------------------------------------------------
// MCP helpers
// ------------------------------------------------------------------------------------------------

async function mcpClient(accessToken) {
  const transport = new StreamableHTTPClientTransport(new URL(MCP), {
    requestInit: { headers: { Authorization: `Bearer ${accessToken}` } },
    fetch: tfetch,
  });
  const client = new Client({ name: 'agent-secrets-broker-e2e', version: '0.1.0' });
  await client.connect(transport);
  return client;
}

async function callTool(accessToken, name, args = {}) {
  const client = await mcpClient(accessToken);
  try {
    const result = await client.callTool({ name, arguments: args });
    const text = result.content?.find((c) => c.type === 'text')?.text ?? '';
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
    return { refused: false, isError: !!result.isError, text, data };
  } catch (err) {
    return { refused: true, isError: true, text: String(err?.message ?? err) };
  } finally {
    await client.close().catch(() => {});
  }
}

async function listTools(accessToken) {
  const client = await mcpClient(accessToken);
  try {
    return { info: client.getServerVersion(), tools: (await client.listTools()).tools.map((t) => t.name) };
  } finally {
    await client.close().catch(() => {});
  }
}

/** Raw MCP POST, to see the HTTP status (the SDK hides it behind an exception). */
async function rawMcp(accessToken) {
  const res = await tfetch(MCP, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '1' } } }),
  });
  return { status: res.status, wwwAuthenticate: res.headers.get('www-authenticate'), text: await res.text() };
}

// ------------------------------------------------------------------------------------------------
// Admin helpers (what the owner does)
// ------------------------------------------------------------------------------------------------

async function admin(method, path, body) {
  const res = await tfetch(`${BASE}/admin/api/${path}`, {
    method,
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

/**
 * Queue the grant a consent just created for revoking at the end. A CIMD client ID is shared by
 * every installation of that app (Jack's own Claude connector included), so CIMD checks revoke only
 * their own grant. Its ID comes from the authorization code (`<userId>:<grantId>:<secret>`): a
 * before/after diff of the grant listing missed grants because KV listings lag (two stray test
 * grants were left on 2026-11-08).
 */
/**
 * The broker keeps one connection per app per owner: a new consent from a client ID revokes that
 * client's earlier grants (it replaced Jack's own Claude connection on 2026-11-12). So a CIMD check
 * stops after the consent page when the client already has a connection, unless the run is told to
 * replace it with --replace-connections.
 */
async function stopIfConnected(clientId, consent, checked) {
  if (argv.includes('--replace-connections')) return;
  const conns = await admin('GET', 'clients');
  const live = conns.body.connections?.find((c) => c.client_id === clientId)?.grants ?? [];
  if (!live.length) return;
  expect(consent.html.includes("replaces this app's existing connection"), 'the consent page does not warn that approving replaces the existing connection');
  throw new Skipped(`${checked}; the page warns that approving replaces the existing connection (agent ${live[0].agent}, since ${live[0].created_at}). Not approved, so that connection stays. Rerun with --replace-connections to test end to end`);
}

function cleanupGrantOf(clientId, redirectLocation) {
  const grantId = new URL(redirectLocation).searchParams.get('code')?.split(':')[1];
  expect(grantId, 'no grant id in the authorization code');
  state.cleanup.push({ client_id: clientId, grant_id: grantId });
}

/** A fresh DCR client connected as an agent (a second app, or a thief's copy of one). */
async function newConnection(clientName, agent, redirectUri = CLAUDE_CALLBACK) {
  const r = await register({ client_name: clientName, redirect_uris: [redirectUri], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' });
  expect(r.status === 201 && r.body.client_id, `register ${clientName}: HTTP ${r.status}`);
  state.cleanup.push({ client_id: r.body.client_id, delete_client: true });
  const c = await connect({ clientId: r.body.client_id, redirectUri, agent });
  return { clientId: r.body.client_id, tokens: c.tokens, consent: c.consent };
}

/** The owner's admin session (password sign-in): the only thing that can approve a call. */
async function ownerSession(returnTo = '/admin') {
  const res = await tfetch(`${BASE}/admin/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: BASE },
    body: new URLSearchParams({ username: 'owner', password: OWNER_PASSWORD, return_to: returnTo }),
    redirect: 'manual',
  });
  const cookie = res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  expect(res.status === 303 && cookie.startsWith('__Host-broker-admin='), `owner sign-in HTTP ${res.status}`);
  return { cookie, location: res.headers.get('location') };
}

async function decideApproval(id, decision, headers) {
  const res = await tfetch(`${BASE}/admin/approvals/${id}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: BASE, ...headers },
    body: new URLSearchParams({ decision }),
    redirect: 'manual',
  });
  return { status: res.status, location: res.headers.get('location'), text: await res.text() };
}

async function approvalsList() {
  return (await admin('GET', 'approvals?limit=100')).body.approvals ?? [];
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const health = async () => (await (await tfetch(`${BASE}/healthz`)).json());

// ------------------------------------------------------------------------------------------------
// Run
// ------------------------------------------------------------------------------------------------

const state = { tail: null, versionBefore: null, cleanup: [] };

async function main() {
  console.log(`Agent Secrets Broker e2e: ${TARGET} ${BASE}\n`);

  if (TARGET === 'remote' && !argv.includes('--no-tail')) {
    state.tail = startProcess('npx', ['wrangler', 'tail', 'agent-secrets-broker-sandbox', '--format', 'json'], join(OUT_DIR, `tail-${STAMP}.log`));
    await new Promise((r) => setTimeout(r, 8000)); // let the tail connect before the first request
  }

  // ---- Preflight -------------------------------------------------------------------------------
  await check('P1', 'Broker is up (healthz) and the sandbox is reset', async () => {
    const h = await health();
    expect(h.ok, 'healthz not ok');
    state.versionBefore = h.version;
    seed({ target: TARGET, values });
    const cleared = await admin('DELETE', 'policy');
    expect(cleared.status === 200 && cleared.body.source === 'bundled', `policy reset: HTTP ${cleared.status}`);
    return `version ${h.version}; vault mockgit/api_key=A, canary=G; upstream accepts A; policy bundled`;
  });

  if (TARGET === 'remote') {
    await check('U1', 'Control: the mock upstream checks the key, and the leak scan catches what it leaks', async () => {
      const MOCK = 'https://agent-secrets-broker-mockgit.jackzhaojin.workers.dev/user/repos?per_page=1';
      // Direct calls (not in the transcript): this is the upstream, not the broker.
      const none = await fetch(MOCK);
      expect(none.status === 401, `no key: HTTP ${none.status}`);
      const bad = await fetch(MOCK, { headers: { authorization: `Bearer ${values.C}` } });
      expect(bad.status === 401 && findSecrets(await bad.text(), values).C === 1, 'wrong key: scan did not find the echoed key');
      const good = await until('upstream accepts A', async () => {
        const r = await fetch(MOCK, { headers: { authorization: `Bearer ${values.A}` } });
        return { done: r.status === 200, state: r.status, text: await r.text() };
      }, { timeoutMs: 90_000 });
      expect(findSecrets(good.text, values).A >= 1, 'right key: scan did not find the key in clone URLs');
      return 'no key 401; wrong key 401 and the body echoes it (scan finds C); right key 200 with the key in clone URLs (scan finds A). The broker must strip both';
    });
  }

  // ---- Discovery (MCP authorization spec + Claude connector docs) -----------------------------
  let prmUrl;
  await check('D1', 'Unauthenticated MCP call gets 401 with a resource_metadata challenge', async () => {
    const r = await rawMcp();
    expect(r.status === 401, `HTTP ${r.status}`);
    prmUrl = r.wwwAuthenticate?.match(/resource_metadata="([^"]+)"/)?.[1];
    expect(prmUrl, `no resource_metadata in WWW-Authenticate: ${r.wwwAuthenticate}`);
    expect(/scope="broker"/.test(r.wwwAuthenticate), 'challenge has no scope="broker"');
    return r.wwwAuthenticate;
  });
  await check('D2', 'Protected resource metadata names the exact MCP URL and the issuer', async () => {
    const prm = await (await tfetch(prmUrl)).json();
    expect(prm.resource === MCP, `resource is ${prm.resource}, expected ${MCP}`);
    expect(prm.authorization_servers?.[0] === BASE, `authorization_servers[0] is ${prm.authorization_servers?.[0]}`);
    return `resource=${prm.resource}`;
  });
  await check('D3', 'Authorization server metadata: PKCE S256, DCR, CIMD, public clients', async () => {
    const as = await (await tfetch(`${BASE}/.well-known/oauth-authorization-server`)).json();
    expect(as.issuer === BASE, `issuer ${as.issuer}`);
    expect(as.code_challenge_methods_supported?.includes('S256'), 'no S256');
    expect(as.registration_endpoint === `${BASE}/register`, 'no registration_endpoint');
    expect(as.client_id_metadata_document_supported === true, 'CIMD not advertised');
    expect(as.token_endpoint_auth_methods_supported?.includes('none'), 'none not in token_endpoint_auth_methods_supported');
    return `token_endpoint=${as.token_endpoint}, grant_types=${as.grant_types_supported.join(',')}`;
  });
  await check('D4', 'A made-up bearer token is refused with 401', async () => {
    const r = await rawMcp(`bogus-${b64url(randomBytes(16))}`);
    expect(r.status === 401, `HTTP ${r.status}`);
    return 'HTTP 401';
  });

  // ---- Connect the way the Claude app does (DCR, claude.ai callback) --------------------------
  const duet = { clientId: null, tokens: null };
  await check('C1', 'Dynamic Client Registration with the claude.ai callback', async () => {
    const r = await register({
      client_name: 'Claude (scripted test)',
      redirect_uris: [CLAUDE_CALLBACK],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    });
    expect(r.status === 201 && r.body.client_id, `HTTP ${r.status} ${JSON.stringify(r.body)}`);
    duet.clientId = r.body.client_id;
    state.cleanup.push({ client_id: duet.clientId, delete_client: true });
    return `client_id ${duet.clientId}`;
  });

  let duetConsent;
  let duetPkce;
  const duetState = b64url(randomBytes(12));
  await check('C2', 'Consent page shows the client, where access goes, and preselects agent duet', async () => {
    duetPkce = pkce();
    duetConsent = await openConsent(authorizeUrl({ clientId: duet.clientId, redirectUri: CLAUDE_CALLBACK, challenge: duetPkce.challenge, state: duetState }));
    expect(duetConsent.status === 200, `HTTP ${duetConsent.status}`);
    expect(duetConsent.html.includes('Claude (scripted test)'), 'client name missing');
    expect(duetConsent.html.includes('<strong>claude.ai</strong>'), 'redirect host claude.ai missing');
    expect(duetConsent.html.includes('not verified'), 'DCR client not marked unverified');
    expect(/value="duet" required checked/.test(duetConsent.html), 'duet not preselected');
    expect(duetConsent.html.includes('type="password"'), 'no owner password field');
    return 'shows name, claude.ai, unverified; duet preselected; password required';
  });
  await check('C3', 'Wrong owner password is refused (no code issued)', async () => {
    const r = await submitConsent(duetConsent, { agent: 'duet', password: 'not-the-password' });
    expect(r.status === 401 && !r.location, `HTTP ${r.status} location=${r.location}`);
    return 'HTTP 401, no redirect';
  });
  let duetCode;
  await check('C4', 'Owner approves as duet: redirect to claude.ai with code, state, iss', async () => {
    const r = await submitConsent(duetConsent, { agent: 'duet', password: OWNER_PASSWORD });
    expect(r.status === 302, `HTTP ${r.status}`);
    const loc = new URL(r.location);
    expect(`${loc.origin}${loc.pathname}` === CLAUDE_CALLBACK, `redirected to ${loc.origin}${loc.pathname}`);
    expect(loc.searchParams.get('state') === duetState, 'state mismatch');
    expect(loc.searchParams.get('iss') === BASE, `iss ${loc.searchParams.get('iss')}`);
    duetCode = loc.searchParams.get('code');
    expect(duetCode, 'no code');
    return `302 to ${CLAUDE_CALLBACK}`;
  });
  await check('C5', 'Code + PKCE verifier exchanged (form-urlencoded): 15-minute access token, refresh token', async () => {
    const r = await token({ grant_type: 'authorization_code', code: duetCode, redirect_uri: CLAUDE_CALLBACK, client_id: duet.clientId, code_verifier: duetPkce.verifier, resource: MCP });
    expect(r.status === 200, `HTTP ${r.status} ${r.body.error ?? ''}`);
    expect(r.body.token_type?.toLowerCase() === 'bearer', 'token_type');
    expect(r.body.expires_in === 900, `expires_in ${r.body.expires_in}`);
    expect(r.body.refresh_token, 'no refresh_token');
    duet.tokens = r.body;
    return `expires_in=${r.body.expires_in}, scope="${r.body.scope}"`;
  });
  await check('C6', 'Replaying a code is refused and revokes what that code issued (OAuth 2.1); reconnect', async () => {
    const r = await token({ grant_type: 'authorization_code', code: duetCode, redirect_uri: CLAUDE_CALLBACK, client_id: duet.clientId, code_verifier: duetPkce.verifier, resource: MCP });
    expect(r.status === 400 && r.body.error === 'invalid_grant', `HTTP ${r.status} ${r.body.error}`);
    const dead = await until('replayed code revokes its tokens', async () => {
      const m = await rawMcp(duet.tokens.access_token);
      return { done: m.status === 401, state: m.status };
    }, { timeoutMs: 90_000, intervalMs: 2000 });
    const again = await connect({ clientId: duet.clientId, redirectUri: CLAUDE_CALLBACK, agent: 'duet' });
    duet.tokens = again.tokens;
    return `invalid_grant; the first access token stopped working after ${Math.round(dead.waitedMs / 1000)}s; reconnected with a fresh consent`;
  });
  await check('C7', 'MCP initialize and tools/list over Streamable HTTP (official SDK client)', async () => {
    const { info, tools } = await listTools(duet.tokens.access_token);
    expect(info?.name === 'agent-secrets-broker', `server ${info?.name}`);
    expect(tools.join(',') === DUET_TOOLS.join(','), `tools ${tools.join(',')}`);
    return `server ${info.name} ${info.version}; tools: ${tools.join(', ')}`;
  });

  // ---- Acceptance tests ------------------------------------------------------------------------
  await check('T2', 'Auth works: whoami returns the client name and allowed tools', async () => {
    const r = await callTool(duet.tokens.access_token, 'whoami');
    expect(!r.isError, r.text);
    expect(r.data.agent === 'duet', `agent ${r.data.agent}`);
    expect(r.data.client.name === 'Claude (scripted test)' && r.data.client.id === duet.clientId, 'client mismatch');
    expect(r.data.allowed_tools.join(',') === DUET_TOOLS.join(','), `allowed ${r.data.allowed_tools}`);
    expect(r.data.approval_required.join(',') === 'mockgit_create_issue', `approval_required ${r.data.approval_required}`);
    return `agent=${r.data.agent}, client="${r.data.client.name}", allowed=[${r.data.allowed_tools.join(', ')}], approval_required=[${r.data.approval_required.join(', ')}]`;
  });
  await check('T3', 'Do something real: mockgit_list_my_repos returns a trimmed list', async () => {
    const r = await callTool(duet.tokens.access_token, 'mockgit_list_my_repos', { limit: 5 });
    expect(!r.isError, r.text);
    expect(r.data.count === 5 && r.data.repos.length === 5, `count ${r.data.count}`);
    for (const repo of r.data.repos) {
      expect(Object.keys(repo).sort().join(',') === 'name,updated,url', `extra fields: ${Object.keys(repo)}`);
      expect(!repo.url.includes('@'), 'credential in url');
    }
    expect(!/clone_url_with_token|email|permissions|x-access-token/.test(r.text), 'untrimmed upstream fields');
    return `${r.data.count} repos, fields name/url/updated only (upstream sent token URLs, emails, permissions)`;
  });
  await check('T4a', 'Forced upstream error (wrong key in the vault): error text has no secret', async () => {
    setUpstreamAccepted({ target: TARGET, values, label: 'B' }); // the provider revoked A
    setVault({ target: TARGET, values, label: 'C' }); // and the vault holds a wrong key
    const r = await until('upstream_401 error', async () => {
      const res = await callTool(duet.tokens.access_token, 'mockgit_list_my_repos', { limit: 3 });
      return { done: res.isError && res.text.includes('upstream_401'), state: res.text.slice(0, 80), res };
    });
    expect(!/presented_key|Bad credentials/.test(r.res.text), 'upstream error body passed through');
    return `after ${Math.round(r.waitedMs / 1000)}s: "${r.res.text}"`;
  });
  await check('T4b', 'Invalid tool input is rejected without leaking anything', async () => {
    const r = await callTool(duet.tokens.access_token, 'mockgit_list_my_repos', { limit: 999 });
    expect(r.isError, 'limit 999 accepted');
    return r.text.slice(0, 120).replace(/\s+/g, ' ');
  });
  await check('T7', 'Rotation: new key in the vault only, next calls use it, no redeploy', async () => {
    setVault({ target: TARGET, values, label: 'B' });
    const r = await until('rotation picked up', async () => {
      const res = await callTool(duet.tokens.access_token, 'mockgit_list_my_repos', { limit: 2 });
      return { done: !res.isError, state: res.text.slice(0, 80) };
    });
    const h = await health();
    expect(h.version === state.versionBefore, `Worker version changed: ${state.versionBefore} -> ${h.version}`);
    return `working ${Math.round(r.waitedMs / 1000)}s after the vault write; Worker version unchanged (${h.version})`;
  });
  await check('T5', 'Policy: remove mockgit_list_my_repos from duet, call is refused and audited', async () => {
    const current = await admin('GET', 'policy');
    const reduced = structuredClone(current.body.policy);
    reduced.agents.duet.tools = ['whoami'];
    const put = await admin('PUT', 'policy', reduced);
    expect(put.status === 200 && put.body.source === 'kv-override', `PUT policy HTTP ${put.status}`);
    const w = await until('policy applied', async () => {
      const res = await callTool(duet.tokens.access_token, 'whoami');
      return { done: res.data?.allowed_tools?.join(',') === 'whoami', state: res.data?.allowed_tools };
    }, { timeoutMs: 90_000 });
    const { tools } = await listTools(duet.tokens.access_token);
    expect(!tools.includes('mockgit_list_my_repos'), 'tool still listed');
    const call = await callTool(duet.tokens.access_token, 'mockgit_list_my_repos', { limit: 2 });
    expect(call.isError, 'tool call was not refused');
    await new Promise((r) => setTimeout(r, 2000));
    const audit = await admin('GET', 'audit?limit=50');
    const denied = audit.body.lines.find((l) => l.tool === 'mockgit_list_my_repos' && l.outcome === 'denied' && l.client_id === duet.clientId);
    expect(denied?.code === 'not_in_policy', 'no denied audit line');
    const restore = await admin('DELETE', 'policy');
    expect(restore.body.source === 'bundled', 'restore failed');
    await until('policy restored', async () => {
      const res = await callTool(duet.tokens.access_token, 'whoami');
      return { done: res.data?.allowed_tools?.includes('mockgit_list_my_repos'), state: res.data?.allowed_tools };
    }, { timeoutMs: 90_000 });
    return `applied in ${Math.round(w.waitedMs / 1000)}s; not listed; call refused ("${call.text.slice(0, 60)}"); audited denied/not_in_policy; restored`;
  });
  await check('R1', 'Refresh token rotates and the new access token works', async () => {
    // A refresh soon after connecting can land in another Cloudflare location that still holds the
    // grant as it was before the code exchange, and the library then answers invalid_grant
    // (seen 2026-11-12: exchange in YYZ, refresh 10 s later in ORD). A refused refresh doesn't use
    // the token up, so wait it out and report how long it took.
    const w = await until('refresh accepted', async () => {
      const x = await token({ grant_type: 'refresh_token', refresh_token: duet.tokens.refresh_token, client_id: duet.clientId, resource: MCP });
      return { done: x.status === 200, state: `HTTP ${x.status} ${x.body.error ?? ''}`, r: x };
    }, { timeoutMs: 90_000, intervalMs: 5000 });
    const r = w.r;
    expect(r.body.access_token !== duet.tokens.access_token && r.body.refresh_token !== duet.tokens.refresh_token, 'tokens did not rotate');
    duet.tokens = r.body;
    const who = await callTool(duet.tokens.access_token, 'whoami');
    expect(!who.isError && who.data.agent === 'duet', 'whoami with refreshed token failed');
    return `new access and refresh tokens${w.waitedMs > 1000 ? ` (accepted after ${Math.round(w.waitedMs / 1000)}s: an earlier try hit a location with a stale grant)` : ''}; whoami OK`;
  });
  await check('T6', 'Revoke: next call 401, refresh refused, reconnecting needs consent again', async () => {
    const rv = await admin('POST', 'revoke', { client_id: duet.clientId });
    expect(rv.status === 200 && rv.body.cut_off_at, `revoke HTTP ${rv.status} ${JSON.stringify(rv.body)}`);
    const dead = await until('access token rejected', async () => {
      const r = await rawMcp(duet.tokens.access_token);
      return { done: r.status === 401, state: r.status };
    }, { timeoutMs: 90_000, intervalMs: 2000 });
    const ref = await token({ grant_type: 'refresh_token', refresh_token: duet.tokens.refresh_token, client_id: duet.clientId, resource: MCP });
    expect(ref.status === 400 && ref.body.error === 'invalid_grant', `refresh HTTP ${ref.status} ${ref.body.error}`);
    const again = await connect({ clientId: duet.clientId, redirectUri: CLAUDE_CALLBACK, agent: 'duet' });
    expect(again.consent.html.includes('type="password"'), 'consent page not shown again');
    duet.tokens = again.tokens;
    const who = await callTool(duet.tokens.access_token, 'whoami');
    expect(!who.isError, 'reconnected whoami failed');
    return `401 after ${Math.round(dead.waitedMs / 1000)}s; refresh invalid_grant; consent page shown again; reconnected`;
  });

  // ---- Cross-agent isolation (Phase 2 D) -------------------------------------------------------
  await check('I1', 'Cross-agent isolation: AnimaMesh gets only its tools, Duet cannot call them, and each refusal is audited', async () => {
    const mesh = await newConnection('AnimaMesh (scripted test)', 'animamesh');
    expect(/value="animamesh" required checked/.test(mesh.consent.html), 'animamesh not preselected');
    state.animamesh = mesh;
    const { tools } = await listTools(mesh.tokens.access_token);
    expect(tools.join(',') === ANIMAMESH_TOOLS.join(','), `animamesh tools ${tools}`);
    const stats = await callTool(mesh.tokens.access_token, 'mockgit_repo_stats');
    expect(!stats.isError && stats.data.total === 8 && !('repos' in stats.data), `stats ${stats.text.slice(0, 80)}`);
    const meshTriesDuet = await callTool(mesh.tokens.access_token, 'mockgit_list_my_repos');
    const meshTriesWrite = await callTool(mesh.tokens.access_token, 'mockgit_create_issue', { repo: 'sandbox-alpha', title: 'x' });
    const duetTriesMesh = await callTool(duet.tokens.access_token, 'mockgit_repo_stats');
    expect(meshTriesDuet.isError && meshTriesWrite.isError && duetTriesMesh.isError, 'a cross-agent call was not refused');
    state.inspector = await newConnection('Inspector (scripted test)', 'inspector');
    await until('refusals audited', async () => {
      const lines = (await admin('GET', 'audit?limit=100')).body.lines;
      const denied = (client, tool) => lines.some((l) => l.client_id === client && l.tool === tool && l.outcome === 'denied' && l.code === 'not_in_policy');
      return { done: denied(mesh.clientId, 'mockgit_list_my_repos') && denied(mesh.clientId, 'mockgit_create_issue') && denied(duet.clientId, 'mockgit_repo_stats'), state: 'not all listed' };
    }, { timeoutMs: 90_000, intervalMs: 3000 });
    return `animamesh tools: ${tools.join(', ')} (counts only); animamesh -> list_my_repos and create_issue, duet -> repo_stats: refused and audited not_in_policy`;
  });

  // ---- Per-call approval (Phase 2 C) ----------------------------------------------------------
  const issueArgs = { repo: 'sandbox-alpha', title: `e2e approval ${STAMP}`, body: 'Opened by the scripted test.' };
  let approvalId;
  await check('AP1', 'Per-call approval: a sensitive call returns pending, nothing runs, the owner sees the request', async () => {
    const first = await callTool(duet.tokens.access_token, 'mockgit_create_issue', issueArgs);
    expect(!first.isError && first.data?.status === 'pending_approval' && first.data.approval_id, `first call: ${first.text.slice(0, 120)}`);
    approvalId = first.data.approval_id;
    expect(first.data.approve_at === `${BASE}/admin/approvals/${approvalId}`, `approve_at ${first.data.approve_at}`);
    const again = await callTool(duet.tokens.access_token, 'mockgit_create_issue', issueArgs);
    expect(again.data?.status === 'pending_approval' && again.data.approval_id === approvalId, 'repeat call did not return the same pending approval');
    const listed = (await approvalsList()).find((a) => a.id === approvalId);
    expect(listed?.status === 'pending' && listed.agent === 'duet' && listed.tool === 'mockgit_create_issue' && listed.summary?.title === issueArgs.title, `admin list: ${JSON.stringify(listed)}`);
    expect(listed.key === undefined, 'internal key exposed');
    return `pending ${approvalId}, same id on repeat; listed for the owner with repo, title and body; nothing created`;
  });
  await check('AP2', "Only the owner's password session can approve: an agent token, the admin token and no session are refused", async () => {
    const withAgent = await decideApproval(approvalId, 'approved', { authorization: `Bearer ${duet.tokens.access_token}` });
    const withAdmin = await decideApproval(approvalId, 'approved', { authorization: `Bearer ${ADMIN_TOKEN}` });
    const apiApprove = await admin('POST', 'approvals', { id: approvalId, decision: 'approved' });
    expect(withAgent.status === 403 && withAdmin.status === 403 && apiApprove.status === 404, `agent ${withAgent.status}, admin token ${withAdmin.status}, admin API ${apiApprove.status}`);
    const still = (await approvalsList()).find((a) => a.id === approvalId);
    expect(still?.status === 'pending', `status after refused attempts: ${still?.status}`);
    const { cookie, location } = await ownerSession(`/admin/approvals/${approvalId}`);
    expect(location === `/admin/approvals/${approvalId}`, `sign-in returned to ${location}`);
    const page = await (await tfetch(`${BASE}/admin/approvals/${approvalId}`, { headers: { cookie } })).text();
    expect(page.includes('mockgit_create_issue') && page.includes(issueArgs.title) && page.includes('Approve once'), 'approval page missing details');
    const ok = await decideApproval(approvalId, 'approved', { cookie });
    expect(ok.status === 303, `owner approve HTTP ${ok.status}`);
    state.ownerCookie = cookie;
    return 'agent token 403, admin token 403, admin API has no approve route (404); owner signed in from the link, saw the call, approved';
  });
  await check('AP3', 'The approved call runs once; the same call again needs a new approval', async () => {
    const run = await callTool(duet.tokens.access_token, 'mockgit_create_issue', issueArgs);
    expect(!run.isError && run.data?.created === true && run.data.number, `approved call: ${run.text.slice(0, 120)}`);
    const keys = Object.keys(run.data).sort().join(',');
    expect(keys === 'created,number,repo,title,url', `fields ${keys}`);
    const next = await callTool(duet.tokens.access_token, 'mockgit_create_issue', issueArgs);
    expect(next.data?.status === 'pending_approval' && next.data.approval_id !== approvalId, 'second run did not need a new approval');
    state.secondApproval = next.data.approval_id;
    await decideApproval(approvalId, 'approved', { cookie: state.ownerCookie });
    const after = (await approvalsList()).find((a) => a.id === approvalId);
    expect(after?.status === 'used', `used approval status ${after?.status}`);
    return `ran once (issue #${run.data.number}; fields created/number/repo/title/url); the repeat is pending as ${next.data.approval_id}; the used approval can't be approved again`;
  });
  await check('AP4', 'An approval covers only the exact arguments and the client that asked', async () => {
    const ok = await decideApproval(state.secondApproval, 'approved', { cookie: state.ownerCookie });
    expect(ok.status === 303, `approve HTTP ${ok.status}`);
    const changed = await callTool(duet.tokens.access_token, 'mockgit_create_issue', { ...issueArgs, title: `${issueArgs.title} (changed)` });
    expect(changed.data?.status === 'pending_approval' && changed.data.approval_id !== state.secondApproval, 'a changed title ran on the old approval');
    const other = await callTool(state.inspector.tokens.access_token, 'mockgit_create_issue', issueArgs);
    expect(other.data?.status === 'pending_approval', "another client ran on duet's approval");
    const mine = await callTool(duet.tokens.access_token, 'mockgit_create_issue', issueArgs);
    expect(mine.data?.created === true, `the approved client and arguments: ${mine.text.slice(0, 100)}`);
    return 'changed title: new pending; another client with the same arguments: its own pending; the approved client with the approved arguments: ran';
  });
  await check('AP5', 'Deny: the call is refused, and asking again stays refused while the denial stands', async () => {
    const args = { repo: 'sandbox-bravo', title: `e2e deny ${STAMP}` };
    const p = await callTool(duet.tokens.access_token, 'mockgit_create_issue', args);
    expect(p.data?.status === 'pending_approval', 'not pending');
    const d = await decideApproval(p.data.approval_id, 'denied', { cookie: state.ownerCookie });
    expect(d.status === 303, `deny HTTP ${d.status}`);
    const r1 = await callTool(duet.tokens.access_token, 'mockgit_create_issue', args);
    const r2 = await callTool(duet.tokens.access_token, 'mockgit_create_issue', args);
    expect(r1.isError && r1.text.includes('approval_denied') && r2.text.includes('approval_denied'), `after deny: ${r1.text.slice(0, 80)}`);
    return `denied ${p.data.approval_id}; the call and a retry both return approval_denied`;
  });
  await check('AP6', 'Policy can put a read-only tool behind approval for one agent only', async () => {
    const insp = await callTool(state.inspector.tokens.access_token, 'mockgit_get_readme', { repo: 'sandbox-alpha' });
    const duetRead = await callTool(duet.tokens.access_token, 'mockgit_get_readme', { repo: 'sandbox-alpha' });
    expect(insp.data?.status === 'pending_approval' && duetRead.data?.untrusted_content === true, `inspector ${insp.text.slice(0, 60)}; duet ${duetRead.text.slice(0, 60)}`);
    return 'inspector (policy approval_required): pending; duet: the same read runs without approval';
  });

  // ---- Negative tests (Phase 2 D) -------------------------------------------------------------
  await check('N1', 'Prompt injection in upstream content: delivered marked untrusted; the write it asks for is refused or waits for the owner', async () => {
    const r = await callTool(duet.tokens.access_token, 'mockgit_get_readme', { repo: 'sandbox-charlie' });
    expect(!r.isError && r.data.untrusted_content === true && r.data.note && r.data.content.includes('INJECTION-MARKER-c7a1'), `readme: ${r.text.slice(0, 100)}`);
    // Play an agent that obeys the injection: first with its access token in the body, then without.
    const leak = await callTool(duet.tokens.access_token, 'mockgit_create_issue', { repo: 'sandbox-alpha', title: 'maintenance', body: `key: none. token: ${duet.tokens.access_token}` });
    expect(leak.isError && leak.text.includes('credential_in_arguments'), `token in body: ${leak.text.slice(0, 100)}`);
    const obey = await callTool(duet.tokens.access_token, 'mockgit_create_issue', { repo: 'sandbox-alpha', title: 'maintenance', body: 'Following the README note.' });
    expect(obey.data?.status === 'pending_approval', 'the injected write did not wait for approval');
    const d = await decideApproval(obey.data.approval_id, 'denied', { cookie: state.ownerCookie });
    expect(d.status === 303, 'deny failed');
    return `README arrives with untrusted_content=true and a note; an obeying agent's write with its token in the body is refused (credential_in_arguments); without the token it waits for the owner (${obey.data.approval_id}, denied)`;
  });
  await check('N2', 'A key embedded in upstream content is scrubbed before the agent sees it, and the redaction is audited', async () => {
    const r = await callTool(duet.tokens.access_token, 'mockgit_get_readme', { repo: 'sandbox-delta' });
    expect(!r.isError && r.text.includes('x-access-token:[REDACTED]@') && r.text.includes('README-MARKER-sandbox-delta'), `readme: ${r.text.slice(0, 120)}`);
    expect(Object.keys(findSecrets(r.text, values)).length === 0, 'a dummy secret reached the agent');
    await until('redaction audited', async () => {
      const lines = (await admin('GET', 'audit?limit=100')).body.lines;
      return { done: lines.some((l) => l.type === 'redaction' && l.tool === 'mockgit_get_readme' && l.client_id === duet.clientId), state: 'not yet listed' };
    }, { timeoutMs: 90_000, intervalMs: 3000 });
    return "the README's clone line arrives as x-access-token:[REDACTED]@...; redaction audited; download_url (which also carries the key) is not passed on";
  });
  await check('N3', 'A stolen access token reaches only its own agent tools, until it expires or is revoked', async () => {
    const t = duet.tokens.access_token;
    const adminApi = await tfetch(`${BASE}/admin/api/clients`, { headers: { authorization: `Bearer ${t}` } });
    const approvalsApi = await tfetch(`${BASE}/admin/api/approvals`, { headers: { authorization: `Bearer ${t}` } });
    const adminPage = await (await tfetch(`${BASE}/admin`, { headers: { authorization: `Bearer ${t}` } })).text();
    const revoke = await tfetch(`${BASE}/admin/revoke`, { method: 'POST', headers: { authorization: `Bearer ${t}`, origin: BASE, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: duet.clientId }), redirect: 'manual' });
    expect(adminApi.status === 401 && approvalsApi.status === 401 && !adminPage.includes('<h2>Connections</h2>') && revoke.status === 403, `admin API ${adminApi.status}, approvals API ${approvalsApi.status}, revoke ${revoke.status}`);
    const other = await callTool(t, 'mockgit_repo_stats');
    expect(other.isError, "a stolen duet token reached animamesh's tool");
    const who = await callTool(t, 'whoami');
    const ttl = Math.round((new Date(who.data.token.expires_at) - Date.now()) / 1000);
    expect(ttl > 0 && ttl <= 900, `token ttl ${ttl}`);
    return `it can call duet's tools (whoami OK, expires in ${ttl}s, at most 900s); admin API 401, approvals API 401, admin page shows sign-in only, revoke 403, approve 403 (AP2), other agents' tools refused; writes still wait for the owner`;
  });
  await check('N4', 'A stolen refresh token: the thief can mint tokens until the owner revokes; revoke cuts everyone off', async () => {
    const victim = await newConnection('Claude (stolen token test)', 'duet');
    const stolen = victim.tokens.refresh_token;
    const wrongClient = await token({ grant_type: 'refresh_token', refresh_token: stolen, client_id: duet.clientId, resource: MCP });
    expect(wrongClient.status >= 400, `refresh under another client_id: HTTP ${wrongClient.status}`);
    const thief = await token({ grant_type: 'refresh_token', refresh_token: stolen, client_id: victim.clientId, resource: MCP });
    expect(thief.status === 200 && thief.body.access_token, `thief refresh HTTP ${thief.status} ${thief.body.error ?? ''}`);
    const thiefWho = await callTool(thief.body.access_token, 'whoami');
    expect(!thiefWho.isError && thiefWho.data.agent === 'duet', 'the thief token did not work');
    // The real client refreshes later with the same refresh token the thief used.
    const legit = await token({ grant_type: 'refresh_token', refresh_token: stolen, client_id: victim.clientId, resource: MCP });
    const legitResult = legit.status === 200 ? 'still worked (the previous refresh token stays valid until the newer one is used)' : `was refused (${legit.body.error})`;
    const thief2 = await token({ grant_type: 'refresh_token', refresh_token: thief.body.refresh_token, client_id: victim.clientId, resource: MCP });
    const thiefLatestRefresh = thief2.status === 200 ? thief2.body.refresh_token : thief.body.refresh_token;
    const thiefLatestAccess = thief2.status === 200 ? thief2.body.access_token : thief.body.access_token;
    const rv = await admin('POST', 'revoke', { client_id: victim.clientId });
    expect(rv.status === 200 && rv.body.cut_off_at, `revoke ${rv.status} ${JSON.stringify(rv.body)}`);
    const dead = await until('thief access token rejected', async () => {
      const r = await rawMcp(thiefLatestAccess);
      return { done: r.status === 401, state: r.status };
    }, { timeoutMs: 90_000, intervalMs: 1000 });
    const after = await token({ grant_type: 'refresh_token', refresh_token: thiefLatestRefresh, client_id: victim.clientId, resource: MCP });
    expect(after.status === 400 && after.body.error === 'invalid_grant', `thief refresh after revoke: HTTP ${after.status} ${after.body.error ?? ''}`);
    return `refresh under another client_id refused (HTTP ${wrongClient.status}); the thief minted a working token; the real client's later refresh with the same token ${legitResult}; revoked seconds after the connection was made (the library's KV listing found ${rv.body.revoked_grants} grant(s)); the broker's revocation list cut the thief's newest access token off within ${Math.round(dead.waitedMs / 1000)}s and its refresh token got invalid_grant`;
  });

  // ---- CIMD: Anthropic's published Claude Code client metadata document ------------------------
  await check('M1', "CIMD: Claude Code's published client ID works end to end (bound to agent inspector)", async () => {
    const redirectUri = 'http://localhost:43210/callback';
    const { verifier, challenge } = pkce();
    const st = b64url(randomBytes(12));
    const consent = await openConsent(authorizeUrl({ clientId: CLAUDE_CODE_CIMD, redirectUri, challenge, state: st }));
    expect(consent.status === 200, `consent HTTP ${consent.status}: ${consent.html.slice(0, 200)}`);
    expect(consent.html.includes('Published by <strong>claude.ai</strong>'), 'CIMD domain not shown');
    expect(consent.html.includes('localhost'), 'loopback warning missing');
    await stopIfConnected(CLAUDE_CODE_CIMD, consent, 'consent page shows "Published by claude.ai" and the localhost warning');
    const done = await submitConsent(consent, { agent: 'inspector', password: OWNER_PASSWORD });
    expect(done.status === 302, `approve HTTP ${done.status}`);
    cleanupGrantOf(CLAUDE_CODE_CIMD, done.location);
    const code = new URL(done.location).searchParams.get('code');
    const tok = await token({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: CLAUDE_CODE_CIMD, code_verifier: verifier, resource: MCP });
    expect(tok.status === 200, `token HTTP ${tok.status} ${tok.body.error ?? ''}`);
    const who = await callTool(tok.body.access_token, 'whoami');
    expect(who.data?.agent === 'inspector' && who.data?.client?.name === 'Claude Code', `whoami ${who.text.slice(0, 100)}`);
    return `consent shows "Published by claude.ai"; token issued; whoami client "Claude Code", agent inspector`;
  });

  // ---- CIMD: the Claude app's own client metadata documents (what acceptance test 1 uses) -------
  await check('M2', "CIMD: claude.ai's published client ID (the Claude app's default) works end to end as duet", async () => {
    const { verifier, challenge } = pkce();
    const st = b64url(randomBytes(12));
    const consent = await openConsent(authorizeUrl({ clientId: CLAUDE_AI_CIMD, redirectUri: CLAUDE_CALLBACK, challenge, state: st }));
    expect(consent.status === 200, `consent HTTP ${consent.status}: ${consent.html.slice(0, 200)}`);
    expect(consent.html.includes('Published by <strong>claude.ai</strong>'), 'CIMD domain not shown');
    expect(consent.html.includes('Access goes to <strong>claude.ai</strong>'), 'redirect host not shown');
    expect(!consent.html.includes('on a computer (localhost)'), 'unexpected loopback warning');
    expect(consent.html.includes('value="duet" required checked'), 'duet not preselected');
    await stopIfConnected(CLAUDE_AI_CIMD, consent, 'consent page shows "Published by claude.ai", access to claude.ai, duet preselected');
    const done = await submitConsent(consent, { agent: 'duet', password: OWNER_PASSWORD });
    expect(done.status === 302 && done.location, `approve HTTP ${done.status}`);
    cleanupGrantOf(CLAUDE_AI_CIMD, done.location);
    const loc = new URL(done.location);
    expect(`${loc.origin}${loc.pathname}` === CLAUDE_CALLBACK, `redirected to ${loc.origin}${loc.pathname}`);
    expect(loc.searchParams.get('state') === st && loc.searchParams.get('iss') === BASE, 'state or iss mismatch');
    const tok = await token({ grant_type: 'authorization_code', code: loc.searchParams.get('code'), redirect_uri: CLAUDE_CALLBACK, client_id: CLAUDE_AI_CIMD, code_verifier: verifier, resource: MCP });
    expect(tok.status === 200 && tok.body.expires_in === 900 && tok.body.refresh_token, `token HTTP ${tok.status} ${tok.body.error ?? ''}`);
    const ref = await token({ grant_type: 'refresh_token', refresh_token: tok.body.refresh_token, client_id: CLAUDE_AI_CIMD, resource: MCP });
    expect(ref.status === 200 && ref.body.access_token && ref.body.refresh_token && ref.body.refresh_token !== tok.body.refresh_token, `refresh HTTP ${ref.status} ${ref.body.error ?? ''}`);
    const who = await callTool(ref.body.access_token, 'whoami');
    expect(who.data?.agent === 'duet' && who.data?.client?.name === 'Claude', `whoami ${who.text.slice(0, 100)}`);
    const repos = await callTool(ref.body.access_token, 'mockgit_list_my_repos', { limit: 2 });
    expect(!repos.isError && repos.data?.count === 2, `repo list ${repos.text.slice(0, 100)}`);
    // A second consent from the same app would replace this connection: the page must say so.
    await until('replace warning on a second consent', async () => {
      const again = await openConsent(authorizeUrl({ clientId: CLAUDE_AI_CIMD, redirectUri: CLAUDE_CALLBACK, challenge, state: st }));
      return { done: again.html.includes("replaces this app's existing connection") && again.html.includes('agent duet'), state: 'no warning yet' };
    }, { timeoutMs: 90_000, intervalMs: 3000 });
    return 'consent "Published by claude.ai", access to claude.ai, duet preselected; public-client token (900s), refresh rotated; whoami client "Claude", agent duet; repo list OK; a second consent page warns that approving replaces this connection';
  });
  await check('M3', "CIMD: claude.ai's confidential client ID gets consent, and its code needs Claude's signed assertion", async () => {
    const { verifier, challenge } = pkce();
    const consent = await openConsent(authorizeUrl({ clientId: CLAUDE_AI_CIMD_CONFIDENTIAL, redirectUri: CLAUDE_CALLBACK, challenge, state: b64url(randomBytes(12)) }));
    expect(consent.status === 200, `consent HTTP ${consent.status}: ${consent.html.slice(0, 200)}`);
    expect(consent.html.includes('Published by <strong>claude.ai</strong>'), 'CIMD domain not shown');
    expect(consent.html.includes('value="duet" required checked'), 'duet not preselected');
    await stopIfConnected(CLAUDE_AI_CIMD_CONFIDENTIAL, consent, 'consent page shows "Published by claude.ai", duet preselected');
    const done = await submitConsent(consent, { agent: 'duet', password: OWNER_PASSWORD });
    expect(done.status === 302 && done.location, `approve HTTP ${done.status}`);
    cleanupGrantOf(CLAUDE_AI_CIMD_CONFIDENTIAL, done.location);
    const code = new URL(done.location).searchParams.get('code');
    expect(code, 'no code');
    const tok = await token({ grant_type: 'authorization_code', code, redirect_uri: CLAUDE_CALLBACK, client_id: CLAUDE_AI_CIMD_CONFIDENTIAL, code_verifier: verifier, resource: MCP });
    expect([400, 401].includes(tok.status) && tok.body.error === 'invalid_client' && !tok.body.access_token, `unsigned exchange: HTTP ${tok.status} ${tok.body.error ?? ''}`);
    return `consent "Published by claude.ai", duet preselected; a code exchange without a private_key_jwt assertion is refused (HTTP ${tok.status} invalid_client). Signing as Claude can't be tested from here`;
  });

  // ---- A stock MCP SDK client with its own OAuth discovery (as Inspector / Claude Code do) -----
  await check('S1', 'Stock MCP SDK client: discovers auth from the 401, registers, authorizes, calls tools', async () => {
    const redirectUrl = 'http://localhost:43211/callback';
    const provider = {
      _client: undefined, _tokens: undefined, _verifier: undefined, authUrl: undefined,
      get redirectUrl() { return redirectUrl; },
      get clientMetadata() {
        return { client_name: 'MCP SDK client (e2e)', redirect_uris: [redirectUrl], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' };
      },
      clientInformation() { return this._client; },
      saveClientInformation(info) { this._client = info; },
      tokens() { return this._tokens; },
      saveTokens(t) { this._tokens = t; },
      redirectToAuthorization(url) { this.authUrl = url; },
      saveCodeVerifier(v) { this._verifier = v; },
      codeVerifier() { return this._verifier; },
    };
    const mk = () => new StreamableHTTPClientTransport(new URL(MCP), { authProvider: provider, fetch: tfetch });
    const first = new Client({ name: 'sdk-oauth-e2e', version: '0.1.0' });
    const firstTransport = mk();
    let threw = false;
    try {
      await first.connect(firstTransport);
    } catch (err) {
      threw = err instanceof UnauthorizedError || /unauthori/i.test(String(err));
    }
    expect(threw && provider.authUrl, 'SDK did not start authorization');
    state.cleanup.push({ client_id: provider._client.client_id, delete_client: true });
    const consent = await openConsent(provider.authUrl);
    expect(consent.status === 200, `consent HTTP ${consent.status}`);
    const done = await submitConsent(consent, { agent: 'inspector', password: OWNER_PASSWORD });
    expect(done.status === 302, `approve HTTP ${done.status}`);
    await firstTransport.finishAuth(new URL(done.location).searchParams.get('code'));
    const client = new Client({ name: 'sdk-oauth-e2e', version: '0.1.0' });
    await client.connect(mk());
    const tools = (await client.listTools()).tools.map((t) => t.name);
    const res = await client.callTool({ name: 'mockgit_list_my_repos', arguments: { limit: 1 } });
    await client.close();
    expect(!res.isError, `tool error: ${res.content?.[0]?.text}`);
    return `SDK found ${provider.authUrl.origin}/authorize from the 401, registered ${provider._client.client_id}; tools: ${tools.join(', ')}`;
  });

  // ---- Admin page (what Jack uses from a phone to revoke) --------------------------------------
  await check('A1', 'Admin page: sign-in needs the owner password and this origin; it lists connections', async () => {
    const post = (password, origin, fetchSite) =>
      tfetch(`${BASE}/admin/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', ...(origin ? { origin } : {}), ...(fetchSite ? { 'sec-fetch-site': fetchSite } : {}) },
        body: new URLSearchParams({ username: 'owner', password }),
        redirect: 'manual',
      });
    expect((await post(OWNER_PASSWORD, null)).status === 403, 'sign-in without Origin was not refused');
    // What a real browser sends from a page with a strict referrer policy: "Origin: null" plus
    // Sec-Fetch-Site. Same-origin must work (it returned Forbidden to Jack on 2026-11-12); cross-site must not.
    expect((await post(OWNER_PASSWORD, 'null', 'cross-site')).status === 403, 'cross-site sign-in with a null Origin was not refused');
    expect((await post(OWNER_PASSWORD, 'https://evil.example', 'same-origin')).status === 403, 'sign-in from another Origin was not refused');
    const browser = await post(OWNER_PASSWORD, 'null', 'same-origin');
    expect(browser.status === 303, `browser-shaped sign-in (Origin: null, Sec-Fetch-Site: same-origin): HTTP ${browser.status}`);
    const adminHeaders = (await tfetch(`${BASE}/admin`)).headers;
    expect(adminHeaders.get('referrer-policy') === 'same-origin', `admin referrer-policy ${adminHeaders.get('referrer-policy')}`);
    expect((await post('not-the-password', BASE)).status === 401, 'wrong password was not refused');
    const ok = await post(OWNER_PASSWORD, BASE);
    const cookie = ok.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
    expect(ok.status === 303 && cookie.startsWith('__Host-broker-admin='), `sign-in HTTP ${ok.status}`);
    const page = await (await tfetch(`${BASE}/admin`, { headers: { cookie } })).text();
    expect(page.includes('<h2>Connections</h2>') && page.includes(duet.clientId) && page.includes('>Revoke</button>'), 'connections table missing');
    const anon = await (await tfetch(`${BASE}/admin`)).text();
    expect(!anon.includes('<h2>Connections</h2>'), 'admin page shown without a session');
    return 'no Origin 403, cross-site 403, another Origin 403, wrong password 401; signed in with this Origin and the way a browser does it (Origin: null + Sec-Fetch-Site: same-origin), 303 with a __Host- cookie; duet connection listed with Revoke';
  });

  // ---- Cleanup ---------------------------------------------------------------------------------
  currentStep = 'cleanup';
  for (const c of state.cleanup) await admin('POST', 'revoke', c);
  setVault({ target: TARGET, values, label: 'A' });
  setUpstreamAccepted({ target: TARGET, values, label: 'A' });
  await admin('DELETE', 'policy');

  // ---- No-leak sweep ---------------------------------------------------------------------------
  await new Promise((r) => setTimeout(r, 3000));
  const audit = await admin('GET', 'audit?limit=1000');
  await check('L1', 'No dummy secret in any response (bodies and headers, including errors)', async () => {
    const text = transcript.map((t) => JSON.stringify(t)).join('\n');
    const hits = findSecrets(text, values);
    expect(Object.keys(hits).length === 0, `hits: ${JSON.stringify(hits)}`);
    const errors = transcript.filter((t) => t.status >= 400).length;
    return `${transcript.length} responses (${errors} with status >= 400), ${Math.round(text.length / 1024)} KB, 0 hits for A-G`;
  });
  await check('L2', 'No dummy secret or upstream content in the audit log; it covers ok, error, denied, consent, revoke, approvals', async () => {
    const lines = audit.body.lines.filter((l) => new Date(l.ts) >= new Date(STARTED.getTime() - 5000));
    const hits = findSecrets(JSON.stringify(audit.body.lines), values);
    expect(Object.keys(hits).length === 0, `hits: ${JSON.stringify(hits)}`);
    const has = (pred, what) => expect(lines.some(pred), `missing audit line: ${what}`);
    has((l) => l.type === 'tool_call' && l.tool === 'whoami' && l.outcome === 'ok', 'whoami ok');
    has((l) => l.type === 'tool_call' && l.tool === 'mockgit_list_my_repos' && l.outcome === 'ok', 'mockgit ok');
    has((l) => l.type === 'tool_call' && l.code === 'upstream_401' && l.outcome === 'error', 'upstream_401 error');
    has((l) => l.type === 'tool_call' && l.outcome === 'denied', 'denied');
    has((l) => l.type === 'consent' && l.outcome === 'ok', 'consent ok');
    has((l) => l.type === 'revoke', 'revoke');
    has((l) => l.type === 'login_failed', 'login_failed');
    has((l) => l.type === 'approval' && l.code === 'approval_requested', 'approval_requested');
    has((l) => l.type === 'approval' && l.code === 'owner_approved', 'owner_approved');
    has((l) => l.type === 'approval' && l.code === 'owner_denied', 'owner_denied');
    has((l) => l.type === 'approval' && l.code === 'approval_used', 'approval_used');
    has((l) => l.type === 'tool_call' && l.code === 'credential_in_arguments' && l.outcome === 'denied', 'credential_in_arguments');
    const content = UPSTREAM_MARKERS.filter((m) => JSON.stringify(audit.body.lines).includes(m));
    expect(content.length === 0, `upstream content in the audit log: ${content.join(', ')}`);
    const redactions = lines.filter((l) => l.type === 'redaction').length;
    return `${lines.length} lines from this run, 0 secret hits, no upstream content (README markers); audit covers approvals and the credential refusal; redaction backstop fired ${redactions} times (N2 makes it fire on purpose)`;
  });
  await check('L3', 'No dummy secret and no upstream content in the Worker logs', async () => {
    let logText;
    let source;
    if (state.tail) {
      await new Promise((r) => setTimeout(r, 5000));
      await state.tail.stop();
      state.tail.save();
      logText = state.tail.output();
      source = 'wrangler tail (JSON events, console output)';
    } else {
      logText = readFileSync(arg('dev-log', join(OUT_DIR, 'dev.log')), 'utf8');
      source = 'wrangler dev output';
    }
    const auditEvents = (logText.match(/\\?"audit\\?"/g) ?? []).length;
    expect(logText.length > 0 && auditEvents > 0, `log capture looks empty (${logText.length} bytes, ${auditEvents} audit events)`);
    const hits = findSecrets(logText, values);
    expect(Object.keys(hits).length === 0, `hits: ${JSON.stringify(hits)}`);
    const content = UPSTREAM_MARKERS.filter((m) => logText.includes(m));
    expect(content.length === 0, `upstream content in the Worker logs: ${content.join(', ')}`);
    return `${source}: ${Math.round(logText.length / 1024)} KB, ${auditEvents} audit events, 0 secret hits, no upstream content (README markers)`;
  });
}

function writeReport() {
  const pass = results.filter((r) => r.status === 'PASS').length;
  const fail = results.filter((r) => r.status === 'FAIL').length;
  const skip = results.filter((r) => r.status === 'SKIP').length;
  const json = { target: TARGET, base: BASE, started: STARTED.toISOString(), finished: new Date().toISOString(), version: state.versionBefore, pass, fail, results };
  writeFileSync(join(OUT_DIR, `e2e-${TARGET}-${STAMP}.json`), JSON.stringify(json, null, 2));
  writeFileSync(join(OUT_DIR, `transcript-${TARGET}-${STAMP}.json`), JSON.stringify(transcript, null, 2));

  const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const spec = {
    T2: 'Acceptance 2', T3: 'Acceptance 3', T4a: 'Acceptance 4', T4b: 'Acceptance 4', T5: 'Acceptance 5', T6: 'Acceptance 6', T7: 'Acceptance 7',
    L1: 'Acceptance 4', L2: 'Acceptance 4', L3: 'Acceptance 4', C1: 'Acceptance 1 (scripted)', C2: 'Acceptance 1 (scripted)', C4: 'Acceptance 1 (scripted)', C5: 'Acceptance 1 (scripted)',
    M2: 'Acceptance 1 (scripted)',
    I1: 'Phase 2 D', AP1: 'Phase 2 C', AP2: 'Phase 2 C', AP3: 'Phase 2 C', AP4: 'Phase 2 C', AP5: 'Phase 2 C', AP6: 'Phase 2 C',
    N1: 'Phase 2 D', N2: 'Phase 2 D', N3: 'Phase 2 D', N4: 'Phase 2 D',
  };
  const md = `# Test log: ${TARGET === 'remote' ? 'deployed sandbox' : 'local wrangler dev'}

Generated by \`node test/e2e.mjs --target ${TARGET}\`. Do not edit by hand; rerun the test.

| | |
|---|---|
| Target | ${BASE} |
| MCP URL | ${MCP} |
| Started | ${STARTED.toISOString()} |
| Worker version | \`${state.versionBefore ?? 'unknown'}\` |
| Result | **${pass} passed, ${fail} failed${skip ? `, ${skip} skipped` : ''}** |
${networkRetries ? `| Network | ${networkRetries} request(s) retried once after the connection dropped before a response |` : ''}

## Results

| ID | Spec | Check | Result | Detail |
|---|---|---|---|---|
${results.map((r) => `| ${r.id} | ${spec[r.id] ?? ''} | ${esc(r.name)} | ${r.status} | ${esc(r.detail)} |`).join('\n')}

Acceptance test 1 (adding the connector in the Claude app) is Jack's own step; his run and Claude Duet's calls are under "Claude Duet on the sandbox" below. Here, C1 to C7 do the same protocol steps with the same callback URL (\`${CLAUDE_CALLBACK}\`) through Dynamic Client Registration, and M2 does them with the Claude app's own published client ID (\`${CLAUDE_AI_CIMD}\`). M3 covers its confidential variant up to the signed assertion, which only Claude can produce. A new consent replaces an app's existing connection, so M1 to M3 stop after the consent page (SKIP) when that app is already connected.

## Dummy secrets searched for

Values live only in the gitignored \`.secrets/sandbox.json\`. Fingerprints are the first 10 hex characters of SHA-256.

| Label | Fingerprint | Role |
|---|---|---|
${Object.entries(ROLES).map(([l, role]) => `| ${l} | \`${fingerprint(values[l])}\` | ${role} |`).join('\n')}
`;
  if (TARGET === 'remote') writeTestLog({ sandbox: md });
  writeFileSync(join(OUT_DIR, `test-log-${TARGET}.md`), md);
  console.log(`\n${pass} passed, ${fail} failed${skip ? `, ${skip} skipped` : ''}. Report: ${TARGET === 'remote' ? 'docs/test-log.md' : `test-output/test-log-${TARGET}.md`}`);
  return fail;
}

try {
  await main();
} catch (err) {
  record('XX', 'Harness crashed', 'FAIL', String(err?.stack ?? err));
} finally {
  if (state.tail) await state.tail.stop();
}
process.exitCode = writeReport() ? 1 : 0;
