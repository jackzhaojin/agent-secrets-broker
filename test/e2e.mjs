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
import { ROLES, ROOT, fingerprint, findSecrets, loadSandbox, seed, setUpstreamAccepted, setVault, startProcess } from '../scripts/lib.mjs';

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

async function tfetch(url, init = {}) {
  const res = await fetch(url, init);
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
  const mark = status === 'PASS' ? 'PASS' : status === 'FAIL' ? 'FAIL' : 'INFO';
  console.log(`${mark.padEnd(4)}  ${id.padEnd(4)} ${name}${detail ? ` - ${detail}` : ''}`);
}

class CheckFailed extends Error {}
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
    expect(tools.join(',') === 'whoami,mockgit_list_my_repos', `tools ${tools.join(',')}`);
    return `server ${info.name} ${info.version}; tools: ${tools.join(', ')}`;
  });

  // ---- Acceptance tests ------------------------------------------------------------------------
  await check('T2', 'Auth works: whoami returns the client name and allowed tools', async () => {
    const r = await callTool(duet.tokens.access_token, 'whoami');
    expect(!r.isError, r.text);
    expect(r.data.agent === 'duet', `agent ${r.data.agent}`);
    expect(r.data.client.name === 'Claude (scripted test)' && r.data.client.id === duet.clientId, 'client mismatch');
    expect(r.data.allowed_tools.join(',') === 'whoami,mockgit_list_my_repos', `allowed ${r.data.allowed_tools}`);
    return `agent=${r.data.agent}, client="${r.data.client.name}", allowed=[${r.data.allowed_tools.join(', ')}]`;
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
    const r = await token({ grant_type: 'refresh_token', refresh_token: duet.tokens.refresh_token, client_id: duet.clientId, resource: MCP });
    expect(r.status === 200, `HTTP ${r.status} ${r.body.error ?? ''}`);
    expect(r.body.access_token !== duet.tokens.access_token && r.body.refresh_token !== duet.tokens.refresh_token, 'tokens did not rotate');
    duet.tokens = r.body;
    const who = await callTool(duet.tokens.access_token, 'whoami');
    expect(!who.isError && who.data.agent === 'duet', 'whoami with refreshed token failed');
    return 'new access and refresh tokens; whoami OK';
  });
  await check('T6', 'Revoke: next call 401, refresh refused, reconnecting needs consent again', async () => {
    const rv = await admin('POST', 'revoke', { client_id: duet.clientId });
    expect(rv.status === 200 && rv.body.revoked_grants >= 1, `revoke HTTP ${rv.status} ${JSON.stringify(rv.body)}`);
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

  // ---- CIMD: Anthropic's published Claude Code client metadata document ------------------------
  await check('M1', "CIMD: Claude Code's published client ID works end to end (bound to agent inspector)", async () => {
    const redirectUri = 'http://localhost:43210/callback';
    const { verifier, challenge } = pkce();
    const st = b64url(randomBytes(12));
    const consent = await openConsent(authorizeUrl({ clientId: CLAUDE_CODE_CIMD, redirectUri, challenge, state: st }));
    expect(consent.status === 200, `consent HTTP ${consent.status}: ${consent.html.slice(0, 200)}`);
    expect(consent.html.includes('Published by <strong>claude.ai</strong>'), 'CIMD domain not shown');
    expect(consent.html.includes('localhost'), 'loopback warning missing');
    const done = await submitConsent(consent, { agent: 'inspector', password: OWNER_PASSWORD });
    expect(done.status === 302, `approve HTTP ${done.status}`);
    const code = new URL(done.location).searchParams.get('code');
    const tok = await token({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: CLAUDE_CODE_CIMD, code_verifier: verifier, resource: MCP });
    expect(tok.status === 200, `token HTTP ${tok.status} ${tok.body.error ?? ''}`);
    const who = await callTool(tok.body.access_token, 'whoami');
    expect(who.data?.agent === 'inspector' && who.data?.client?.name === 'Claude Code', `whoami ${who.text.slice(0, 100)}`);
    const conns = await admin('GET', 'clients');
    const mine = conns.body.connections.find((c) => c.client_id === CLAUDE_CODE_CIMD)?.grants.filter((g) => new Date(g.created_at) >= new Date(STARTED.getTime() - 60_000)) ?? [];
    for (const g of mine) state.cleanup.push({ client_id: CLAUDE_CODE_CIMD, grant_id: g.id });
    return `consent shows "Published by claude.ai"; token issued; whoami client "Claude Code", agent inspector`;
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
    const post = (password, origin) =>
      tfetch(`${BASE}/admin/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', ...(origin ? { origin } : {}) },
        body: new URLSearchParams({ username: 'owner', password }),
        redirect: 'manual',
      });
    expect((await post(OWNER_PASSWORD, null)).status === 403, 'sign-in without Origin was not refused');
    expect((await post('not-the-password', BASE)).status === 401, 'wrong password was not refused');
    const ok = await post(OWNER_PASSWORD, BASE);
    const cookie = ok.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
    expect(ok.status === 303 && cookie.startsWith('__Host-broker-admin='), `sign-in HTTP ${ok.status}`);
    const page = await (await tfetch(`${BASE}/admin`, { headers: { cookie } })).text();
    expect(page.includes('<h2>Connections</h2>') && page.includes(duet.clientId) && page.includes('>Revoke</button>'), 'connections table missing');
    const anon = await (await tfetch(`${BASE}/admin`)).text();
    expect(!anon.includes('<h2>Connections</h2>'), 'admin page shown without a session');
    return 'no Origin 403, wrong password 401, signed in (303, __Host- cookie); duet connection listed with Revoke';
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
  await check('L2', 'No dummy secret in the audit log; audit covers ok, error, denied, consent, revoke', async () => {
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
    const redactions = lines.filter((l) => l.type === 'redaction').length;
    return `${lines.length} lines from this run, 0 hits; redaction backstop fired ${redactions} times`;
  });
  await check('L3', 'No dummy secret in the Worker logs', async () => {
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
    return `${source}: ${Math.round(logText.length / 1024)} KB, ${auditEvents} audit events, 0 hits`;
  });
}

function writeReport() {
  const pass = results.filter((r) => r.status === 'PASS').length;
  const fail = results.filter((r) => r.status === 'FAIL').length;
  const json = { target: TARGET, base: BASE, started: STARTED.toISOString(), finished: new Date().toISOString(), version: state.versionBefore, pass, fail, results };
  writeFileSync(join(OUT_DIR, `e2e-${TARGET}-${STAMP}.json`), JSON.stringify(json, null, 2));
  writeFileSync(join(OUT_DIR, `transcript-${TARGET}-${STAMP}.json`), JSON.stringify(transcript, null, 2));

  const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const spec = {
    T2: 'Acceptance 2', T3: 'Acceptance 3', T4a: 'Acceptance 4', T4b: 'Acceptance 4', T5: 'Acceptance 5', T6: 'Acceptance 6', T7: 'Acceptance 7',
    L1: 'Acceptance 4', L2: 'Acceptance 4', L3: 'Acceptance 4', C1: 'Acceptance 1 (scripted)', C2: 'Acceptance 1 (scripted)', C4: 'Acceptance 1 (scripted)', C5: 'Acceptance 1 (scripted)',
  };
  const md = `# Test log: ${TARGET === 'remote' ? 'deployed sandbox' : 'local wrangler dev'}

Generated by \`node test/e2e.mjs --target ${TARGET}\`. Do not edit by hand; rerun the test.

| | |
|---|---|
| Target | ${BASE} |
| MCP URL | ${MCP} |
| Started | ${STARTED.toISOString()} |
| Worker version | \`${state.versionBefore ?? 'unknown'}\` |
| Result | **${pass} passed, ${fail} failed** |

## Results

| ID | Spec | Check | Result | Detail |
|---|---|---|---|---|
${results.map((r) => `| ${r.id} | ${spec[r.id] ?? ''} | ${esc(r.name)} | ${r.status} | ${esc(r.detail)} |`).join('\n')}

Acceptance test 1 (adding the connector in the Claude app) needs Jack in the app. C1 to C7 do the same protocol steps with the same callback URL (\`${CLAUDE_CALLBACK}\`).

## Dummy secrets searched for

Values live only in the gitignored \`.secrets/sandbox.json\`. Fingerprints are the first 10 hex characters of SHA-256.

| Label | Fingerprint | Role |
|---|---|---|
${Object.entries(ROLES).map(([l, role]) => `| ${l} | \`${fingerprint(values[l])}\` | ${role} |`).join('\n')}
`;
  if (TARGET === 'remote') writeFileSync(join(ROOT, 'docs', 'test-log.md'), md);
  writeFileSync(join(OUT_DIR, `test-log-${TARGET}.md`), md);
  console.log(`\n${pass} passed, ${fail} failed. Report: ${TARGET === 'remote' ? 'docs/test-log.md' : `test-output/test-log-${TARGET}.md`}`);
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
