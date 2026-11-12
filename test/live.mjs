#!/usr/bin/env node
// Checks against the LIVE broker (agent-secrets-broker-live), written to the "Live broker" section of
// docs/test-log.md. It never holds a real secret: it has the live admin token (read and revoke only,
// .secrets/live.json) and the sandbox's dummy values. It can't connect an agent to the live broker
// (that needs Jack's owner password), so positives on real accounts come from Claude Duet's own
// calls, read back from the live audit log (LV6).
//
//   npm run test:live                    checks + Duet evidence
//   npm run test:live -- --tail 300      also capture `wrangler tail` for 300 s while Duet runs its
//                                        tests, and search it for tokens and document content

import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LIVE_HEADING, ROOT, SECRETS_DIR, loadSandbox, startProcess, writeTestLog } from '../scripts/lib.mjs';

const LIVE = 'https://agent-secrets-broker-live.jackzhaojin.workers.dev';
const SANDBOX = 'https://agent-secrets-broker-sandbox.jackzhaojin.workers.dev';
const argv = process.argv.slice(2);
const tailSeconds = argv.includes('--tail') ? Number(argv[argv.indexOf('--tail') + 1]) || 300 : 0;
const ADMIN = JSON.parse(readFileSync(join(SECRETS_DIR, 'live.json'), 'utf8')).ADMIN_TOKEN;
const sandboxValues = loadSandbox().values;
const STARTED = new Date();
const results = [];

const b64url = (b) => Buffer.from(b).toString('base64url');
const expect = (cond, msg) => { if (!cond) throw new Error(msg); };
async function check(id, name, fn, { info = false } = {}) {
  try {
    const detail = await fn();
    results.push({ id, name, status: info ? 'INFO' : 'PASS', detail });
  } catch (err) {
    results.push({ id, name, status: 'FAIL', detail: String(err?.message ?? err) });
  }
  const r = results.at(-1);
  console.log(`${r.status.padEnd(4)}  ${id.padEnd(4)} ${name} - ${r.detail}`);
}
const admin = (path, base = LIVE, token = ADMIN) =>
  fetch(`${base}/admin/api/${path}`, { headers: { authorization: `Bearer ${token}` } }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

async function sandboxToken() {
  // A real token from the sandbox broker (dummy owner password D), to try on the live broker.
  const reg = await fetch(`${SANDBOX}/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Inspector (cross-deployment test)', redirect_uris: ['http://localhost:43299/callback'], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' }),
  }).then((r) => r.json());
  const verifier = b64url(randomBytes(32));
  const url = new URL(`${SANDBOX}/authorize`);
  url.search = new URLSearchParams({ response_type: 'code', client_id: reg.client_id, redirect_uri: 'http://localhost:43299/callback', code_challenge: b64url(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256', state: 's', scope: 'broker', resource: `${SANDBOX}/mcp` }).toString();
  const consent = await fetch(url, { redirect: 'manual' });
  const html = await consent.text();
  const field = (n) => html.match(new RegExp(`name="${n}" value="([^"]*)"`))?.[1];
  const form = new URLSearchParams({ handle: field('handle'), return_to: field('return_to')?.replace(/&#38;/g, '&') ?? '', decision: 'approve', agent: 'inspector', password: sandboxValues.D, scope: 'broker' });
  const approved = await fetch(`${SANDBOX}/authorize`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: SANDBOX, cookie: consent.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ') }, body: form });
  const code = new URL(approved.headers.get('location')).searchParams.get('code');
  const tok = await fetch(`${SANDBOX}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: 'http://localhost:43299/callback', client_id: reg.client_id, code_verifier: verifier, resource: `${SANDBOX}/mcp` }) }).then((r) => r.json());
  return { clientId: reg.client_id, token: tok.access_token };
}

const AUDIT_FIELDS = new Set(['ts', 'type', 'outcome', 'client_id', 'client_name', 'agent', 'tool', 'code', 'approval_id', 'ms']);

async function main() {
  const tail = tailSeconds ? startProcess('npx', ['wrangler', 'tail', 'agent-secrets-broker-live', '--format', 'json'], join(ROOT, 'test-output', `tail-live-${STARTED.toISOString().replace(/[:.]/g, '-')}.log`)) : null;

  await check('LV1', 'Live broker is up, separate from the sandbox', async () => {
    const [l, s] = await Promise.all([fetch(`${LIVE}/healthz`).then((r) => r.json()), fetch(`${SANDBOX}/healthz`).then((r) => r.json())]);
    expect(l.ok && l.environment === 'live' && s.environment === 'sandbox' && l.version !== s.version, `live ${l.environment} ${l.version}, sandbox ${s.environment}`);
    return `live version ${l.version}, policy ${l.policy.source} ${l.policy.hash}`;
  });
  await check('LV2', 'Discovery on the live URL names the live MCP resource', async () => {
    const r = await fetch(`${LIVE}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    const prmUrl = r.headers.get('www-authenticate')?.match(/resource_metadata="([^"]+)"/)?.[1];
    expect(r.status === 401 && prmUrl?.startsWith(LIVE), `HTTP ${r.status}, ${prmUrl}`);
    const prm = await fetch(prmUrl).then((x) => x.json());
    expect(prm.resource === `${LIVE}/mcp` && prm.authorization_servers[0] === LIVE, `resource ${prm.resource}`);
    return `401 challenge -> ${prm.resource}`;
  });
  await check('LV3', "A sandbox token and the sandbox admin token don't work on the live broker", async () => {
    const s = await sandboxToken();
    expect(s.token, 'could not get a sandbox token');
    const onSandbox = await fetch(`${SANDBOX}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${s.token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'x', version: '1' } } }) });
    const onLive = await fetch(`${LIVE}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${s.token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'x', version: '1' } } }) });
    const adminOnLive = await admin('clients', LIVE, sandboxValues.E);
    await fetch(`${SANDBOX}/admin/api/revoke`, { method: 'POST', headers: { authorization: `Bearer ${sandboxValues.E}`, 'content-type': 'application/json' }, body: JSON.stringify({ client_id: s.clientId, delete_client: true }) });
    expect(onSandbox.status === 200 && onLive.status === 401 && adminOnLive.status === 401, `sandbox ${onSandbox.status}, live ${onLive.status}, sandbox admin token on live ${adminOnLive.status}`);
    return 'the token works on the sandbox (200) and gets 401 on live; the sandbox admin token gets 401 on live';
  });
  await check('LV4', 'Owner-only surfaces on live refuse everyone else', async () => {
    const noToken = await fetch(`${LIVE}/admin/api/clients`);
    const connect = await fetch(`${LIVE}/connect/adobe`, { redirect: 'manual' });
    const connectHtml = await connect.text();
    const callback = await fetch(`${LIVE}/connect/adobe/callback?state=forged&code=forged`, { redirect: 'manual' });
    const disconnect = await fetch(`${LIVE}/connect/adobe/disconnect`, { method: 'POST', headers: { origin: LIVE } });
    const approve = await fetch(`${LIVE}/admin/approvals/000000000000`, { method: 'POST', headers: { origin: LIVE, 'content-type': 'application/x-www-form-urlencoded', authorization: `Bearer ${ADMIN}` }, body: 'decision=approved' });
    expect(noToken.status === 401 && connect.status === 200 && connectHtml.includes('Owner password') && callback.status === 400 && disconnect.status === 403 && approve.status === 403,
      `admin API ${noToken.status}, /connect/adobe ${connect.status}, forged callback ${callback.status}, disconnect ${disconnect.status}, approve with admin token ${approve.status}`);
    return 'admin API without token 401; /connect/adobe asks for the owner password; a forged callback 400; disconnect 403; approving with the admin token 403';
  });
  await check('LV5', 'Setup status (names and booleans only)', async () => {
    const s = (await admin('status')).body;
    const a = s.adobe ?? {};
    return [
      `owner password ${s.owner_password_set ? 'set' : 'NOT set'}`,
      `1Password token ${s.onepassword?.service_account_token_set ? 'set' : 'NOT set'}`,
      `adobe-oauth item ${s.onepassword?.adobe_client_readable ? 'readable' : 'not readable'}`,
      `scratch ${s.da_scratch ?? 'NOT set'}`,
      a.connected ? `Adobe connected as ${a.account} (scope ${a.scope}; access until ${a.access_expires_at}; refresh token ${a.has_refresh_token ? 'yes' : 'no'}; refreshed ${a.refresh_count}x, refresh token replaced ${a.refresh_token_changes}x)` : 'Adobe not connected',
    ].join('; ');
  }, { info: true });

  if (tail) {
    console.log(`Capturing wrangler tail for ${tailSeconds}s: have Duet run its live tests now.`);
    await new Promise((r) => setTimeout(r, tailSeconds * 1000));
  }

  const audit = (await admin('audit?limit=1000')).body.lines ?? [];
  await check('LV6', 'Claude Duet calling the live tools remotely (live audit log)', async () => {
    const duet = audit.filter((l) => l.agent === 'duet' && (l.type === 'tool_call' || l.type === 'approval'));
    if (!duet.length) return 'no calls from duet yet';
    const byTool = {};
    for (const l of duet) {
      const k = `${l.tool} ${l.type === 'approval' ? l.code : l.outcome}${l.type === 'tool_call' && l.code ? ` (${l.code})` : ''}`;
      byTool[k] = (byTool[k] ?? 0) + 1;
    }
    const clients = [...new Set(duet.map((l) => l.client_name))].join(', ');
    const first = duet.at(-1)?.ts;
    const last = duet[0]?.ts;
    return `clients: ${clients}; ${first} to ${last}; ${Object.entries(byTool).map(([k, n]) => `${k} x${n}`).join('; ')}`;
  }, { info: true });
  await check('LV7', 'The live audit log holds only structured fields (no arguments, content or tokens)', async () => {
    const extra = [...new Set(audit.flatMap((l) => Object.keys(l).filter((k) => !AUDIT_FIELDS.has(k))))];
    const text = JSON.stringify(audit);
    const jwt = (text.match(/eyJ[\w-]{10,}\.[\w-]{10,}/g) ?? []).length;
    const html = /<(body|main|div|p)[\s>]/i.test(text);
    expect(extra.length === 0 && jwt === 0 && !html, `extra fields ${extra.join(',')}; JWT-shaped ${jwt}; HTML ${html}`);
    return `${audit.length} lines, fields only ${[...AUDIT_FIELDS].join('/')}; 0 JWT-shaped strings (Adobe tokens are JWTs); no HTML`;
  });
  if (tail) {
    await check('LV8', 'The live Worker logs hold no tokens or document content', async () => {
      await new Promise((r) => setTimeout(r, 5000));
      await tail.stop();
      tail.save();
      const text = tail.output();
      const jwt = (text.match(/eyJ[\w-]{10,}\.[\w-]{10,}/g) ?? []).length;
      const html = /<(body|main|div|p)[\s>]/i.test(text);
      const bearer = /Bearer\s+[\w.-]{20,}/.test(text);
      expect(text.length > 0 && jwt === 0 && !html && !bearer, `JWT-shaped ${jwt}; HTML ${html}; bearer ${bearer}`);
      return `wrangler tail ${Math.round(text.length / 1024)} KB over ${tailSeconds}s: 0 JWT-shaped strings, no bearer values, no HTML`;
    });
  }
}

try {
  await main();
} catch (err) {
  results.push({ id: 'XX', name: 'Harness crashed', status: 'FAIL', detail: String(err?.stack ?? err) });
}

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const pass = results.filter((r) => r.status === 'PASS').length;
const fail = results.filter((r) => r.status === 'FAIL').length;
writeTestLog({
  sections: { [LIVE_HEADING]: `${LIVE_HEADING}

Generated by \`node test/live.mjs\` against ${LIVE} at ${STARTED.toISOString()}: **${pass} passed, ${fail} failed** (INFO rows are status, not checks). Do not edit by hand.

The script holds no real secret and can't connect an agent to the live broker (that takes Jack's owner password), so real-account positives are Claude Duet's own calls, read back from the live audit log (LV6). The audit log stores who, which tool and the outcome, never arguments or results.

| ID | Check | Result | Detail |
|---|---|---|---|
${results.map((r) => `| ${r.id} | ${esc(r.name)} | ${r.status} | ${esc(r.detail)} |`).join('\n')}
` },
});
console.log(`\n${pass} passed, ${fail} failed. Report: docs/test-log.md (${LIVE_HEADING})`);
process.exitCode = fail ? 1 : 0;
