#!/usr/bin/env node
// Registers the live broker as an OAuth client of Adobe's hosted Experience Workspace (DA) MCP
// server (Dynamic Client Registration at oauth.adobeaemcloud.com), then puts the issued client ID
// and client secret straight into the live Worker's secrets (ADOBE_OAUTH_CLIENT_ID,
// ADOBE_OAUTH_CLIENT_SECRET) over stdin. The secret is never printed or written to disk; if it's
// lost, register again. What is kept (gitignored, .secrets/adobe-mcp-client.json): the client ID,
// the redirect URIs and the time, which aren't secret.
//
//   npm run live -- status                 before and after
//   node scripts/adobe-register.mjs        register with the broker's own callback and a localhost one
//   node scripts/adobe-register.mjs --redirect <uri> [--redirect <uri>]   choose the redirect URIs
//   node scripts/adobe-register.mjs --dry  show the request, send nothing

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, SECRETS_DIR, wrangler } from './lib.mjs';

const AS = 'https://oauth.adobeaemcloud.com';
const LIVE = 'https://agent-secrets-broker-live.jackzhaojin.workers.dev';
export const LOCAL_REDIRECT = 'http://localhost:8976/callback';
const argv = process.argv.slice(2);
const redirects = argv.flatMap((a, i) => (a === '--redirect' ? [argv[i + 1]] : []));
const redirect_uris = redirects.length ? redirects : [`${LIVE}/connect/adobe/callback`, LOCAL_REDIRECT];

const meta = await fetch(`${AS}/.well-known/oauth-authorization-server`).then((r) => r.json());
const body = {
  client_name: 'Agent Secrets Broker (Jack Jin, personal)',
  client_uri: 'https://github.com/jackzhaojin/agent-secrets-broker',
  redirect_uris,
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_post',
  scope: 'aem.mcp.experience-workspace openid AdobeID',
};
console.log(`POST ${meta.registration_endpoint}`);
console.log(JSON.stringify(body, null, 2));
if (argv.includes('--dry')) process.exit(0);

const res = await fetch(meta.registration_endpoint, {
  method: 'POST',
  headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'agent-secrets-broker' },
  body: JSON.stringify(body),
});
const text = await res.text();
let reg;
try {
  reg = JSON.parse(text);
} catch {
  reg = null;
}
if (!res.ok || !reg?.client_id) {
  // An error body holds no secret: it's Adobe's reason for refusing.
  console.error(`\nRegistration refused: HTTP ${res.status}\n${text.slice(0, 600)}`);
  process.exit(1);
}

const SECRET_FIELDS = new Set(['client_secret', 'registration_access_token']);
console.log(`\nRegistered: HTTP ${res.status}`);
for (const [k, v] of Object.entries(reg)) console.log(`  ${k}: ${SECRET_FIELDS.has(k) ? '(set, not shown)' : JSON.stringify(v)}`);

const secrets = { ADOBE_OAUTH_CLIENT_ID: reg.client_id };
if (reg.client_secret) secrets.ADOBE_OAUTH_CLIENT_SECRET = reg.client_secret;
wrangler(['secret', 'bulk', '-c', join(ROOT, 'wrangler.live.jsonc')], { input: JSON.stringify(secrets) });
if (!existsSync(SECRETS_DIR)) mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o700 });
writeFileSync(
  join(SECRETS_DIR, 'adobe-mcp-client.json'),
  JSON.stringify({ registered_at: new Date().toISOString(), authorization_server: AS, client_id: reg.client_id, redirect_uris: reg.redirect_uris ?? redirect_uris, scope: reg.scope ?? body.scope, client_secret_expires_at: reg.client_secret_expires_at ?? null }, null, 2) + '\n',
  { mode: 0o600 },
);
console.log(`\nSet ${Object.keys(secrets).join(', ')} on agent-secrets-broker-live. Client details (no secret) in .secrets/adobe-mcp-client.json.`);
