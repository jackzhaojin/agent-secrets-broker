#!/usr/bin/env node
// Live broker helpers. Real secrets are entered by Jack (`wrangler secret put`); this
// script only handles the broker's own random keys and never prints a secret value.
//
//   npm run live -- init-keys     generate ADMIN_TOKEN, COOKIE_SECRET, TOKEN_ENC_KEY and push them to
//                                 agent-secrets-broker-live in one `wrangler secret bulk` (stdin);
//                                 keeps only ADMIN_TOKEN in .secrets/live.json (0600, gitignored)
//   npm run live -- status        which Worker secrets are set (names only) and /healthz
//   npm run live -- adobe-connect listen on localhost:8976 for Adobe's sign-in redirect and forward
//                                 the browser to the broker's callback; opens /connect/adobe.
//                                 It sees only the one-time code (useless without the PKCE verifier
//                                 and client secret in the Worker) and prints nothing from it.
//
// Admin API against the live broker: npm run admin -- --live clients | audit | approvals | policy

import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, SECRETS_DIR, wrangler } from './lib.mjs';

const LIVE_BASE = 'https://agent-secrets-broker-live.jackzhaojin.workers.dev';
const LIVE_FILE = join(SECRETS_DIR, 'live.json');
const CONFIG = join(ROOT, 'wrangler.live.jsonc');

const [cmd] = process.argv.slice(2);

switch (cmd) {
  case 'init-keys': {
    if (existsSync(LIVE_FILE)) {
      console.error(`${LIVE_FILE} exists; refusing to rotate keys silently. Delete it first to rotate (this signs out admin sessions and makes stored Adobe tokens unreadable, so reconnect Adobe afterwards).`);
      process.exit(2);
    }
    const keys = {
      ADMIN_TOKEN: randomBytes(32).toString('base64url'),
      COOKIE_SECRET: randomBytes(48).toString('base64url'),
      TOKEN_ENC_KEY: randomBytes(32).toString('base64'),
    };
    wrangler(['secret', 'bulk', '-c', CONFIG], { input: JSON.stringify(keys) });
    mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(LIVE_FILE, JSON.stringify({ created: new Date().toISOString(), note: 'Live broker admin token. Gitignored. Never commit or print.', ADMIN_TOKEN: keys.ADMIN_TOKEN }, null, 2) + '\n', { mode: 0o600 });
    chmodSync(LIVE_FILE, 0o600);
    console.log('Set ADMIN_TOKEN, COOKIE_SECRET, TOKEN_ENC_KEY on agent-secrets-broker-live; kept ADMIN_TOKEN in .secrets/live.json.');
    break;
  }
  case 'status': {
    const out = wrangler(['secret', 'list', '-c', CONFIG, '--format', 'json']);
    const names = JSON.parse(out).map((s) => s.name).sort();
    for (const n of ['OWNER_PASSWORD', 'ADOBE_OAUTH_CLIENT_ID', 'ADOBE_OAUTH_CLIENT_SECRET', 'ADMIN_TOKEN', 'COOKIE_SECRET', 'TOKEN_ENC_KEY']) {
      console.log(`  ${names.includes(n) ? 'set    ' : 'MISSING'}  ${n}`);
    }
    const h = await fetch(`${LIVE_BASE}/healthz`).then((r) => r.json()).catch((e) => ({ error: String(e) }));
    console.log('healthz:', JSON.stringify(h));
    break;
  }
  case 'adobe-connect': {
    const PORT = 8976;
    let done;
    const finished = new Promise((r) => { done = r; });
    const handler = (req, res) => {
      const url = new URL(req.url, `http://localhost:${PORT}`);
      if (url.pathname !== '/callback') {
        res.writeHead(404).end('Not found');
        return;
      }
      // Pass Adobe's answer (code and state, or an error) on to the broker, in the same browser.
      res.writeHead(302, { location: `${LIVE_BASE}/connect/adobe/callback${url.search}`, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }).end();
      console.log(`Forwarded Adobe's redirect to the broker (${url.searchParams.has('code') ? 'with a code' : `error: ${url.searchParams.get('error') ?? 'no code'}`}).`);
      done('forwarded');
    };
    const servers = ['127.0.0.1', '::1'].map((host) => createServer(handler).listen(PORT, host).on('error', (e) => console.error(`listen ${host}: ${e.code}`)));
    console.log(`Listening on http://localhost:${PORT}/callback for up to 15 minutes.`);
    console.log(`Opening ${LIVE_BASE}/connect/adobe : sign in with the owner password, then on Adobe's page.`);
    if (!process.argv.includes('--no-open')) execFile('open', [`${LIVE_BASE}/connect/adobe`], () => {});
    const outcome = await Promise.race([finished, new Promise((r) => setTimeout(() => r('timed out'), 15 * 60 * 1000))]);
    await new Promise((r) => setTimeout(r, 500));
    for (const srv of servers) srv.close();
    console.log(outcome === 'forwarded' ? 'Done. The broker page in your browser says whether Adobe connected.' : 'Timed out waiting for the redirect.');
    break;
  }
  default:
    console.error('Commands: init-keys, status, adobe-connect');
    process.exit(2);
}
