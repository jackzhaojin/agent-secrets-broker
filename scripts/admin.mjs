#!/usr/bin/env node
// Owner's admin CLI for the broker. Uses the admin token (E) from .secrets/sandbox.json, or
// BROKER_ADMIN_TOKEN from the environment.
//
//   npm run admin -- clients                       connections and their grants
//   npm run admin -- revoke <client_id> [--delete] revoke all of a client's grants (and delete a DCR client)
//   npm run admin -- audit [n]                     latest audit lines (default 30)
//   npm run admin -- policy                        the policy in force
//   npm run admin -- policy push [file]            set a KV override (default: policy.json)
//   npm run admin -- policy reset                  remove the override (back to the bundled policy.json)
//
// --base <url> targets another deployment (default: the sandbox; http://localhost:8787 for wrangler dev).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, loadSandbox } from './lib.mjs';

const args = process.argv.slice(2);
const baseIdx = args.indexOf('--base');
const BASE = (baseIdx >= 0 ? args.splice(baseIdx, 2)[1] : 'https://agent-secrets-broker-sandbox.jackzhaojin.workers.dev').replace(/\/$/, '');
const TOKEN = process.env.BROKER_ADMIN_TOKEN ?? loadSandbox().values.E;
const [cmd, a1, a2] = args;

async function api(method, path, body) {
  const res = await fetch(`${BASE}/admin/api/${path}`, {
    method,
    headers: { authorization: `Bearer ${TOKEN}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${JSON.stringify(json)}`);
  return json;
}

const print = (x) => console.log(JSON.stringify(x, null, 2));

switch (cmd) {
  case 'clients':
    print(await api('GET', 'clients'));
    break;
  case 'revoke':
    if (!a1) throw new Error('usage: revoke <client_id> [--delete]');
    print(await api('POST', 'revoke', { client_id: a1, delete_client: args.includes('--delete') }));
    break;
  case 'audit':
    for (const l of (await api('GET', `audit?limit=${Number(a1) || 30}`)).lines) {
      console.log([l.ts, l.type, l.outcome, l.agent ?? '-', l.tool ?? '-', l.code ?? '', l.client_name ?? ''].join('  '));
    }
    break;
  case 'policy':
    if (a1 === 'push') print(await api('PUT', 'policy', JSON.parse(readFileSync(a2 ?? join(ROOT, 'policy.json'), 'utf8'))));
    else if (a1 === 'reset') print(await api('DELETE', 'policy'));
    else print(await api('GET', 'policy'));
    break;
  default:
    console.error('Commands: clients, revoke <client_id> [--delete], audit [n], policy [push [file] | reset]');
    process.exit(2);
}
