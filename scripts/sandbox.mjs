#!/usr/bin/env node
// Manage the sandbox's dummy secrets. Prints labels and fingerprints, never values
// (except `owner-password`, which exists so the owner can read the consent password).
//
//   npm run sandbox -- init                  create .secrets/sandbox.json (A-G) and .dev.vars
//   npm run sandbox -- push                  set the broker's Worker secrets (D, E, F) on Cloudflare
//   npm run sandbox -- seed --remote|--local vault: mockgit/api_key=A, canary/unused=G; upstream accepts A
//   npm run sandbox -- vault <A-G> --remote|--local     put a label's value in the vault (mockgit/api_key)
//   npm run sandbox -- upstream <A-G> --remote|--local  make the mock upstream accept a label's value
//   npm run sandbox -- show                  labels, roles, fingerprints
//   npm run sandbox -- owner-password        print D (the consent page password)

import { ROLES, fingerprint, loadSandbox, pushWorkerSecrets, seed, setUpstreamAccepted, setVault, writeDevVars } from './lib.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const target = rest.includes('--local') ? 'local' : rest.includes('--remote') ? 'remote' : null;
const label = rest.find((a) => /^[A-G]$/.test(a));

function needTarget() {
  if (!target) {
    console.error('Pass --remote (deployed Workers) or --local (wrangler dev state).');
    process.exit(2);
  }
}

switch (cmd) {
  case 'init': {
    const { values } = loadSandbox({ create: true });
    writeDevVars(values);
    console.log('Dummy secrets ready in .secrets/sandbox.json (gitignored); .dev.vars written for wrangler dev.');
    for (const [l, role] of Object.entries(ROLES)) console.log(`  ${l}  ${fingerprint(values[l])}  ${role}`);
    break;
  }
  case 'push': {
    const { values } = loadSandbox();
    pushWorkerSecrets(values);
    console.log('Set OWNER_PASSWORD (D), ADMIN_TOKEN (E), COOKIE_SECRET (F) on agent-secrets-broker-sandbox.');
    break;
  }
  case 'seed': {
    needTarget();
    const { values } = loadSandbox();
    seed({ target, values });
    console.log(`Seeded (${target}): vault mockgit/api_key=A, canary/unused=G; upstream accepts A.`);
    break;
  }
  case 'vault':
  case 'upstream': {
    needTarget();
    if (!label) throw new Error('Pass a label A-G');
    const { values } = loadSandbox();
    if (cmd === 'vault') setVault({ target, values, label });
    else setUpstreamAccepted({ target, values, label });
    console.log(`${cmd === 'vault' ? 'Vault mockgit/api_key' : 'Upstream accepted key'} is now ${label} (${target}).`);
    break;
  }
  case 'show': {
    const { values, created } = loadSandbox();
    console.log(`Created ${created}`);
    for (const [l, role] of Object.entries(ROLES)) console.log(`  ${l}  ${fingerprint(values[l])}  ${role}`);
    break;
  }
  case 'owner-password': {
    console.log(loadSandbox().values.D);
    break;
  }
  default:
    console.error('Commands: init, push, seed, vault, upstream, show, owner-password');
    process.exit(2);
}
