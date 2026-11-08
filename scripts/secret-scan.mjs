#!/usr/bin/env node
// Pre-push secret scan. Exits 1 on any finding.
//   1. Every dummy secret value (A-G, from .secrets/sandbox.json) in tracked and untracked files
//      and in the full git history.
//   2. Files that must never be tracked (.env, .dev.vars, .secrets/, keys).
//   3. Common real-credential shapes (GitHub, 1Password, Anthropic, AWS, Slack, private keys).
//   4. gitleaks over the working tree and history, if installed.

import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT, SANDBOX_FILE, findSecrets } from './lib.mjs';

const git = (...args) => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
const findings = [];

const files = git('ls-files', '-co', '--exclude-standard').split('\n').filter(Boolean);
const hasCommits = (() => {
  try {
    execFileSync('git', ['rev-parse', '--verify', '--quiet', 'HEAD'], { cwd: ROOT, stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();
const history = hasCommits ? git('log', '-p', '--all', '--no-color') : '';

// 1. Dummy secret values
if (existsSync(SANDBOX_FILE)) {
  const { values } = JSON.parse(readFileSync(SANDBOX_FILE, 'utf8'));
  for (const f of files) {
    const hits = findSecrets(readFileSync(join(ROOT, f), 'latin1'), values);
    if (Object.keys(hits).length) findings.push(`dummy secret ${Object.keys(hits).join(',')} in ${f}`);
  }
  const histHits = findSecrets(history, values);
  if (Object.keys(histHits).length) findings.push(`dummy secret ${Object.keys(histHits).join(',')} in git history`);
} else {
  console.log('note: no .secrets/sandbox.json, skipping the dummy-value scan');
}

// 2. Paths that must never be tracked
const tracked = hasCommits ? git('log', '--all', '--name-only', '--pretty=format:').split('\n').filter(Boolean) : [];
const forbidden = /(^|\/)(\.env(\..*)?|\.dev\.vars(\..*)?|\.secrets\/.*|.*\.pem|.*\.key|id_rsa.*)$/;
for (const f of new Set([...files, ...tracked])) {
  if (forbidden.test(f) && !f.endsWith('.env.example')) findings.push(`forbidden file: ${f}`);
}

// 3. Real credential shapes
const patterns = {
  'GitHub token': /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
  '1Password service account token': /\bops_[A-Za-z0-9_-]{40,}/,
  'Anthropic key': /\bsk-ant-[A-Za-z0-9_-]{20,}/,
  'OpenAI-style key': /\bsk-(proj-)?[A-Za-z0-9]{32,}/,
  'AWS access key': /\bAKIA[0-9A-Z]{16}\b/,
  'Slack token': /\bxox[abpr]-[A-Za-z0-9-]{10,}/,
  'Private key': /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
};
for (const f of files) {
  const text = readFileSync(join(ROOT, f), 'latin1');
  for (const [name, re] of Object.entries(patterns)) if (re.test(text)) findings.push(`${name} shape in ${f}`);
}
for (const [name, re] of Object.entries(patterns)) if (re.test(history)) findings.push(`${name} shape in git history`);

// 4. gitleaks
let gitleaks = 'not installed';
try {
  execFileSync('gitleaks', ['version'], { stdio: 'ignore' });
  // Scan exactly what git would publish (tracked + untracked-not-ignored), not ignored local
  // files such as .dev.vars, which hold dummy values on purpose.
  const stage = mkdtempSync(join(tmpdir(), 'asb-scan-'));
  for (const f of files) {
    cpSync(join(ROOT, f), join(stage, f), { recursive: true });
  }
  const run = (args, cwd = ROOT) => {
    try {
      execFileSync('gitleaks', args, { cwd, stdio: 'pipe' });
      return 'clean';
    } catch (err) {
      findings.push(`gitleaks ${args[0]}: ${String(err.stdout ?? '').trim() || 'leaks found'}`);
      return 'FOUND LEAKS';
    }
  };
  const dir = run(['dir', '.', '--no-banner', '--redact'], stage);
  rmSync(stage, { recursive: true, force: true });
  const hist = hasCommits ? run(['git', '.', '--no-banner', '--redact', '--log-opts=--all']) : 'no commits';
  gitleaks = `dir ${dir}, history ${hist}`;
} catch {
  /* not installed */
}

console.log(`Scanned ${files.length} files${hasCommits ? ' and the full git history' : ''}; gitleaks: ${gitleaks}`);
if (findings.length) {
  console.error(`\nSECRET SCAN FAILED (${findings.length}):\n- ${findings.join('\n- ')}`);
  process.exit(1);
}
console.log('Secret scan clean.');
