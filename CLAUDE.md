# agent-secrets-broker

Remote MCP server + OAuth 2.1 authorization server on Cloudflare Workers that calls APIs for agents with secrets they never see. README.md has the design and what it can and can't do; docs/findings.md the Phase 2 results; docs/test-log.md the latest deployed test runs.

- Node 22 (`source ~/.nvm/nvm.sh && nvm use 22`). `npm run typecheck`, `npm run dev`, `npm run test:e2e [-- --target local]`, `npm run deploy`, `npm run scan`.
- Two deployments from one codebase: sandbox (`wrangler.jsonc`, entry `src/index.ts`, dummy secrets) and live (`wrangler.live.jsonc`, entry `src/live.ts`, real accounts; secrets are Worker secrets for now, Jack's choice on 2026-11-12, with the 1Password variant kept in `src/live-1password.ts`). Live: `npm run deploy:live`, `npm run test:live`, `npm run admin -- --live ...`.
- Real secrets never go in the sandbox, and sandbox dummies never go in live. Jack enters every real password, token and OAuth consent himself (`wrangler secret put`, the provider's page); never type, print or commit one.
- Real-account tools are read-only except `da_put_draft` (scratch folder, always behind approval). No purchases, publishing or account changes.
- Public repo. Run `npm run scan` before every push. Never commit `.secrets/`, `.dev.vars`, `patched/` or anything from them.
- Never print a secret value, including the sandbox dummies A-G: refer to them by label. The scripts only print labels and fingerprints; keep it that way.
- No tool may return a secret, token or credential, and there is no `get_secret` tool. New tools allow-list the fields they return and never pass upstream bodies through; text that must pass through is marked `untrusted_content`.
- After any change to `src/` or `mock-upstream/`, deploy and rerun `npm run test:e2e` (sandbox) and, if live code changed, `npm run deploy:live` and `npm run test:live`, so docs/test-log.md matches what is live. Each e2e run sends 2 wrong owner passwords; a correct sign-in clears the count, so runs no longer add up to the 10-per-15-minutes lockout. Don't run e2e while Jack or Duet is testing the sandbox: it resets the vault and briefly changes duet's policy.
- Cloudflare changes (deploys, KV, secrets, Durable Objects) are recorded in `../jack-dev-server-configs/server/cloudflare/history.md` and `workers.md`.
