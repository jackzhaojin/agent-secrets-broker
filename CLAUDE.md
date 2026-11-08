# agent-secrets-broker

Remote MCP server + OAuth 2.1 authorization server on Cloudflare Workers that calls APIs for agents with secrets they never see. README.md has the design; docs/test-log.md the latest deployed test run.

- Node 22 (`source ~/.nvm/nvm.sh && nvm use 22`). `npm run typecheck`, `npm run dev`, `npm run test:e2e [-- --target local]`, `npm run deploy`, `npm run scan`.
- Public repo. Run `npm run scan` before every push. Never commit `.secrets/`, `.dev.vars` or anything from them.
- Never print a secret value, including the sandbox dummies A-G: refer to them by label. The scripts only print labels and fingerprints; keep it that way.
- No tool may return a secret, token or credential, and there is no `get_secret` tool. New tools allow-list the fields they return and never pass upstream bodies through.
- After any change to `src/` or `mock-upstream/`, deploy and rerun `npm run test:e2e` so docs/test-log.md matches what is live.
- Cloudflare changes (deploys, KV, secrets) are recorded in `../jack-dev-server-configs/server/cloudflare/history.md` and `workers.md`.
