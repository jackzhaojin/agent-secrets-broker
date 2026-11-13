# Notes for an agent working in this repo

Read `CLAUDE.md` first: it has the rules. This file has the context behind them. For the design itself read [../docs/architecture.md](../docs/architecture.md).

## What this is, in three lines

- A remote MCP server plus OAuth 2.1 authorization server on Cloudflare Workers. Agents connect to it and call task-shaped tools; it calls upstream APIs with credentials only it holds.
- Two deployments from one codebase: **sandbox** (dummy secrets, a mock upstream, the automated tests) and **live** (Jack's real Adobe sign-in for da.live).
- The owner (Jack) is a separate channel: he approves connections and sensitive calls on the broker's own pages with his own password.

## Map of the code

| Path | What it does |
|---|---|
| `src/index.ts` | Sandbox entry point: registers the sandbox deployment (KV vault, Mock Git tools, `policy.json`) |
| `src/live.ts`, `src/live-common.ts` | Live entry point (Worker secrets) and what both live variants share: DA tools, Adobe routes, daily refresh cron, `policy.live.json` |
| `src/live-1password.ts` | Live entry point with the 1Password secret store. Kept, not deployed |
| `src/deployment.ts` | The registry an entry point fills in: tools, policy, secret store, extra routes |
| `src/worker.ts` | Wires `@cloudflare/workers-oauth-provider`: endpoints, token lifetimes, and the refresh check against the revocation list |
| `src/app.ts` | Consent page, admin page and admin API, approval pages, revoke |
| `src/mcp.ts` | The MCP endpoint: revocation check, policy filter, credential-in-arguments refusal, approval gate, redaction, audit |
| `src/approvals.ts`, `src/revocations.ts` | Durable Objects: per-call approvals; revocation list and the broker's own record of each client's grant |
| `src/tools/` | `core.ts` (whoami), `mockgit.ts` (sandbox), `da.ts` (live), `types.ts` |
| `src/upstream/adobe.ts` | Sign-in B: the broker as an OAuth client of Adobe's sign-in server; token storage and refresh |
| `src/upstream/adobe-mcp.ts` | The broker as an MCP client of Adobe's hosted DA MCP server |
| `src/secrets/` | `SecretStore` and its three implementations: KV vault, Worker secrets, 1Password |
| `mock-upstream/` | The Mock Git Worker: a fake API that leaks keys on purpose, so tests can prove the broker strips them |
| `scripts/` | `sandbox.mjs` (dummy secrets), `live.mjs` (live keys, status, the localhost sign-in helper), `adobe-register.mjs`, `admin.mjs`, `secret-scan.mjs` |
| `test/e2e.mjs` | The sandbox end-to-end test. Writes the top of `docs/test-log.md` |
| `test/duet.mjs` | Reads Claude Duet's own calls from an audit log and writes its section of the test log (`--live` for the live broker) |
| `test/live.mjs` | Checks against the live broker that need no owner password |

## Invariants

- **No tool returns a secret, token or credential.** There is no `get_secret`. Tools allow-list the fields they return; upstream bodies are never passed through; text that must pass through is marked `untrusted_content`.
- **The agent can't choose the upstream call.** Each broker tool calls one fixed upstream operation with arguments the broker built.
- **Writes need the owner's approval, set in code** (`requiresApproval`), so a policy change can't remove it.
- **Only the owner's password session approves.** Not the admin token, not an agent's token.
- **Real secrets never enter the sandbox; dummies never enter live.** Jack enters every real password, token and consent himself. Never type, print or commit one.
- **Logs hold codes, not content.** No request bodies, tokens, upstream responses or error descriptions.

## Traps already hit (don't repeat them)

- **The end-to-end test can evict the owner's real connection.** A new consent from the same client ID replaces the earlier grant, and the test consents with Claude's real client ID. It now skips that step when a connection exists. Still: don't run `npm run test:e2e` while Jack or Duet is using the sandbox. It also resets the vault and briefly changes duet's policy.
- **Cloudflare KV is eventually consistent.** A listing can lag by up to a minute, and a read at another location can be stale. Anything that must be immediate or single-use (revocation, approvals, the per-client grant record) lives in a Durable Object. Tests that read the audit log poll for it.
- **A scripted pass is not a browser pass.** Two bugs passed every scripted check and failed in Jack's browser: a same-origin check tripped by `Origin: null`, and a `__Host-` cookie with a path other than `/`, which browsers drop silently. If a change touches a page a person uses, say plainly that it wasn't tested in a browser.
- **The owner sign-in locks out an IP after 10 wrong passwords in a sliding 15 minutes.** The test sends 2 per run. A correct sign-in now clears the count.
- **workers.dev answers Python's default user agent with Cloudflare error 1010.** Set a user agent in ad hoc probes.
- **Mermaid reads a node label starting with `1.` as a markdown list** and renders "Unsupported markdown: list". Parsing succeeds; only a visual check catches it. Diagrams wider than about 880 px shrink on GitHub.
- **`wrangler` needs Node 22.** Jack's default shell is on Node 20: prefix commands for him with `source ~/.nvm/nvm.sh && nvm use 22 &&`.

## Things that are true but surprising

- **"duet" is not Duet.** A connector belongs to Jack's Claude account, so any Claude on it that loads connectors reaches the broker as the same agent. The OAuth client ID identifies the app, not a user or an agent.
- **Adobe's Developer Console can't issue the credential you'd expect.** For da.live it offers Jack's org server-to-server only. The working route is Adobe's hosted DA MCP server, whose sign-in server registers clients only for callback addresses it knows: `http://localhost:8976/callback` works, the broker's own URL doesn't.
- **The broker never holds a raw Adobe token.** Adobe's access token is a wrapper around an encrypted IMS token. No ID token, email or name comes with it. A token from sign-in has no `sub`; a refreshed one does (a stable Adobe user ID). Seen twice on 2026-11-12. Never put that ID in the repo: `test/live.mjs` masks it in the test log.
- **Reconnecting Adobe needs Jack's Mac**, because the sign-in returns to localhost. `npm run live -- adobe-connect` runs the helper.
- **The live secrets are Worker secrets, not 1Password**, by Jack's choice on 2026-11-12. The 1Password path is built and unproven with a real service account.

## How to check state before assuming anything

```bash
npm run live -- status              # which live secrets are set (names only) and /healthz
npm run admin -- clients            # sandbox connections; add --live for the live broker
npm run admin -- --live audit 30    # recent live audit lines
npm run test:live                   # live checks that need no owner password
```

## Open threads (as of 2026-11-13)

- Approval notifications: the admin page only. Email or push needs an account Jack would set up.
- Approval friction: reads run without approval on live now. A time-boxed or batched approval isn't built.
- 1Password with a real service account: untested.
- Per-agent identity (so "duet" means Duet) and multi-user (separate people, separate permissions): not built. Options talked through with Jack on 2026-11-12: an identity provider (Google, Microsoft, Cloudflare Access) in place of the owner password; or Adobe's sign-in doing both jobs, which gives a user ID but no email or name. Also discussed, not built: a `local` deployment on localhost for local agents (weaker isolation, no helper hop).
- The Adobe client registration rides on a localhost callback Adobe allows for local tools. The supported route is asking Adobe to allowlist the broker.
- `agent-test.html` is still in the scratch folder on da.live; the broker has no delete tool.
- The sandbox connector in Jack's claude.ai was disconnected by a test run and hasn't been reconnected.
