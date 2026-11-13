# Agent Secrets Broker

A small service that holds secrets and makes API calls on behalf of AI agents. Agents connect to it as a remote MCP server, sign in with OAuth, and can call only the tools their policy allows. No tool ever returns a secret.

The test it is built to pass: *Claude Duet asks the broker to do something that needs an API key, gets the result back, and the key never appears anywhere Duet can see.*

**Status: proof of concept.** Two deployments:

- **The sandbox** holds dummy test secrets (`TEST_SECRET_A` to `G` style values) and calls a mock upstream it hosts itself. It carries the mechanism tests, all passing against the deployed URL, and Claude Duet's own run through a claude.ai connector on 2026-11-12: six of six ([docs/test-log.md](docs/test-log.md)).
- **The live broker** is for real accounts. It holds Jack's Adobe sign-in for da.live, and Claude Duet has used it end to end (2026-11-13). Its secrets are Cloudflare Worker secrets for now; 1Password is built but not in use ([docs/live-setup.md](docs/live-setup.md)).

Phase 2 results, negatives included, are in [docs/findings.md](docs/findings.md).

## What the broker can and can't do

Phase 2 at a glance (details and evidence in [docs/findings.md](docs/findings.md)):

| | Experiment | Result |
|---|---|---|
| A | da.live as Jack (Adobe sign-in held by the broker) | **Works.** Claude Duet listed, read and saved a draft on da.live as Jack, each call approved by him. It goes through Adobe's hosted DA MCP server with a localhost sign-in, because Adobe's Developer Console offers Jack's org only server-to-server credentials |
| B | Best Buy orders with Jack's username and password | **Blocked** by Best Buy's terms for AI agents. No attempt made |
| C | Per-call approval for sensitive tools | **Works.** Shown by Claude Duet on both brokers: pending, Jack approved, ran once. Approving every call was slow for simple jobs, so on the live broker only writes need approval now |
| D | Negative tests: prompt injection, stolen tokens, revoke speed, cross-agent isolation, logs | **Works with caveats.** The broker contains a fooled agent but can't prevent one; a stolen refresh token works until revoke; "duet" is any Claude on Jack's account |

**It can:**

- **Call APIs with keys agents never see.** No tool returns a secret, token or credential, error messages included. A redactor scrubs every secret it has handled from anything it sends out.
- **Give each agent its own tools.** The owner picks the agent when approving a connection. Each agent gets only its policy's tools, and other calls are refused and audited (Duet vs AnimaMesh, tested).
- **Hold a call until the owner approves it.** Sensitive tools return "pending" until Jack approves that exact call on the admin page, and it then runs once. Only the owner's password session can approve, never an agent's token or the admin token. Claude Duet did this end to end on the sandbox.
- **Contain a fooled agent.** Text from upstreams arrives marked untrusted. A call that tries to send out a credential (its own access token, a key) is refused, and writes wait for approval. A key embedded in upstream content is redacted.
- **Cut a connection off at once.** Revoke takes effect on the next call and the next refresh, including tokens minted seconds earlier; that needed a fix, see findings D3.
- **Rotate keys without a redeploy, and keep an audit trail.** The audit log records who called what and how it went, with no arguments, contents or tokens.
- **Hold a user's own sign-in for an upstream.** Jack signed in on Adobe's page; the broker stores the tokens encrypted and refreshes them, and its DA tools act as him through Adobe's hosted MCP server (findings A).

**It can't, or doesn't yet:**

- **Stop an agent from being fooled.** It limits what a fooled agent can do; it can't stop the agent from believing injected text.
- **Detect a stolen refresh token.** The thief and the real client can both refresh until the owner revokes; there's no reuse detection.
- **Get user-delegated access from a provider's developer console when it only issues service credentials.** Adobe's console gave Jack's org server-to-server only; the broker got in through Adobe's own MCP server instead, on a localhost redirect Adobe happens to allow (findings A).
- **Sign in with a username and password where the site forbids agents.** Best Buy's terms allow agents only through published methods, and there are none. Blocked, no attempt made (findings B).
- **Solve CAPTCHAs, get past bot checks, or answer MFA prompts.** It doesn't, by design.
- **Notify the owner of a pending approval, or approve in bulk.** Jack has to open the admin page for each call; one simple da.live job took three approvals. Email or push needs an account.
- **Limit an upstream token to less than the user's own rights.** Jack's Adobe token can write wherever he can; only the broker enforces the scratch folder.
- **Tell one Claude from another.** A connector added in claude.ai belongs to Jack's account, so every Claude on it that loads connectors (Duet, a normal chat, Claude Code) reaches the broker as the same agent. Confirmed 2026-11-12: a Claude Code session showed up as `duet`. Narrow tool lists, approval on writes and revoking when idle limit this; binding to one agent needs that agent to prove its identity (findings, section 0).
- **Hold two connections from one app.** A new consent from the same app (same client ID) replaces the earlier connection; the consent page warns before it does.
- **Tell people apart.** There is one owner. The OAuth client ID identifies the app (every Claude user presents the same published ID), not the person, and every connection is approved with the one owner password. Separate users with their own permissions, accounts and approvals would need per-person sign-in on the consent page (for example Google sign-in for an allow-list of emails). Not built.

| | Sandbox | Live |
|---|---|---|
| MCP server URL | `https://agent-secrets-broker-sandbox.jackzhaojin.workers.dev/mcp` | `https://agent-secrets-broker-live.jackzhaojin.workers.dev/mcp` |
| Admin | `.../admin` | `.../admin` (and `/connect/adobe`) |
| Secrets | KV vault, dummy values A to G | Cloudflare Worker secrets set by Jack (1Password variant kept, not deployed) |
| Tools | `whoami`, Mock Git tools | `whoami`, `da_list`, `da_get`, `da_put_draft` |
| Upstream | Mock Git (`agent-secrets-broker-mockgit.jackzhaojin.workers.dev`) | Adobe da.live through Adobe's hosted MCP server, one scratch folder |

Runtime: Cloudflare Workers (three Workers, six KV namespaces, Durable Objects for approvals and revocations).

## Connect an agent

### Claude (claude.ai, desktop, mobile and Claude Duet)

1. Get the sandbox owner password on the Mac that holds this repo: `npm run sandbox -- owner-password` (it reads the gitignored `.secrets/sandbox.json`). It is a dummy value, but keep it to yourself: anyone with it can approve a connection.
2. In claude.ai go to **Customize > Connectors** (`https://claude.ai/customize/connectors`; some app builds call it **Settings > Connectors**) and add a custom connector.
3. Name: `Agent Secrets Broker (sandbox)`. URL: `https://agent-secrets-broker-sandbox.jackzhaojin.workers.dev/mcp`
4. OAuth client: either option works. The broker supports both.
   - **Use Claude's published identity** (Claude's default, a Client ID Metadata Document). Claude's client ID is `https://claude.ai/oauth/mcp-oauth-client-metadata`, or its `/confidential_client` variant, which signs its token requests. The consent page will then say "Published by claude.ai". The scripted test runs this path end to end with the public document (M2), and the confidential one up to the signature only Claude can make (M3).
   - **Register automatically** (Dynamic Client Registration). The scripted test runs this path too, with the exact claude.ai callback URL (C1 to C7). If the first option fails, remove the connector and add it again with this one: Claude doesn't let you change auth settings after adding.
   - Leave client ID and secret empty.
5. Click **Connect**. A window opens on the broker's consent page. Check that access goes to `claude.ai`, keep agent **duet** selected (it is preselected for clients named Claude), type the owner password, and press **Approve**.
6. The connector shows as connected, with four tools: `whoami`, `mockgit_list_my_repos`, `mockgit_get_readme` and `mockgit_create_issue` (the last one needs your approval on every call).
7. Ask Duet (or any Claude chat with the connector on) to run acceptance tests 2 to 4:
   - "Call whoami on the Agent Secrets Broker." Expect agent `duet`, your client's name, the four tools, and `mockgit_create_issue` under approval_required.
   - "List my repos with the broker." Expect the 8 mock repos (`sandbox-alpha` to `sandbox-hotel`), each with only name, url and updated.
   - "Did any tool result contain an API key, token or password?" Expect no. (You can also check: the key values are in `.secrets/sandbox.json`; none should appear in the chat.)

To cut Duet off: open `/admin`, sign in with the owner password, and press **Revoke** on its row. Its next call fails with 401, and reconnecting needs your approval again.

### Any other MCP client

Point it at the MCP URL. It needs Streamable HTTP and OAuth 2.1 with PKCE (S256), and either Dynamic Client Registration or a Client ID Metadata Document. MCP Inspector and Claude Code work as is. Pick the agent it should be on the consent page; `inspector` exists for manual testing.

## How it works

```
 Agent (Duet / AnimaMesh / Claude Code)
        |  MCP over HTTPS + OAuth access token (15 min)
        v
 +---------------------------------------------+
 | agent-secrets-broker-sandbox (Worker)       |
 |  - OAuth 2.1 authorization server           |
 |    DCR, CIMD, PKCE S256, refresh rotation   |
 |  - Consent page: owner password + agent     |
 |  - Policy: agent -> allowed tools           |
 |  - Tools fetch the secret at call time      |
 |  - Audit log, redaction backstop            |
 +---------------------------------------------+
        |  read secret by reference (cached 5 min in memory)
        v
 Vault (KV namespace VAULT; 1Password for real secrets)
        |
        v  Service Binding, Authorization: Bearer <secret>
 agent-secrets-broker-mockgit (Worker): Mock Git API, a stand-in for GitHub
```

- **One Worker is both the OAuth authorization server and the MCP server**, using [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider) 1.2 and the MCP TypeScript SDK's web-standard Streamable HTTP transport (stateless, no Durable Objects).
- **Discovery follows the MCP authorization spec and Claude's connector docs:** an unauthenticated call gets `401` with `WWW-Authenticate: Bearer resource_metadata=".../.well-known/oauth-protected-resource/mcp", scope="broker"`. The protected resource metadata names the exact MCP URL. The authorization server metadata advertises S256, the registration endpoint, `client_id_metadata_document_supported: true` and the `none` auth method.
- **Each connection is bound to an agent.** The owner picks the agent on the consent page. The grant stores it (encrypted), and every MCP request builds a server with only that agent's tools. A call to any other tool is refused and audited as `denied`.
- **Tools are task-shaped.** There is no `get_secret`. `mockgit_list_my_repos` reads `mockgit/api_key` from the vault, calls the upstream, and returns only name, url and updated. If the upstream rejects the key, the tool drops its cached copy, re-reads the vault and retries once. That is why a rotation works with no redeploy.
- **The upstream is careless on purpose.** Its 401 echoes the key it was given, and its listing puts the key in `clone_url_with_token`. The broker never passes upstream bodies through and allow-lists the fields it returns. A redactor scrubs any known secret value from tool output as a last line of defense (it has never fired in the tests).
- **Audit:** one line per tool call, consent, revoke, policy change and failed sign-in: time, client, agent, tool, outcome, short code. No arguments, tokens or upstream data. Kept 30 days in KV, also written to Workers Logs.
- **Revoke:** the admin page or `npm run admin -- revoke <client_id>` revokes every grant of a client. Its access and refresh tokens stop working at once.

### Policy

[`policy.json`](policy.json) maps agents to tools:

| Agent | Tools | For |
|---|---|---|
| `duet` | `whoami`, `mockgit_list_my_repos`, `mockgit_get_readme`, `mockgit_create_issue` (approval) | Claude Duet through a claude.ai connector |
| `animamesh` | `whoami`, `mockgit_repo_stats` | AnimaMesh: counts only, nothing Duet has (isolation tests) |
| `inspector` | Duet's tools, with `mockgit_get_readme` also behind approval | MCP Inspector and scripted tests |

Tools marked `requiresApproval` in code (`mockgit_create_issue`) need the owner's approval on every call; a policy's `approval_required` can add more per agent. See "Per-call approval" below.

`policy.json` is bundled with each deploy. To change policy without a deploy, push an override (`npm run admin -- policy push edited.json`); `npm run admin -- policy reset` goes back to the file. A malformed override fails closed: no agent gets any tool.

### Per-call approval

A tool that needs approval answers its first call with `pending_approval`, an approval id and a link (`/admin/approvals/<id>`); nothing runs. The owner opens the link (signing in with the owner password returns to it), checks the arguments and presses **Approve once** or **Deny**. The agent then repeats the exact same call, which runs once. An approval is bound to the client, the agent, the tool and the exact arguments, lasts 15 minutes, and is single use; a denial stands for 15 minutes. Only the owner's password session can decide: an agent's OAuth token, the admin API token and the admin API itself cannot (the API lists approvals read-only). Approvals live in a Durable Object, so approve-then-run-once is atomic and takes effect at once. Notifications are the admin page only for now.

## Tests

`npm run test:e2e` (default `--target remote`) runs the whole flow against the deployed sandbox and writes [docs/test-log.md](docs/test-log.md). `--target local` runs it against `npm run dev`.

`npm run test:duet -- --since <ISO time>` reads Claude Duet's own calls on the sandbox from the audit log (the connection Jack added in claude.ai) and writes them to the "Claude Duet on the sandbox" section of the test log. Pick a window with no e2e run in it: the e2e's M2 check also connects as duet with the Claude app's client ID. Add `--live` for Duet's calls on the live broker (the da.live tools).

It acts as the agent's MCP client and as the owner:

- **Discovery**: the 401 challenge, both metadata documents, a made-up token refused.
- **Connect like the Claude app**: DCR with `https://claude.ai/api/mcp/auth_callback`, the consent page (wrong password refused, right password approved), the PKCE code exchange, code replay refused (which also revokes that code's tokens), then MCP initialize and tools/list with the official SDK client.
- **Acceptance tests 2 to 7** from the spec, against the deployed URL.
- **CIMD with Anthropic's real documents**: `https://claude.ai/oauth/claude-code-client-metadata` (Claude Code's published client ID, M1), and the Claude app's own `https://claude.ai/oauth/mcp-oauth-client-metadata` bound to `duet`, through token, refresh and both tools (M2). Its `/confidential_client` variant gets the consent page, and its code is refused without Claude's signed assertion (M3). Each CIMD check revokes only the grants it created, because a CIMD client ID is shared by every install of that app, Jack's own connector included.
- **A stock MCP SDK client** that discovers auth from the 401 by itself, the way MCP Inspector and Claude Code do.
- **No-leak sweep**: every response body and header (errors included), the audit log, and the Worker's own logs from `wrangler tail`, searched for all seven dummy values. A control check first proves the scan finds the values in the mock upstream's own careless responses.

## Run and deploy

Node 22 and a `wrangler login` to the Cloudflare account.

```bash
npm install
npm run sandbox -- init           # dummy secrets A-G in .secrets/sandbox.json (gitignored), plus .dev.vars
npm run dev                       # both Workers locally on :8787
npm run sandbox -- seed --local   # vault and mock upstream state for local
npm run test:e2e -- --target local
```

Deploy (the KV namespace IDs in the two `wrangler.jsonc` files belong to Jack's account; create your own with `npx wrangler kv namespace create <name>` and replace them):

```bash
npm run deploy                    # mock upstream, then the broker
npm run sandbox -- push           # OWNER_PASSWORD (D), ADMIN_TOKEN (E), COOKIE_SECRET (F) as Worker secrets
npm run sandbox -- seed --remote  # vault mockgit/api_key=A, canary/unused=G; upstream accepts A
npm run test:e2e                  # writes docs/test-log.md
npm run scan                      # before every push: dummy values, forbidden files, key shapes, gitleaks
```

Live broker (real secrets; Jack sets `OWNER_PASSWORD`, `ADOBE_OAUTH_CLIENT_ID` and `ADOBE_OAUTH_CLIENT_SECRET` himself, see [docs/live-setup.md](docs/live-setup.md)):

```bash
npm run deploy:live               # deploys wrangler.live.jsonc (secrets as Worker secrets)
npm run deploy:live:1password     # the 1Password variant instead: patches its SDK for workerd first
npm run live -- init-keys         # ADMIN_TOKEN, COOKIE_SECRET, TOKEN_ENC_KEY: random, never printed
npm run live -- status            # which secrets are set (names only)
npm run test:live                 # live checks + Duet's calls from the audit log; add -- --tail 300 while Duet runs
npm run admin -- --live audit     # the live audit log
```

Other sandbox commands: `npm run sandbox -- vault B --remote` (rotate the vault), `npm run sandbox -- upstream B --remote` (rotate what the upstream accepts), `npm run sandbox -- show` (labels and fingerprints). `npm run admin -- clients | audit | policy`.

## Security rules this follows

- No tool returns a secret, token or credential. There is no `get_secret` tool.
- Upstream bodies are never passed through. Tool output is allow-listed, then redacted.
- No request bodies, tokens or upstream responses in logs or the audit log.
- Access tokens last 15 minutes. Refresh tokens rotate on use and are revocable. PKCE S256 is required. Redirect URIs are matched exactly (loopback ports excepted, per RFC 8252).
- The consent page shows the client's name, whether it is verified (CIMD) or self-registered (DCR), where access goes, and a warning for localhost. It can't be framed, loads nothing external, and takes a single-use handle bound to the browser.
- Owner sign-in locks out an IP after 10 failures in 15 minutes.
- HTTPS only (Workers). Sandbox secrets are dummy values that never leave `.secrets/sandbox.json` and the Worker's secret store.

## Findings (spec section 8)

| Question | Answer |
|---|---|
| What OAuth does a Claude custom connector expect? | Callback `https://claude.ai/api/mcp/auth_callback`. Claude prefers a Client ID Metadata Document when the server advertises `client_id_metadata_document_supported` and the `none` auth method, else falls back to DCR. It needs a 401 with `resource_metadata`, a protected resource whose `resource` is the MCP URL as entered, PKCE S256, and a form-urlencoded token endpoint. Traffic comes from `160.79.104.0/21`, IPv4 only. Source: claude.com/docs/connectors/building/authentication. The docs don't name the Claude app's client ID; it is `https://claude.ai/oauth/mcp-oauth-client-metadata` (public, `none`), plus `.../confidential_client` (`private_key_jwt`, ES256, keys at `https://claude.ai/v1/mcp/jwks`) for servers that list `private_key_jwt`, as this one does. Both reach the consent page on the deployed broker, and the public one works end to end (M2, M3). |
| Can Duet add a connector itself? | Not by itself: connectors are added in claude.ai settings (Customize > Connectors). A connector added there was available in Claude Duet (2026-11-12): Duet ran acceptance tests 2 to 4 through it ([findings](docs/findings.md), section 0). |
| Does the 1Password JS SDK run in Workers? | Not as published (its WASM core is read with `fs.readFileSync` and compiled at runtime, which Workers forbid). **Yes with a build-time patch**: verified in workerd, where the core runs and reaches 1Password's sign-in endpoint. 4.1 MB gzipped, so Workers Paid. See [docs/1password.md](docs/1password.md) and [spikes/1password-workers](spikes/1password-workers). |
| Can Grok Bot, Muse or Dots use remote MCP? | Not checked (out of the baseline). |

## Phase 2

Done this phase:

- Per-call approval.
- Negative tests (prompt injection, stolen tokens, revoke speed, cross-agent isolation, logs), plus the fixes they drove.
- The live deployment (built on 1Password, now running on Worker secrets by Jack's choice).
- Adobe user-delegated OAuth with the DA tools.

Results and the blocked Best Buy experiment are in [docs/findings.md](docs/findings.md).

Still open:

- **The real-account runs:** Jack's setup, Adobe consent, and Duet calling the live tools.
- **From the original spec:** approval notifications, AnimaMesh as a client-credentials client, a metadata-only `secrets_inventory` tool, agent-to-agent grants, and a Grok Bot connector test.

## Layout

```
src/index.ts          sandbox entry: KV vault, Mock Git tools, policy.json
src/live.ts           live entry (Worker secrets); live-1password.ts is the 1Password variant; live-common.ts holds
                      what they share: DA tools, Adobe connect, daily refresh cron, policy.live.json
src/worker.ts         OAuthProvider wiring: routes, scopes, token lifetimes, CIMD, DCR, refresh revocation check
src/deployment.ts     what differs between the two deployments
src/app.ts            consent page, admin page and admin API, approvals pages, landing, healthz
src/mcp.ts            MCP endpoint: policy-filtered tools, approval gate, credential-in-arguments refusal, revocation check, redaction
src/tools/            core.ts (whoami), mockgit.ts (sandbox), da.ts (live, da.live scratch folder), types.ts
src/upstream/adobe.ts Adobe IMS user OAuth: /connect/adobe, token refresh, admin status
src/sealed.ts         AES-GCM for upstream tokens at rest
src/approvals.ts      per-call approval store (Durable Object)
src/revocations.ts    revocation list (Durable Object): revoke takes effect at once
src/secrets/          store.ts (SecretStore, KV vault, cache), worker-secrets.ts (live), onepassword.ts (kept)
src/policy.ts, policy.json, policy.live.json, src/audit.ts, src/auth.ts, src/redact.ts, src/html.ts
mock-upstream/        the Mock Git API Worker
scripts/              sandbox secrets, live keys, admin CLI, 1Password patch, secret scan
test/e2e.mjs          the sandbox acceptance and negative tests
test/live.mjs         checks against the live broker, and Duet's calls from its audit log
docs/                 findings, test log, live setup, 1Password notes
spikes/               1password-workers: the patched SDK running in workerd
```

MIT license.
