# Agent Secrets Broker

A small service that holds secrets and makes API calls on behalf of AI agents. Agents connect to it as a remote MCP server, sign in with OAuth, and can call only the tools their policy allows. No tool ever returns a secret.

The test it is built to pass: *Claude Duet asks the broker to do something that needs an API key, gets the result back, and the key never appears anywhere Duet can see.*

**Status: proof of concept, sandbox only.** The deployed sandbox holds dummy test secrets (`TEST_SECRET_A` to `G` style values) and calls a mock upstream API that it hosts itself. All acceptance tests pass against the deployed URL; see [docs/test-log.md](docs/test-log.md).

| | |
|---|---|
| MCP server URL | `https://agent-secrets-broker-sandbox.jackzhaojin.workers.dev/mcp` |
| Admin | `https://agent-secrets-broker-sandbox.jackzhaojin.workers.dev/admin` |
| Mock upstream | `https://agent-secrets-broker-mockgit.jackzhaojin.workers.dev` |
| Runtime | Cloudflare Workers (two Workers, four KV namespaces) |

## Connect an agent

### Claude (claude.ai, desktop, mobile, and Duet if it shares claude.ai connectors)

1. Get the sandbox owner password on the Mac that holds this repo: `npm run sandbox -- owner-password` (it reads the gitignored `.secrets/sandbox.json`). It is a dummy value, but keep it to yourself: anyone with it can approve a connection.
2. In claude.ai go to **Customize > Connectors** (`https://claude.ai/customize/connectors`; some app builds call it **Settings > Connectors**) and add a custom connector.
3. Name: `Agent Secrets Broker (sandbox)`. URL: `https://agent-secrets-broker-sandbox.jackzhaojin.workers.dev/mcp`
4. OAuth client: either option works. The broker supports both.
   - **Use Claude's published identity** (Claude's default, a Client ID Metadata Document). Claude's client ID is `https://claude.ai/oauth/mcp-oauth-client-metadata`, or its `/confidential_client` variant, which signs its token requests. The consent page will then say "Published by claude.ai". The scripted test runs this path end to end with the public document (M2), and the confidential one up to the signature only Claude can make (M3).
   - **Register automatically** (Dynamic Client Registration). The scripted test runs this path too, with the exact claude.ai callback URL (C1 to C7). If the first option fails, remove the connector and add it again with this one: Claude doesn't let you change auth settings after adding.
   - Leave client ID and secret empty.
5. Click **Connect**. A window opens on the broker's consent page. Check that access goes to `claude.ai`, keep agent **duet** selected (it is preselected for clients named Claude), type the owner password, and press **Approve**.
6. The connector shows as connected, with two tools: `whoami` and `mockgit_list_my_repos`.
7. Ask Duet (or any Claude chat with the connector on) to run acceptance tests 2 to 4:
   - "Call whoami on the Agent Secrets Broker." Expect agent `duet`, your client's name, and the two tools.
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
| `duet` | `whoami`, `mockgit_list_my_repos` | Claude Duet through a claude.ai connector |
| `animamesh` | `whoami` | AnimaMesh (Phase 2 gives it its own client) |
| `inspector` | `whoami`, `mockgit_list_my_repos` | MCP Inspector and scripted tests |

`policy.json` is bundled with each deploy. To change policy without a deploy, push an override (`npm run admin -- policy push edited.json`); `npm run admin -- policy reset` goes back to the file. A malformed override fails closed: no agent gets any tool.

## Tests

`npm run test:e2e` (default `--target remote`) runs the whole flow against the deployed sandbox and writes [docs/test-log.md](docs/test-log.md). `--target local` runs it against `npm run dev`.

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
| Can Duet add a connector itself? | Not verified. Connectors are added in the Claude app's settings; whether Duet sees claude.ai connectors needs Jack's check in step 7 above. |
| Does the 1Password JS SDK run in Workers? | Not as published (its WASM core is read with `fs.readFileSync` and compiled at runtime, which Workers forbid). **Yes with a build-time patch**: verified in workerd, where the core runs and reaches 1Password's sign-in endpoint. 4.1 MB gzipped, so Workers Paid. See [docs/1password.md](docs/1password.md) and [spikes/1password-workers](spikes/1password-workers). |
| Can Grok Bot, Muse or Dots use remote MCP? | Not checked (out of the baseline). |

## Phase 2

From the spec: AnimaMesh as its own OAuth client (client credentials), upstream OAuth refresh tokens held by the broker, per-call approval for sensitive tools, key notes and a metadata-only `secrets_inventory` tool, agent-to-agent grants, and a Grok Bot connector test. Real secrets get their own deployment (a Worker without `-sandbox`) backed by 1Password.

## Layout

```
src/index.ts          OAuthProvider wiring: routes, scopes, token lifetimes, CIMD, DCR
src/app.ts            consent page, admin page and admin API, landing, healthz
src/mcp.ts            MCP endpoint: policy-filtered tools, denied-call audit, redaction
src/tools/index.ts    whoami, mockgit_list_my_repos
src/secrets/store.ts  SecretStore interface, KV vault, in-memory cache
src/policy.ts, policy.json, src/audit.ts, src/auth.ts, src/redact.ts, src/html.ts
mock-upstream/        the Mock Git API Worker
scripts/              sandbox secrets, admin CLI, secret scan
test/e2e.mjs          the acceptance test
docs/                 test log, 1Password notes
spikes/               1password-workers: the patched SDK running in workerd
```

MIT license.
