# Phase 2 findings

Phase 2 pushes the broker against real accounts and records the negatives as carefully as the positives. Each experiment gets a verdict:

- **Works**: shown end to end.
- **Works with caveats**: works, with limits worth knowing.
- **Blocked**: can't be done, or shouldn't be, and why.
- **Pending**: built, but waiting on a step only Jack can take (an account, a password, a consent).

The sandbox (`agent-secrets-broker-sandbox`, dummy secrets) carries the mechanism tests. The live broker (`agent-secrets-broker-live`, 1Password, real accounts) carries the real-account ones. Test evidence is in [test-log.md](test-log.md): the sandbox run is IDs P1 to L3, the live checks are under "Live broker" (LV1 to LV8).

Last updated 2026-11-08.

## Summary

| | Experiment | Verdict | Evidence |
|---|---|---|---|
| A | da.live as Jack (Adobe IMS, user-delegated OAuth) | **Pending** (built and deployed; waiting on Jack's 1Password, Adobe credential and consent) | Research below; live checks LV1 to LV7 |
| B | Best Buy recent orders with Jack's username and password | **Blocked by terms of use** (no attempt made) | Best Buy Terms, "Digital Agents" section, updated 2026-09-25 |
| C | Per-call approval for sensitive tools | **Works** on the sandbox; Duet's handling of "pending" not yet seen | AP1 to AP6 |
| D1 | Prompt injection via upstream content | **Works with caveats**: the broker contains it, it can't prevent it | N1, N2 |
| D2 | What a stolen connector token can do | **Works with caveats**: its own agent's tools until it expires (15 min) or is revoked | N3, N4 |
| D3 | How fast revoke cuts a token off | **Works, after a fix**: was eventually consistent and could miss a fresh grant; now immediate | N4, T6; run 2026-11-08T22:17:40Z before the fix |
| D4 | Cross-agent isolation | **Works** | I1, T5, AP4, LV3 |
| D5 | No secrets or full real-account responses in logs | **Works** on the sandbox; **pending** on live until Duet's calls are captured | L1 to L3, LV7; LV8 needs Duet |

## A. Adobe da.live as Jack

**Verdict: pending.** Everything up to Jack's consent is built and deployed on the live broker. The remaining steps are his: the 1Password service account, an Adobe Developer Console credential, the scratch folder name, and consent on Adobe's page. See [live-setup.md](live-setup.md).

### How da.live calls authenticate

- **The token:** `admin.da.live` takes `Authorization: Bearer <Adobe IMS access token>`. da-admin ([src/utils/auth.js](https://github.com/adobe/da-admin/blob/main/src/utils/auth.js)) checks the JWT signature against IMS's published keys. It checks no audience, issuer or client ID.
- **The profile lookup:** da-admin then calls `/ims/profile/v1` and `/ims/organizations/v5` with the same token. If either fails the caller is anonymous, and anonymous gets 401. So any valid IMS *user* access token works if its scopes cover those calls: `openid`, `AdobeID`, `read_organizations` (inferred from the code).
- **Permissions:** an org can restrict paths in its permissions sheet. Without one, any signed-in user can read and write.
- **Jack's existing DA Live MCP server** (`azure-da-mcp`) has used OAuth Server-to-Server since 2026-05-16: `client_credentials` with a Developer Console client. Writes appear as a `@techacct.adobe.com` technical account, which had to be added to the permissions sheet. Its fallback is a user token from `da-auth-helper` (da.live's own `darkalley` client, implicit flow, 24 h, no refresh). The S2S path already shows that da-admin accepts tokens from clients other than `darkalley`.

### What the broker does

- **Credential:** an OAuth Web App credential, which is a confidential client. The secret is sent as HTTP Basic at `/ims/token/v3`.
- **Consent:** the owner starts it at `/connect/adobe` (owner-password session). The flow uses PKCE and a `state` bound to the browser by a cookie. Jack consents on Adobe's page, and the callback exchanges the code.
- **Where things live:**
  - The client ID and secret are read from 1Password: `op://Broker/adobe-oauth/client_id` and `.../client_secret`.
  - The tokens are kept AES-GCM-encrypted in KV under a Worker-secret key.
  - Every token value is added to the redactor's set, so it can't reach a tool result or tool arguments.
- **Scopes requested:** `openid, AdobeID, read_organizations, offline_access, additional_info.projectedProductContext`.
- **Refresh:** within 10 minutes of expiry. A daily cron also refreshes if the last refresh is 3 days old, because Adobe expires an unused refresh token after 14 days.
- **Tools** (live policy, agent `duet`):
  - `da_list` and `da_get` are read-only and behind approval on every call, by policy.
  - `da_put_draft` always needs approval, whatever the policy says. It saves a draft only: never preview or publish, which are separate `admin.hlx.page` calls. It sends `x-da-initiator: mcp`, so da.live's version history shows an agent wrote it.
- **Path rules:** every path must sit inside the scratch folder Jack names (`DA_SCRATCH`). Segments are lowercase letters, digits and hyphens only, so `..`, hidden folders and `.da` config are impossible. Documents must end in `.html`.
- **Untrusted content:** `da_get` returns the HTML marked `untrusted_content`.

### Limits to record once Jack has connected

| Limit | Expected (from docs) | Measured |
|---|---|---|
| Credential type available to a personal or org Adobe ID | OAuth Web App, if an API in the console offers user auth with `offline_access` ("Not all APIs and Services support `offline_access`") | pending |
| Consent screen | Adobe's own page; company/school accounts may need "an Adobe review" for apps outside Development | pending |
| Access token lifetime | 24 h | pending (shown on /admin and LV5) |
| Refresh token lifetime | 14 days by default; an Adobe forum answer says the same refresh token comes back for 7 days, then a new one | pending (`refresh_token_changes` counter on /admin) |
| da-admin accepts the custom client's token | yes per the code (no client check) | pending. da-admin caches the profile by user until the token expires, so test at least 24 h after Jack's last da.live browser session |

### Risks

- **Jack's token is broader than the folder.** It carries all of his DA write rights, so only the broker enforces the scratch folder. A tighter design: an S2S technical account with write access to the scratch path alone in the permissions sheet, at the cost of losing Jack as the author.
- **Adobe could add a client check.** If da-admin starts checking audience or client, user-delegated OAuth with a custom client is blocked. The fallbacks are `darkalley` (manual, every 24 h) or S2S.

## B. Best Buy username and password

**Verdict: blocked by terms of use, before any technical attempt.** No credential was stored, no headless browser was started, and Best Buy's sign-in page was never requested.

- **The terms:** [Best Buy Terms and Conditions](https://www.bestbuy.com/site/help-topics/terms-and-conditions/pcmcat204400050067.c?id=pcmcat204400050067), last updated 2026-09-25.
  - **Digital Agents section:** an agent acting for a customer may use Best Buy only through Best Buy's "expressly authorized or published methods", within rate limits. It must identify itself in every request, must not mimic human typing or navigation, and must not solve or bypass CAPTCHAs. Best Buy publishes no such method; the Digital Agent Access Policy it refers to isn't public.
  - **Security section:** bans robots and "intelligent agents" except Best Buy's own search and ordinary browsers.
  - **Credentials:** a customer may not share account credentials.
- **Bot checks (inferred):** bestbuy.com is served through Akamai (edgekey.net), which a third-party tracker lists as Akamai Bot Manager.
  - Cloudflare's server-side browser (Browser Run, formerly Browser Rendering) adds headers that can't be removed and a Web Bot Auth signature. Cloudflare scores it as a bot, and it runs from datacenter IPs.
  - A challenge is likely. Under the rule "do not evade bot checks", that ends the attempt.
- **MFA:** Best Buy's 2-Step Verification is optional (SMS or an authenticator app, with a trusted-device cookie). If Jack has it on, a broker can't complete sign-in without a code from him on every new session.
- **Session cookies as secrets:** the session cookies would be credentials too, and the broker would have to hold them. Not built.
- **Official alternatives:**
  - developer.bestbuy.com is catalog only: no customer OAuth and no orders.
  - A privacy access request (bestbuy.com/ccpa, the Privacy Hub) returns "commercial information" including purchases, twice a year, after a median of about 40 days.
  - Order confirmation emails are the practical source (inferred).

**Recommendation:** leave B blocked. Revisit if Best Buy publishes its Digital Agent Access Policy or an authorized method. An email-based order tool would be the realistic route.

## C. Per-call approval

**Verdict: works** on the sandbox: AP1 to AP6 on the deployed URL. Duet's side (does it wait, then repeat the exact call?) is not yet observed.

- **The flow:** a gated call returns `pending_approval` with an approval ID and a link (`/admin/approvals/<id>`), and nothing runs. Jack opens the link (sign-in returns to it), checks the arguments and presses Approve once or Deny. The agent repeats the exact call, which runs once.
- **Binding:** an approval covers one client, one agent, one tool and a hash of the exact arguments, and it is single use (AP3, AP4). A changed argument needs a new approval, and so does another client sending the same arguments.
- **Timing:** pending requests and unused approvals expire after 15 minutes. A denial stands for 15 minutes, and retries are refused (AP5).
- **Who can approve:** only the owner's password session can decide (AP2). The admin API lists approvals read-only. An agent's OAuth token and the admin token get 403. This is deliberate: the admin token lives in a file on Jack's Mac, where an agent could read it.
- **Policy control:** a policy can put a read tool behind approval for one agent (AP6). On live, all three DA tools need approval.
- **Atomicity:** approvals live in a Durable Object, so approve-then-run-once is atomic and immediate. KV would serve a stale "pending" for up to a minute and can't enforce single use.

Caveats:

- **No notification yet.** Approval happens on the admin page, and Jack has to look. Email needs Email Routing on one of his zones; push needs a service account (ntfy, Pushover). Not set up (an account step).
- **The agent has to retry.** That relies on the agent following the `next` instruction in the pending result. MCP elicitation wasn't used: the agent's own client answers it, so it isn't an out-of-band check by the owner.

## D. Negative tests

### D1. Prompt injection via upstream content

**Verdict: works with caveats.** The broker can't stop an agent from reading and believing injected text. It can limit what a fooled agent can do. The sandbox's Mock Git README for `sandbox-charlie` tells agents to put their API key and access token in a new issue (N1):

- The text reaches the agent marked `untrusted_content: true`, with a note to treat it as data (`mockgit_get_readme`, and `da_get` on live). The server instructions say the same.
- A write that carries the caller's access token, any broker-token shape, or any secret the broker holds is refused (`credential_in_arguments`), audited, and never reaches the upstream. **This check was added because of this test:** without it, a fooled agent could post its own MCP token into an issue body.
- The write the injection asks for (`mockgit_create_issue`) waits for Jack's approval. The approval page shows the arguments and warns that an agent can be tricked by text it read.
- A key embedded in upstream content (`sandbox-delta`'s README carries the Mock Git key) is redacted to `[REDACTED]` before the agent sees it, and audited (N2). The README's `download_url`, which also carries the key, is never passed on.

Not yet tested: whether Duet itself follows the injection. Ask Duet to read `sandbox-charlie`'s README and see what it attempts (the audit log records it).

### D2. What a stolen connector token can do

**Verdict: works with caveats.**

- **A stolen access token** (N3) can call its own agent's tools until it expires (15 minutes) or is revoked. Writes still wait for Jack.
  - It cannot use the admin API (401), list approvals (401), revoke (403) or approve (403).
  - It cannot see the admin page or call another agent's tools.
  - A sandbox token doesn't work on the live broker (LV3).
- **A stolen refresh token** (N4) can mint new access tokens until Jack revokes. Refreshing under another `client_id` is refused.
  - **There's no reuse detection.** After the thief refreshes, the real client's refresh with the same old token still works: the library keeps the previous refresh token valid until the newer one is used. Neither side is cut off, and nothing alerts Jack.
  - Only revoke stops it. The audit log shows every call with client and agent.

### D3. How fast revoke cuts a token off

**Verdict: works, after a fix.** Found and fixed in this phase:

- **Before the fix:** the OAuth library validates an access token by reading only that token's record. It revokes by listing a grant's tokens in KV, and KV listings lag up to about a minute. On the deployed sandbox, a revoke seconds after a connection was made revoked **0 grants** (run 2026-11-08T22:17:40Z, response `revoked_grants: 0`).
- **What that meant:** a fresh connection's tokens would have kept working, the access token until it expired and the refresh token until a later revoke found it (from the code; not run to completion).
- **The fix:** the broker keeps its own revocation list in a Durable Object (strongly consistent). Revoke writes to it first, and every MCP call and every refresh is checked against it, by grant ID and by client plus consent time. A later consent still works, which matters for client IDs shared by every user of an app, like claude.ai's.
- **After the fix:** the thief's newest access token got 401 within 0 s and its refresh token `invalid_grant` (N4); a revoked connection's token got 401 after 0 s (T6).

### D4. Cross-agent isolation

**Verdict: works.**

- AnimaMesh's connection lists and calls only `whoami` and `mockgit_repo_stats`. Its calls to Duet's tools, and Duet's calls to AnimaMesh's tool, are refused and audited `not_in_policy` (I1).
- Removing a tool from a policy takes effect on the next call (T5).
- An approval given to one client doesn't let another client run the same call (AP4).
- Sandbox and live are separate deployments with separate OAuth state (LV3).

### D5. No secrets or full real-account responses in logs

**Verdict: works on the sandbox; pending on live until Duet's calls are captured.**

- **Sandbox:** every response body and header, the audit log, and the Worker logs (`wrangler tail`) are searched for all seven dummy secrets: 0 hits (L1 to L3). Each README carries a marker line that may reach the agent but must never reach a log; it never does (L2, L3).
- **Live:** the audit log holds only structured fields (time, type, outcome, client, agent, tool, code, approval ID, duration), with no JWT-shaped strings (Adobe tokens are JWTs) and no HTML (LV7).
  - `npm run test:live -- --tail 300` captures the Worker logs while Duet runs its tests and searches them the same way (LV8, pending).
- **Code rules:**
  - The broker logs codes, never upstream bodies, IMS error descriptions or SDK messages.
  - The 1Password store logs only the error name.

## Other findings along the way

- **The Claude app's client ID.** It is `https://claude.ai/oauth/mcp-oauth-client-metadata`, plus `.../confidential_client`, which signs with `private_key_jwt` (ES256). Claude's docs don't name it. Both reach the consent page; the public one works end to end (M2, M3).
- **workers.dev blocks Python's default user agent.** Cloudflare answers `Python-urllib` with error 1010 (403) before the Worker runs. Use another client or set a user agent in ad hoc probes.
- **KV listings lag.** Besides revoke, the audit log (a KV listing) can take seconds to show a new line, so tests poll it.
- **The 1Password SDK on Workers** needs the build-time patch from the spike. The live bundle is 4.4 MB gzipped (Workers Paid), with a 39 ms startup. The WASM core is instantiated on the first secret read.
