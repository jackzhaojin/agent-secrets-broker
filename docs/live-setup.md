# Live broker: setup Jack does himself

The live broker (`agent-secrets-broker-live`) holds real credentials, so every password, key and consent below is entered by Jack, at a `wrangler secret put` prompt or on the provider's own page. Claude never types, prints or stores one. The sandbox keeps dummy secrets only.

Live URL: `https://agent-secrets-broker-live.jackzhaojin.workers.dev` (MCP at `/mcp`, admin at `/admin`).

> **Changed (2026-11-13).** Step 2 below (an Adobe Developer Console credential) can't be done: the console offers only server-to-server credentials. The broker now signs in through Adobe's hosted DA MCP server instead, and Jack is connected. To reconnect: on the Mac with the repo run `npm run live -- adobe-connect` (it listens on localhost:8976 for Adobe's redirect and opens `/connect/adobe`), sign in with the owner password, then on Adobe's page. To register the broker with Adobe again: `node scripts/adobe-register.mjs --redirect http://localhost:8976/callback`. See [findings.md](findings.md), A.

**Secrets are Cloudflare Worker secrets for now, not 1Password** (Jack's call, 2026-11-12, to get the Adobe experiment running). There's no vault and no service account to set up. The 1Password variant is still in the repo; see the end of this page.

## 1. Owner password

Choose the live broker's owner password (it approves connections and tool calls; keep it in your own password manager) and set it. Paste at the prompt; it isn't echoed or saved anywhere else:

```bash
npx wrangler secret put OWNER_PASSWORD -c wrangler.live.jsonc
```

## 2. Adobe (da.live as Jack): OAuth Web App credential

1. Sign in at https://developer.adobe.com/console in the org that has your existing da.live server-to-server project, and create a project named `Agent Secrets Broker (live)`.
2. Add an API that offers **User Authentication > OAuth Web App** and lists the scopes `openid`, `AdobeID`, `read_organizations` and `offline_access` (try the AEM / Edge Delivery entries first). If none offers OAuth Web App with `offline_access`, stop and tell Claude which credential types and scopes you see: that's a finding.
3. Credential type **OAuth Web App**:
   - Default redirect URI: `https://agent-secrets-broker-live.jackzhaojin.workers.dev/connect/adobe/callback`
   - Redirect URI pattern: `https://agent-secrets-broker-live\.jackzhaojin\.workers\.dev/connect/adobe/callback`
4. Set the credential's client ID and client secret as Worker secrets, pasting each at its prompt:
   ```bash
   npx wrangler secret put ADOBE_OAUTH_CLIENT_ID -c wrangler.live.jsonc
   ```
   ```bash
   npx wrangler secret put ADOBE_OAUTH_CLIENT_SECRET -c wrangler.live.jsonc
   ```

## 3. Scratch folder

**Set (2026-11-12): `jackzhaojin/www-eds/drafts/sites-ai-webinar`**, from the preview URL Jack gave (`https://main--www-eds--jackzhaojin.aem.page/drafts/sites-ai-webinar/`). The tools can only list, read and write inside it.

That folder is not empty: it holds the "Sites and AI" webinar page (`index.html`). `da_put_draft` can replace a document there, with your approval on each call; the approval page shows the path and the start of the new HTML, so check the path before approving. Nothing is previewed or published. To keep the agent away from real pages, name an empty folder instead (for example `jackzhaojin/www-eds/drafts/agent-scratch`) and Claude redeploys with it.

Check that your Adobe user can write there (the DA permissions sheet, if the org has one).

Check progress any time (names only, no values):

```bash
npm run live -- status
```

## 4. Consent on Adobe's page

Open `https://agent-secrets-broker-live.jackzhaojin.workers.dev/connect/adobe`, sign in with the owner password, and consent on Adobe's page. The admin page then shows who is connected and when the tokens expire.

### Check who is signed in, or refresh now

```bash
npm run admin -- --live status
```

shows the Adobe connection: scopes, expiry, how many refreshes, and which fields Adobe sent. It prints names and shapes only; the Adobe user ID appears masked (`<24 chars>@AdobeID`). The full ID is on the `/admin` page.

Adobe only says who signed in after the first refresh ([findings](findings.md#who-signed-in-what-adobe-tells-the-broker)), so right after a new sign-in the admin page shows "unknown". The broker refreshes by itself about once a day. To do it now:

```bash
npm run admin -- --live adobe-refresh
```

Signing in again replaces the stored tokens without revoking the earlier refresh token at Adobe. Use "Disconnect Adobe" on `/admin` first if you want the old one revoked.

## 5. Connect Claude to the live broker

claude.ai > Customize > Connectors > add a custom connector named `Agent Secrets Broker (live)` with URL `https://agent-secrets-broker-live.jackzhaojin.workers.dev/mcp`, and approve as **duet** with the live owner password. The connector belongs to your Claude account, so every Claude on it that loads connectors can use it.

## Best Buy: not set up (blocked by terms)

Best Buy's terms (updated 2026-09-25) allow AI agents only through Best Buy's "expressly authorized or published methods", and none is published. See docs/findings.md, B.

## Decisions (defaults in force unless Jack says otherwise)

- **Approval on writes only (changed 2026-11-13):** `da_list` and `da_get` run without approval; `da_put_draft` needs approval on every call, whatever the policy says. Duet's first run had all three behind approval, which took three approvals for one small job.
- **da_put_draft writes a draft into the scratch folder** (never preview or publish). It is the one write in an otherwise read-only phase.
- **Approval notifications:** the admin page only.
- **Best Buy:** recorded as blocked by terms, no attempt made.

## Going back to 1Password later

The 1Password store and its entry point (`src/live-1password.ts`) are kept. To switch: create the vault **Broker** with an item **adobe-oauth** (fields `client_id`, `client_secret`) and a read-only service account with an expiry, set `OP_SERVICE_ACCOUNT_TOKEN` with `wrangler secret put`, and deploy with `npm run deploy:live:1password`. Whether the 1Password SDK works on Workers with a real service account is still untested ([1password.md](1password.md)).
