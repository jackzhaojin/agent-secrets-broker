# Live broker: setup Jack does himself

The live broker (`agent-secrets-broker-live`) holds real credentials, so every password, token and consent below is entered by Jack, in 1Password or on the provider's own page. Claude never types, prints or stores one. The sandbox keeps dummy secrets only.

Live URL: `https://agent-secrets-broker-live.jackzhaojin.workers.dev` (MCP at `/mcp`, admin at `/admin`).

## 1. 1Password (vault and read-only service account)

1. In 1Password, create a vault named **Broker**.
2. Create a **service account** (1Password.com > Developer > Service Accounts) with **read** access to **Broker** only, no other vaults, and an **expiry** (90 days suggested). Copy its token when 1Password shows it (it's shown once).
3. In a terminal in this repo, store the token as a Worker secret. Paste it at the prompt; it isn't echoed or saved anywhere else:
   ```bash
   npx wrangler secret put OP_SERVICE_ACCOUNT_TOKEN -c wrangler.live.jsonc
   ```
4. Choose the live broker's **owner password** (it approves connections and tool calls; keep it in your own 1Password vault, not Broker) and set it the same way:
   ```bash
   npx wrangler secret put OWNER_PASSWORD -c wrangler.live.jsonc
   ```

The broker's internal keys (`ADMIN_TOKEN`, `COOKIE_SECRET`, `TOKEN_ENC_KEY`) are random values that `npm run live -- init-keys` pipes straight into `wrangler secret bulk` without printing them. It keeps only `ADMIN_TOKEN` in the gitignored `.secrets/live.json`, so the scripts can read the live audit log. The admin token can't approve tool calls or connections: those need the owner password.

## 2. Adobe (da.live as Jack): OAuth Web App credential

1. Sign in at https://developer.adobe.com/console in the org that has your existing da.live server-to-server project, and create a project named `Agent Secrets Broker (live)`.
2. Add an API that offers **User Authentication > OAuth Web App** and lists the scopes `openid`, `AdobeID`, `read_organizations` and `offline_access` (try the AEM / Edge Delivery entries first). If none offers OAuth Web App with `offline_access`, stop and tell Claude which credential types and scopes you see: that's a finding.
3. Credential type **OAuth Web App**:
   - Default redirect URI: `https://agent-secrets-broker-live.jackzhaojin.workers.dev/connect/adobe/callback`
   - Redirect URI pattern: `https://agent-secrets-broker-live\.jackzhaojin\.workers\.dev/connect/adobe/callback`
4. In the 1Password vault **Broker**, create an item named **adobe-oauth** with two fields: `client_id` and `client_secret` (copy both from the credential page).
5. Tell Claude the **scratch folder** for the agent: `org/site/folder` on da.live (for example `jackzhaojin/my-site/agent-scratch`). The tools can only list, read and write inside it. Check that your Adobe user can write there (the DA permissions sheet, if the org has one).
6. Once Claude has deployed with that folder: open `https://agent-secrets-broker-live.jackzhaojin.workers.dev/connect/adobe`, sign in with the owner password, and consent on Adobe's page. The admin page then shows who is connected and when the tokens expire.

## 3. Connect Claude to the live broker

claude.ai > Customize > Connectors > add a custom connector named `Agent Secrets Broker (live)` with URL `https://agent-secrets-broker-live.jackzhaojin.workers.dev/mcp`, approve as **duet** with the live owner password. Keep the sandbox connector too (acceptance test 1 on the sandbox is still open).

## 4. Best Buy: not set up (blocked by terms)

Best Buy's terms (updated 2026-09-25) allow AI agents only through Best Buy's "expressly authorized or published methods", and none is published. They also ban robots and intelligent agents and sharing account credentials, and sign-in sits behind Akamai bot management. See docs/findings.md, B. Don't put the Best Buy login in 1Password unless you decide to override that finding.

## Decisions for Jack

- **da_list and da_get behind approval too?** Default: yes, all three DA tools need your approval on each call (the literal reading of the brief). `da_put_draft` always does, whatever the policy says.
- **da_put_draft writes a draft into the scratch folder** (never preview or publish). It is the one write in an otherwise read-only phase. OK?
- **Approval notifications:** the admin page only for now. Email needs Email Routing on one of your zones, and push needs a service account (ntfy, Pushover). Want either?
- **Best Buy:** recorded as blocked by terms, no attempt made. Override only if you accept the account risk.
