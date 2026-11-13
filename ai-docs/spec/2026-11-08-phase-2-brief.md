<!-- Jack's Phase 2 brief, as he gave it on 2026-11-08. Kept verbatim. Results are in docs/findings.md. -->

# Phase 2 brief

Phase 2 goal: push the boundaries with real accounts and document negatives as carefully as positives. A blocked experiment with a clear reason is a good result. Log each in docs/findings.md (works / works with caveats / blocked, and why).

Ground rules: real secrets never go in the sandbox. Stand up a separate agent-secrets-broker-live deployment backed by 1Password (read-only service account, one vault "Broker"). Jack enters every real password, token and OAuth consent himself, in 1Password or on the provider's own page; never type, print or commit one. Real-account tools are read-only this phase: no purchases, publishing or account changes.

A. Adobe da.live as Jack: research how da.live API calls authenticate (Adobe IMS), which Developer Console credential and scopes allow user-delegated OAuth, and how Jack's existing DA Live MCP server authenticates. Add /connect/adobe where Jack consents on Adobe's page; broker stores and refreshes the token. Tools da_list, da_get, and da_put_draft limited to a scratch folder Jack names, behind per-call approval. Record scope, consent and token-lifetime limits.

B. Best Buy username and password: Jack stores the login in 1Password. Tool bestbuy_recent_orders uses a server-side headless browser, returns a trimmed list. Expect bot checks, MFA codes, terms of use, and session cookies as secrets. Stop after two honest attempts if blocked and record why. Do not evade bot checks.

C. Per-call approval: sensitive tools return "pending" until Jack approves (admin page, email link or push).

D. Negative tests: prompt injection via upstream content, what a stolen connector token can do and how fast revoke cuts it off, cross-agent isolation, no full real-account responses in logs.

Done: findings.md covers A to D, every positive shown by Claude Duet calling the tool remotely and logged in test-log.md, and a "What the broker can and can't do" summary at the top of the README. Ask Jack before any account, billing or sign-in step.
