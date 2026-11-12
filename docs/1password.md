# 1Password on Workers

**Not in use right now.** On 2026-11-12 Jack moved the live broker to Cloudflare Worker secrets to get the Adobe experiment running ([findings.md](findings.md), A). The 1Password store and its entry point (`src/live-1password.ts`, `npm run deploy:live:1password`) are kept, and the open question below (a real service account) is still open.

The spec puts real secrets in a 1Password vault named `Broker`, read by a read-only service account. The sandbox uses a KV namespace (`VAULT`) behind the same `SecretStore` interface instead, because it holds dummy values only. This page records what it takes to swap in 1Password.

## Does the 1Password JS SDK run in Workers?

**Not as published, yes with a build-time patch.** Tested 2026-11-08 with `@1password/sdk` 0.5.0 and wrangler 4.158.0 (workerd, `nodejs_compat`).

The blocker: `@1password/sdk-core` is wasm-bindgen glue for Node. It reads `core_bg.wasm` with `fs.readFileSync` and compiles it with `new WebAssembly.Module(bytes)`. Workers forbid compiling WASM from bytes at runtime.

The fix, in [`spikes/1password-workers`](../spikes/1password-workers): [`scripts/patch-sdk-core.mjs`](../spikes/1password-workers/scripts/patch-sdk-core.mjs) generates an ESM copy of the glue that:

- imports `core_bg.wasm` at build time (wrangler ships it as a precompiled module) and keeps `new WebAssembly.Instance(...)`, which workerd allows
- uses the global `TextEncoder`/`TextDecoder` instead of `require('util')`
- re-exports the core's functions as ESM

`wrangler.jsonc` aliases `@1password/sdk-core` to the generated file. `--lazy` instantiates on the first call instead of at startup.

What was observed:

| Check | Result |
|---|---|
| WASM instantiates in workerd | Yes. `createClient` with a malformed token fails inside the Rust core ("service account token had invalid format") with no network call. |
| Reaches 1Password | Yes. During the spike, a fabricated token with the right field names got as far as `POST https://my.1password.com/api/v3/auth/start` from inside the Worker (500 for the fake identity, the same as stock Node). The published spike only runs the local check, so it never contacts 1Password. |
| Bundle size | 13.7 MB raw, 4.1 MB gzipped. Fits the Workers Paid limit (10 MB compressed, which this account has), not the Free limit (3 MB). |
| Startup | About 20 ms in local `wrangler check startup`, which may not include compiling the 14 MB module. Measure on a real deploy. |
| Node APIs at runtime | `os.arch()` and `os.type()` on every `createClient` (fine under `nodejs_compat`). Desktop-app auth needs `fs` and `process.dlopen` and would fail, but service accounts never use it. No sync XHR, threads or SharedArrayBuffer. |

Not tested: a real service account token (the POC uses dummy secrets only), production startup time, and 1Password's rate limits.

## Wiring it in (Phase 2, real secrets)

A separate deployment without `-sandbox`, so real secrets never share a Worker with the test fixtures:

1. In 1Password: a vault `Broker`, one item per upstream key, and a service account with read access to that vault only, with an expiry date.
2. `OP_SERVICE_ACCOUNT_TOKEN` as a Worker secret (`wrangler secret put`, typed by Jack, never in a file in the repo).
3. A `OnePasswordStore implements SecretStore` in `src/secrets/`: create the client once per isolate (each `createClient` is a full sign-in), then `client.secrets.resolve('op://Broker/<item>/<field>')`. Keep the existing 5-minute cache and the drop-and-retry on an upstream 401, which is what makes rotation work without a redeploy.
4. The patch script and alias from the spike, run as a `prebuild` step so a reinstall can't ship the unpatched glue.
5. Rate limits: service account reads on the Individual plan are reported at around 1,000 a day. With a 5-minute cache per isolate that is plenty for a few agents, but check the account's actual limit first.

Fallbacks if the patched SDK proves fragile: a small Node sidecar that runs the stock SDK and answers the Worker over a Service Binding or mTLS, or 1Password Connect.
