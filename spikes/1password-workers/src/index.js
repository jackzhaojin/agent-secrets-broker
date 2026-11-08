// Proves the 1Password SDK's WASM core runs in workerd. Uses a malformed token on purpose, so the
// core rejects it locally (no request reaches 1Password). Run: npm install && npm run patch && npm run dev
import { createClient } from '@1password/sdk';

export default {
  async fetch() {
    const calls = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (input, init) => {
      calls.push(String(input));
      return realFetch(input, init);
    };
    try {
      await createClient({ auth: `not-a-token-${crypto.randomUUID()}`, integrationName: 'workers-spike', integrationVersion: '0.0.1' });
      return Response.json({ ok: true });
    } catch (e) {
      // Expected: "invalid user input: ... service account token had invalid format", from the Rust core.
      return Response.json({
        ok: false,
        error: String(e?.message ?? e).slice(0, 200),
        wasmInstantiated: globalThis.__opInstantiateMs != null,
        networkCalls: calls.length,
      });
    } finally {
      globalThis.fetch = realFetch;
    }
  },
};
