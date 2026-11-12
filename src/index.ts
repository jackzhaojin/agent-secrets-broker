/**
 * Sandbox entry point (agent-secrets-broker-sandbox): dummy secrets in a KV vault, Mock Git tools.
 * The handler and routes are in src/worker.ts; the live deployment's entry is src/live.ts.
 */
import sandboxPolicy from '../policy.json';
import { useDeployment } from './deployment';
import type { Env } from './env';
import { KvVault } from './secrets/store';
import { CORE_TOOLS } from './tools/core';
import { MOCKGIT_TOOLS } from './tools/mockgit';
import { handleFetch } from './worker';

useDeployment({
  name: 'sandbox',
  tools: { ...CORE_TOOLS, ...MOCKGIT_TOOLS },
  policy: sandboxPolicy,
  secretStore: (env) => new KvVault(env.VAULT),
  secretStoreName: 'kv-vault',
});

export { ApprovalStore } from './approvals';
export { RevocationList } from './revocations';

export default { fetch: handleFetch } satisfies ExportedHandler<Env>;
