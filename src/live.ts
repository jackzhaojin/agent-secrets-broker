/**
 * Live entry point (agent-secrets-broker-live): real accounts, secrets in 1Password (vault
 * "Broker", read-only service account), Jack's Adobe account for da.live. Never deploy this with
 * the sandbox's dummy secrets, or the sandbox with real ones.
 */
import livePolicy from '../policy.live.json';
import { signInPage } from './app';
import { useDeployment } from './deployment';
import type { Env } from './env';
import { OnePasswordStore } from './secrets/onepassword';
import { CORE_TOOLS } from './tools/core';
import { DA_TOOLS } from './tools/da';
import { adobeAdminSection, adobeKeepAlive, adobeRoutes, liveStatus } from './upstream/adobe';
import { handleFetch } from './worker';

useDeployment({
  name: 'live',
  tools: { ...CORE_TOOLS, ...DA_TOOLS },
  policy: livePolicy,
  secretStore: (env) => new OnePasswordStore(env),
  routes: (request, env, ctx) => adobeRoutes(request, env, ctx, signInPage),
  adminSections: adobeAdminSection,
  status: liveStatus,
});

export { ApprovalStore } from './approvals';
export { RevocationList } from './revocations';

export default {
  fetch: handleFetch,
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(adobeKeepAlive(env));
  },
} satisfies ExportedHandler<Env>;
