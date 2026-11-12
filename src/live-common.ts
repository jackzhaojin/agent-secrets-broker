import livePolicy from '../policy.live.json';
import { signInPage } from './app';
import { useDeployment } from './deployment';
import type { Env } from './env';
import type { SecretStore } from './secrets/store';
import { CORE_TOOLS } from './tools/core';
import { DA_TOOLS } from './tools/da';
import { adobeAdminSection, adobeKeepAlive, adobeRoutes, liveStatus } from './upstream/adobe';
import { handleFetch } from './worker';

/**
 * The live broker (agent-secrets-broker-live): real accounts, Jack's Adobe account for da.live.
 * Its two entry points differ only in where secrets are read from: src/live.ts (Worker secrets)
 * and src/live-1password.ts (1Password). Never deploy either with the sandbox's dummy secrets.
 */
export function liveWorker(store: { name: string; hint: string; make(env: Env): SecretStore }): ExportedHandler<Env> {
  useDeployment({
    name: 'live',
    tools: { ...CORE_TOOLS, ...DA_TOOLS },
    policy: livePolicy,
    secretStore: store.make,
    secretStoreName: store.name,
    secretStoreHint: store.hint,
    routes: (request, env, ctx) => adobeRoutes(request, env, ctx, signInPage),
    adminSections: adobeAdminSection,
    status: liveStatus,
  });
  return {
    fetch: handleFetch,
    async scheduled(_controller, env, ctx) {
      ctx.waitUntil(adobeKeepAlive(env));
    },
  };
}
