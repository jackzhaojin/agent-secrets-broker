/**
 * Live entry point, secrets as Cloudflare Worker secrets (the current choice, see
 * src/secrets/worker-secrets.ts). To go back to 1Password, point "main" in wrangler.live.jsonc at
 * src/live-1password.ts and set OP_SERVICE_ACCOUNT_TOKEN.
 */
import { liveWorker } from './live-common';
import { WorkerSecretStore } from './secrets/worker-secrets';

export { ApprovalStore } from './approvals';
export { RevocationList } from './revocations';

export default liveWorker({
  name: 'worker-secrets',
  hint: 'Set the Worker secrets ADOBE_OAUTH_CLIENT_ID and ADOBE_OAUTH_CLIENT_SECRET with `wrangler secret put <NAME> -c wrangler.live.jsonc`.',
  make: (env) => new WorkerSecretStore(env),
});
