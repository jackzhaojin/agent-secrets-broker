/**
 * Live entry point, secrets in 1Password (vault "Broker", read-only service account). Not deployed
 * at the moment: the live broker runs src/live.ts. This bundle carries the patched 1Password SDK
 * (4.4 MB gzipped, scripts/patch-1password.mjs, docs/1password.md).
 */
import { liveWorker } from './live-common';
import { OnePasswordStore } from './secrets/onepassword';

export { ApprovalStore } from './approvals';
export { RevocationList } from './revocations';

export default liveWorker({
  name: '1password',
  hint: 'Check the item adobe-oauth (fields client_id, client_secret) in the 1Password vault, and OP_SERVICE_ACCOUNT_TOKEN.',
  make: (env) => new OnePasswordStore(env),
});
