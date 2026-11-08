import { ok, type ToolDef } from './types';

/** Tools every deployment has. */
export const CORE_TOOLS: Record<string, ToolDef> = {
  whoami: {
    title: 'Who am I',
    description:
      'Shows which client and agent this connection is, which tools the broker allows it to call, and which of those need the owner to approve each call. Makes no upstream call.',
    async run({ env, caller, policy, allowed, approvalRequired }) {
      return ok({
        agent: caller.agent,
        client: { id: caller.clientId, name: caller.clientName },
        allowed_tools: allowed,
        approval_required: approvalRequired,
        approved_at: caller.approvedAt,
        token: {
          scopes: caller.scopes,
          expires_at: caller.tokenExpiresAt ? new Date(caller.tokenExpiresAt * 1000).toISOString() : null,
        },
        policy: { source: policy.source, hash: policy.hash },
        broker: { environment: env.ENVIRONMENT, version: env.CF_VERSION?.id ?? 'local' },
      });
    },
  },
};
