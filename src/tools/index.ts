import { z } from 'zod';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { Env, GrantProps } from '../env';
import type { LoadedPolicy } from '../policy';
import { secretsFor } from '../secrets/store';

/** Who is calling, as established by the OAuth token. */
export interface Caller extends GrantProps {
  scopes: string[];
  tokenExpiresAt?: number;
}

export interface ToolContext {
  env: Env;
  caller: Caller;
  policy: LoadedPolicy;
  allowed: string[];
}

/** A tool result plus a short audit code. Text must never contain a secret. */
export interface ToolOutcome {
  result: CallToolResult;
  code?: string;
}

export interface ToolDef {
  title: string;
  description: string;
  inputSchema?: z.ZodRawShape;
  run(ctx: ToolContext, args: Record<string, unknown>): Promise<ToolOutcome>;
}

const ok = (data: unknown): ToolOutcome => ({
  result: { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] },
});

const fail = (code: string, message: string): ToolOutcome => ({
  code,
  result: { isError: true, content: [{ type: 'text', text: `${message} (code: ${code})` }] },
});

const MOCKGIT_KEY_REF = 'mockgit/api_key';

export const TOOLS: Record<string, ToolDef> = {
  whoami: {
    title: 'Who am I',
    description:
      'Shows which client and agent this connection is, and which tools the broker allows it to call. Makes no upstream call.',
    async run({ env, caller, policy, allowed }) {
      return ok({
        agent: caller.agent,
        client: { id: caller.clientId, name: caller.clientName },
        allowed_tools: allowed,
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

  mockgit_list_my_repos: {
    title: 'List my repos (Mock Git)',
    description:
      "Lists the owner's repositories on Mock Git, a stand-in for GitHub. The broker signs the request with an API key it holds; " +
      'the key is never returned. Returns name, url and last-updated time for each repo, newest first.',
    inputSchema: {
      limit: z.number().int().min(1).max(25).optional().describe('How many repos to return (1-25, default 10)'),
    },
    async run({ env }, args) {
      const limit = typeof args.limit === 'number' ? args.limit : 10;
      const secrets = secretsFor(env);
      const call = (key: string) =>
        env.MOCKGIT.fetch(`https://mockgit.internal/user/repos?per_page=${limit}`, {
          headers: { authorization: `Bearer ${key}`, accept: 'application/json', 'user-agent': 'agent-secrets-broker' },
        });

      let key = await secrets.get(MOCKGIT_KEY_REF);
      if (!key) return fail('secret_missing', 'The broker has no Mock Git key in its vault yet. Ask the owner to add one.');

      let res = await call(key);
      if (res.status === 401 || res.status === 403) {
        // The key was probably rotated: drop the cached copy, re-read the vault, retry once.
        await res.body?.cancel();
        secrets.invalidate(MOCKGIT_KEY_REF);
        const fresh = await secrets.get(MOCKGIT_KEY_REF);
        if (fresh && fresh !== key) {
          key = fresh;
          res = await call(key);
        }
      }
      if (!res.ok) {
        // Never pass the upstream body through: it may echo the key.
        await res.body?.cancel();
        if (res.status === 401 || res.status === 403) {
          secrets.invalidate(MOCKGIT_KEY_REF);
          return fail(
            `upstream_${res.status}`,
            `Mock Git rejected the broker's key (HTTP ${res.status}). The owner may need to rotate it in the vault.`,
          );
        }
        return fail(`upstream_${res.status}`, `Mock Git returned HTTP ${res.status}. Try again later.`);
      }

      const body = (await res.json()) as unknown;
      if (!Array.isArray(body)) return fail('upstream_bad_shape', 'Mock Git returned an unexpected response.');
      // Allow-list the fields: everything else (tokens in URLs, emails, permissions) is dropped.
      const repos = body.slice(0, limit).map((r: Record<string, unknown>) => ({
        name: typeof r.name === 'string' ? r.name : null,
        url: typeof r.html_url === 'string' ? r.html_url : null,
        updated: typeof r.updated_at === 'string' ? r.updated_at : null,
      }));
      return ok({ source: 'mockgit', count: repos.length, repos });
    },
  },
};
