import bundled from '../policy.json';
import type { Env } from './env';

export interface AgentPolicy {
  description?: string;
  match_client_names?: string[];
  tools: string[];
}

export interface Policy {
  version: number;
  notes?: string;
  agents: Record<string, AgentPolicy>;
}

export interface LoadedPolicy {
  policy: Policy;
  source: 'kv-override' | 'bundled';
  hash: string;
}

const POLICY_KEY = 'policy:override';
const AGENT_ID = /^[a-z][a-z0-9-]{0,31}$/;
const TOOL_ID = /^[a-z][a-z0-9_]{0,63}$/;

/** Throws a readable error if the policy is malformed. */
export function validatePolicy(input: unknown): Policy {
  if (!input || typeof input !== 'object') throw new Error('policy must be a JSON object');
  const p = input as Record<string, unknown>;
  if (typeof p.version !== 'number') throw new Error('policy.version must be a number');
  if (!p.agents || typeof p.agents !== 'object') throw new Error('policy.agents must be an object');
  for (const [id, agent] of Object.entries(p.agents as Record<string, unknown>)) {
    if (!AGENT_ID.test(id)) throw new Error(`agent id "${id}" must match ${AGENT_ID}`);
    const a = agent as Record<string, unknown>;
    if (!Array.isArray(a.tools) || !a.tools.every((t) => typeof t === 'string' && TOOL_ID.test(t))) {
      throw new Error(`agents.${id}.tools must be an array of tool names`);
    }
    if (a.match_client_names !== undefined && !(Array.isArray(a.match_client_names) && a.match_client_names.every((s) => typeof s === 'string'))) {
      throw new Error(`agents.${id}.match_client_names must be an array of strings`);
    }
  }
  return input as Policy;
}

async function hashOf(policy: Policy): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(policy)));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 12);
}

/**
 * The policy in force: the KV override if one is set, otherwise the reviewed policy.json bundled
 * with the deploy. A malformed override fails closed (no agent gets any tool).
 */
export async function loadPolicy(env: Env): Promise<LoadedPolicy> {
  const raw = await env.BROKER_KV.get(POLICY_KEY, { cacheTtl: 30 });
  if (raw) {
    try {
      const policy = validatePolicy(JSON.parse(raw));
      return { policy, source: 'kv-override', hash: await hashOf(policy) };
    } catch (err) {
      console.error(JSON.stringify({ level: 'error', msg: 'policy override is invalid; failing closed', error: String(err) }));
      const closed: Policy = { version: 0, agents: {} };
      return { policy: closed, source: 'kv-override', hash: 'invalid' };
    }
  }
  const policy = validatePolicy(bundled);
  return { policy, source: 'bundled', hash: await hashOf(policy) };
}

export async function setPolicyOverride(env: Env, policy: Policy): Promise<void> {
  await env.BROKER_KV.put(POLICY_KEY, JSON.stringify(validatePolicy(policy)));
}

export async function clearPolicyOverride(env: Env): Promise<void> {
  await env.BROKER_KV.delete(POLICY_KEY);
}

export function allowedTools(loaded: LoadedPolicy, agent: string): string[] {
  return loaded.policy.agents[agent]?.tools ?? [];
}

/** Agent to preselect on the consent page for a client name, if exactly one agent matches. */
export function suggestAgent(policy: Policy, clientName: string): string | undefined {
  const name = clientName.toLowerCase();
  const hits = Object.entries(policy.agents).filter(([, a]) =>
    (a.match_client_names ?? []).some((m) => m && name.includes(m.toLowerCase())),
  );
  return hits.length === 1 ? hits[0][0] : undefined;
}
