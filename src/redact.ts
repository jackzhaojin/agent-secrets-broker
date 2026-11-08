import type { Env } from './env';
import { handledSecretValues } from './secrets/store';

/**
 * Last line of defense. Tools shape their output so secrets never get in, but anything about to
 * leave the broker is still checked against every secret value this isolate has seen, including
 * the broker's own credentials. A hit is replaced and reported (and audited by the caller).
 */
export function redact(env: Env, text: string): { text: string; hits: number } {
  const values = new Set<string>(handledSecretValues);
  for (const v of [env.OWNER_PASSWORD, env.ADMIN_TOKEN, env.COOKIE_SECRET]) if (v) values.add(v);
  let hits = 0;
  let out = text;
  for (const value of values) {
    if (value.length < 8 || !out.includes(value)) continue;
    const parts = out.split(value);
    hits += parts.length - 1;
    out = parts.join('[REDACTED]');
  }
  return { text: out, hits };
}
