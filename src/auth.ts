import type { Env } from './env';

/** Constant-time string comparison (hash both sides so lengths always match). */
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(da, db);
}

function clientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? 'local';
}

const MAX_FAILURES = 10;
const LOCKOUT_SECONDS = 15 * 60;

/** Owner password check with a simple per-IP lockout (10 failures per 15 minutes). */
export async function checkOwnerPassword(env: Env, request: Request, password: string): Promise<'ok' | 'bad' | 'locked'> {
  const key = `rl:login:${clientIp(request)}`;
  const failures = Number((await env.BROKER_KV.get(key)) ?? '0');
  if (failures >= MAX_FAILURES) return 'locked';
  if (env.OWNER_PASSWORD && password && (await safeEqual(password, env.OWNER_PASSWORD))) return 'ok';
  await env.BROKER_KV.put(key, String(failures + 1), { expirationTtl: LOCKOUT_SECONDS });
  return 'bad';
}

export async function hasAdminToken(env: Env, request: Request): Promise<boolean> {
  const header = request.headers.get('authorization') ?? '';
  const token = header.replace(/^Bearer\s+/i, '');
  return !!env.ADMIN_TOKEN && token !== header && (await safeEqual(token, env.ADMIN_TOKEN));
}

// Admin browser session: "<expiry>.<hmac>" in a __Host- cookie, 30 minutes.
const SESSION_COOKIE = '__Host-broker-admin';
const SESSION_SECONDS = 30 * 60;

async function hmac(env: Env, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.COOKIE_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function adminSessionCookie(env: Env): Promise<string> {
  const exp = String(Math.floor(Date.now() / 1000) + SESSION_SECONDS);
  return `${SESSION_COOKIE}=${exp}.${await hmac(env, exp)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_SECONDS}`;
}

export const clearAdminSessionCookie = `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;

export async function hasAdminSession(env: Env, request: Request): Promise<boolean> {
  if (!env.COOKIE_SECRET) return false;
  const cookie = (request.headers.get('cookie') ?? '').split(/;\s*/).find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  if (!cookie) return false;
  const [exp, sig] = cookie.slice(SESSION_COOKIE.length + 1).split('.');
  if (!exp || !sig || Number(exp) < Date.now() / 1000) return false;
  return safeEqual(sig, await hmac(env, exp));
}

/** Form posts on admin pages must come from this origin (on top of SameSite=Strict). */
export function sameOrigin(env: Env, request: Request): boolean {
  const origin = request.headers.get('origin');
  return !!origin && origin === new URL(env.PUBLIC_BASE_URL).origin;
}
