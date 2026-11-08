import type { Env } from './env';

/**
 * Encrypts upstream OAuth tokens (for example Jack's Adobe refresh token) before they go into KV,
 * with AES-GCM under TOKEN_ENC_KEY (a Worker secret). The KV key name is bound in as additional
 * data, so a sealed value can't be moved to another key. No key configured: nothing is stored.
 */

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function aesKey(env: Env): Promise<CryptoKey> {
  const raw = env.TOKEN_ENC_KEY ? unb64(env.TOKEN_ENC_KEY) : new Uint8Array();
  if (raw.length !== 32) throw new Error('TOKEN_ENC_KEY must be 32 bytes, base64');
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function putSealed(env: Env, key: string, value: unknown): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(key) },
    await aesKey(env),
    new TextEncoder().encode(JSON.stringify(value)),
  );
  await env.BROKER_KV.put(key, `v1.${b64(iv)}.${b64(new Uint8Array(ct))}`);
}

export async function getSealed<T>(env: Env, key: string): Promise<T | null> {
  const stored = await env.BROKER_KV.get(key);
  if (!stored) return null;
  const [v, iv, ct] = stored.split('.');
  if (v !== 'v1' || !iv || !ct) return null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(iv), additionalData: new TextEncoder().encode(key) },
      await aesKey(env),
      unb64(ct),
    );
    return JSON.parse(new TextDecoder().decode(pt)) as T;
  } catch {
    return null; // wrong key or tampered: treat as absent
  }
}
