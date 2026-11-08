import { createClient, type Client } from '@1password/sdk';
import type { Env } from '../env';
import type { SecretStore } from './store';

/**
 * Real secrets for the live deployment: the 1Password vault named in OP_VAULT ("Broker"), read with
 * a read-only service account (OP_SERVICE_ACCOUNT_TOKEN). A reference such as
 * "adobe-oauth/client_secret" resolves to op://Broker/adobe-oauth/client_secret.
 *
 * The SDK's WASM core is patched at build time to run in workerd (scripts/patch-1password.mjs,
 * docs/1password.md). One client per isolate: each createClient is a full sign-in. Reads go through
 * CachedSecrets (5 minutes) so an Individual-plan service account's daily read limit is not a problem.
 */

let client: Promise<Client> | undefined;
let clientToken: string | undefined;

export class OnePasswordStore implements SecretStore {
  constructor(private readonly env: Env) {}

  async get(ref: string): Promise<string | null> {
    const token = this.env.OP_SERVICE_ACCOUNT_TOKEN;
    if (!token) return null;
    if (!/^[A-Za-z0-9 _.-]+\/[A-Za-z0-9 _.-]+$/.test(ref)) throw new Error('bad secret reference');
    if (!client || clientToken !== token) {
      clientToken = token;
      client = createClient({ auth: token, integrationName: 'agent-secrets-broker', integrationVersion: '0.2.0' });
    }
    try {
      return await (await client).secrets.resolve(`op://${this.env.OP_VAULT ?? 'Broker'}/${ref}`);
    } catch (err) {
      client = undefined; // a failed sign-in or an expired service account: start over next time
      // The error name only: SDK messages can quote the reference or account details.
      console.error(JSON.stringify({ level: 'error', msg: '1password read failed', ref, error: err instanceof Error ? err.name : 'unknown' }));
      return null;
    }
  }
}
