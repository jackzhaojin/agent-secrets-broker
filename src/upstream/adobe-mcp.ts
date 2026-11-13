import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/cfworker';
import type { Env } from '../env';
import { ADOBE_MCP_URL, adobeAccessToken } from './adobe';

/**
 * The broker as an MCP client of Adobe's hosted Experience Workspace (DA) MCP server, acting as
 * Jack. Only the broker's own DA tools call this, each with a fixed upstream tool name and
 * arguments the broker built itself: an agent can't choose the upstream tool, so Adobe's delete,
 * move, preview and publish tools are out of reach.
 */

export type UpstreamResult = { ok: true; text: string } | { ok: false; code: string; status?: number };

async function callOnce(token: string, name: string, args: Record<string, unknown>): Promise<{ isError: boolean; text: string }> {
  const transport = new StreamableHTTPClientTransport(new URL(ADOBE_MCP_URL), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  // The default validator compiles schemas with new Function, which Workers forbid.
  const client = new Client({ name: 'agent-secrets-broker', version: '0.2.0' }, { jsonSchemaValidator: new CfWorkerJsonSchemaValidator() });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name, arguments: args });
    const content = Array.isArray(result.content) ? (result.content as { type?: string; text?: string }[]) : [];
    return { isError: !!result.isError, text: content.filter((c) => c.type === 'text' && typeof c.text === 'string').map((c) => c.text).join('\n') };
  } finally {
    await client.close().catch(() => {});
  }
}

const isUnauthorized = (err: unknown) => /\b401\b|unauthori[sz]ed/i.test(err instanceof Error ? err.message : String(err));

export async function callAdobeDa(env: Env, name: string, args: Record<string, unknown>): Promise<UpstreamResult> {
  let auth = await adobeAccessToken(env, null);
  if ('error' in auth) return { ok: false, code: auth.error };
  let out: { isError: boolean; text: string };
  try {
    out = await callOnce(auth.token, name, args);
  } catch (err) {
    if (!isUnauthorized(err)) {
      console.error(JSON.stringify({ level: 'error', upstream: 'adobe-mcp', tool: name, error: err instanceof Error ? err.name : 'unknown' }));
      return { ok: false, code: 'upstream_unreachable' };
    }
    // The access token was refused: refresh once and try again.
    auth = await adobeAccessToken(env, null, { forceRefresh: true });
    if ('error' in auth) return { ok: false, code: auth.error };
    try {
      out = await callOnce(auth.token, name, args);
    } catch (again) {
      return { ok: false, code: isUnauthorized(again) ? 'upstream_401' : 'upstream_unreachable', status: isUnauthorized(again) ? 401 : undefined };
    }
  }
  if (out.isError) {
    // Adobe's error text is "<label> (<status>): <message>". Keep the status, drop the rest.
    const status = Number(out.text.match(/\((\d{3})\)/)?.[1]) || undefined;
    return { ok: false, code: status ? `upstream_${status}` : 'upstream_error', status };
  }
  return { ok: true, text: out.text };
}
