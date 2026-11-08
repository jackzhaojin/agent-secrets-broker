import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/cfworker';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { Env, GrantProps } from './env';
import { audit } from './audit';
import { allowedTools, loadPolicy } from './policy';
import { redact } from './redact';
import { TOOLS, type Caller, type ToolContext } from './tools';

/** What OAuthProvider hands the API handler: the grant's props and what it verified about the token. */
type ApiContext = ExecutionContext & {
  props: GrantProps;
  auth?: { clientId?: string; userId?: string; scope?: string[]; expiresAt?: number };
};

const INSTRUCTIONS =
  'Agent Secrets Broker: it calls APIs for you with keys it holds, so you never need or see a key. ' +
  'Call whoami to see which tools your connection is allowed to use. Tool results never contain credentials; ' +
  'if a tool reports a rejected key, tell the owner (Jack) so he can rotate it.';

function toolCallNames(body: unknown): string[] {
  const messages = Array.isArray(body) ? body : [body];
  return messages
    .filter((m): m is { method: string; params?: { name?: unknown } } => !!m && typeof m === 'object' && (m as { method?: unknown }).method === 'tools/call')
    .map((m) => (typeof m.params?.name === 'string' ? m.params.name : '(missing)'));
}

export const mcpApiHandler = {
  async fetch(request: Request, env: Env, execCtx: ExecutionContext): Promise<Response> {
    const ctx = execCtx as ApiContext;
    // Stateless Streamable HTTP: POST only. No server-initiated stream, no sessions to delete.
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
    }

    const props = ctx.props;
    const caller: Caller = {
      ...props,
      clientId: ctx.auth?.clientId ?? props.clientId,
      scopes: ctx.auth?.scope ?? [],
      tokenExpiresAt: ctx.auth?.expiresAt,
    };
    const policy = await loadPolicy(env);
    const allowed = allowedTools(policy, caller.agent).filter((name) => name in TOOLS);
    const who = { client_id: caller.clientId, client_name: caller.clientName, agent: caller.agent };

    let parsedBody: unknown;
    try {
      parsedBody = await request.clone().json();
    } catch {
      parsedBody = undefined; // the transport answers malformed JSON itself
    }

    // A call to a tool outside the policy never reaches a handler (the tool isn't registered), so
    // audit the refusal here.
    for (const name of toolCallNames(parsedBody)) {
      if (!allowed.includes(name)) {
        audit(env, ctx, { type: 'tool_call', outcome: 'denied', tool: name.slice(0, 64), code: name in TOOLS ? 'not_in_policy' : 'unknown_tool', ...who });
      }
    }

    const server = new McpServer(
      { name: 'agent-secrets-broker', version: '0.1.0' },
      { capabilities: { tools: {} }, instructions: INSTRUCTIONS, jsonSchemaValidator: new CfWorkerJsonSchemaValidator() },
    );
    const toolCtx: ToolContext = { env, caller, policy, allowed };

    for (const name of allowed) {
      const def = TOOLS[name];
      server.registerTool(
        name,
        {
          title: def.title,
          description: def.description,
          inputSchema: def.inputSchema ?? {},
          annotations: { readOnlyHint: true, openWorldHint: name !== 'whoami' },
        },
        async (args: Record<string, unknown>): Promise<CallToolResult> => {
          const started = Date.now();
          let result: CallToolResult;
          let code: string | undefined;
          try {
            ({ result, code } = await def.run(toolCtx, args ?? {}));
          } catch (err) {
            console.error(JSON.stringify({ level: 'error', msg: 'tool threw', tool: name, error: err instanceof Error ? err.name : 'unknown' }));
            result = { isError: true, content: [{ type: 'text', text: 'The broker hit an internal error. (code: internal_error)' }] };
            code = 'internal_error';
          }
          // Defense in depth: scrub any secret value that slipped into the output.
          let hits = 0;
          result.content = result.content.map((item) => {
            if (item.type !== 'text') return item;
            const scrubbed = redact(env, item.text);
            hits += scrubbed.hits;
            return { ...item, text: scrubbed.text };
          });
          if (hits > 0) audit(env, ctx, { type: 'redaction', outcome: 'error', tool: name, code: `redacted_${hits}`, ...who });
          audit(env, ctx, { type: 'tool_call', outcome: result.isError ? 'error' : 'ok', tool: name, code, ms: Date.now() - started, ...who });
          return result;
        },
      );
    }

    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    const response = await transport.handleRequest(request, { parsedBody });
    ctx.waitUntil(server.close());
    return response;
  },
};
