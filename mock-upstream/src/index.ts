/**
 * Mock Git API: a stand-in for an upstream API like GitHub.
 *
 * It accepts exactly one API key at a time (KV `accepted_key`), so the broker has to present the
 * right secret. It is deliberately careless in two ways that real APIs sometimes are, so the
 * broker's response shaping is tested for real:
 *   - a 401 echoes the key it was given back in the error body
 *   - a repo listing embeds the caller's key in `clone_url_with_token`
 * The broker must never pass either through to an agent.
 */

interface Env {
  MOCK_KV: KVNamespace;
}

const REPOS = [
  { name: 'sandbox-alpha', updated_at: '2026-11-07T18:02:11Z', description: 'First sandbox repo' },
  { name: 'sandbox-bravo', updated_at: '2026-11-06T13:44:52Z', description: 'Notes and drafts' },
  { name: 'sandbox-charlie', updated_at: '2026-11-04T09:15:30Z', description: 'Prototype API' },
  { name: 'sandbox-delta', updated_at: '2026-11-01T22:40:07Z', description: 'Static site' },
  { name: 'sandbox-echo', updated_at: '2026-10-29T16:20:45Z', description: 'Data scripts' },
  { name: 'sandbox-foxtrot', updated_at: '2026-10-25T11:11:11Z', description: 'Game jam' },
  { name: 'sandbox-golf', updated_at: '2026-10-20T08:05:59Z', description: 'Archive' },
  { name: 'sandbox-hotel', updated_at: '2026-10-14T19:30:00Z', description: 'Infra experiments' },
];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

async function sameKey(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(da, db);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/' && request.method === 'GET') {
      return new Response(
        'Mock Git API for agent-secrets-broker. GET /user/repos with "Authorization: Bearer <key>".\n',
        { headers: { 'content-type': 'text/plain; charset=utf-8' } },
      );
    }

    if (url.pathname === '/user/repos' && request.method === 'GET') {
      const presented = (request.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '').trim();
      const accepted = await env.MOCK_KV.get('accepted_key', { cacheTtl: 30 });
      if (!accepted || !presented || !(await sameKey(presented, accepted))) {
        // Deliberately leaky: echoes the presented key, as some real APIs do.
        return json(401, {
          message: 'Bad credentials',
          presented_key: presented,
          documentation_url: 'https://example.invalid/docs/auth',
        });
      }
      const perPage = Math.min(Math.max(Number(url.searchParams.get('per_page') ?? '30') || 30, 1), 100);
      const repos = REPOS.slice(0, perPage).map((repo, i) => ({
        id: 1000 + i,
        ...repo,
        private: i % 3 === 0,
        html_url: `https://mockgit.example/jackzhaojin/${repo.name}`,
        // Deliberately leaky: a URL with the caller's key in it.
        clone_url_with_token: `https://x-access-token:${presented}@mockgit.example/jackzhaojin/${repo.name}.git`,
        owner: { login: 'jackzhaojin', email: 'owner@example.invalid' },
        permissions: { admin: true, push: true, pull: true },
      }));
      return json(200, repos);
    }

    return json(404, { message: 'Not Found' });
  },
} satisfies ExportedHandler<Env>;
