export const escape = (value: unknown): string =>
  String(value ?? '').replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

const STYLE = `
:root{--bg:#fff;--fg:#1d1d1f;--muted:#5f6368;--line:#dadce0;--card:#f8f9fa;--accent:#1a5fd0;--warn-bg:#fff4e5;--warn-fg:#8a4b00;--bad:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#121212;--fg:#e8eaed;--muted:#9aa0a6;--line:#3c4043;--card:#1e1f20;--accent:#8ab4f8;--warn-bg:#3a2a12;--warn-fg:#ffcc80;--bad:#f28b82}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 16px 48px}h1{font-size:1.5rem;margin:0 0 8px}h2{font-size:1.1rem;margin:28px 0 8px}
p{margin:8px 0}a{color:var(--accent)}.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.warn{background:var(--warn-bg);color:var(--warn-fg);border-radius:8px;padding:10px 12px}.bad{color:var(--bad)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}pre{white-space:pre-wrap;word-break:break-word;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px}
label.agent{display:block;border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0;cursor:pointer}
input[type=password],input[type=text]{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:16px}
button{font-size:16px;padding:10px 18px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}@media (prefers-color-scheme:dark){button.primary{color:#0b1b33}}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}.scroll{overflow-x:auto}
`;

export function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${escape(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>`;
}

/** Headers for pages we render ourselves (not the consent page, which gets the library's headers). */
export function htmlHeaders(extra?: HeadersInit): Headers {
  const h = new Headers(extra);
  h.set('content-type', 'text/html; charset=utf-8');
  h.set('cache-control', 'no-store');
  h.set('x-frame-options', 'DENY');
  h.set('content-security-policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
  // same-origin, not no-referrer: with no-referrer, browsers send "Origin: null" on our own form
  // posts, which the admin origin check refuses. Other sites still get no referrer.
  h.set('referrer-policy', 'same-origin');
  return h;
}

export function htmlResponse(status: number, title: string, body: string, extra?: HeadersInit): Response {
  return new Response(page(title, body), { status, headers: htmlHeaders(extra) });
}
