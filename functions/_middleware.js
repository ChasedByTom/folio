// Cloudflare Pages Function — password-gate the case-study pages at the edge.
// The shared password is read from env.SITE_PASSWORD (set as a secret in the
// Pages project settings — never stored in the repo). Requests to a protected
// page without a valid auth cookie get the login screen instead of the page,
// so the HTML is never served to an unauthenticated visitor.

const PROTECTED = new Set([
  '/zadinga', '/zadinga.html',
  '/deem', '/deem.html',
  '/motor', '/motor.html',
  '/avataar', '/avataar.html',
]);

const COOKIE = 'cbt_gate';
const MAX_AGE = 60 * 60 * 24; // 1 day

// Derive an opaque cookie token from the password. Can't be forged without it.
async function tokenFor(password) {
  const data = new TextEncoder().encode('cbt-gate:v2:' + password);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  });
  return out;
}

function loginPage(actionPath, error) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Protected · Jerry Jose</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Source+Serif+4:wght@500;600&display=swap" rel="stylesheet"/>
<style>
:root{--paper:#faf8f4;--ink:#1f1d1a;--ink-muted:#5b574f;--line:rgba(31,29,26,.12);--accent:#0b7d4f}
*{box-sizing:border-box}html,body{margin:0}
body{min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px;background:var(--paper);color:var(--ink);font-family:'Inter',system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased}
.card{width:100%;max-width:380px;text-align:center}
h1{font-family:'Source Serif 4',Georgia,serif;font-weight:600;font-size:1.55rem;letter-spacing:-.02em;margin:0 0 8px}
p.sub{color:var(--ink-muted);font-size:.98rem;margin:0 0 22px;line-height:1.5}
form{display:flex;flex-direction:column;gap:10px}
input{padding:13px 15px;border:1px solid var(--line);border-radius:10px;font-size:1rem;background:#fff;color:var(--ink)}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,125,79,.12)}
button{padding:13px 15px;border:none;border-radius:10px;background:var(--ink);color:var(--paper);font-weight:600;font-size:1rem;cursor:pointer;transition:background .15s ease}
button:hover{background:#2a2723}
.err{color:#b3261e;font-size:.88rem;margin:4px 0 0;min-height:1.1em}
.back{position:fixed;top:22px;left:clamp(20px,5vw,60px);display:inline-flex;align-items:center;gap:8px;font-size:14px;font-weight:500;color:var(--ink-muted);text-decoration:none}
.back::before{content:'←';transition:transform .2s ease}
.back:hover{color:var(--ink)}.back:hover::before{transform:translateX(-3px)}
</style></head>
<body><a class="back" href="/landing#work" onclick="if(document.referrer&&history.length>1){history.back();return false}">Back</a><main class="card">
<h1>This case study is private</h1>
<p class="sub">Enter the password to continue.</p>
<form method="POST" action="${actionPath}">
<input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required/>
<button type="submit">View case study</button>
<p class="err">${error || ''}</p>
</form>
</main></body></html>`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  // Homepage: serve the portfolio (landing.html) at chasedbytom.com itself,
  // keeping the address bar on "/". The old holding page is archived outside
  // the repo (Claude/archive/holding-page); see its README to take the site offline.
  if (path === '/' && (request.method === 'GET' || request.method === 'HEAD')) {
    const target = new URL('/landing', url);
    return env.ASSETS.fetch(new Request(target.toString(), request));
  }

  // Not a protected page → serve normally.
  if (!PROTECTED.has(path)) return next();

  const password = env.SITE_PASSWORD;
  // Not configured yet → fail open so the owner is never locked out during setup.
  // (Set SITE_PASSWORD in the Pages project for protection to take effect.)
  if (!password) return next();

  const expected = await tokenFor(password);
  const cookies = parseCookies(request.headers.get('Cookie'));

  // Already unlocked.
  if (cookies[COOKIE] && cookies[COOKIE] === expected) return next();

  // Login submission.
  if (request.method === 'POST') {
    const form = await request.formData();
    const supplied = (form.get('password') || '').toString();
    if (supplied === password) {
      const headers = new Headers();
      headers.append(
        'Set-Cookie',
        `${COOKIE}=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`
      );
      headers.set('Location', url.pathname + url.search);
      return new Response(null, { status: 303, headers });
    }
    return new Response(loginPage(url.pathname, 'Incorrect password. Please try again.'), {
      status: 401,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }

  // No cookie → show the gate.
  return new Response(loginPage(url.pathname), {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
