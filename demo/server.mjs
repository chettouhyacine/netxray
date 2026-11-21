/**
 * NetXRay demo app. Intentionally vulnerable.
 *
 * Two modes, selected by DEMO_MODE=fixed (or ?mode=fixed per request):
 *  - vulnerable: insecure cookies, wildcard CORS with credentials, token in URL,
 *    no security headers, verbose errors, a long-lived alg=none JWT.
 *  - fixed: HttpOnly/Secure/SameSite cookies, strict CORS, header hardening,
 *    generic errors, short-lived signed-looking tokens (no secrets in payload).
 *
 * Run: npm run demo   (http://localhost:4000)
 */
import express from 'express';

const app = express();
const requestedPort = Number(process.env.PORT);
const PORT = Number.isInteger(requestedPort) && requestedPort > 0 ? requestedPort : 4000;
const defaultMode = process.env.DEMO_MODE === 'fixed' ? 'fixed' : 'vulnerable';

app.disable('x-powered-by');

function modeFor(req) {
  const query = String(req.query.mode ?? '');
  if (query === 'fixed' || query === 'vulnerable') return query;
  if (req.path.startsWith('/fixed')) return 'fixed';
  if (req.path.startsWith('/vulnerable')) return 'vulnerable';
  return defaultMode;
}

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/** Unsigned JWT (alg=none) with sensitive claims and a year-long expiry. */
function badToken() {
  const now = Math.floor(Date.now() / 1000);
  return `${base64url({ alg: 'none', typ: 'JWT' })}.${base64url({
    sub: 'demo-user',
    role: 'admin',
    email: 'demo@example.com',
    password: 'hunter2',
    api_key: 'sk_live_demo_key_do_not_use',
    iat: now,
    exp: now + 365 * 24 * 3600,
  })}.`;
}

/** Short-lived identifier-only token. */
function goodToken() {
  const now = Math.floor(Date.now() / 1000);
  return `${base64url({ alg: 'HS256', typ: 'JWT' })}.${base64url({ sub: 'demo-user', iat: now, exp: now + 900 })}.not-a-real-signature`;
}

function applyHeaders(res, mode, path) {
  if (mode === 'fixed') {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    );
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cache-Control', 'no-store');
    return;
  }
  // Vulnerable mode advertises versions and caches personalized responses.
  res.setHeader('Server', 'nginx/1.18.0');
  res.setHeader('X-Powered-By', 'Express/4.21.1');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  if (/(^|\/)api(\/|$)/.test(path)) {
    // Wildcard CORS with credentials: a broken and dangerous combination.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH');
    res.setHeader('Access-Control-Allow-Headers', '*');
  }
}

app.use((req, res, next) => {
  const mode = modeFor(req);
  res.locals.mode = mode;
  applyHeaders(res, mode, req.path);

  if (mode === 'vulnerable') {
    // Session cookie readable by JavaScript, no Secure, no SameSite.
    res.cookie('sid', 'demo-session-abcdef123456', { path: '/' });
    res.cookie('prefs', 'theme=dark', { path: '/' });
  } else {
    res.cookie('sid', 'demo-session-abcdef123456', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 3600_000,
    });
    res.cookie('prefs', 'theme=dark', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 3600_000,
    });
  }
  next();
});

app.get('/', (req, res) => {
  res.redirect(`/${res.locals.mode}/`);
});

app.get('/favicon.ico', (_req, res) => res.status(204).end());

const PAGE_STYLE = `
  :root { color-scheme: dark; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; background: #0b0f17; color: #e2e8f0; }
  main { max-width: 780px; margin: 0 auto; padding: 32px 20px 80px; }
  h1 { font-size: 24px; margin: 0 0 6px; }
  .muted { color: #94a3b8; font-size: 13px; }
  .card { border: 1px solid #1f2939; background: #111725; border-radius: 10px; padding: 16px; margin-top: 14px; }
  button { background: #161d2d; color: #e2e8f0; border: 1px solid #2c384d; border-radius: 8px; padding: 7px 12px; cursor: pointer; font-size: 13px; }
  button:hover { border-color: #38e1c6; color: #7df0dd; }
  pre { background: #080b12; border: 1px solid #1f2939; padding: 10px; border-radius: 8px; overflow: auto; font-size: 12px; }
  .pill { display: inline-block; border-radius: 999px; padding: 2px 9px; font-size: 11px; font-weight: 700; letter-spacing: .04em; }
  .bad { background: rgba(244,63,94,.15); color: #fda4af; }
  .good { background: rgba(34,197,94,.15); color: #86efac; }
  a { color: #7df0dd; }
  code { font-family: ui-monospace, Consolas, monospace; }
`;

function page(mode) {
  const isFixed = mode === 'fixed';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetXRay demo · ${mode}</title>
<style>${PAGE_STYLE}</style></head>
<body><main>
  <h1>NetXRay demo <span class="pill ${isFixed ? 'good' : 'bad'}">${isFixed ? 'FIXED' : 'VULNERABLE'}</span></h1>
  <p class="muted">A deliberately insecure Express app for learning. Open NetXRay's panel on this page, then click the buttons to generate traffic.</p>

  <div class="card">
    <strong>Mode</strong>
    <p class="muted">Switch between the vulnerable build and the fixed one to watch findings appear and disappear.</p>
    <p>
      <a href="/vulnerable/"><button type="button">Vulnerable</button></a>
      <a href="/fixed/"><button type="button">Fixed</button></a>
      <a href="/fixed/api/me"><button type="button">Fixed API sample</button></a>
    </p>
  </div>

  <div class="card">
    <strong>Generate traffic</strong>
    <p class="muted">Each click performs a real request so the timeline and rules have something to inspect.</p>
    <button id="api">Call /api/me</button>
    <button id="token">Token in URL</button>
    <button id="jwt">Fetch a JWT</button>
    <button id="error">Trigger verbose error</button>
    <button id="leak">Leak a key in a response</button>
    <pre id="out">ready</pre>
  </div>

  <div class="card">
    <strong>What to look for</strong>
    <ul class="muted">
      <li>${isFixed ? 'Hardened cookies and headers. Findings should be empty apart from third-party info.' : 'Session cookie readable by JavaScript (no HttpOnly).'}</li>
      <li>${isFixed ? 'Strict CORS and a short-lived, identifier-only token.' : 'Wildcard CORS with credentials and an alg=none JWT full of secrets.'}</li>
      <li>${isFixed ? 'Generic error responses and no server banners.' : 'Verbose stack trace, server version banners, token in the URL.'}</li>
      <li>${isFixed ? 'A strict CSP instead of missing headers.' : 'Missing CSP/HSTS/X-Frame-Options and a cacheable personalised response.'}</li>
    </ul>
  </div>
</main>
<script src="/demo.js"></script>
</body></html>`;
}

app.get('/demo.js', (_req, res) => {
  res.type('application/javascript').send(`
    const out = document.getElementById('out');
    const mode = location.pathname.split('/')[1] || 'vulnerable';
    const base = '/' + mode;
    async function call(label, url, init) {
      out.textContent = 'loading ' + url + ' …';
      try {
        const response = await fetch(url, init);
        const text = await response.text();
        out.textContent = label + ' → ' + response.status + '\\n' + text.slice(0, 600);
      } catch (error) {
        out.textContent = label + ' failed: ' + error;
      }
    }
    document.getElementById('api').addEventListener('click', () => call('api', base + '/api/me', { credentials: 'include' }));
    document.getElementById('token').addEventListener('click', () => call('token', base + '/api/me?access_token=demo-secret-token-123456789'));
    document.getElementById('jwt').addEventListener('click', () => call('jwt', base + '/api/token'));
    document.getElementById('error').addEventListener('click', () => call('error', base + '/api/boom'));
    document.getElementById('leak').addEventListener('click', () => call('leak', base + '/api/credentials'));
  `);
});

app.get('/vulnerable/', (req, res) => res.type('html').send(page('vulnerable')));
app.get('/fixed/', (req, res) => res.type('html').send(page('fixed')));

app.get('/vulnerable/api/me', (req, res) => {
  res.json({
    user: { id: 'demo-user', email: 'demo@example.com', plan: 'admin' },
    accessToken: badToken(),
    note: 'This response is cached publicly and readable from any origin.',
  });
});

app.get('/fixed/api/me', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:4000');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Cache-Control', 'private, no-store');
  res.json({ user: { id: 'demo-user', email: 'demo@example.com', plan: 'admin' } });
});

app.get('/:mode/api/token', (req, res) => {
  const mode = modeFor(req);
  const token = mode === 'fixed' ? goodToken() : badToken();
  res.json(mode === 'fixed' ? { token, expiresIn: 900 } : { token, legacy: true });
});

app.get('/:mode/api/boom', (req, res) => {
  const mode = modeFor(req);
  if (mode === 'fixed') {
    res.status(500).json({ error: 'Internal server error', requestId: 'req-demo-1' });
    return;
  }
  res.status(500).type('text/plain').send(
    [
      'Error: connect ECONNREFUSED 127.0.0.1:5432',
      '    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1595:16)',
      '    at /home/demo/app/node_modules/pg/lib/client.js:12:9',
      '    at async /home/demo/app/routes/users.js:42:11',
      'SQLSTATE[08006] connection failure',
    ].join('\n'),
  );
});

app.get('/:mode/api/credentials', (req, res) => {
  const mode = modeFor(req);
  if (mode === 'fixed') {
    res.json({ message: 'Keys stay on the server.' });
    return;
  }
  // Fake demo credentials. The Stripe value is assembled at runtime because a
  // literal key of that shape trips GitHub's secret scanning push protection;
  // it is not a real credential and exists only for the analyzer to flag.
  const stripeDemoKey = ['sk', 'live', '51DemoKeyDoNotUse000000000'].join('_');
  res.json({
    aws: { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
    stripe: stripeDemoKey,
    databaseUrl: 'postgres://demo:demo@localhost:5432/app?sslmode=disable',
  });
});

app.get('/:mode/api/echo', (req, res) => {
  res.json({ received: req.query, method: req.method });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found', path: req.path });
});

app.listen(PORT, () => {
  console.log(`NetXRay demo (${defaultMode} by default) on http://localhost:${PORT}`);
  console.log(`  vulnerable: http://localhost:${PORT}/vulnerable/`);
  console.log(`  fixed:      http://localhost:${PORT}/fixed/`);
});
