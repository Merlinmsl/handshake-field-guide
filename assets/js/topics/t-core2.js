/* Core web: sessions & cookies, API keys, JWT */
(function () {
  'use strict';
  const HS = window.HS, C = window.C;

  /* ---------------- Sessions & cookies ---------------- */
  HS.add({
    id: 'sessions', group: 'core', short: 'Sessions & cookies', icon: 'browser',
    title: 'Sessions & Cookies',
    tagline: 'How websites remember you are logged in across a stateless protocol. The default for traditional web apps, and the home of two famous attacks — CSRF and session hijacking — that interviewers always probe.',
    level: 'Beginner', kind: 'Stateful / server-side',
    spec: [['State lives', 'Server-side'], ['Client holds', 'Opaque session ID'], ['Transport', 'Cookie header'], ['Revocable', 'Yes, instantly']],
    analogy: `<p>A nightclub gives you a wristband at the door after checking your ID. Inside, you don't re-show ID at every bar — you flash the wristband. The wristband itself says nothing about you; the club keeps a list matching band numbers to who was admitted. Lose the wristband and whoever finds it is "you" until the club voids that number.</p><p>The session ID in your cookie is that wristband: an opaque reference, meaningless on its own, pointing at state the server holds.</p>`,
    flow: {
      nodes: [
        { id: 'b', label: 'Browser', sub: 'cookie jar', icon: 'browser', x: 100, y: 150 },
        { id: 's', label: 'App server', sub: 'session logic', icon: 'server', x: 360, y: 90 },
        { id: 'st', label: 'Session store', sub: 'Redis / DB', icon: 'db', x: 565, y: 150 },
      ],
      order: ['b', 's', 'st'],
      normal: {
        name: 'Login then reuse', summary: 'Login creates server-side state keyed by a random ID; the browser stores that ID in a cookie and the server attaches it automatically to every later request.',
        steps: [
          { f: 'b', t: 's', k: 'req', l: 'POST /login user+pass', title: 'User logs in', d: 'Credentials are posted once over TLS.', data: { 'POST': '/login', body: 'username=sakitha&password=…' }, enc: true, port: 'TLS 443' },
          { f: 's', t: 'st', k: 'req', l: 'create session record', title: 'Server creates session state', d: 'On success the server generates a long random session ID and stores the real state (user id, roles, CSRF token, expiry) against it.', data: { sid: 's:9fK2a7… (128-bit random)', value: '{ user:8842, role:editor, exp:+30m }' } },
          { f: 's', t: 'b', k: 'res', l: 'Set-Cookie: sid=…; HttpOnly', title: 'Hand back only the ID', d: 'The response sets a cookie containing <em>only</em> the opaque ID, flagged <code>HttpOnly; Secure; SameSite</code> so script can\'t read it and it rides only over HTTPS.', data: { 'Set-Cookie': 'sid=s%3A9fK2a7…; HttpOnly; Secure; SameSite=Lax; Max-Age=1800' }, ok: 'Logged in — browser stores the cookie' },
          { f: 'b', t: 's', k: 'req', l: 'GET /dashboard (Cookie: sid)', title: 'Next request carries the cookie', d: 'The browser automatically attaches the cookie to every same-site request. The user never re-enters a password.', data: { 'GET': '/dashboard', 'Cookie': 'sid=s%3A9fK2a7…' } },
          { f: 's', t: 'st', k: 'req', l: 'look up sid', title: 'Server resolves the ID', d: 'The server looks the ID up in its store to recover who you are. If found and not expired, you\'re authenticated for this request.', data: { lookup: 's:9fK2a7…', found: '{ user:8842, role:editor }', expired: false } },
          { f: 's', t: 'b', k: 'res', l: '200 OK — your dashboard', title: 'Served as you', d: 'Identity is re-established from server state on every request. Logout or an admin can delete the record to revoke instantly.', data: { status: 200, revocation: 'delete record = instant logout' }, ok: 'Authenticated via session lookup' },
        ],
      },
      attack: {
        name: 'CSRF — riding your cookie', summary: 'Because browsers attach cookies automatically, a malicious page can make your browser send an authenticated request you never intended. The SameSite attribute and CSRF tokens stop it.',
        steps: [
          { f: 'b', t: 'b', k: 'int', l: 'already logged in to bank.com', title: 'You hold a live session', d: 'You logged into your bank in one tab; the browser holds a valid <code>bank.com</code> session cookie.', data: { cookie: 'sid=live-session', site: 'bank.com' } },
          { f: 'b', t: 'b', k: 'atk', l: 'you open evil.com in another tab', title: 'You visit a malicious page', d: 'In another tab you open an attacker\'s page, which contains a hidden auto-submitting form targeting the bank.', data: { page: 'evil.com', hidden_form: 'POST bank.com/transfer amount=5000 to=attacker' } },
          { f: 'b', t: 's', k: 'atk', l: 'POST /transfer (+ your cookie!)', title: 'Browser attaches your cookie', d: 'The browser sends the forged request to the bank and — by default — includes your bank cookie, because cookies are attached by destination, not by which page triggered the request.', data: { 'POST': 'bank.com/transfer', 'Cookie': 'sid=live-session (auto-attached)', origin: 'evil.com' } },
          { f: 's', t: 's', k: 'int', l: 'defense: SameSite + CSRF token', title: 'What stops it', d: 'A <code>SameSite=Lax/Strict</code> cookie is not sent on this cross-site POST, so the request arrives unauthenticated. Even without that, the server requires a secret CSRF token that evil.com cannot read (same-origin policy), so the forged request is missing it.', data: { 'SameSite': 'cookie withheld on cross-site POST', 'CSRF token': 'missing / wrong → reject', result: 'request refused' }, ok: 'Defended: SameSite cookie + CSRF token' },
          { f: 's', t: 'b', k: 'res', l: '403 — CSRF token missing', title: 'Forged request rejected', d: 'With either defence in place the transfer never happens. This is why session-cookie apps must always pair cookies with CSRF protection.', data: { status: 403, reason: 'CSRF validation failed' }, fail: 'Attack blocked (undefended apps would transfer!)' },
        ],
      },
    },
    basics: `
      <p>HTTP is <em>stateless</em> — each request stands alone, with no memory of the last. Sessions add memory. After you log in, the server keeps your state and hands your browser a small token (the session ID) in a cookie. The browser sends that cookie back on every request, and the server uses it to look you up.</p>
      <p>The crucial design point: the cookie holds an <strong>opaque reference</strong>, not your data. Your roles, permissions and identity live in the server's session store (memory, Redis, or a database). The cookie is just a claim-ticket. This is the opposite of a <a href="#jwt">JWT</a>, where the data travels in the token itself.</p>
      <h4>The cookie flags that matter</h4>
      <ul>
        <li><code>HttpOnly</code> — JavaScript cannot read the cookie, blunting cookie theft via XSS.</li>
        <li><code>Secure</code> — the cookie is sent only over HTTPS.</li>
        <li><code>SameSite=Lax|Strict|None</code> — controls whether the cookie rides on cross-site requests; the main built-in CSRF defence.</li>
        <li><code>Max-Age</code>/<code>Expires</code>, <code>Domain</code>, <code>Path</code> — scope and lifetime.</li>
      </ul>`,
    deep: `
      <h3>Stateful vs stateless auth — the headline trade-off</h3>
      <p>Sessions are <em>stateful</em>: the server is the source of truth, so you can revoke a session instantly (delete the record) and store as much as you like. The cost is that every server handling a request needs access to the session store, which matters when you scale out.</p>
      <p>Approaches to that scaling problem are a favourite interview thread:</p>
      <ul>
        <li><b>Sticky sessions</b> — the load balancer pins a user to one server. Simple, but that server becomes a single point of failure and rebalancing is painful.</li>
        <li><b>Shared session store</b> — all servers read/write a central Redis/DB. The standard answer; adds a network hop and a dependency.</li>
        <li><b>Stateless tokens</b> — push the state into a signed token so no lookup is needed. That's JWTs, with their own revocation headaches.</li>
      </ul>
      <h3>Session fixation</h3>
      <p>A subtle attack: if the server reuses the pre-login session ID after you authenticate, an attacker who planted a known ID in your browser beforehand now shares your authenticated session. The fix is one line of discipline — <b>regenerate the session ID on privilege change (login)</b> — and interviewers love to hear it unprompted.</p>
      <h3>Where to store the ID client-side</h3>
      <p>Cookies (with the flags above) are generally safer than <code>localStorage</code> for session IDs, because <code>HttpOnly</code> hides them from script. Tokens kept in <code>localStorage</code> are readable by any XSS on the page. The trade-off: cookies are auto-attached (hence CSRF), tokens in headers are not (no CSRF, but XSS-exposed). There's no free lunch — you pick which attack class to defend hardest against.</p>`,
    howto: `
      <p>Frameworks handle the mechanics; your job is the flags and the regeneration:</p>
      ${C('javascript', `
        // Express — secure session cookie settings
        app.use(session({
          secret: process.env.SESSION_SECRET,
          name: 'sid',
          resave: false,
          saveUninitialized: false,
          store: new RedisStore({ client }),   // shared store, scales out
          cookie: {
            httpOnly: true,        // JS can't read it
            secure: true,          // HTTPS only
            sameSite: 'lax',       // CSRF defence for top-level POSTs
            maxAge: 30 * 60 * 1000 // 30 min
          }
        }));

        app.post('/login', async (req, res) => {
          const user = await verify(req.body);          // check password hash
          req.session.regenerate(() => {                 // STOP session fixation
            req.session.userId = user.id;
            res.redirect('/dashboard');
          });
        });
      `, 'Hardened session configuration')}
      <div class="callout"><b>Always pair cookies with CSRF defence</b>Use <code>SameSite</code> cookies <em>and</em>, for sensitive actions, a synchroniser or double-submit CSRF token. Treat them as belt and braces, not either/or.</div>
      <p>The playground below shows exactly what a session cookie looks like on the wire versus other schemes.</p>`,
    tool: 'apikey',
    pros: ['Instantly revocable — delete the record to log out everywhere', 'Opaque ID leaks no user data if intercepted', 'Server controls all state; easy to store rich context', 'Mature, battle-tested framework support', 'HttpOnly cookie resists script-based theft'],
    cons: ['Requires server-side storage, a scaling concern', 'Every node needs the session store (sticky sessions or shared cache)', 'Cookies are auto-attached → CSRF risk needing its own defence', 'Cross-domain / mobile-API use is awkward compared to tokens', 'A lookup on every request adds latency'],
    history: [
      ['1994', 'Netscape invents the HTTP cookie to add state to the stateless web — originally for a shopping cart.'],
      ['1997', 'RFC 2109 standardises cookies; session IDs become the default web login mechanism.'],
      ['2001', 'The term "cross-site request forgery" is coined, naming the cookie model\'s structural weakness.'],
      ['2016', 'The SameSite cookie attribute is introduced to curb CSRF at the browser level.'],
      ['2020', 'Chrome makes SameSite=Lax the default, quietly killing a large class of CSRF.'],
    ],
    hidden: [
      ['SameSite=Lax is the Chromium default', 'Chrome and other Chromium-based browsers treat cookies without a SameSite attribute as Lax (Firefox and Safari don\'t apply that default), so many legacy CSRF attacks simply stop working — but never rely on it alone; older clients and GET-based actions still need care.'],
      ['Regenerating the ID on login is free security', 'A single call prevents session fixation. Forgetting it is a classic finding in security audits.'],
      ['Cookies are attached by destination, not origin', 'The reason CSRF exists: the browser decides whether to send a cookie based on where the request is going, not which page launched it. Internalise this and CSRF suddenly makes sense.'],
      ['"Remember me" is a second, longer-lived token', 'Persistent login uses a separate long-lived token that mints fresh sessions. If mishandled it becomes a permanent backdoor, so it needs its own rotation and revocation.'],
    ],
    attacks: [
      ['CSRF (cross-site request forgery)', 'A malicious page triggers an authenticated request using your auto-attached cookie.', 'SameSite cookies + synchroniser/double-submit CSRF tokens; require re-auth for sensitive actions.'],
      ['Session hijacking', 'An attacker steals the session ID (sniffing, XSS) and impersonates you.', 'TLS everywhere, HttpOnly + Secure cookies, bind sessions to context, short expiry.'],
      ['Session fixation', 'Attacker pre-sets a known session ID, then you log in to it.', 'Regenerate the session ID on login/privilege change.'],
      ['XSS cookie theft', 'Injected script reads document.cookie and exfiltrates it.', 'HttpOnly flag; fix the XSS; a strong Content-Security-Policy.'],
    ],
    interview: [
      ['Where is the actual user data stored in cookie-based sessions?', '<p>On the <b>server</b>. The cookie holds only an opaque, random session ID; the real state (user id, roles, expiry) lives in a server-side store like Redis or a database. The server looks the ID up on each request. That\'s the key contrast with JWTs, where the data travels inside the token.</p>', 'junior'],
      ['What is CSRF and why do cookies make it possible?', '<p>Cross-Site Request Forgery tricks your browser into sending an authenticated request you didn\'t intend — e.g. a hidden form on a malicious page POSTing to your bank. It works because the browser <b>auto-attaches cookies by destination</b>, so the forged request carries your live session cookie. Defences: <code>SameSite</code> cookies so the cookie isn\'t sent cross-site, and a secret CSRF token the attacker\'s origin can\'t read.</p>', 'mid'],
      ['How do you scale session-based auth across many servers?', '<p>The state has to be reachable by whichever server handles a request. Options: <b>sticky sessions</b> (LB pins the user to one node — simple but fragile), a <b>shared session store</b> (central Redis/DB — the common choice, adds a hop and a dependency), or going <b>stateless with signed tokens</b> (no lookup, but you lose easy revocation). I\'d default to a shared Redis store and reach for tokens only if the lookup latency or cross-service reach truly demanded it.</p>', 'senior'],
      ['Cookie vs localStorage for storing an auth token — which and why?', '<p>Prefer an <code>HttpOnly</code> cookie for the session identifier: script can\'t read it, so XSS can\'t directly steal it, though you then owe CSRF defence. <code>localStorage</code> is readable by any JavaScript on the page, so a single XSS exfiltrates the token — but it\'s not auto-attached, so no CSRF. You\'re choosing which attack to harden against; for most apps HttpOnly cookies + CSRF tokens is the safer default.</p>', 'mid'],
    ],
    quiz: [
      { q: 'What does a session cookie actually contain in the classic model?', o: ['The user\'s roles and data', 'An opaque random session ID', 'An encrypted password', 'A signed JWT'], a: 1, e: 'The cookie holds only a reference; the real state lives server-side. That\'s the defining property of session-based auth.' },
      { q: 'Which cookie attribute is the primary built-in defence against CSRF?', o: ['HttpOnly', 'Secure', 'SameSite', 'Path'], a: 2, e: 'SameSite controls whether the cookie is sent on cross-site requests. HttpOnly defends against XSS theft, Secure enforces HTTPS.' },
      { q: 'You must regenerate the session ID on login to prevent…', o: ['CSRF', 'Session fixation', 'Rainbow tables', 'Replay of JWTs'], a: 1, e: 'Reusing a pre-login ID lets an attacker who planted it share your authenticated session. Regenerating on login stops fixation.' },
      { q: 'A big advantage of server-side sessions over stateless tokens is…', o: ['No server storage needed', 'Instant revocation by deleting the record', 'They work without cookies', 'They never expire'], a: 1, e: 'Because state is server-side, you can revoke a session immediately — the classic pain point of stateless JWTs.' },
    ],
    related: ['concepts', 'jwt', 'basic-auth', 'oauth'],
  });

  /* ---------------- API keys ---------------- */
  HS.add({
    id: 'api-keys', group: 'core', short: 'API keys', icon: 'key',
    title: 'API Keys',
    tagline: 'The simplest way to let one program call another. A single long string that is both your name and your password. Easy to start with, easy to leak — the trade-offs here teach you why richer token schemes exist.',
    level: 'Beginner', kind: 'Machine-to-machine',
    spec: [['Identifies', 'An application, not a user'], ['Transport', 'Authorization / custom header'], ['Secrecy', 'Bearer — whoever holds it, uses it'], ['Expiry', 'Usually none unless rotated']],
    analogy: `<p>An API key is like the key to a storage unit. It doesn't prove <em>who</em> you are — it just opens the door, and anyone holding it can open the same door. There's no PIN pad, no photo ID. That makes it effortless to hand to a trusted contractor (your backend service) and terrifying if it falls out of your pocket (gets committed to GitHub).</p>`,
    flow: {
      nodes: [
        { id: 'app', label: 'Your service', sub: 'holds the key', icon: 'server', x: 110, y: 150 },
        { id: 'gw', label: 'API gateway', sub: 'key check', icon: 'net', x: 360, y: 90 },
        { id: 'api', label: 'Upstream API', sub: 'the data', icon: 'cloud', x: 565, y: 150 },
      ],
      order: ['app', 'gw', 'api'],
      normal: {
        name: 'A key-authenticated call', summary: 'The caller attaches a secret key to each request; the gateway looks it up, finds the owning account and its scopes, and forwards the call.',
        steps: [
          { f: 'app', t: 'gw', k: 'req', l: 'GET /charges  Authorization: Bearer sk_live_…', title: 'Request carries the key', d: 'Your backend attaches the key in a header on every request, over TLS. The key is both identity and secret.', data: { 'GET': '/v1/charges', 'Authorization': 'Bearer sk_live_8fK2…9aD1' }, enc: true, port: 'TLS 443' },
          { f: 'gw', t: 'gw', k: 'int', l: 'hash key → look up account', title: 'Gateway validates', d: 'The gateway hashes the presented key and looks up the stored hash (keys should be stored hashed, like passwords). It finds the owning account, its plan, scopes and rate limit.', data: { lookup: 'sha256(key) → acct_42', scopes: 'charges:read', rate_limit: '100/min', valid: true } },
          { f: 'gw', t: 'api', k: 'req', l: 'forward as acct_42', title: 'Forward with identity', d: 'Having authenticated the key, the gateway forwards the request tagged with the resolved account and enforces its scopes and quota.', data: { account: 'acct_42', allowed: 'scope charges:read ✓' } },
          { f: 'api', t: 'app', k: 'res', l: '200 OK + data', title: 'Response returned', d: 'The upstream returns the data. Every future call repeats the exact same key — there is no handshake or session.', data: { status: 200, note: 'same key reused indefinitely until rotated' }, ok: 'Authenticated as acct_42' },
        ],
      },
      attack: {
        name: 'A leaked key in a public repo', summary: 'Because a key is a bearer credential with no expiry, a single leak gives an attacker full access until someone notices and rotates it. Scoping and detection limit the blast radius.',
        steps: [
          { f: 'app', t: 'app', k: 'atk', l: 'key committed to GitHub', title: 'Accidental exposure', d: 'A developer hard-codes the key and pushes it to a public repo. Automated scanners crawl new commits within seconds.', data: { leaked: 'sk_live_8fK2…9aD1', where: 'public git history', found_in: '~seconds by bots' } },
          { f: 'app', t: 'gw', k: 'atk', l: 'attacker replays the key', title: 'Attacker uses it directly', d: 'No password, no second factor — the key <em>is</em> the access. The attacker calls the API as your account.', data: { 'Authorization': 'Bearer sk_live_8fK2…9aD1', origin: 'attacker host' } },
          { f: 'gw', t: 'gw', k: 'int', l: 'scoping + anomaly detection', title: 'What limits the damage', d: 'Least-privilege scopes mean a read-only key can\'t delete or move money. Anomaly detection (new IP, rate spike) and provider-side secret scanning flag the misuse.', data: { scope: 'read-only → no writes possible', signals: 'new IP + rate spike → alert', provider: 'secret-scanning auto-revokes' } },
          { f: 'gw', t: 'app', k: 'res', l: 'key revoked & rotated', title: 'Contain and rotate', d: 'The key is revoked and a new one issued. The lesson: keys need rotation, scoping, secret storage and leak detection precisely because they never expire on their own.', data: { action: 'revoke old, issue new', prevention: 'env vars + secret manager, never in code' }, ok: 'Contained — rotate immediately on any leak' },
        ],
      },
    },
    basics: `
      <p>An API key is a single secret string that a client sends to identify and authenticate itself to an API. Unlike a session, it typically represents an <em>application or account</em>, not a logged-in human, and it's the staple of machine-to-machine and server-to-server calls.</p>
      <p>Its defining trait is that it is a <strong>bearer credential</strong>: possession is everything. There's no proof of who's holding it, so whoever has the string has the access. That simplicity is the whole appeal and the whole danger.</p>
      <p>Send it in a header, never in the URL:</p>
      ${C('http', `
        GET /v1/charges HTTP/1.1
        Host: api.example.com
        Authorization: Bearer sk_live_8fK2a7Qx9aD1
        # some APIs use a custom header, e.g.  X-API-Key: sk_live_…
      `, 'An API-key request')}
      <div class="callout warn"><b>Keys in URLs leak</b>A key in a query string (<code>?api_key=…</code>) ends up in server logs, browser history, proxy caches and the <code>Referer</code> header. Always use a header.</div>`,
    deep: `
      <h3>Good API-key hygiene</h3>
      <ul>
        <li><b>Store them hashed.</b> On the server side, keep only a hash of the key (like a password), so a database breach doesn't hand out live keys. Show the plaintext to the user only once, at creation.</li>
        <li><b>Prefix and label them.</b> Stripe-style prefixes (<code>sk_live_</code>, <code>pk_test_</code>) let both humans and automated secret-scanners recognise and classify a key instantly.</li>
        <li><b>Scope to least privilege.</b> A key that only reads shouldn't be able to write. Separate keys per environment and per integration.</li>
        <li><b>Rotate regularly and support dual keys</b> so you can roll over without downtime.</li>
        <li><b>Rate-limit and monitor per key</b> to cap abuse and spot leaks via anomalies.</li>
      </ul>
      <h3>API key vs JWT vs OAuth — when to use which</h3>
      <p>This comparison is a frequent interview question:</p>
      <ul>
        <li><b>API key</b> — simplest; good for server-to-server where one app calls another and you control both ends. No user context, no built-in expiry.</li>
        <li><b>JWT</b> — self-contained, carries claims (user, roles, expiry), verifiable without a lookup; good when you need identity and short-lived access.</li>
        <li><b>OAuth 2.0</b> — when a user delegates access to their data to a third-party app without sharing their password; issues scoped, expiring tokens.</li>
      </ul>
      <h3>HMAC-signed requests: the grown-up API key</h3>
      <p>Cloud providers (notably AWS) don't send the secret at all. Instead the client uses the secret to compute an HMAC signature over the request, and sends the signature. The server recomputes it. The secret never travels, and the signature covers the request contents so it can't be tampered with or (with a timestamp) replayed. See the dedicated <a href="#hmac-sig">HMAC request signing</a> page.</p>`,
    howto: `
      <p>Keep keys out of code and in the environment or a secret manager:</p>
      ${C('javascript', `
        // ✗ never
        const key = "sk_live_8fK2a7Qx9aD1";

        // ✓ from environment / secret manager, injected at deploy
        const key = process.env.PAYMENTS_API_KEY;

        await fetch("https://api.example.com/v1/charges", {
          headers: { Authorization: \`Bearer \${key}\` }   // header, not URL
        });
      `, 'Loading a key safely')}
      <ul>
        <li>Add the key file / <code>.env</code> to <code>.gitignore</code>; use pre-commit secret scanners.</li>
        <li>In CI/CD and cloud, inject keys as masked secrets, not plaintext config.</li>
        <li>On any suspicion of leak: revoke first, investigate second.</li>
      </ul>
      <p>The playground lets you compare what travels on an API-key request versus Basic, Bearer and session schemes.</p>`,
    tool: 'apikey',
    pros: ['Dead simple to issue and use', 'Perfect for server-to-server where you own both ends', 'Stateless — no login handshake', 'Easy to scope and rate-limit per key', 'Language- and platform-agnostic'],
    cons: ['Bearer credential: whoever holds it has full access', 'Usually no built-in expiry — a leak lasts until noticed', 'No user identity or delegation', 'Frequently leaked via code, logs and URLs', 'No standard; every API invents its own header and format'],
    history: [
      ['2000s', 'Public web APIs (Flickr, Google Maps, Twitter) popularise simple keys for developer access and quota tracking.'],
      ['2010s', 'Growth of secret-scanning as leaked keys on GitHub become a routine incident class.'],
      ['2011→', 'AWS Signature (HMAC-signed requests) shows the more secure alternative to sending raw keys.'],
      ['2020s', 'Providers add key prefixes, fine-grained scopes and auto-revocation on detected leaks.'],
    ],
    hidden: [
      ['GitHub leak bots are instant', 'Automated scanners detect new secret commits within seconds and some providers auto-revoke. Assume a committed key is compromised the moment it\'s pushed — rotate, don\'t just delete the commit.'],
      ['Prefixes exist for machines, not looks', 'That <code>sk_live_</code> prefix lets scanners and the provider classify a key without decoding it, and tells you at a glance it\'s a secret, live key — don\'t strip them.'],
      ['"Bearer" is literal', 'The word "Bearer" in the header means exactly what it says in finance — a bearer bond belongs to whoever holds it. The scheme assumes the holder is authorised; there is no further check.'],
      ['Keys often outlive the projects that made them', 'Because they rarely expire, old keys linger in forgotten scripts and VMs for years, a common path into "how did they still have access?" breaches.'],
    ],
    attacks: [
      ['Accidental leak', 'Key committed to a repo, printed in logs, or placed in a URL.', 'Secret managers, header-only transport, secret scanning, prefixes, rotation.'],
      ['Over-privileged key abuse', 'A broadly scoped key is used far beyond its intended purpose.', 'Least-privilege scopes, separate keys per integration/environment.'],
      ['Replay / sharing', 'The same key is reused forever and freely copied.', 'HMAC-signed requests with timestamps; short-lived tokens where possible.'],
      ['No expiry', 'A forgotten key stays valid indefinitely.', 'Forced rotation policies, expiry dates, usage-based reaping of idle keys.'],
    ],
    interview: [
      ['What does an API key authenticate — a user or an application?', '<p>Typically an <b>application or account</b>, not an individual user. It\'s a bearer credential for machine-to-machine calls: whoever holds the string gets the access, with no user identity or delegation attached. If you need per-user identity or a user granting access to a third party, that points to JWTs or OAuth instead.</p>', 'junior'],
      ['Your API key just got committed to a public repo. What now, and how do you prevent it?', '<p>Assume it\'s compromised immediately — scanners find public secrets in seconds. <b>Revoke/rotate first</b>, then investigate usage via logs. Prevention: load keys from environment or a secret manager (never hard-code), add <code>.env</code> to <code>.gitignore</code>, run pre-commit and CI secret scanning, use recognisable prefixes, scope keys to least privilege so the blast radius is small, and enable provider-side leak auto-revocation.</p>', 'mid'],
      ['API key vs JWT vs OAuth — when would you choose each?', '<p><b>API key</b>: simplest, for server-to-server where you own both ends and need no user context. <b>JWT</b>: when you want a self-contained, verifiable token carrying identity/roles and a short expiry, checkable without a central lookup. <b>OAuth 2.0</b>: when a user delegates access to their data to a third-party app without sharing credentials, yielding scoped, expiring tokens. They\'re not exclusive — OAuth issues JWTs, and gateways may sit in front of all three.</p>', 'senior'],
      ['Why send an API key in a header rather than the query string?', '<p>Query strings leak into places you don\'t control: web-server access logs, browser history, proxy and CDN caches, and the <code>Referer</code> header sent to third parties. A header (<code>Authorization</code> or a custom <code>X-API-Key</code>) avoids all of that, and of course the whole thing must be over TLS so the header itself isn\'t sniffed.</p>', 'mid'],
    ],
    quiz: [
      { q: 'An API key is best described as…', o: ['A signed token carrying user claims', 'A bearer credential — possession equals access', 'An encrypted password', 'A short-lived session'], a: 1, e: 'Whoever holds the key has the access; there\'s no proof of identity beyond possession. That\'s its strength and its danger.' },
      { q: 'Where should an API key travel?', o: ['In the URL query string', 'In a request header over TLS', 'In a cookie set by JavaScript', 'In the page title'], a: 1, e: 'Headers over HTTPS keep the key out of logs, history, caches and Referer headers.' },
      { q: 'Why store API keys hashed on the server?', o: ['To make them shorter', 'So a database breach doesn\'t expose live keys', 'To encrypt the traffic', 'To allow longer expiry'], a: 1, e: 'Like passwords, keys should be stored as hashes so a leaked database can\'t be used directly. Show the plaintext only once at creation.' },
      { q: 'The main risk unique to API keys versus session tokens is…', o: ['They can\'t use TLS', 'They usually never expire, so a leak lasts until noticed', 'They require a login form', 'They can\'t be rate-limited'], a: 1, e: 'Keys are long-lived bearer secrets with no built-in expiry, so leaks persist until someone rotates them — hence scoping, rotation and detection matter.' },
    ],
    related: ['basic-auth', 'jwt', 'oauth', 'hmac-sig'],
  });

  /* ---------------- JWT ---------------- */
  HS.add({
    id: 'jwt', group: 'core', short: 'JWT', icon: 'ticket',
    title: 'JSON Web Tokens (JWT)',
    tagline: 'A signed, self-contained token that carries its own claims. The engine behind most modern stateless APIs and the currency OAuth and OIDC hand out. Loved for scaling, infamous for its footguns.',
    level: 'Intermediate', kind: 'Stateless / self-contained',
    spec: [['Defined in', 'RFC 7519'], ['Shape', 'header.payload.signature'], ['Common alg', 'HS256, RS256, ES256'], ['Encoding', 'Base64URL (not encrypted)']],
    analogy: `<p>A JWT is a festival wristband with your details printed on it and the organiser's tamper-proof holographic seal across it. Any staff member can read your details and check the seal <em>without phoning head office</em> — that's what makes it fast and scalable. But the printing is in plain sight (don't print secrets on it), and once issued, a wristband is valid until it expires; you can't easily un-issue one already on someone's wrist.</p>`,
    flow: {
      nodes: [
        { id: 'c', label: 'Client', sub: 'holds token', icon: 'browser', x: 100, y: 150 },
        { id: 'auth', label: 'Auth service', sub: 'signs tokens', icon: 'idp', x: 360, y: 80 },
        { id: 'api', label: 'API service', sub: 'verifies locally', icon: 'server', x: 565, y: 170 },
      ],
      order: ['c', 'auth', 'api'],
      normal: {
        name: 'Issue once, verify everywhere', summary: 'The auth service signs a token once. Every API can then verify it locally with the public key — no database lookup, no call back to the auth service.',
        steps: [
          { f: 'c', t: 'auth', k: 'req', l: 'POST /login user+pass', title: 'Authenticate once', d: 'The client proves identity to the auth service.', data: { 'POST': '/login', body: 'username + password' }, enc: true, port: 'TLS 443' },
          { f: 'auth', t: 'auth', k: 'int', l: 'build claims, sign', title: 'Mint and sign the token', d: 'The service builds a claims payload and signs <code>base64url(header).base64url(payload)</code> with its private key (RS256) or a shared secret (HS256).', data: { header: '{ alg: RS256, typ: JWT }', payload: '{ sub:8842, role:editor, exp:+15m }', signature: 'sign(header.payload, privateKey)' } },
          { f: 'auth', t: 'c', k: 'res', l: 'eyJ…​.eyJ…​.sig', title: 'Return the JWT', d: 'The three Base64URL parts, dot-joined, go back to the client. The payload is readable by anyone — it is signed, not encrypted.', data: { token: 'eyJhbGc….eyJzdWI….K3f9…', storage: 'memory / cookie', readable: 'yes — never put secrets inside' }, ok: 'Token issued (self-contained)' },
          { f: 'c', t: 'api', k: 'req', l: 'GET /orders  Bearer eyJ…', title: 'Call any API with it', d: 'The client sends the token to a completely different service, which has never seen this user before.', data: { 'GET': '/orders', 'Authorization': 'Bearer eyJhbGc….eyJzdWI….K3f9…' } },
          { f: 'api', t: 'api', k: 'int', l: 'verify signature + exp locally', title: 'Verify without a lookup', d: 'The API checks the signature with the auth service\'s <em>public</em> key (fetched once from its JWKS) and checks <code>exp</code>, <code>iss</code>, <code>aud</code>. No network call, no shared session store.', data: { verify: 'signature valid (public key)', exp: 'not expired', aud: 'orders-api ✓', lookup: 'NONE needed' }, ok: 'Verified locally — this is why JWTs scale' },
          { f: 'api', t: 'c', k: 'res', l: '200 OK + orders', title: 'Served statelessly', d: 'Identity and permissions came entirely from the trusted token. Add more API services and none of them need to coordinate.', data: { status: 200, scaling: 'any service verifies independently' }, ok: 'Stateless auth achieved' },
        ],
      },
      attack: {
        name: 'The alg:none / tamper attempt', summary: 'Since the payload is public and editable, attackers try to change claims or strip the signature. A correct verifier defeats both — but only if it is configured correctly.',
        steps: [
          { f: 'c', t: 'c', k: 'atk', l: 'edit payload: role → admin', title: 'Tamper with the claims', d: 'The attacker Base64-decodes the payload, flips <code>role: editor</code> to <code>role: admin</code>, and re-encodes it. The payload is not secret, so this part is trivial.', data: { before: 'role: editor', after: 'role: admin', note: 'payload is only encoded, not encrypted' } },
          { f: 'c', t: 'api', k: 'atk', l: 'send tampered token', title: 'Present the forged token', d: 'The edited token goes to the API. But changing the payload breaks the signature, which was computed over the original bytes.', data: { payload: 'changed', signature: 'still the OLD one — no longer matches' } },
          { f: 'api', t: 'api', k: 'int', l: 'recompute signature → mismatch', title: 'Signature check fails', d: 'The API recomputes the signature over the received header+payload and compares. It doesn\'t match, so the token is rejected. The attacker can\'t forge a new signature without the key.', data: { expected: 'sign(newPayload) ≠ received sig', result: 'REJECT' }, fail: 'Tampered token rejected' },
          { f: 'c', t: 'api', k: 'atk', l: 'try alg:none (no signature)', title: 'The alg:none trick', d: 'The attacker instead sets the header to <code>alg: none</code> and removes the signature entirely — betting the server will "verify" a token that claims to need no verification.', data: { header: '{ alg: "none" }', signature: '(empty)', hope: 'server skips verification' } },
          { f: 'api', t: 'api', k: 'int', l: 'reject alg:none; pin algorithm', title: 'Correct verifier refuses', d: 'A properly configured verifier rejects <code>none</code> and pins the expected algorithm, so this famous attack fails. Vulnerable libraries from the 2010s did not — hence its fame.', data: { policy: 'allowed algs = [RS256] only', 'alg:none': 'rejected', lesson: 'always pin the algorithm' }, ok: 'Defended — pin algs, reject none' },
        ],
      },
    },
    basics: `
      <p>A JWT (pronounced "jot") is a compact, URL-safe token made of three Base64URL parts joined by dots:</p>
      ${C('text', `
        eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9  .  eyJzdWIiOiI4ODQyIiwicm9sZSI6ImVkaXRvciJ9  .  K3f9Qx…sig
        └────────── header ──────────┘        └──────────── payload (claims) ───────────┘    └ signature ┘
      `, 'The three parts of a JWT')}
      <ul>
        <li><b>Header</b> — the algorithm and token type, e.g. <code>{ "alg": "RS256", "typ": "JWT" }</code>.</li>
        <li><b>Payload</b> — the <em>claims</em>: statements about the user and token. Standard ones include <code>sub</code> (subject/user), <code>iss</code> (issuer), <code>aud</code> (audience), <code>exp</code> (expiry), <code>iat</code> (issued-at).</li>
        <li><b>Signature</b> — proves the first two parts were issued by someone holding the key and haven't been altered.</li>
      </ul>
      <div class="callout warn"><b>A JWT is signed, not encrypted</b>The header and payload are only Base64URL-<em>encoded</em> — anyone can read them. Never put passwords, card numbers or secrets in a JWT payload. (Encryption is a separate standard, JWE.)</div>
      <p>The magic is that the signature lets <em>any</em> service verify the token independently, so you don't need a central session store. That's what makes JWTs the natural fit for microservices and APIs.</p>`,
    deep: `
      <h3>HS256 vs RS256 — symmetric vs asymmetric</h3>
      <ul>
        <li><b>HS256 (HMAC-SHA256)</b> — one shared secret both signs and verifies. Simple, but every service that verifies must hold the secret, and any of them could therefore <em>forge</em> tokens. Fine within one trust boundary.</li>
        <li><b>RS256 / ES256 (asymmetric)</b> — the auth service signs with a <em>private</em> key; everyone else verifies with the <em>public</em> key. Verifiers can check but not mint tokens. This is what you want across service and organisational boundaries, and what OIDC uses.</li>
      </ul>
      <p>The public keys are published at a <b>JWKS</b> endpoint (<code>/.well-known/jwks.json</code>), which verifiers fetch and cache, keyed by the <code>kid</code> (key ID) in the header — enabling smooth key rotation.</p>
      <h3>The revocation problem — the big trade-off</h3>
      <p>A session can be deleted server-side to log someone out instantly. A JWT is valid until it expires, by design, because nobody checks a central store. So how do you "log out" or ban a compromised token? The standard answers (and a classic interview question):</p>
      <ul>
        <li><b>Short-lived access tokens</b> (5–15 min) + a long-lived <b>refresh token</b>. The access token can't be revoked, but it dies quickly; revocation is enforced at refresh time.</li>
        <li><b>A denylist/blocklist</b> of revoked token IDs (<code>jti</code>) — but this reintroduces the very server-side lookup JWTs were meant to avoid.</li>
        <li><b>Rotate the signing key</b> to invalidate everything at once (a blunt instrument).</li>
      </ul>
      <p>If you find yourself needing fine-grained instant revocation, that's often a sign sessions were the better fit. Knowing <em>when not</em> to use JWTs is a senior signal.</p>
      <h3>Validate everything, not just the signature</h3>
      <p>A valid signature only means "someone with the key issued this". You must also check <code>exp</code> (not expired), <code>nbf</code> (not before), <code>iss</code> (expected issuer), and <code>aud</code> (this token was meant for <em>my</em> service). Skipping <code>aud</code> lets a token minted for service A be replayed against service B.</p>`,
    howto: `
      <p>Lean on a vetted library and configure it strictly:</p>
      ${C('javascript', `
        import jwt from "jsonwebtoken";

        // sign (auth service) — short expiry, explicit algorithm
        const token = jwt.sign(
          { sub: user.id, role: user.role },
          privateKey,
          { algorithm: "RS256", expiresIn: "15m", issuer: "auth.example.com", audience: "orders-api" }
        );

        // verify (any API) — PIN the algorithm, check iss + aud
        const claims = jwt.verify(token, publicKey, {
          algorithms: ["RS256"],          // never allow "none" or a client-chosen alg
          issuer: "auth.example.com",
          audience: "orders-api"
        });
      `, 'Signing and strictly verifying a JWT')}
      <ul>
        <li>Always pass an explicit <code>algorithms</code> allow-list — this single line defeats the <code>alg:none</code> and HS/RS confusion attacks.</li>
        <li>Keep access tokens short; use refresh tokens for longevity.</li>
        <li>Store tokens carefully: an <code>HttpOnly</code> cookie resists XSS theft but needs CSRF defence; <code>localStorage</code> is the reverse trade-off (see <a href="#sessions">Sessions</a>).</li>
      </ul>
      <p>Use the decoder below to build, tamper with and verify tokens — watch the signature check catch every edit.</p>`,
    tool: 'jwt',
    pros: ['Stateless — verify locally with no database lookup, so it scales horizontally', 'Self-contained: carries identity and claims', 'Works cleanly across services and domains (great for microservices, SPAs, mobile)', 'Asymmetric signing lets many services verify but not forge', 'The standard token format OAuth/OIDC hand out'],
    cons: ['Hard to revoke before expiry — the defining weakness', 'Payload is readable; never store secrets in it', 'Footguns: alg:none, HS/RS confusion, unchecked aud/exp', 'Bigger than a session ID; sent on every request', 'If stored in localStorage, XSS steals it'],
    history: [
      ['2010–2013', 'JWT drafted at the IETF alongside the JOSE suite (JWS, JWE, JWK).'],
      ['2015', 'Critical "alg:none" and HMAC/RSA key-confusion vulnerabilities are disclosed across many JWT libraries.'],
      ['2015', 'RFC 7519 standardises JWT; it becomes the default token for OAuth 2.0 and OIDC.'],
      ['2015→', 'JWKS + kid-based key rotation and short-lived-access + refresh-token patterns become best practice.'],
      ['2020s', 'Ongoing debate — "stop using JWTs for sessions" — clarifies where they fit and where sessions win.'],
    ],
    hidden: [
      ['alg:none is the most famous JWT bug ever', 'Early libraries would "verify" a token whose header said <code>alg: none</code> — i.e. no signature at all. Always pin an algorithm allow-list; never trust the client-supplied alg.'],
      ['HS/RS key confusion', 'If a server will verify with either HMAC or RSA based on the token\'s own header, an attacker can take the public RSA key (which is public!) and use it as an HMAC secret to forge tokens. Pin the algorithm to stop this.'],
      ['The payload is a billboard', 'Developers routinely leak emails, internal IDs and roles because they forget the payload is world-readable. Decode any JWT at the playground and you\'ll see everything.'],
      ['"exp" is seconds, and clock skew bites', 'Expiry is a UNIX time in seconds, not milliseconds — a frequent bug. Verifiers usually allow a small leeway for clock skew between servers.'],
      ['You can\'t truly log out a JWT', 'Server-side "logout" for pure JWTs is a comforting illusion unless you add a denylist. The honest fix is short expiry plus refresh-token revocation.'],
    ],
    attacks: [
      ['alg:none', 'Attacker sets header alg to "none" and strips the signature, hoping verification is skipped.', 'Pin an explicit algorithm allow-list; reject "none".'],
      ['Algorithm confusion (HS/RS)', 'Attacker signs with the public key as an HMAC secret when the server accepts either.', 'Never let the token choose the algorithm; separate keys per algorithm.'],
      ['Tampering', 'Edit claims (e.g. role→admin) in the readable payload.', 'Signature verification catches any change — if you actually verify it.'],
      ['Token theft (XSS)', 'Script reads a JWT from localStorage and exfiltrates it.', 'HttpOnly cookies, short expiry, strong CSP; fix the XSS.'],
      ['Missing aud/exp checks', 'Replay a token meant for one service against another, or use an expired one.', 'Always validate iss, aud, exp, nbf — not just the signature.'],
    ],
    interview: [
      ['Is a JWT encrypted? Can I store a password in it?', '<p>No and no. A standard JWT is <b>signed, not encrypted</b> — the header and payload are only Base64URL-encoded and anyone can read them. Never put secrets (passwords, card numbers) in the payload. If you genuinely need confidentiality you use JWE (encrypted JWT), but usually you just avoid putting sensitive data in the token.</p>', 'junior'],
      ['Why do JWTs scale better than server-side sessions?', '<p>Because verification is <b>local and stateless</b>. Any service can validate a JWT using the issuer\'s (public) key and the claims inside it — checking the signature and <code>exp</code>/<code>iss</code>/<code>aud</code> — with no call back to an auth server or shared session store. Add more services and none of them need to coordinate. Sessions, by contrast, need every node to reach a central store.</p>', 'mid'],
      ['How do you revoke a JWT before it expires?', '<p>You largely can\'t, by design — that\'s the core trade-off. The standard mitigations: issue <b>short-lived access tokens</b> (minutes) with a <b>long-lived refresh token</b>, so revocation is enforced when the client tries to refresh; keep a <b>denylist of <code>jti</code> values</b> for emergency revocation (accepting that this reintroduces a lookup); or rotate the signing key to invalidate everything. If you need instant, fine-grained revocation routinely, sessions are probably the better choice.</p>', 'senior'],
      ['What is the alg:none attack and how do you prevent it?', '<p>Some early JWT libraries honoured a header of <code>alg: none</code>, meaning "no signature" — so an attacker could forge any claims and strip the signature, and the server would accept it. Prevention is one rule: <b>never trust the algorithm declared in the token</b>. Configure the verifier with an explicit allow-list (e.g. <code>["RS256"]</code>) and reject anything else, including <code>none</code>. The related HS/RS confusion attack is defeated the same way.</p>', 'mid'],
      ['A valid signature is not enough — what else must you check?', '<p>The signature only proves the token was issued by a key-holder and not altered. You must also check: <code>exp</code> (not expired) and <code>nbf</code> (active yet), <code>iss</code> (from the issuer you trust), and crucially <code>aud</code> (this token was intended for <em>your</em> service, so a token minted for service A can\'t be replayed against service B). Skipping <code>aud</code> is a common, exploitable mistake.</p>', 'senior'],
    ],
    quiz: [
      { q: 'What are the three parts of a JWT, in order?', o: ['key . value . signature', 'header . payload . signature', 'issuer . subject . audience', 'alg . claims . secret'], a: 1, e: 'header.payload.signature, each Base64URL-encoded and dot-joined. Header and payload are readable; the signature authenticates them.' },
      { q: 'A JWT payload is…', o: ['Encrypted and unreadable', 'Base64URL-encoded and readable by anyone', 'Hashed one-way', 'Compressed binary'], a: 1, e: 'It\'s only encoded, not encrypted. Never store secrets in it — decode any JWT and you see the claims.' },
      { q: 'Why can\'t you easily revoke a standard JWT before it expires?', o: ['It is encrypted', 'No central store is checked on each request', 'The signature changes over time', 'Browsers delete it automatically'], a: 1, e: 'JWTs are verified locally with no server-side lookup, so there\'s nothing central to delete. Short expiry + refresh tokens are the usual workaround.' },
      { q: 'Which configuration defeats the alg:none and key-confusion attacks?', o: ['Using a longer secret', 'Pinning an explicit algorithm allow-list on the verifier', 'Storing the token in a cookie', 'Base64-encoding twice'], a: 1, e: 'Never trust the token\'s declared alg. An explicit allow-list (e.g. ["RS256"]) and rejecting "none" stops both attacks.' },
      { q: 'Besides the signature, which claim stops a token for service A being replayed against service B?', o: ['iat', 'aud (audience)', 'sub', 'typ'], a: 1, e: 'The aud claim names the intended recipient. Verifiers must check it, or tokens become reusable across services.' },
    ],
    related: ['sessions', 'oauth', 'oidc', 'api-keys'],
  });
})();
