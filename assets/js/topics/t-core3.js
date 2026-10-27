/* Core web & transport: OAuth, OIDC, TLS, mTLS, SSH */
(function () {
  'use strict';
  const HS = window.HS, C = window.C;

  /* ---------------- OAuth 2.0 ---------------- */
  HS.add({
    id: 'oauth', group: 'core', short: 'OAuth 2.0', icon: 'idp',
    title: 'OAuth 2.0',
    tagline: 'The "Sign in with…" and "allow this app to access your…" framework. Famously misunderstood: OAuth is about delegated authorization, not logging you in. Getting that distinction right is a senior-level interview marker.',
    level: 'Intermediate', kind: 'Delegated authorization',
    spec: [['Defined in', 'RFC 6749 / 6750'], ['Purpose', 'Delegated access, not login'], ['Default flow', 'Authorization Code + PKCE'], ['Issues', 'Access + refresh tokens']],
    analogy: `<p>OAuth is the <strong>valet key</strong> for your car. The valet key starts the engine and moves the car, but won't open the glovebox or the boot. You hand it over without giving away your master key, it works only for a limited purpose, and you can get it back. OAuth lets you give an app a "valet key" to <em>part</em> of your data at another service — without ever handing over your password.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'You', sub: 'resource owner', icon: 'user', x: 90, y: 80 },
        { id: 'app', label: 'App', sub: 'client', icon: 'browser', x: 90, y: 225 },
        { id: 'as', label: 'Auth server', sub: 'e.g. Google', icon: 'idp', x: 370, y: 80 },
        { id: 'rs', label: 'Resource API', sub: 'your photos', icon: 'cloud', x: 575, y: 225 },
      ],
      order: ['u', 'app', 'as', 'rs'],
      normal: {
        name: 'Authorization Code + PKCE', summary: 'The app never sees your password. You approve a scoped grant at the provider, the app receives a one-time code, and swaps it (plus a PKCE secret) for a scoped access token.',
        steps: [
          { f: 'app', t: 'app', k: 'int', l: 'build verifier + challenge', title: 'App prepares PKCE', d: 'The app invents a random <code>code_verifier</code>, hashes it to a <code>code_challenge</code>, and keeps the verifier to itself.', data: { code_verifier: 'kept secret in app', code_challenge: 'SHA256(verifier)', method: 'S256' } },
          { f: 'app', t: 'as', k: 'req', l: 'redirect to consent (scope=photos.read)', title: 'Redirect to the provider', d: 'The app sends your browser to the auth server with the scopes it wants and the challenge. Note: you\'re now on the <em>provider\'s</em> domain, not the app\'s.', data: { 'GET': '/authorize', client_id: 'app-123', scope: 'photos.read', code_challenge: '…', redirect_uri: 'https://app/cb' } },
          { f: 'u', t: 'as', k: 'req', l: 'log in & approve', title: 'You authenticate & consent', d: 'You log into the provider directly and see a consent screen: "App wants to read your photos." You approve. Your password never touches the app.', data: { login: 'at provider only', consent: 'read your photos? → Allow' }, enc: true },
          { f: 'as', t: 'app', k: 'res', l: 'redirect back with ?code=…', title: 'One-time code returned', d: 'The provider redirects back to the app with a short-lived, single-use authorization <em>code</em> — not a token yet.', data: { redirect: 'https://app/cb?code=AUTH_CODE', code: 'single-use, ~60s life' } },
          { f: 'app', t: 'as', k: 'req', l: 'exchange code + verifier', title: 'Back-channel token exchange', d: 'Server-to-server, the app sends the code plus the original <code>code_verifier</code>. The provider re-hashes the verifier and checks it matches the earlier challenge.', data: { 'POST': '/token', code: 'AUTH_CODE', code_verifier: 'original random', check: 'SHA256(verifier)==challenge ✓' }, enc: true },
          { f: 'as', t: 'app', k: 'res', l: 'access_token (+refresh)', title: 'Scoped token issued', d: 'The provider returns an access token (often a JWT) scoped to <code>photos.read</code>, plus a refresh token for renewal. The app still never learned your password.', data: { access_token: 'Bearer … (scope photos.read)', expires_in: 3600, refresh_token: '…' }, ok: 'App holds a scoped, expiring token' },
          { f: 'app', t: 'rs', k: 'req', l: 'GET /photos  Bearer token', title: 'Call the API with the token', d: 'The app calls the resource API with the access token. The API checks the token and its scope and returns only what was granted.', data: { 'GET': '/photos', 'Authorization': 'Bearer …', enforced: 'scope photos.read only' }, ok: 'Access limited to granted scope' },
        ],
      },
      attack: {
        name: 'Stolen authorization code', summary: 'An attacker who intercepts the one-time code tries to redeem it. PKCE and redirect-URI validation make the stolen code useless.',
        steps: [
          { f: 'as', t: 'app', k: 'res', l: 'redirect ?code=AUTH_CODE', title: 'The code in transit', d: 'The authorization code travels back through the browser redirect — a place an attacker might observe it (a malicious app on a phone registering the same custom URL scheme, say).', data: { code: 'AUTH_CODE', exposure: 'browser redirect / custom URI scheme' } },
          { f: 'app', t: 'as', k: 'atk', l: 'attacker redeems code', title: 'Attacker tries the code', d: 'The attacker races to exchange the stolen code for a token at the <code>/token</code> endpoint.', data: { 'POST': '/token', code: 'AUTH_CODE (stolen)', code_verifier: '??? attacker does not have it' } },
          { f: 'as', t: 'as', k: 'int', l: 'verifier hash mismatch', title: 'PKCE blocks it', d: 'The provider demands the <code>code_verifier</code> whose hash equals the challenge bound to this code. The attacker never saw the verifier (it stayed inside the real app), so the hash check fails.', data: { expected: 'SHA256(verifier)==challenge', attacker_has: 'no verifier', redirect_uri: 'must also match registered value' }, ok: 'Stolen code rejected (PKCE)' },
          { f: 'as', t: 'app', k: 'res', l: 'invalid_grant', title: 'Exchange refused', d: 'The exchange fails. PKCE turns a stolen code into a useless string, which is why it\'s now mandatory for all clients, not just mobile.', data: { error: 'invalid_grant', lesson: 'PKCE + exact redirect_uri + single-use codes' }, fail: 'Attacker gets nothing' },
        ],
      },
    },
    basics: `
      <p>OAuth 2.0 solves one specific problem: <em>how can I let an app use some of my data on another service, without giving that app my password?</em> Before OAuth, apps asked for your actual Gmail password to read your contacts — a disaster. OAuth replaces that with a scoped, revocable, password-free grant.</p>
      <p>The four roles (learn these names — interviewers use them):</p>
      <ul>
        <li><b>Resource owner</b> — you, the user who owns the data.</li>
        <li><b>Client</b> — the app that wants access.</li>
        <li><b>Authorization server</b> — issues tokens after you consent (e.g. Google's login).</li>
        <li><b>Resource server</b> — the API holding your data, which accepts the token.</li>
      </ul>
      <div class="callout warn"><b>OAuth is authorization, not authentication</b>OAuth gives an app a token to <em>access</em> things. It does not, by itself, reliably tell the app <em>who you are</em> — using a raw access token as "proof of login" is a classic security mistake. The layer that adds real login on top of OAuth is <a href="#oidc">OpenID Connect</a>.</div>`,
    deep: `
      <h3>The grant types (flows)</h3>
      <ul>
        <li><b>Authorization Code + PKCE</b> — the default for essentially everything today: web apps, SPAs and mobile. The app gets a one-time code via redirect, then exchanges it (back-channel) for tokens. PKCE binds the exchange to a secret only the real client holds.</li>
        <li><b>Client Credentials</b> — no user involved; one service authenticates as itself to call another. Machine-to-machine.</li>
        <li><b>Device Code</b> — for input-constrained devices (TVs, CLIs): you visit a URL on your phone and enter a code.</li>
        <li><b>Implicit</b> and <b>Resource Owner Password</b> — <em>deprecated</em>. Implicit returned tokens straight in the URL (leaky); the password grant had the app handle your password (defeating the point). Mentioning they\'re deprecated, and why, is a strong signal.</li>
      </ul>
      <h3>Why PKCE became mandatory</h3>
      <p>PKCE (Proof Key for Code Exchange, "pixie") was added for mobile apps that can\'t keep a client secret. The app makes a random <code>code_verifier</code>, sends only its SHA-256 hash when starting the flow, and reveals the verifier at token exchange. A stolen authorization code is worthless without the verifier. It worked so well that the OAuth 2.1 consolidation makes it required for <em>all</em> clients. Build the challenge yourself in the playground below.</p>
      <h3>Access tokens vs refresh tokens</h3>
      <p>Access tokens are short-lived (minutes–an hour) and sent to APIs on every call. Refresh tokens are long-lived, kept private by the client, and used only to obtain new access tokens — so a leaked access token expires fast, while the powerful refresh token stays off the wire. Refresh-token <b>rotation</b> (each use issues a new one and invalidates the old) detects theft.</p>
      <h3>Scopes</h3>
      <p>Scopes (<code>photos.read</code>, <code>mail.send</code>) are how OAuth expresses least privilege: the token grants exactly what you consented to and no more. The resource server enforces them. See <a href="#oauth-scopes">OAuth scopes</a> in the authorization section.</p>`,
    howto: `
      <p>Never implement the endpoints yourself — use a certified provider/library and the Authorization Code + PKCE flow. The essential discipline:</p>
      ${C('text', `
        1. Register your app → get client_id and (for confidential apps) client_secret.
        2. Register EXACT redirect URIs. The provider must reject any other.
        3. Start the flow with: response_type=code, scope (least privilege),
           state (anti-CSRF, random per request), code_challenge (PKCE).
        4. On return: verify 'state' matches, exchange code + code_verifier server-side.
        5. Store refresh tokens securely; send access tokens over TLS only.
        6. Validate the token (and for login, the OIDC id_token) before trusting it.
      `, 'OAuth client checklist')}
      <div class="callout"><b>Always use <code>state</code></b>The <code>state</code> parameter is a random value you send and check on return — it ties the callback to the request you started and blocks CSRF on the redirect. PKCE protects the code; <code>state</code> protects the flow.</div>
      <p>The PKCE playground shows how the verifier and challenge relate.</p>`,
    tool: 'pkce',
    pros: ['Apps get access without ever seeing your password', 'Scoped, least-privilege grants you explicitly consent to', 'Tokens are revocable and expiring', 'An open standard supported by every major provider', 'Separates who issues tokens from who holds the data'],
    cons: ['Complex — many flows and parameters, easy to misconfigure', 'Not authentication on its own (needs OIDC for login)', 'Redirect-URI and state mistakes cause real breaches', 'Token storage and refresh handling are easy to get wrong', 'Deprecated flows (implicit/password) still linger in old code'],
    history: [
      ['2007', 'OAuth 1.0 appears, using request signatures — secure but painful to implement.'],
      ['2012', 'OAuth 2.0 (RFC 6749) drops signatures for bearer tokens over TLS; adoption explodes.'],
      ['2012', 'A lead author resigns and removes his name, warning 2.0 is too complex and enterprise-driven.'],
      ['2015', 'PKCE (RFC 7636) secures mobile/public clients against code interception.'],
      ['2019', 'Guidance deprecates the implicit and password grants.'],
      ['2025', 'RFC 9700 ("Best Current Practice for OAuth 2.0 Security") is published; the OAuth 2.1 consolidation — Authorization Code + PKCE everywhere, no implicit flow — continues as an Internet-Draft.'],
    ],
    hidden: [
      ['A founding author quit over the complexity', 'Eran Hammer, a lead editor, resigned and pulled his name in 2012, calling OAuth 2.0 "a bad protocol" shaped by enterprise interests. The complexity he warned about is exactly where today\'s misconfigurations come from.'],
      ['Using an access token as "login" is a real bug', 'An access token proves an app may act on an API — not who the user is. Apps that treat "I got a Facebook token" as "this user is X" have been tricked with tokens minted for a different app. That\'s why OIDC\'s id_token exists.'],
      ['PKCE is pronounced "pixie"', 'And it\'s required for all clients in the OAuth 2.1 draft (and recommended by RFC 9700), not just mobile — a small bit of trivia that shows you follow the spec\'s direction.'],
      ['The "confused deputy" lurks here', 'OAuth\'s whole risk model is the confused-deputy problem: the authorization server is a powerful deputy that must be careful whose instructions it follows — hence exact redirect URIs and state.'],
    ],
    attacks: [
      ['Authorization code interception', 'Steal the one-time code from a redirect (esp. mobile custom URL schemes).', 'PKCE binds the code to a client-only secret; exact redirect-URI matching; single-use codes.'],
      ['CSRF on the redirect', 'Trick a user into completing a flow the attacker started, linking the attacker\'s account.', 'The random <code>state</code> parameter, verified on return.'],
      ['Open redirect / redirect-URI manipulation', 'Send the code/token to an attacker URL by abusing loose redirect matching.', 'Exact, pre-registered redirect URIs; no wildcards.'],
      ['Token leakage', 'Access tokens leak via logs, Referer, or the deprecated implicit flow\'s URL fragment.', 'Authorization Code flow (not implicit), TLS, short expiry, header-only transport.'],
      ['Mix-up / token substitution', 'In multi-provider setups, swap which provider a response came from.', 'Validate <code>iss</code>/<code>aud</code>, use distinct redirect URIs per provider.'],
    ],
    interview: [
      ['Is OAuth 2.0 authentication or authorization?', '<p><b>Authorization</b> — delegated access. It lets an app obtain a scoped token to act on your behalf at an API without your password. It does <em>not</em> reliably tell the app who you are; treating an access token as proof of identity is a known vulnerability. Authentication/login on top of OAuth is provided by <b>OpenID Connect</b>, which adds an <code>id_token</code>.</p>', 'junior'],
      ['Explain the Authorization Code flow with PKCE at a high level.', '<p>The app sends you to the authorization server with the scopes it wants and a PKCE <code>code_challenge</code> (the hash of a secret it keeps). You log in and consent at the provider — the app never sees your password. The provider redirects back with a one-time <code>code</code>. The app exchanges that code, plus the original <code>code_verifier</code>, at the token endpoint; the provider checks the verifier hashes to the challenge and returns a scoped access token (and refresh token). PKCE ensures a stolen code is useless without the verifier.</p>', 'mid'],
      ['Why were the implicit and password grants deprecated?', '<p>The <b>implicit</b> flow returned the access token directly in the redirect URL fragment, where it leaks into history, logs and scripts, with no exchange step to protect it — Authorization Code + PKCE now covers SPAs safely. The <b>resource-owner password</b> grant had the app collect and forward your actual password, defeating OAuth\'s core purpose and precluding MFA/SSO. Both are removed in OAuth 2.1.</p>', 'mid'],
      ['What\'s the point of a refresh token if you already have an access token?', '<p>It separates longevity from exposure. The <b>access token</b> is short-lived and sent to resource APIs on every request, so it\'s the most exposed — keeping it short limits damage if it leaks. The <b>refresh token</b> is long-lived but stays private to the client and only touches the authorization server to mint new access tokens. With <b>rotation</b> (each refresh invalidates the previous token), reuse of a stolen refresh token is detectable. It\'s defence-in-depth around token lifetime.</p>', 'senior'],
      ['What does the <code>state</code> parameter defend against, and how is it different from PKCE?', '<p><code>state</code> is a random value the client sends on the authorize request and verifies on the callback; it binds the response to the request the user actually started, defeating <b>CSRF</b> on the redirect (an attacker can\'t stitch their own flow into your session). <b>PKCE</b> protects the <em>authorization code itself</em> from being redeemed by anyone but the originating client. They\'re complementary: <code>state</code> secures the round-trip, PKCE secures the code exchange.</p>', 'senior'],
    ],
    quiz: [
      { q: 'OAuth 2.0 is fundamentally about…', o: ['Proving who you are (login)', 'Delegated access to resources without sharing your password', 'Encrypting traffic', 'Storing passwords safely'], a: 1, e: 'OAuth grants scoped access on your behalf. Login on top of it is OpenID Connect.' },
      { q: 'In the Authorization Code flow, what does the app receive first from the redirect?', o: ['An access token', 'A one-time authorization code', 'The user\'s password', 'A refresh token'], a: 1, e: 'It gets a single-use code via the browser redirect, then exchanges it server-side for tokens — safer than handing out a token directly.' },
      { q: 'PKCE primarily protects against…', o: ['Expired tokens', 'A stolen authorization code being redeemed by an attacker', 'Weak passwords', 'CSRF on the redirect'], a: 1, e: 'PKCE binds the code exchange to a secret only the real client holds, so an intercepted code is useless. CSRF on the redirect is handled by the state parameter.' },
      { q: 'Which OAuth flow is deprecated because it leaked tokens in the URL?', o: ['Authorization Code', 'Client Credentials', 'Implicit', 'Device Code'], a: 2, e: 'The implicit flow returned the access token in the URL fragment. Authorization Code + PKCE replaces it for SPAs.' },
      { q: 'Why keep a refresh token separate from the access token?', o: ['Refresh tokens are encrypted', 'The access token is short-lived and exposed; the refresh token stays private and long-lived', 'Access tokens can\'t be revoked', 'The API requires both'], a: 1, e: 'Short access-token life limits leak damage; the powerful refresh token rarely leaves the client and can be rotated to detect theft.' },
    ],
    related: ['oidc', 'jwt', 'oauth-scopes', 'sso'],
  });

  /* ---------------- OpenID Connect ---------------- */
  HS.add({
    id: 'oidc', group: 'core', short: 'OpenID Connect', icon: 'idp',
    title: 'OpenID Connect (OIDC)',
    tagline: 'The thin identity layer on top of OAuth 2.0 that actually logs you in. Every "Sign in with Google/Microsoft/Apple" button is OIDC. The one addition — the id_token — is what turns "access" into "identity".',
    level: 'Intermediate', kind: 'Federated authentication',
    spec: [['Built on', 'OAuth 2.0'], ['Adds', 'id_token (a JWT)'], ['Discovery', '/.well-known/openid-configuration'], ['Keys', 'JWKS endpoint']],
    analogy: `<p>If OAuth is a valet key that lets an app <em>do</em> something with your data, OIDC adds a <strong>verified ID card</strong> issued by a trusted authority. When you "Sign in with Google", Google hands the app a tamper-proof card saying "this is user 8842, email verified, signed by Google at 10:14". The app doesn't run its own passport office — it trusts Google's.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'You', sub: 'end user', icon: 'user', x: 90, y: 150 },
        { id: 'app', label: 'App (RP)', sub: 'relying party', icon: 'browser', x: 320, y: 80 },
        { id: 'idp', label: 'Google (OP)', sub: 'OpenID provider', icon: 'idp', x: 320, y: 230 },
        { id: 'jwks', label: 'JWKS', sub: 'public keys', icon: 'key', x: 575, y: 150 },
      ],
      order: ['u', 'app', 'idp', 'jwks'],
      normal: {
        name: '"Sign in with Google"', summary: 'OIDC runs the OAuth code flow but adds the openid scope and returns an id_token — a signed JWT asserting who you are, which the app verifies against the provider\'s public keys.',
        steps: [
          { f: 'app', t: 'idp', k: 'req', l: 'authorize scope=openid profile email', title: 'Start login with openid scope', d: 'The relying party (app) redirects you to the provider with <code>scope=openid</code> — the magic word that asks for an identity token, not just access.', data: { 'GET': '/authorize', scope: 'openid profile email', nonce: 'random (binds id_token to this login)' } },
          { f: 'u', t: 'idp', k: 'req', l: 'authenticate at Google', title: 'You log in at the provider', d: 'You authenticate directly with Google (password + MFA, perhaps an existing session). The app never sees any of it.', data: { login: 'password/passkey + MFA at Google', consent: 'share name + email with app?' }, enc: true },
          { f: 'idp', t: 'app', k: 'res', l: 'code → exchange → id_token + access_token', title: 'Receive the id_token', d: 'After the usual code exchange, the app gets an <b>id_token</b> (a signed JWT about <em>you</em>) alongside the access token.', data: { id_token: 'JWT { iss:google, sub:8842, email, nonce, exp }', access_token: 'for calling Google APIs' }, enc: true },
          { f: 'app', t: 'jwks', k: 'req', l: 'fetch Google public keys', title: 'Fetch verification keys', d: 'The app fetches Google\'s public signing keys from the JWKS endpoint (discovered via <code>/.well-known/openid-configuration</code>), cached and keyed by <code>kid</code>.', data: { 'GET': '/.well-known/jwks.json', keys: 'public RSA/EC keys by kid' } },
          { f: 'app', t: 'app', k: 'int', l: 'verify sig, iss, aud, nonce, exp', title: 'Validate the id_token', d: 'The app verifies the signature with Google\'s public key and checks <code>iss</code> (really Google), <code>aud</code> (this token is for me), <code>nonce</code> (matches my login request), and <code>exp</code>.', data: { signature: 'valid (Google key) ✓', aud: 'my client_id ✓', nonce: 'matches ✓', iss: 'accounts.google.com ✓' }, ok: 'Identity proven — user logged in' },
          { f: 'app', t: 'u', k: 'res', l: 'logged in as you', title: 'Session established', d: 'The app now knows who you are, with no password of its own to store, and creates its local session. That\'s federated login.', data: { identity: 'user 8842 (verified by Google)', app_passwords_stored: 'none' }, ok: 'Federated authentication complete' },
        ],
      },
      attack: {
        name: 'Forged / replayed id_token', summary: 'Attackers try to forge an identity token or replay an old one. Signature verification, audience and nonce checks defeat these.',
        steps: [
          { f: 'app', t: 'app', k: 'atk', l: 'attacker crafts id_token {sub: victim}', title: 'Forge an identity claim', d: 'An attacker builds an id_token claiming to be the victim and presents it to the app, hoping the app only decodes it.', data: { forged: '{ sub: victim, email: victim@x }', signature: 'attacker cannot sign as Google' } },
          { f: 'app', t: 'app', k: 'int', l: 'signature check vs Google key → fail', title: 'Signature stops forgery', d: 'The app verifies against Google\'s published public key. The attacker can\'t produce a valid Google signature, so the forged token is rejected — provided the app actually verifies and doesn\'t accept <code>alg:none</code>.', data: { verify: 'needs Google private key', attacker_has: 'none', result: 'REJECT' }, ok: 'Forgery blocked by signature' },
          { f: 'idp', t: 'app', k: 'atk', l: 'replay a real but old token', title: 'Replay a genuine token', d: 'The attacker instead replays a real id_token captured earlier, or one minted for a <em>different</em> app.', data: { token: 'genuine but old / wrong aud', attack: 'reuse elsewhere' } },
          { f: 'app', t: 'app', k: 'int', l: 'check aud + nonce + exp', title: 'aud/nonce/exp defeat replay', d: 'The <code>aud</code> check rejects tokens minted for another app; the <code>nonce</code> (bound to this specific login request) rejects replays; <code>exp</code> rejects stale tokens. All three must be validated.', data: { aud: 'wrong client_id → reject', nonce: 'does not match → reject', exp: 'expired → reject' }, ok: 'Replay blocked (aud + nonce + exp)' },
        ],
      },
    },
    basics: `
      <p>OAuth 2.0 gives apps <em>access</em> but, as its own page stresses, doesn't reliably say <em>who you are</em>. Developers kept bolting identity onto OAuth in incompatible, insecure ways. OpenID Connect standardises that: it's a thin layer on top of OAuth that adds a proper login result.</p>
      <p>The one big addition is the <strong>id_token</strong> — a signed JWT whose claims describe the user:</p>
      <ul>
        <li><code>iss</code> — who issued it (the provider).</li>
        <li><code>sub</code> — the stable unique user ID at that provider.</li>
        <li><code>aud</code> — which app it was minted for (your client_id).</li>
        <li><code>nonce</code> — ties the token to a specific login attempt (anti-replay).</li>
        <li><code>exp</code>, <code>iat</code>, plus profile claims like <code>email</code>, <code>name</code>.</li>
      </ul>
      <p>You trigger OIDC simply by including <code>scope=openid</code> in an OAuth request. The vocabulary shifts slightly: the app is the <b>Relying Party (RP)</b>, the provider is the <b>OpenID Provider (OP)</b>.</p>`,
    deep: `
      <h3>id_token vs access_token — a crucial distinction</h3>
      <p>They look similar (both often JWTs) but mean different things, and interviewers test this:</p>
      <ul>
        <li><b>id_token</b> — <em>for the app</em>, about <em>the user</em>. It answers "who logged in?" The app consumes and verifies it, then discards it. It is <b>not</b> meant to be sent to APIs.</li>
        <li><b>access_token</b> — <em>for the API</em>, grants access to resources. It answers "what may the bearer do?" The app forwards it to resource servers; it should be opaque to the app.</li>
      </ul>
      <p>Sending an id_token to an API, or using an access token to decide identity, are two of the most common OIDC mistakes.</p>
      <h3>Discovery & JWKS — zero-config trust</h3>
      <p>A provider publishes a discovery document at <code>/.well-known/openid-configuration</code> listing its endpoints and its JWKS URL. The RP fetches the provider's public keys from JWKS, caches them by <code>kid</code>, and verifies id_tokens offline. Key rotation is seamless because new keys just appear in JWKS under new IDs.</p>
      <h3>The nonce</h3>
      <p>OAuth\'s <code>state</code> protects the redirect against CSRF; OIDC adds <code>nonce</code>, which is embedded <em>inside</em> the id_token. The RP generates it per login and checks the returned token contains the same value — defeating replay of a previously captured id_token.</p>
      <h3>Where you meet it</h3>
      <p>Every social and enterprise "Sign in with…" button is OIDC. It also underlies most modern enterprise SSO (see <a href="#sso">SSO</a>), increasingly replacing <a href="#saml">SAML</a> for new applications because JSON/JWT is far lighter than SAML's XML.</p>`,
    howto: `
      <p>Use a certified OIDC library and let it do discovery and validation. The checklist that matters:</p>
      ${C('text', `
        Request:  scope=openid (+ profile, email as needed), a fresh nonce, and state.
        On return, the library MUST validate the id_token:
          • signature against the provider's JWKS key (matching kid)
          • iss  == the expected provider
          • aud  == your client_id
          • exp  not passed, iat reasonable
          • nonce == the one you sent for this login
        Use the id_token ONLY to establish identity.
        Use the access_token ONLY to call APIs. Never mix them up.
      `, 'OIDC relying-party validation checklist')}
      <div class="callout"><b>Don't hand-roll it</b>Use providers\' SDKs or a vetted library (e.g. a certified OIDC client). The validation steps are exactly where hand-written code goes wrong — skipped <code>aud</code>/<code>nonce</code> checks are common and exploitable.</div>
      <p>The JWT playground lets you inspect an id_token-style payload and watch verification succeed or fail.</p>`,
    tool: 'jwt',
    pros: ['Real, standardised authentication on top of OAuth', 'Users reuse one trusted identity — no new password per app', 'App stores no passwords, shrinking its breach surface', 'Discovery + JWKS make integration and key rotation easy', 'JSON/JWT based — lighter and more web-native than SAML'],
    cons: ['Inherits OAuth\'s complexity and misconfiguration risks', 'Central provider is a single point of failure and tracking', 'Validation mistakes (skipped aud/nonce) are security holes', 'Account recovery/lockout at the provider affects every app', 'Logout across federated apps is genuinely hard'],
    history: [
      ['2005–2007', 'Original OpenID (1.0, then 2.0) offers decentralised login but is clunky and URL-based.'],
      ['2014', 'OpenID Connect 1.0 launches, rebuilt cleanly on OAuth 2.0 with JWTs.'],
      ['2015→', '"Sign in with Google/Microsoft" standardise on OIDC; it becomes the default consumer login.'],
      ['2019', 'Sign in with Apple launches on OIDC, adding privacy features like email relay.'],
      ['2020s', 'OIDC increasingly displaces SAML for new enterprise SSO integrations.'],
    ],
    hidden: [
      ['The whole layer is basically one scope and one token', 'OIDC is "OAuth + <code>scope=openid</code> + an id_token". That minimalism is deliberate — it reused OAuth\'s battle-tested plumbing instead of inventing a new protocol.'],
      ['id_token is not for APIs', 'A very common bug is sending the id_token to resource servers. It\'s for the app to learn who you are; APIs want the access token. Keep them in separate lanes.'],
      ['nonce vs state trips people up', 'state lives in the redirect (CSRF on the round-trip); nonce lives inside the id_token (replay of the token). You generally use both.'],
      ['"Sign in with Apple" hides your email', 'Apple\'s OIDC can issue a per-app relay address, so the app never learns your real email — a privacy feature layered onto the standard claims.'],
    ],
    attacks: [
      ['id_token forgery', 'Craft a token claiming to be the victim.', 'Verify the signature against the provider\'s JWKS key; reject alg:none.'],
      ['Token replay', 'Reuse a captured id_token.', 'Validate nonce (per-login) and exp; bind sessions to the nonce.'],
      ['Audience confusion', 'Present a token minted for another app.', 'Strictly check aud == your client_id.'],
      ['Provider impersonation / mix-up', 'In multi-provider setups, confuse which OP responded.', 'Validate iss, use per-provider redirect URIs, follow mix-up mitigation.'],
      ['Phishing the provider login', 'Fake the provider\'s login page.', 'Phishing-resistant MFA (passkeys) at the provider; users check the real domain.'],
    ],
    interview: [
      ['What does OpenID Connect add to OAuth 2.0?', '<p>A standard <b>authentication</b> layer. OAuth alone grants access but doesn\'t reliably tell the app who you are. OIDC adds the <b>id_token</b> — a signed JWT with identity claims (<code>sub</code>, <code>iss</code>, <code>aud</code>, <code>email</code>, etc.) — obtained by including <code>scope=openid</code>. That\'s what makes "Sign in with Google" an actual login rather than just an access grant.</p>', 'junior'],
      ['What\'s the difference between an id_token and an access_token?', '<p>The <b>id_token</b> is for the <em>app</em> and is about <em>the user</em> — it answers "who logged in?", is verified by the app, and should never be sent to APIs. The <b>access_token</b> is for the <em>API</em> and grants access to resources — the app forwards it to resource servers and treats it as opaque. Mixing them up (id_token to an API, or access_token used as identity) is a classic, exploitable mistake.</p>', 'mid'],
      ['How does a relying party verify an id_token?', '<p>It validates: the <b>signature</b> against the provider\'s public key fetched from the JWKS endpoint (matched by <code>kid</code>, discovered via <code>/.well-known/openid-configuration</code>); <b>iss</b> equals the expected provider; <b>aud</b> equals its own client_id; <b>exp</b> not passed; and the <b>nonce</b> matches the one it sent for this login. All of these, not just the signature — skipping <code>aud</code> or <code>nonce</code> opens replay and audience-confusion attacks.</p>', 'senior'],
      ['Why is OIDC increasingly chosen over SAML for new apps?', '<p>OIDC is JSON/JWT over simple HTTPS redirects, which is lighter, mobile- and SPA-friendly, and easy to integrate with discovery and JWKS. SAML is verbose XML with XML-DSig and heavier tooling, strong in legacy enterprise but awkward for modern web/mobile. Many orgs still run SAML for existing apps but default to OIDC for anything new.</p>', 'mid'],
    ],
    quiz: [
      { q: 'What single addition turns OAuth into OIDC?', o: ['A refresh token', 'The id_token (requested via scope=openid)', 'TLS', 'A client secret'], a: 1, e: 'OIDC = OAuth + scope=openid + a signed id_token describing the user. That identity token is the whole point.' },
      { q: 'An id_token should be sent to…', o: ['Resource APIs on every call', 'Only the app, to establish who logged in', 'The JWKS endpoint', 'The user\'s browser storage for APIs'], a: 1, e: 'The id_token is for the app to learn identity. APIs take the access token. Sending id_tokens to APIs is a common bug.' },
      { q: 'Which claim must the relying party check to stop replay of a captured id_token?', o: ['sub', 'nonce', 'name', 'iat'], a: 1, e: 'The nonce is bound to a specific login request; checking it (plus exp) defeats replay. aud stops cross-app reuse.' },
      { q: 'In OIDC terminology, the application logging the user in is the…', o: ['OpenID Provider (OP)', 'Resource server', 'Relying Party (RP)', 'Authorization code'], a: 2, e: 'The app is the Relying Party; the identity provider is the OpenID Provider.' },
    ],
    related: ['oauth', 'jwt', 'sso', 'saml'],
  });

  /* ---------------- TLS ---------------- */
  HS.add({
    id: 'tls', group: 'core', short: 'TLS / HTTPS', icon: 'lock', port: '443',
    title: 'TLS — Transport Layer Security',
    tagline: 'The padlock in your address bar. The protocol that authenticates the server and encrypts everything above it, so the whole rest of this guide can send passwords and tokens safely. Understanding the handshake is foundational for any backend or security role.',
    level: 'Intermediate', kind: 'Transport security',
    spec: [['Current version', 'TLS 1.3 (RFC 8446)'], ['Authenticates', 'The server (via certificate)'], ['Provides', 'Confidentiality + integrity'], ['Trust anchor', 'Certificate Authorities']],
    analogy: `<p>TLS does two jobs at once, like a sealed diplomatic pouch delivered by a verified courier. First, the courier shows credentials proving they're really from the embassy you expect (server authentication via certificate). Second, the pouch is sealed so nobody en route can read or alter the contents (encryption + integrity). Without the first, you might hand your letter to an impostor; without the second, anyone on the road could read it.</p>`,
    flow: {
      nodes: [
        { id: 'c', label: 'Browser', sub: 'client', icon: 'browser', x: 100, y: 150 },
        { id: 's', label: 'Server', sub: 'shop.example.com', icon: 'server', x: 400, y: 90 },
        { id: 'ca', label: 'CA', sub: 'trust store', icon: 'idp', x: 400, y: 235 },
      ],
      order: ['c', 's', 'ca'],
      normal: {
        name: 'TLS 1.3 handshake', summary: 'In one round trip the client and server agree on keys (Diffie–Hellman), the server proves its identity with a certificate chaining to a trusted CA, and everything after the ServerHello is encrypted.',
        steps: [
          { f: 'c', t: 's', k: 'req', l: 'ClientHello + key share', title: 'ClientHello', d: 'The client offers its TLS versions and cipher suites and — new in 1.3 — already sends its Diffie–Hellman key share, saving a round trip.', data: { versions: 'TLS 1.3', ciphers: 'AES-128-GCM, ChaCha20…', key_share: 'client DH public value', sni: 'shop.example.com' } },
          { f: 's', t: 'c', k: 'res', l: 'ServerHello + key share', title: 'ServerHello', d: 'The server picks the cipher suite and sends its own DH key share, in plaintext. Each side now combines its private value with the other\'s public share and derives the same handshake keys. Nothing secret crossed the wire.', data: { cipher: 'TLS_AES_128_GCM_SHA256', key_share: 'server DH public value', derived: 'handshake keys, on both sides' } },
          { f: 's', t: 'c', k: 'res', l: '{Certificate, CertificateVerify, Finished}', title: 'Certificate, sent encrypted', d: 'Under the new handshake keys the server sends its certificate chain, a <code>CertificateVerify</code> signature proving it holds the certificate\'s private key, and <code>Finished</code>. New in TLS 1.3: the certificate is encrypted, so an eavesdropper can\'t read it.', data: { certificate: 'CN=shop.example.com + intermediate', CertificateVerify: 'signature over the handshake transcript', Finished: 'MAC over the handshake' }, enc: true },
          { f: 'c', t: 'ca', k: 'int', l: 'verify cert chains to trusted root', title: 'Validate the certificate', d: 'The client checks the certificate: does it chain to a Certificate Authority in the OS/browser trust store? Is it unexpired, unrevoked, and does the name match the address bar?', data: { chain: 'leaf → intermediate → trusted root ✓', hostname: 'matches shop.example.com ✓', expiry: 'valid', revocation: 'OCSP/CRL ok' }, ok: 'Server identity verified' },
          { f: 'c', t: 's', k: 'req', l: '{Finished}', title: 'Client Finished', d: 'The client sends its own encrypted <code>Finished</code>. Both sides switch to application traffic keys derived from the same DH secret — keys that were never transmitted.', data: { Finished: 'MAC over the handshake', session_keys: 'symmetric (AES-GCM), derived on both sides', secret_on_wire: 'never' }, enc: true },
          { f: 'c', t: 's', k: 'req', l: 'GET / (encrypted)', title: 'Encrypted application data', d: 'The actual HTTP request now flows inside the encrypted channel. An eavesdropper sees only ciphertext; tampering is detected by the authentication tag.', data: { 'GET': '/ HTTP/2', visible_to_sniffer: 'ciphertext only', integrity: 'AEAD tag detects tampering' }, enc: true, ok: 'Confidential + authenticated channel' },
        ],
      },
      attack: {
        name: 'Man-in-the-middle attempt', summary: 'An attacker between you and the server tries to impersonate it. The certificate check is what stops them — unless the user clicks through a warning.',
        steps: [
          { f: 'c', t: 's', k: 'atk', l: 'attacker intercepts connection', title: 'MITM intercepts', d: 'An attacker on the network (rogue Wi-Fi, compromised router) intercepts the connection and tries to pose as <code>shop.example.com</code>.', data: { position: 'between client and server', goal: 'read/modify traffic' } },
          { f: 's', t: 'c', k: 'atk', l: 'presents attacker certificate', title: 'Fake certificate offered', d: 'The attacker can\'t obtain a CA-signed certificate for a domain they don\'t control, so they present a self-signed or mismatched one.', data: { certificate: 'self-signed / wrong hostname', signed_by: 'not a trusted CA' } },
          { f: 'c', t: 'ca', k: 'int', l: 'chain does not reach trusted root', title: 'Validation fails', d: 'The client\'s check fails: the certificate doesn\'t chain to a trusted root, or the hostname doesn\'t match. The browser shows a full-page security warning rather than connecting.', data: { chain: 'does NOT reach trusted root ✗', hostname: 'mismatch ✗', result: 'NET::ERR_CERT_AUTHORITY_INVALID' }, ok: 'MITM detected — warning shown' },
          { f: 'c', t: 'c', k: 'int', l: 'HSTS forbids click-through', title: 'HSTS seals the gap', d: 'The remaining risk is a user clicking "proceed anyway". <code>HSTS</code> tells browsers to refuse insecure connections to the site entirely, removing the bypass button. Certificate pinning hardens it further.', data: { 'HSTS': 'Strict-Transport-Security → no override', effect: 'user cannot click through', pinning: 'optional extra binding' }, fail: 'Without HSTS, a user clicking through defeats TLS' },
        ],
      },
    },
    basics: `
      <p>TLS (Transport Layer Security, the successor to SSL) is the layer that makes <code>https://</code> secure. It sits between TCP and your application and provides three guarantees:</p>
      <ul>
        <li><b>Confidentiality</b> — traffic is encrypted; eavesdroppers see only ciphertext.</li>
        <li><b>Integrity</b> — any tampering in transit is detected.</li>
        <li><b>Authentication</b> — the server proves it is who the address bar says, via a certificate. (Client authentication is optional — see <a href="#mtls">mTLS</a>.)</li>
      </ul>
      <p>That third point is what makes everything else in this guide possible. You can only safely send a password, cookie or token <em>after</em> you know you're talking to the real server over an encrypted channel. "Just use TLS" is the one-line answer to a huge fraction of security questions.</p>
      <div class="callout"><b>SSL is dead; we just kept the word</b>SSL 2.0/3.0 are broken and disabled. "SSL certificate" and "SSL" in casual use almost always mean TLS today. In an interview, say TLS.</div>`,
    deep: `
      <h3>The handshake, and why TLS 1.3 is faster</h3>
      <p>The handshake agrees on keys and authenticates the server. TLS 1.3 (2018) streamlined it dramatically:</p>
      <ul>
        <li><b>One round trip (1-RTT)</b> instead of two — the client sends its key share in the first message, so data can flow after a single exchange. <b>0-RTT</b> resumption can send data immediately on reconnect (with replay caveats).</li>
        <li><b>Only forward-secret ciphers.</b> Old RSA key exchange (where compromising the server key later decrypts past traffic) is gone. TLS 1.3 mandates ephemeral Diffie–Hellman, giving <b>forward secrecy</b>: recording today's traffic and stealing the key tomorrow still won't decrypt it.</li>
        <li><b>Legacy cruft removed</b> — no more weak ciphers, compression, or renegotiation that caused attacks like CRIME and the RSA-downgrade family.</li>
      </ul>
      <h3>Diffie–Hellman: agreeing on a secret in the open</h3>
      <p>The clever heart of the handshake: two parties derive a shared secret while only exchanging <em>public</em> values, so an eavesdropper who sees the whole exchange still can't compute the key. Play with the toy numbers below to see it work. Real TLS uses elliptic-curve DH over far larger values.</p>
      <h3>Certificates and the CA trust model</h3>
      <p>A certificate binds a public key to a domain name, signed by a Certificate Authority. Your device ships with a list of trusted root CAs. A server cert chains <em>leaf → intermediate → trusted root</em>; break any link and trust fails. Walk a chain in the certificate playground. Certificates today are often free (Let's Encrypt) and short-lived (~90 days), automatically renewed via ACME — and getting shorter: in 2025 the CA/Browser Forum approved a schedule that cuts the maximum lifetime from 398 days to 200 (2026), 100 (2027) and finally 47 days (2029), which makes automated renewal mandatory in practice.</p>
      <h3>Beyond the basics</h3>
      <ul>
        <li><b>SNI</b> (Server Name Indication) lets one IP host many TLS sites by naming the host in the ClientHello. Encrypted Client Hello (ECH) is closing the privacy gap that the hostname was visible.</li>
        <li><b>HSTS</b> forces HTTPS and removes the "proceed anyway" button, closing the user-click-through hole.</li>
        <li><b>Certificate Transparency</b> logs every issued cert publicly, so mis-issued certificates for your domain can be detected.</li>
        <li><b>OCSP/CRL</b> handle revocation of compromised certificates.</li>
      </ul>`,
    howto: `
      <p>You rarely implement TLS, but you configure it constantly. The modern baseline:</p>
      ${C('text', `
        • Serve only TLS 1.2 and 1.3; disable SSL and TLS 1.0/1.1.
        • Prefer forward-secret suites (ECDHE); TLS 1.3 enforces this for you.
        • Get certs via Let's Encrypt / ACME; automate renewal (they expire ~90 days).
        • Send HSTS: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
        • Redirect all http:// to https://; never serve auth over plain HTTP.
        • Test with SSL Labs or 'openssl s_client -connect host:443'.
      `, 'TLS configuration baseline')}
      ${C('bash', `
        # inspect a server's certificate chain and handshake
        openssl s_client -connect shop.example.com:443 -servername shop.example.com </dev/null \\
          | openssl x509 -noout -issuer -subject -dates
      `, 'Inspecting a live certificate')}
      <p>Try the Diffie–Hellman and certificate-chain playgrounds to see the two halves of the handshake.</p>`,
    tool: ['dh', 'certchain'],
    pros: ['Encrypts and authenticates almost all modern internet traffic', 'TLS 1.3 is fast (1-RTT) and forward-secret by default', 'Free, automated certificates (Let\'s Encrypt/ACME) removed cost barriers', 'Transparent to application code — "just works" under HTTPS', 'Certificate Transparency makes mis-issuance detectable'],
    cons: ['Trust depends on ~hundreds of CAs — any one can mis-issue', 'Certificate expiry/misconfiguration causes real outages', 'Only authenticates the server by default, not the client', 'Users can be trained to click through warnings (mitigated by HSTS)', 'Does nothing once data is decrypted at the endpoints'],
    history: [
      ['1995', 'Netscape ships SSL 2.0 (3.0 in 1996); the web gains encryption.'],
      ['1999', 'TLS 1.0 standardises SSL under the IETF (RFC 2246).'],
      ['2008', 'TLS 1.2 adds modern hashes and AEAD ciphers.'],
      ['2014', 'POODLE kills SSL 3.0; Heartbleed (an OpenSSL bug) shakes trust in implementations.'],
      ['2015', 'Let\'s Encrypt launches free automated certificates; HTTPS adoption soars.'],
      ['2018', 'TLS 1.3 (RFC 8446): 1-RTT, mandatory forward secrecy, legacy cruft removed.'],
    ],
    hidden: [
      ['Forward secrecy means stealing the key later doesn\'t help', 'Because TLS 1.3 uses ephemeral Diffie–Hellman, each session\'s keys vanish afterward. An attacker who records traffic now and steals the server\'s private key next year still can\'t decrypt the recording. This is why "harvest now, decrypt later" worries focus on quantum computers, not stolen keys.'],
      ['The hostname used to leak even over HTTPS', 'SNI sends the site name in cleartext in the ClientHello so shared IPs work — meaning a network observer could see <em>which</em> site you visit even if not the content. Encrypted Client Hello (ECH) is closing this.'],
      ['Certificates are now short-lived on purpose', 'Modern certs last ~90 days, and the industry maximum is scheduled to fall to 47 days by 2029 (a 2025 CA/Browser Forum decision), so that revocation matters less — a compromised cert simply expires soon. This only works because ACME automates renewal.'],
      ['Certificate Transparency catches rogue CAs', 'Every issued certificate is logged in public append-only logs. Domain owners monitor them to spot a CA mistakenly (or maliciously) issuing a cert for their domain — a real check on the sprawling CA trust model.'],
    ],
    attacks: [
      ['Man-in-the-middle', 'Intercept and impersonate the server on the network path.', 'Certificate validation against trusted CAs; HSTS to forbid click-through; pinning.'],
      ['Downgrade attack', 'Force the connection to an older, weaker protocol or cipher.', 'Disable old versions; TLS 1.3 removes negotiable weak options; downgrade-protection in the handshake.'],
      ['Mis-issued / rogue certificate', 'A compromised or coerced CA issues a valid cert for your domain.', 'Certificate Transparency monitoring; CAA DNS records; (carefully) pinning.'],
      ['Implementation bugs (e.g. Heartbleed)', 'Flaws in the TLS library leak memory or keys.', 'Keep libraries patched; rotate keys after disclosures; reduce attack surface.'],
      ['Stripping (HTTP downgrade)', 'Redirect the user to plain HTTP so there\'s no TLS at all.', 'HSTS (with preload), redirect all HTTP to HTTPS, secure cookies.'],
    ],
    interview: [
      ['What three guarantees does TLS provide?', '<p><b>Confidentiality</b> (traffic is encrypted), <b>integrity</b> (tampering is detected), and <b>authentication</b> (the server proves its identity with a certificate; client auth is optional via mTLS). The authentication part is what lets you safely send credentials — you first confirm you\'re talking to the real server over an encrypted channel.</p>', 'junior'],
      ['How do two parties end up with the same session key without sending it?', '<p>Via <b>Diffie–Hellman</b> key exchange: each side generates a private value and sends only the corresponding public value. Combining your private value with the other side\'s public value yields the same shared secret on both ends, while an eavesdropper who sees both public values can\'t feasibly compute it. TLS 1.3 uses <em>ephemeral</em> DH per session, which also gives forward secrecy. The secret itself never crosses the wire.</p>', 'mid'],
      ['What is forward secrecy and why does TLS 1.3 guarantee it?', '<p>Forward secrecy means a session\'s keys can\'t be recovered later even if the server\'s long-term private key is compromised. TLS 1.3 mandates <b>ephemeral Diffie–Hellman</b> and removed static RSA key exchange, so each session\'s keys are derived from throwaway values and discarded. An attacker recording traffic today and stealing the key tomorrow gains nothing — which is exactly the property static RSA lacked.</p>', 'senior'],
      ['How does your browser decide to trust a certificate?', '<p>It builds a chain from the server\'s leaf certificate up through intermediates to a <b>root CA in its trust store</b>, verifying each signature. It also checks the certificate isn\'t expired or revoked (OCSP/CRL) and that the hostname matches the one being visited. If any link fails, it shows a warning. Certificate Transparency and CAA records add further checks against mis-issuance.</p>', 'mid'],
      ['A user is on hostile Wi-Fi. What actually stops a man-in-the-middle reading their HTTPS traffic?', '<p>The attacker can intercept packets but can\'t present a valid CA-signed certificate for the target domain, so certificate validation fails and the browser warns instead of connecting. The residual risk is the user clicking "proceed anyway", which <b>HSTS</b> removes by instructing browsers to refuse insecure connections to the site outright (ideally via the preload list). TLS 1.3\'s forward secrecy additionally means passively recorded traffic stays safe even if keys leak later.</p>', 'senior'],
    ],
    quiz: [
      { q: 'Besides encryption, what does a server\'s TLS certificate provide?', o: ['Faster downloads', 'Proof of the server\'s identity', 'User authentication', 'Password storage'], a: 1, e: 'The certificate authenticates the server — proving you\'re talking to the real domain, not an impostor. Client auth is the optional mTLS extension.' },
      { q: 'In Diffie–Hellman, what crosses the wire?', o: ['The shared secret itself', 'Only public values, from which both sides derive the same secret', 'Each party\'s private key', 'The server certificate only'], a: 1, e: 'Only public values are exchanged; the shared secret is computed on each side and never transmitted — so an eavesdropper can\'t recover it.' },
      { q: 'Forward secrecy (in TLS 1.3) means…', o: ['Certificates never expire', 'Stealing the server key later can\'t decrypt past recorded traffic', 'Traffic is compressed', 'The client is authenticated'], a: 1, e: 'Ephemeral DH keys per session are discarded afterward, so a later key compromise doesn\'t unlock recorded sessions.' },
      { q: 'What does HSTS accomplish?', o: ['It encrypts cookies', 'It forces HTTPS and removes the "proceed anyway" bypass', 'It issues certificates', 'It replaces Diffie–Hellman'], a: 1, e: 'HSTS tells browsers to use only HTTPS for the site and refuse insecure connections, closing the user-click-through hole in MITM defence.' },
      { q: 'A valid certificate chain must end at…', o: ['Any self-signed certificate', 'A root CA in the client\'s trust store', 'The server\'s own key', 'The user\'s password'], a: 1, e: 'Trust requires chaining leaf → intermediate → a root CA the device already trusts. Break any link and validation fails.' },
    ],
    related: ['mtls', 'ssh', 'jwt', 'hmac-sig'],
  });

  /* ---------------- mTLS ---------------- */
  HS.add({
    id: 'mtls', group: 'core', short: 'Mutual TLS', icon: 'lock', port: '443',
    title: 'Mutual TLS (mTLS)',
    tagline: 'Ordinary TLS checks the server; mutual TLS also makes the client prove itself with a certificate. The backbone of zero-trust service meshes and high-security APIs, where both ends must be certain who they\'re talking to.',
    level: 'Advanced', kind: 'Two-way certificate auth',
    spec: [['Extends', 'TLS with client certs'], ['Authenticates', 'Both client and server'], ['Common in', 'Service meshes, banking APIs'], ['Identity', 'The certificate itself']],
    analogy: `<p>Normal TLS is a customer checking the bank's credentials before handing over a deposit. Mutual TLS is the bank <em>also</em> demanding the customer's verified ID before the conversation continues — both parties show papers from an authority they both trust. Nobody talks until both are satisfied. That's why it suits machines in a data centre: each service carries an identity card and refuses to speak to anything without one.</p>`,
    flow: {
      nodes: [
        { id: 'c', label: 'Service A', sub: 'client cert', icon: 'server', x: 110, y: 150 },
        { id: 's', label: 'Service B', sub: 'server cert', icon: 'server', x: 410, y: 90 },
        { id: 'ca', label: 'Internal CA', sub: 'issues both', icon: 'idp', x: 410, y: 235 },
      ],
      order: ['c', 's', 'ca'],
      normal: {
        name: 'Both sides present certificates', summary: 'The TLS handshake proceeds as usual, but the server also requests the client\'s certificate, and each side verifies the other against a shared (often internal) CA.',
        steps: [
          { f: 'c', t: 's', k: 'req', l: 'ClientHello', title: 'Handshake begins', d: 'Service A opens a normal TLS handshake to Service B.', data: { versions: 'TLS 1.3', note: 'standard start' } },
          { f: 's', t: 'c', k: 'res', l: 'ServerHello + cert + CertificateRequest', title: 'Server asks for a client cert', d: 'Service B sends its own certificate <em>and</em> a <code>CertificateRequest</code> — the signal that this is mutual TLS. A plain client would stop here.', data: { server_cert: 'CN=service-b.internal', CertificateRequest: 'present your cert', acceptable_cas: 'Internal Root CA' }, enc: true },
          { f: 'c', t: 's', k: 'req', l: 'client Certificate + proof', title: 'Client presents its certificate', d: 'Service A sends its own certificate and signs part of the handshake with its private key, proving it owns the cert.', data: { client_cert: 'CN=service-a.internal, SPIFFE id', proof: 'CertificateVerify signature' }, enc: true },
          { f: 's', t: 'ca', k: 'int', l: 'verify client cert vs internal CA', title: 'Server verifies the client', d: 'Service B checks that Service A\'s certificate chains to the trusted internal CA and isn\'t revoked — authenticating the <em>client</em>, which ordinary TLS never does.', data: { chain: 'client cert → Internal Root CA ✓', identity: 'service-a.internal', revoked: 'no' }, ok: 'Client identity verified' },
          { f: 'c', t: 'ca', k: 'int', l: 'client also verified server', title: 'Mutual verification', d: 'Meanwhile Service A verified Service B\'s certificate too. Both ends now know exactly who the other is, cryptographically — no shared passwords or API keys needed.', data: { server_verified: 'service-b.internal ✓', mutual: 'both authenticated', secrets_exchanged: 'none — identity is the cert' } },
          { f: 'c', t: 's', k: 'req', l: 'encrypted request (trusted peer)', title: 'Authenticated channel', d: 'Application traffic flows, encrypted and with both identities established. The certificate itself is the credential, so there\'s nothing to phish or leak.', data: { channel: 'encrypted + mutually authenticated', authz: 'B can apply policy based on A\'s verified identity' }, enc: true, ok: 'Zero-trust service call established' },
        ],
      },
      attack: {
        name: 'Rogue service with no valid cert', summary: 'An attacker who breaches the network but lacks a CA-issued client certificate simply cannot complete the handshake — the core appeal of mTLS for zero-trust.',
        steps: [
          { f: 'c', t: 's', k: 'atk', l: 'rogue pod connects to Service B', title: 'Attacker inside the network', d: 'An attacker compromises a container and tries to call Service B directly, as lateral movement.', data: { source: 'compromised pod', has_network_access: 'yes', has_client_cert: 'NO' } },
          { f: 's', t: 'c', k: 'res', l: 'CertificateRequest', title: 'Server demands a certificate', d: 'Service B requires a client certificate as always. The attacker must now produce one that chains to the internal CA.', data: { CertificateRequest: 'present valid client cert', acceptable_cas: 'Internal Root CA only' } },
          { f: 'c', t: 's', k: 'atk', l: 'no CA-signed cert to present', title: 'Attacker can\'t comply', d: 'The attacker has no certificate issued by the internal CA (they can\'t sign one without the CA\'s private key), so they either present nothing or an untrusted cert.', data: { presented: 'self-signed / none', chains_to_internal_ca: 'no' } },
          { f: 's', t: 's', k: 'int', l: 'handshake aborted', title: 'Connection refused', d: 'The handshake fails before any application data flows. Network access alone is useless without a valid identity — exactly the zero-trust property mTLS provides.', data: { result: 'TLS handshake failure', lesson: 'network position ≠ authorization' }, fail: 'Rogue service blocked — no valid certificate' },
        ],
      },
    },
    basics: `
      <p>In standard TLS, only the <em>server</em> proves its identity; the client stays anonymous at the transport layer and authenticates later (password, token). <strong>Mutual TLS</strong> adds the reverse step: the server also demands a certificate from the client and verifies it. Both ends authenticate each other before any application data flows.</p>
      <p>The key shift is that <b>the certificate becomes the identity</b>. There's no password or API key to send — a service's private key, backing a cert issued by a trusted CA, <em>is</em> its credential. That makes mTLS ideal for machine-to-machine communication where you want strong, phishing-proof, non-replayable identity.</p>
      <div class="callout"><b>Where you actually see it</b>mTLS is uncommon for human users (managing client certs in browsers is painful) but pervasive between services: Kubernetes service meshes (Istio, Linkerd), bank and payment APIs, IoT fleets, and anything building "zero trust" where network location grants nothing.</div>`,
    deep: `
      <h3>Why it underpins zero-trust</h3>
      <p>The old model trusted the network: inside the firewall was "safe". Zero-trust assumes the network is hostile and requires every call to be authenticated and authorized regardless of origin. mTLS is the natural enforcement mechanism — a service refuses to talk to any peer that can't present a valid identity certificate, so breaching the network perimeter buys an attacker nothing. They still can't impersonate a service without its private key.</p>
      <h3>The operational cost: certificate lifecycle</h3>
      <p>The hard part of mTLS isn't the protocol — it's managing thousands of short-lived certificates: issuing, distributing, rotating and revoking them without downtime. This is why mTLS at scale almost always rides on automation:</p>
      <ul>
        <li><b>SPIFFE/SPIRE</b> — a standard for issuing cryptographic service identities (an <em>SVID</em>) automatically, with short lifetimes.</li>
        <li><b>Service meshes</b> (Istio, Linkerd) — sidecar proxies that establish mTLS transparently, so application code is unchanged and certs rotate behind the scenes.</li>
        <li><b>Internal/private CA</b> — you run your own CA for service certs rather than using public ones.</li>
      </ul>
      <h3>mTLS vs tokens for service auth</h3>
      <p>A common design question: mTLS or JWTs for service-to-service? mTLS authenticates at the <em>connection</em> level (strong, transparent, but coarse — it says "this is service A"), while JWTs authenticate at the <em>request</em> level and can carry fine-grained claims and propagate a user\'s identity through a call chain. Many architectures use <b>both</b>: mTLS for the channel, a token for the caller\'s detailed context.</p>`,
    howto: `
      <p>You configure the server to request and require client certs, and you need a CA to issue them:</p>
      ${C('nginx', `
        # nginx requiring client certificates
        server {
          listen 443 ssl;
          ssl_certificate     /etc/tls/service-b.crt;
          ssl_certificate_key /etc/tls/service-b.key;

          ssl_client_certificate /etc/tls/internal-ca.crt;  # CA that signs client certs
          ssl_verify_client on;        # REQUIRE a valid client cert
          ssl_verify_depth 2;
        }
      `, 'Requiring client certificates in nginx')}
      <ul>
        <li>In Kubernetes, prefer a service mesh (Istio/Linkerd) so mTLS and rotation are automatic — don\'t hand-manage certs per pod.</li>
        <li>Keep client-cert lifetimes short and automate renewal (SPIFFE/SPIRE or mesh-issued).</li>
        <li>Map the cert\'s subject/SAN to an identity and apply authorization policy on top.</li>
      </ul>
      <p>The certificate-chain playground (on the <a href="#tls">TLS page</a>) shows how each cert is validated — the same logic applies to the client cert here.</p>`,
    tool: 'certchain',
    pros: ['Both parties are cryptographically authenticated — no anonymous clients', 'No shared secret to phish, replay, or leak; identity is the key', 'Ideal for zero-trust: network access alone grants nothing', 'Transparent to app code when run via a service mesh', 'Strong, standards-based machine identity'],
    cons: ['Certificate lifecycle at scale is operationally heavy', 'Painful for human/browser users to manage client certs', 'Revocation and rotation must be automated or outages follow', 'Debugging handshake failures is notoriously fiddly', 'Coarse-grained: authenticates the connection, not per-request context'],
    history: [
      ['1990s', 'Client-certificate support exists in SSL/TLS from early on but sees niche use (some banking, government).'],
      ['2010s', 'Microservices and the collapse of the network perimeter revive interest in strong service identity.'],
      ['2017–2019', 'Istio and Linkerd bring transparent, automated mTLS to Kubernetes via sidecar proxies.'],
      ['2018', 'SPIFFE/SPIRE standardise automatic, short-lived service identities.'],
      ['2020s', 'mTLS becomes a default building block of zero-trust architectures.'],
    ],
    hidden: [
      ['The certificate IS the password', 'With mTLS there\'s nothing extra to send — a service authenticates purely by proving it holds the private key for a CA-issued cert. There\'s no secret in a request to intercept, which is a big part of the appeal.'],
      ['Meshes do it without touching your code', 'In Istio/Linkerd, a sidecar proxy intercepts traffic and performs mTLS transparently. Your application still thinks it\'s making a plain HTTP call — the identity and encryption are added beside it.'],
      ['Network position becomes worthless', 'The whole point for zero-trust: an attacker who gets a shell inside your cluster still can\'t call protected services, because they lack a valid client certificate. "Inside the firewall" stops meaning "trusted".'],
      ['Short-lived certs dodge revocation pain', 'Rather than maintain revocation lists, zero-trust systems issue certs that live minutes to hours (SPIFFE SVIDs), so a compromised identity self-expires almost immediately.'],
    ],
    attacks: [
      ['Lateral movement after breach', 'Attacker with network access tries to call internal services.', 'mTLS requires a valid client cert they don\'t have; handshake fails.'],
      ['Stolen client key', 'An attacker exfiltrates a service\'s private key.', 'Short-lived certs, key storage in HSM/secure enclave, prompt rotation, revocation.'],
      ['Compromised internal CA', 'Breaching the CA lets an attacker mint trusted identities.', 'Protect CA keys (HSM), intermediate CAs, tight issuance policy, monitoring.'],
      ['Misconfigured verification', 'Server set to request but not require, or skips chain checks.', 'Set verify to "require", validate the full chain and depth, test explicitly.'],
    ],
    interview: [
      ['How does mTLS differ from regular TLS?', '<p>Regular TLS authenticates only the <b>server</b> (via its certificate); the client is anonymous at the transport layer. <b>Mutual TLS</b> adds a step where the server also requests and verifies the <b>client\'s</b> certificate, so both ends prove their identity before any data flows. The certificate itself becomes the credential — there\'s no password or token to exchange at the transport layer.</p>', 'mid'],
      ['Why is mTLS a natural fit for zero-trust architectures?', '<p>Zero-trust assumes the network is hostile and grants nothing based on location. mTLS enforces that: every service demands a valid, CA-issued identity certificate from its peers, so an attacker who breaches the network but lacks a certificate (and the private key behind it) still can\'t talk to protected services. It turns identity, not network position, into the basis for access.</p>', 'senior'],
      ['What\'s the hardest part of running mTLS at scale, and how is it solved?', '<p>The <b>certificate lifecycle</b> — issuing, distributing, rotating and revoking certificates for thousands of short-lived workloads without causing outages. It\'s solved with automation: a service mesh (Istio/Linkerd) that establishes mTLS transparently via sidecars, and an identity framework like <b>SPIFFE/SPIRE</b> that issues short-lived service identities automatically. Short lifetimes also sidestep most revocation complexity, since compromised certs expire quickly.</p>', 'senior'],
      ['Would you use mTLS or JWTs for service-to-service auth?', '<p>They operate at different layers and often combine. mTLS authenticates the <b>connection</b> — strong, transparent, phishing-proof, but coarse ("this is service A"). JWTs authenticate the <b>request</b> and carry fine-grained claims, including propagating an end user\'s identity through a call chain. A common pattern is mTLS for the channel plus a signed token for per-request context and authorization.</p>', 'senior'],
    ],
    quiz: [
      { q: 'What does mTLS add over standard TLS?', o: ['Faster handshakes', 'The client also authenticates with a certificate', 'Password storage', 'Compression'], a: 1, e: 'Mutual TLS makes both ends present and verify certificates, authenticating the client too — not just the server.' },
      { q: 'In mTLS, a service\'s identity is essentially…', o: ['Its IP address', 'Its CA-issued certificate and private key', 'A shared API key', 'Its hostname alone'], a: 1, e: 'The certificate (backed by the private key) is the credential — there\'s no separate password or key to send.' },
      { q: 'Why does mTLS suit zero-trust networks?', o: ['It trusts everything inside the firewall', 'Network access alone is useless without a valid client certificate', 'It removes the need for encryption', 'It authenticates users via passwords'], a: 1, e: 'An attacker on the network still can\'t call services without a valid cert, so network position grants no trust.' },
      { q: 'The biggest operational challenge of mTLS at scale is…', o: ['Choosing a cipher', 'Managing the lifecycle of many short-lived certificates', 'Writing the HTML', 'Picking a port'], a: 1, e: 'Issuing, rotating and revoking certs for many workloads is the hard part — hence service meshes and SPIFFE/SPIRE automate it.' },
    ],
    related: ['tls', 'ssh', 'api-keys', 'authz-models'],
  });

  /* ---------------- SSH ---------------- */
  HS.add({
    id: 'ssh', group: 'core', short: 'SSH', icon: 'terminal', port: '22',
    title: 'SSH — Secure Shell',
    tagline: 'How you log into servers. Public-key cryptography you use every day: the key pair, the known_hosts prompt, the agent. Understanding why SSH keys beat passwords — and what that first "fingerprint" prompt really protects — is table stakes for any backend, DevOps or SRE role.',
    level: 'Intermediate', kind: 'Remote access / key-based',
    spec: [['Defined in', 'RFC 4251–4254'], ['Default port', 'TCP 22'], ['Best practice', 'Key pairs, not passwords'], ['Key types', 'Ed25519 (preferred), RSA']],
    analogy: `<p>An SSH key pair is a lock and its only key. You bolt the <em>lock</em> (public key) onto any door you want to enter — you can hand it out freely, even publish it. You keep the <em>key</em> (private key) and never let it leave your pocket. To get in, you prove you hold the key without ever sliding it under the door. And the first time you visit a building, you memorise its unique doorplate (the host fingerprint) so an impostor can't swap the whole building on you later.</p>`,
    flow: {
      nodes: [
        { id: 'c', label: 'Your laptop', sub: 'private key', icon: 'terminal', x: 110, y: 150 },
        { id: 's', label: 'Server', sub: 'authorized_keys', icon: 'server', x: 460, y: 150 },
      ],
      order: ['c', 's'],
      normal: {
        name: 'Public-key login', summary: 'The server encrypts a challenge to your public key (or verifies your signature); only the matching private key can answer, so the private key never travels and there is no password to steal.',
        steps: [
          { f: 'c', t: 's', k: 'req', l: 'version + key exchange init', title: 'Connect & negotiate', d: 'The client connects on port 22. Both sides swap version strings and algorithm lists and start an ECDH key exchange. This part is plaintext; it produces the keys that encrypt everything afterwards.', data: { port: 'TCP 22', kex: 'ECDH (curve25519)', encrypted: 'not yet' } },
          { f: 's', t: 'c', k: 'res', l: 'key exchange reply + host key signature', title: 'Server proves its identity', d: 'The server completes the key exchange and signs the exchange hash with its host key. The client checks that host key against <code>known_hosts</code>: first connection → the famous "fingerprint" prompt; later → it must match or SSH refuses. From here the channel is encrypted.', data: { host_key: 'ed25519 SHA256:aX9…', signature: 'over the exchange hash (the session ID)', known_hosts: 'first time: TOFU prompt / later: must match' }, ok: 'Server identity checked; channel encrypted' },
          { f: 'c', t: 's', k: 'req', l: 'offer public key', title: 'Client offers its public key', d: 'The client says "I\'d like to authenticate with this public key." The server checks whether that key is listed in the account\'s <code>authorized_keys</code>.', data: { offered: 'ssh-ed25519 AAAA… (public key)', server_checks: 'is it in ~/.ssh/authorized_keys?' } },
          { f: 's', t: 'c', k: 'res', l: 'PK_OK: that key is acceptable', title: 'Server accepts the key', d: 'If the public key is listed, the server says so. The client must now prove it holds the matching private key. No separate challenge is sent: the unique session ID from the key exchange is what gets signed, so the proof only works for this connection.', data: { reply: 'SSH_MSG_USERAUTH_PK_OK', to_sign: 'session ID + auth request', why: 'proves possession, not transmission' }, enc: true },
          { f: 'c', t: 's', k: 'req', l: 'signature with private key', title: 'Client signs the session ID', d: 'The client signs the session ID and request with its private key (ideally held in an agent). Because the session ID is unique to this connection, a captured signature is useless anywhere else.', data: { signature: 'sign(session ID + request, privateKey)', private_key: 'never leaves the client', replay: 'bound to session → useless elsewhere' }, enc: true },
          { f: 's', t: 'c', k: 'res', l: 'signature valid → shell', title: 'Verified — access granted', d: 'The server verifies the signature with the stored public key. Match → you get a shell. No password crossed the wire, and nothing reusable was exposed.', data: { verify: 'signature valid with stored public key ✓', granted: 'interactive shell', password_sent: 'none' }, ok: 'Logged in via key pair' },
        ],
      },
      attack: {
        name: 'The known_hosts / MITM prompt', summary: 'That "authenticity of host can\'t be established" message is a real security control. Blindly accepting it, or ignoring a changed-key warning, is how a man-in-the-middle wins.',
        steps: [
          { f: 'c', t: 's', k: 'atk', l: 'attacker intercepts port 22', title: 'MITM on the connection', d: 'An attacker between you and the server intercepts the SSH connection and presents their <em>own</em> host key, hoping to relay your session and capture everything.', data: { position: 'man in the middle', presents: 'attacker host key (not the real one)' } },
          { f: 'c', t: 'c', k: 'int', l: 'compare host key to known_hosts', title: 'The client checks known_hosts', d: 'If you\'ve connected before, the real host key is pinned in <code>known_hosts</code>. The attacker\'s key doesn\'t match, so SSH shows a loud warning and refuses by default.', data: { known_hosts: 'has real key SHA256:aX9…', presented: 'SHA256:Zz1… (different!)', action: 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED' } },
          { f: 'c', t: 'c', k: 'int', l: 'first-ever connection = weak point', title: 'First-connection trust (TOFU)', d: 'The gap is the <em>very first</em> connection, where there\'s nothing to compare to — "trust on first use". If you blindly type "yes" while an attacker is already in the middle, you pin <em>their</em> key.', data: { risk: 'first connect has no baseline', mitigation: 'verify fingerprint out-of-band, or distribute host keys / use SSH CA' }, fail: 'Blindly accepting the first prompt can pin an attacker' },
          { f: 'c', t: 'c', k: 'int', l: 'verify fingerprint out-of-band', title: 'The right habit', d: 'Confirm the fingerprint through a trusted channel (provisioning output, a config-managed <code>known_hosts</code>, or an SSH certificate authority) rather than eyeballing it. Then the warning becomes a reliable alarm.', data: { good: 'SSH CA signs host keys → no TOFU', also: 'push known_hosts via config management' }, ok: 'Host identity verified properly' },
        ],
      },
    },
    basics: `
      <p>SSH gives you an encrypted channel to a remote machine — a shell, file transfers (<code>scp</code>/<code>sftp</code>), and tunnels. You almost always authenticate with a <strong>key pair</strong> rather than a password, and understanding that pair is the whole game:</p>
      <ul>
        <li>The <b>private key</b> (<code>~/.ssh/id_ed25519</code>) stays on your machine, secret, ideally passphrase-protected. It never leaves.</li>
        <li>The <b>public key</b> (<code>id_ed25519.pub</code>) you copy to the server, into <code>~/.ssh/authorized_keys</code>. It's safe to share.</li>
      </ul>
      <p>To log in, you prove you hold the private key by signing a server challenge — the key itself is never transmitted. Compare that to a password, which must cross the wire (encrypted, but still) and can be guessed, phished or reused. A 256-bit key can't be brute-forced and isn't something you can be tricked into typing into a fake prompt.</p>
      <div class="callout"><b>This is public-key crypto you touch daily</b>SSH, TLS client certs and GPG all use the same idea: a keypair where one half verifies what the other half signs. Internalise it here and the rest of asymmetric crypto clicks.</div>`,
    deep: `
      <h3>The two authentications in every SSH session</h3>
      <p>People focus on logging <em>in</em>, but SSH authenticates in <b>both directions</b>:</p>
      <ul>
        <li><b>Host authentication</b> — the <em>server</em> proves itself to you with its host key, checked against <code>known_hosts</code>. This is what the first-connection fingerprint prompt is about, and it's your defence against connecting to an impostor server.</li>
        <li><b>User authentication</b> — <em>you</em> prove yourself to the server with your key.</li>
      </ul>
      <p>Most people wave through the host prompt, which is precisely the weak point — see the attack flow.</p>
      <h3>The SSH agent and agent forwarding</h3>
      <p>The <b>agent</b> (<code>ssh-agent</code>) holds your decrypted private key in memory so you type your passphrase once per session, and signs challenges on request — the key never hits disk unencrypted or crosses the network. <b>Agent forwarding</b> (<code>-A</code>) lets a remote host use your local agent to hop onward, which is convenient but risky: a compromised intermediate host can abuse your agent while you're connected. Prefer <code>ProxyJump</code> for multi-hop.</p>
      <h3>SSH certificates — escaping known_hosts and authorized_keys sprawl</h3>
      <p>Managing <code>authorized_keys</code> across a fleet (and <code>known_hosts</code> on every laptop) doesn't scale. An <b>SSH certificate authority</b> fixes both: a trusted CA signs user keys (so servers trust any key the CA vouches for, with an expiry) and signs host keys (so clients trust any host the CA vouches for — no TOFU prompt). This is how large infrastructures do SSH, and mentioning it signals real operational depth.</p>
      <h3>Key types</h3>
      <p><b>Ed25519</b> is the modern default: small, fast, secure. <b>RSA</b> is still common but use ≥3072-bit. Avoid DSA and ECDSA-with-NIST-curves where you can. Always protect private keys with a passphrase.</p>`,
    howto: `
      ${C('bash', `
        # 1. generate a modern key pair (prompts for a passphrase)
        ssh-keygen -t ed25519 -C "sakitha@laptop"

        # 2. copy the PUBLIC key to the server's authorized_keys
        ssh-copy-id sakitha@server.example.com

        # 3. load it into the agent once (signs challenges without re-reading disk)
        ssh-add ~/.ssh/id_ed25519

        # 4. log in — no password crosses the wire
        ssh sakitha@server.example.com

        # verify a host fingerprint out-of-band before trusting it
        ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
      `, 'Everyday SSH key workflow')}
      <div class="callout warn"><b>Harden the server</b>In <code>sshd_config</code>: <code>PasswordAuthentication no</code> (keys only), <code>PermitRootLogin no</code>, and consider a non-default port plus <code>fail2ban</code> to cut brute-force noise. Keys-only login eliminates password guessing entirely.</div>`,
    pros: ['Key pairs can\'t be guessed, phished, or reused like passwords', 'Private key never crosses the network', 'Encrypted channel for shells, file transfer and tunnels', 'Host keys detect server impersonation (known_hosts)', 'Scales with an SSH CA; integrates with agents and hardware keys'],
    cons: ['First-connection trust (TOFU) is a real weak point', 'Private-key sprawl and unmanaged authorized_keys become a liability', 'Agent forwarding can expose your key to compromised hosts', 'Lost/stolen unprotected private keys grant direct access', 'Port 22 is relentlessly scanned and brute-forced'],
    history: [
      ['1995', 'Tatu Ylönen writes SSH-1 after a password-sniffing attack on his university network.'],
      ['1996', 'SSH-2 redesigns the protocol with stronger crypto and separate transport/auth/connection layers.'],
      ['1999', 'OpenSSH is created from the last free SSH release; becomes the de-facto implementation.'],
      ['2006', 'SSH-2 standardised by the IETF (RFC 4251–4254).'],
      ['2014→', 'Ed25519 keys and SSH certificate authorities gain adoption for modern, scalable deployments.'],
    ],
    hidden: [
      ['SSH was born from a sniffing attack', 'Tatu Ylönen wrote SSH in 1995 after passwords were sniffed off his university network — it was a direct response to the insecurity of telnet/rlogin sending credentials in the clear.'],
      ['The fingerprint prompt is a real control, not a nuisance', 'That "authenticity of host can\'t be established" message is host authentication. Reflexively typing "yes" on an untrusted network can pin a man-in-the-middle\'s key. Verify out-of-band or use an SSH CA.'],
      ['Agent forwarding can bite you', 'With <code>-A</code>, any root user on the host you connect to can use your agent to authenticate as you elsewhere while you\'re connected. Prefer <code>ProxyJump</code>/<code>-J</code> for hopping through bastions.'],
      ['An SSH CA removes both TOFU and key sprawl', 'Big infrastructures sign short-lived user and host certificates with a CA, so there\'s no per-host authorized_keys to manage and no first-use prompt. It\'s the SSH equivalent of what PKI does for TLS.'],
      ['You can back SSH keys with hardware', 'FIDO2/U2F security keys (ed25519-sk) and smartcards store the private key in hardware, so even a fully compromised laptop can\'t exfiltrate it.'],
    ],
    attacks: [
      ['Password brute force', 'Automated guessing against port 22.', 'Disable password auth (keys only); fail2ban; rate limiting; non-default port.'],
      ['Man-in-the-middle on first connect', 'Attacker presents a fake host key during TOFU.', 'Verify fingerprints out-of-band; distribute known_hosts; use an SSH CA to sign host keys.'],
      ['Stolen private key', 'An unprotected key file is exfiltrated.', 'Passphrase-protect keys; store in an agent/HSM/FIDO2 key; rotate and remove from authorized_keys.'],
      ['Agent-forwarding abuse', 'A compromised intermediate host uses your forwarded agent.', 'Avoid -A; use ProxyJump; confirm with the agent only when prompted (confirm mode).'],
      ['authorized_keys tampering', 'Attacker adds their key to a compromised account.', 'Monitor the file, manage it via config management or an SSH CA, least-privilege accounts.'],
    ],
    interview: [
      ['Why are SSH keys preferred over passwords?', '<p>A key pair proves possession of a private key by signing a challenge, so the secret <b>never crosses the network</b> and there\'s nothing to phish or reuse. A 256-bit key can\'t be brute-forced, unlike a human password. Passwords must be transmitted (even if encrypted), can be guessed or phished, and are often reused. Best practice is to disable password auth entirely and allow keys only.</p>', 'junior'],
      ['What is the "authenticity of host can\'t be established" prompt actually protecting against?', '<p>It\'s <b>host authentication</b> — the server proving its identity with its host key. On first connect there\'s no stored key to compare against (trust on first use), so SSH asks you to confirm the fingerprint. On later connects it must match <code>known_hosts</code> or SSH warns loudly and refuses, which detects a man-in-the-middle or a swapped server. The weak point is blindly accepting the first prompt on an untrusted network; you should verify the fingerprint out-of-band or use an SSH CA.</p>', 'mid'],
      ['What does the SSH agent do, and what\'s the risk of agent forwarding?', '<p>The agent holds your decrypted private key in memory and signs challenges on demand, so you enter your passphrase once and the key never touches disk unencrypted or the network. <b>Agent forwarding</b> (<code>-A</code>) lets a remote host reach back to your local agent to authenticate onward — convenient for multi-hop, but a compromised intermediate host can then use your agent to impersonate you elsewhere while you\'re connected. Prefer <code>ProxyJump</code>, or use the agent\'s confirm mode.</p>', 'senior'],
      ['How do large fleets manage SSH without per-host authorized_keys and known_hosts chaos?', '<p>With an <b>SSH certificate authority</b>. A trusted CA signs <em>user</em> keys (so any server trusts a key the CA vouched for, with a short expiry — no per-host authorized_keys) and signs <em>host</em> keys (so clients trust any host the CA vouched for — no TOFU prompt). It\'s the SSH analogue of PKI for TLS: central trust, short-lived credentials, easy revocation by expiry. This scales far better than distributing individual keys.</p>', 'senior'],
    ],
    quiz: [
      { q: 'In SSH key authentication, what travels to the server?', o: ['Your private key', 'A signature proving you hold the private key', 'Your passphrase', 'The decrypted key file'], a: 1, e: 'You sign a challenge with the private key; only the signature (and your public key) is seen. The private key never leaves your machine.' },
      { q: 'The first-connection fingerprint prompt is an example of…', o: ['User authentication', 'Host authentication (trust on first use)', 'Encryption setup', 'Authorization'], a: 1, e: 'It\'s the server proving its identity via its host key. With nothing to compare against on first use, SSH asks you to confirm — the TOFU weak point.' },
      { q: 'Which public key goes into the server\'s authorized_keys file?', o: ['The private key', 'The user\'s public key', 'The host key', 'A password hash'], a: 1, e: 'Your public key is placed in authorized_keys; the matching private key stays with you and signs the login challenge.' },
      { q: 'How do large infrastructures avoid managing authorized_keys and known_hosts per machine?', o: ['They use passwords instead', 'An SSH certificate authority signs short-lived user and host keys', 'They disable host checking', 'They share one key for everyone'], a: 1, e: 'An SSH CA centralises trust: it vouches for user and host keys with expiry, removing per-host key files and the TOFU prompt.' },
    ],
    related: ['tls', 'mtls', 'passwords', 'webauthn'],
  });
})();
