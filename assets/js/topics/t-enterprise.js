/* Enterprise & SSO: SSO overview, SAML, Kerberos, LDAP, RADIUS */
(function () {
  'use strict';
  const HS = window.HS, C = window.C;

  /* ---------------- SSO ---------------- */
  HS.add({
    id: 'sso', group: 'ent', short: 'Single Sign-On', icon: 'idp',
    title: 'Single Sign-On (SSO)',
    tagline: 'Log in once, reach everything. The pattern — not a single protocol — behind corporate logins and "Sign in with Google". Understanding the IdP/SP split and the session-vs-federation distinction frames every enterprise auth question.',
    level: 'Intermediate', kind: 'Pattern / federation',
    spec: [['Is', 'A pattern, not one protocol'], ['Built with', 'SAML, OIDC, Kerberos'], ['Key roles', 'IdP and SP'], ['Trade-off', 'Convenience vs central risk']],
    analogy: `<p>SSO is the wristband at a theme park. You show ID once at the gate, get a wristband, and every ride just checks the band — no re-proving who you are at each queue. The park gate is the <em>identity provider</em>; each ride is a <em>service provider</em> that trusts the gate. Lose the band or let someone copy it, though, and they ride everything — which is why the gate needs strong checks (MFA) and the band needs to expire.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'Employee', sub: 'browser', icon: 'user', x: 95, y: 150 },
        { id: 'sp1', label: 'App A', sub: 'service provider', icon: 'cloud', x: 330, y: 70 },
        { id: 'idp', label: 'IdP', sub: 'Okta / Entra', icon: 'idp', x: 330, y: 230 },
        { id: 'sp2', label: 'App B', sub: 'service provider', icon: 'cloud', x: 565, y: 150 },
      ],
      order: ['u', 'sp1', 'idp', 'sp2'],
      normal: {
        name: 'One login, many apps', summary: 'The first app bounces you to the identity provider; after you authenticate once there, every other app trusts the IdP\'s assertion and you skip logging in again.',
        steps: [
          { f: 'u', t: 'sp1', k: 'req', l: 'open App A', title: 'Reach the first app', d: 'You open App A. It has no session for you and doesn\'t handle passwords itself — it delegates login to the IdP.', data: { app: 'App A (e.g. Jira)', local_session: 'none', handles_passwords: 'no' } },
          { f: 'sp1', t: 'idp', k: 'req', l: 'redirect to IdP', title: 'Redirect to the IdP', d: 'App A redirects your browser to the company IdP with an authentication request (SAML or OIDC under the hood).', data: { redirect: 'to idp.company.com', protocol: 'SAML AuthnRequest or OIDC authorize' } },
          { f: 'u', t: 'idp', k: 'req', l: 'authenticate once (+ MFA)', title: 'Authenticate at the IdP', d: 'You log in at the IdP — password plus MFA, ideally a passkey. The IdP creates an <em>IdP session</em> in your browser. This is the one time you prove yourself.', data: { login: 'password + MFA / passkey', idp_session: 'cookie set at IdP' }, enc: true },
          { f: 'idp', t: 'sp1', k: 'res', l: 'signed assertion → App A', title: 'IdP vouches to App A', d: 'The IdP sends App A a signed assertion/token saying "this is employee 8842, authenticated". App A verifies the signature and creates its own local session.', data: { assertion: 'signed: user=8842, authenticated', verify: 'IdP signature ✓', result: 'App A session created' }, ok: 'Logged into App A' },
          { f: 'u', t: 'sp2', k: 'req', l: 'open App B', title: 'Now open a second app', d: 'Later you open App B. It also redirects to the IdP — but your IdP session cookie is already there.', data: { app: 'App B (e.g. Confluence)', redirect: 'to idp.company.com' } },
          { f: 'idp', t: 'sp2', k: 'res', l: 'already authenticated → assertion', title: 'No second login', d: 'The IdP sees its existing session, so it issues App B an assertion immediately — no password prompt. That seamless jump is the whole point of SSO.', data: { idp_session: 'still valid → no prompt', assertion: 'signed for App B' }, ok: 'Logged into App B without re-entering anything' },
        ],
      },
      attack: {
        name: 'Phished IdP session / token theft', summary: 'SSO concentrates risk: one stolen IdP session can unlock every app. Phishing-resistant MFA and short, bound sessions are the defences.',
        steps: [
          { f: 'u', t: 'idp', k: 'atk', l: 'user phished → IdP creds captured', title: 'Attacker phishes the IdP login', d: 'Because the IdP is the master key, it\'s the prime phishing target. A fake login page or a real-time relay proxy captures the user\'s credentials and even their OTP.', data: { target: 'the IdP login (master key)', captured: 'password + OTP via relay proxy' } },
          { f: 'idp', t: 'idp', k: 'int', l: 'OTP MFA can be relayed', title: 'Why OTP alone isn\'t enough', d: 'A one-time code typed into a phishing proxy is forwarded to the real IdP in real time — so SMS/app OTP doesn\'t stop a determined phisher. The attacker rides in.', data: { 'OTP MFA': 'relayed in real time → bypassed', effect: 'attacker obtains an IdP session' } },
          { f: 'idp', t: 'idp', k: 'int', l: 'defense: phishing-resistant MFA', title: 'Passkeys break the relay', d: 'A <a href="#webauthn">passkey/FIDO2</a> signs the IdP\'s real origin, so a phishing domain can\'t produce a valid assertion — the relay fails. This is why enterprises move SSO MFA to passkeys.', data: { 'passkey MFA': 'bound to real origin → relay fails', also: 'device-bound session tokens' }, ok: 'Phishing-resistant MFA stops the relay' },
          { f: 'idp', t: 'idp', k: 'int', l: 'limit blast radius', title: 'Contain the concentration risk', d: 'Beyond MFA: short IdP sessions, step-up auth for sensitive apps, continuous/risk-based checks, and token binding limit what one stolen session reaches. SSO\'s convenience and its risk are two sides of the same coin.', data: { controls: 'short sessions · step-up · risk-based · token binding', principle: 'one key opens many doors → protect the key' }, ok: 'Blast radius contained' },
        ],
      },
    },
    basics: `
      <p>Single Sign-On lets a user authenticate <em>once</em> and access many independent applications without logging in again. It isn't a protocol — it's a pattern implemented <em>using</em> protocols like <a href="#saml">SAML</a>, <a href="#oidc">OIDC</a> and <a href="#kerberos">Kerberos</a>.</p>
      <p>Two roles appear everywhere in SSO (and across SAML/OIDC):</p>
      <ul>
        <li><b>Identity Provider (IdP)</b> — the single place that authenticates users and vouches for them: Okta, Microsoft Entra ID (Azure AD), Google Workspace, Ping.</li>
        <li><b>Service Provider (SP)</b> — each application that trusts the IdP and consumes its assertions (also called the Relying Party in OIDC).</li>
      </ul>
      <p>The flow is always the same shape: an app redirects you to the IdP; you authenticate there once; the IdP sends the app a signed assertion; the app trusts it and logs you in. Your browser holds an <em>IdP session</em>, so subsequent apps skip the prompt entirely.</p>
      <div class="callout"><b>SSO ≠ password manager</b>A password manager still logs into each app separately with its own password. True SSO means the apps don't have their own password for you at all — they defer to the IdP. That's why SSO also enables instant off-boarding: disable one IdP account and every app access dies at once.</div>`,
    deep: `
      <h3>Why enterprises love it (and why it's risky)</h3>
      <p>SSO's benefits are organisational as much as technical:</p>
      <ul>
        <li><b>One strong login</b> to protect instead of dozens of weak app passwords — concentrate MFA and monitoring in one place.</li>
        <li><b>Instant provisioning/deprovisioning</b> — IT grants or revokes access to everything centrally; a departing employee is cut off everywhere immediately.</li>
        <li><b>Audit and compliance</b> — a single authoritative log of who accessed what.</li>
        <li><b>Better UX</b> — fewer prompts, fewer forgotten-password tickets.</li>
      </ul>
      <p>The flip side, and the interview talking point: SSO is a <b>single point of failure and a concentrated target</b>. One phished IdP credential can open every connected app, and an IdP outage locks everyone out of everything. So the IdP must have the strongest possible protection (phishing-resistant MFA), and architects plan for its availability.</p>
      <h3>SSO vs federation vs social login</h3>
      <ul>
        <li><b>SSO</b> usually means one login across apps within <em>one</em> organisation/trust domain.</li>
        <li><b>Federation</b> extends trust <em>across</em> organisations — e.g. a university letting you use your home institution's login at a partner (eduGAIN), or a B2B app accepting a customer company's IdP.</li>
        <li><b>Social login</b> ("Sign in with Google/Apple") is consumer SSO/federation built on OIDC.</li>
      </ul>
      <h3>Session layering — where "logged in" actually lives</h3>
      <p>There are really two sessions: the <b>IdP session</b> (in your browser, the thing that makes the second app seamless) and each app's <b>local session</b> created after it receives the assertion. This layering explains a classic gotcha: <b>Single Logout (SLO)</b> is hard. Killing the IdP session doesn't automatically end every app's local session, so "log out everywhere" is notoriously unreliable across SSO.</p>`,
    uses: [
      ['Corporate app suites', 'One Okta/Entra login opens email, chat, HR, code hosting, cloud consoles.'],
      ['Consumer social login', '"Sign in with Google/Apple" reuses one identity across third-party sites (OIDC).'],
      ['University / research federation', 'Shibboleth/eduGAIN let students log into partner resources with their home credentials.'],
      ['B2B SaaS', 'Enterprise customers connect their own IdP so their staff log into your product with company credentials.'],
    ],
    howto: `
      <p>As an app developer you usually <em>integrate with</em> an IdP rather than build SSO:</p>
      ${C('text', `
        • Prefer OIDC for new apps; SAML when the enterprise IdP or app requires it.
        • Register your app with the IdP; exchange metadata (endpoints, signing certs).
        • Validate the assertion/token properly (signature, issuer, audience, expiry, nonce).
        • Map IdP attributes/claims to your app's roles (authorization stays your job).
        • Support SCIM for automated user provisioning/deprovisioning where possible.
        • Plan for IdP outages and test Single Logout behaviour explicitly.
      `, 'Integrating an app with an enterprise IdP')}
      <div class="callout warn"><b>Authentication is delegated; authorization is not</b>SSO tells your app <em>who</em> the user is. Deciding what they may do inside your app is still yours — map IdP groups/claims to roles, and never assume "authenticated via IdP" means "allowed to do anything".</div>`,
    pros: ['One strong, well-protected login instead of many weak ones', 'Central provisioning and instant deprovisioning', 'Single audit trail for compliance', 'Fewer passwords and reset tickets; better UX', 'MFA enforced in one place for all apps'],
    cons: ['Single point of failure — IdP outage locks out everything', 'Concentrated target — one phished credential unlocks all apps', 'Single Logout across apps is unreliable', 'Integration complexity and per-app trust setup', 'Vendor lock-in to the IdP platform'],
    history: [
      ['1988', 'Kerberos (MIT Project Athena) delivers early campus-wide single sign-on.'],
      ['2002', 'SAML 1.0 standardises web SSO assertions for the enterprise.'],
      ['2005', 'SAML 2.0 becomes the dominant enterprise/federation SSO protocol.'],
      ['2014', 'OpenID Connect brings lightweight SSO to web, mobile and consumer apps.'],
      ['2020s', 'Phishing-resistant MFA (passkeys) and SCIM provisioning become SSO best practice; zero-trust reshapes session handling.'],
    ],
    hidden: [
      ['"Log out everywhere" rarely works', 'Because each app holds its own local session after the IdP vouches for you, Single Logout (SLO) is famously flaky. Ending the IdP session doesn\'t reliably tear down every app session — a real operational gotcha.'],
      ['SSO makes the IdP the crown jewels', 'Attackers increasingly skip the apps and phish the IdP directly, because one IdP session opens everything. This is exactly why IdP MFA should be phishing-resistant (passkeys), not SMS codes.'],
      ['SSO and provisioning are different problems', 'SSO handles <em>login</em>; getting accounts created/removed in each app is <em>provisioning</em>, usually done with SCIM. Conflating them is a common interview slip.'],
      ['"SSO tax" is a real debate', 'Many SaaS vendors gate SSO behind their most expensive tier, so security teams half-joke about the "SSO tax" that pushes smaller orgs toward weaker per-app passwords.'],
    ],
    attacks: [
      ['IdP phishing', 'Steal the master credential/session that unlocks all apps.', 'Phishing-resistant MFA (passkeys/FIDO2), user training, domain checks.'],
      ['Session/token theft', 'Steal the IdP session cookie or assertion and replay it.', 'Short sessions, token binding/DPoP, device posture checks, re-auth for sensitive actions.'],
      ['Assertion forgery/replay', 'Forge or reuse a SAML/OIDC assertion (see those pages).', 'Verify signatures, audience, timestamps and one-time IDs.'],
      ['IdP compromise', 'Breach the IdP itself and mint assertions at will.', 'Harden/monitor the IdP, limit admins, alert on anomalous issuance, break-glass plans.'],
    ],
    interview: [
      ['Is SSO a protocol?', '<p>No — it\'s a <b>pattern</b>: authenticate once, access many apps. It\'s implemented using protocols like SAML, OpenID Connect and Kerberos. The common shape is an app (service provider) redirecting you to an identity provider, you authenticating once there, and the IdP returning a signed assertion each app trusts.</p>', 'junior'],
      ['What are the security trade-offs of SSO?', '<p>Upside: one strong, centrally-protected login with MFA and a single audit trail, plus instant deprovisioning. Downside: the IdP becomes a <b>single point of failure</b> (outage = everyone locked out) and a <b>concentrated target</b> (one phished credential unlocks every app). So the IdP needs the strongest protection — phishing-resistant MFA — and you plan for its availability and contain blast radius with short sessions and step-up auth.</p>', 'mid'],
      ['Why is Single Logout hard in SSO?', '<p>Because there are two session layers: the IdP session in the browser and a separate local session each app created after receiving the assertion. Ending the IdP session doesn\'t automatically terminate every app\'s local session, and not all apps implement the logout callbacks reliably. So "log out everywhere" is best-effort — a real operational weakness teams must account for, often with short app-session lifetimes.</p>', 'senior'],
      ['SSO delegates authentication — what\'s still your app\'s responsibility?', '<p><b>Authorization.</b> The IdP tells you <em>who</em> the user is; your app still decides <em>what they may do</em>, by mapping IdP groups/claims to its own roles and enforcing them. You also still own validating the assertion correctly (signature, audience, expiry) and often provisioning accounts (SCIM). Treating "authenticated via IdP" as "allowed everything" is a classic mistake.</p>', 'mid'],
    ],
    quiz: [
      { q: 'In SSO terminology, the service that authenticates users and vouches for them is the…', o: ['Service Provider', 'Identity Provider (IdP)', 'Resource Server', 'Relying Party'], a: 1, e: 'The IdP authenticates and issues assertions; each app is a Service Provider (Relying Party in OIDC) that trusts it.' },
      { q: 'A key risk introduced by SSO is…', o: ['Slower logins', 'One phished credential or IdP outage affects all connected apps', 'Weaker encryption', 'More passwords to remember'], a: 1, e: 'SSO concentrates both convenience and risk in the IdP — a single point of failure and a prime phishing target.' },
      { q: 'Why is "log out everywhere" unreliable in SSO?', o: ['Browsers block it', 'Each app holds its own local session separate from the IdP session', 'Passwords are cached', 'The IdP never logs out'], a: 1, e: 'Single Logout must tear down every app\'s independent local session, which many apps implement poorly — so it\'s best-effort.' },
      { q: 'After SSO authenticates a user, deciding what they can do in your app is…', o: ['Handled entirely by the IdP', 'Still your app\'s authorization responsibility', 'Impossible', 'Done by the browser'], a: 1, e: 'SSO delegates authentication only. Your app still maps IdP claims to roles and enforces authorization.' },
    ],
    related: ['saml', 'oidc', 'kerberos', 'oauth'],
  });

  /* ---------------- SAML ---------------- */
  HS.add({
    id: 'saml', group: 'ent', short: 'SAML 2.0', icon: 'idp',
    title: 'SAML 2.0',
    tagline: 'The XML grandfather of enterprise SSO. Verbose and old, but still everywhere in corporate and government systems. Knowing the SP-initiated flow, the signed assertion, and why XML signatures are perilous is classic enterprise-interview territory.',
    level: 'Advanced', kind: 'XML federation',
    spec: [['Standard', 'OASIS SAML 2.0 (2005)'], ['Format', 'XML + XML-DSig'], ['Carries', 'Signed assertions'], ['Bindings', 'HTTP-Redirect, HTTP-POST']],
    analogy: `<p>SAML is a sealed, notarised letter of introduction. Your identity provider writes "I vouch that this is employee 8842," stamps it with a tamper-proof wax seal (an XML signature), and hands it to you to carry — via your browser — to the application. The app doesn't phone the IdP; it just checks the seal is genuine and unbroken, then lets you in. The letter is bulky (XML), the seal is fiddly to verify correctly, and forging or altering the seal is exactly where attacks happen.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'Browser', sub: 'employee', icon: 'browser', x: 100, y: 150 },
        { id: 'sp', label: 'App (SP)', sub: 'service provider', icon: 'cloud', x: 360, y: 75 },
        { id: 'idp', label: 'IdP', sub: 'ADFS / Okta', icon: 'idp', x: 360, y: 230 },
      ],
      order: ['u', 'sp', 'idp'],
      normal: {
        name: 'SP-initiated SSO', summary: 'The app creates an AuthnRequest, the browser carries it to the IdP, and after login the IdP POSTs a signed assertion back through the browser to the app.',
        steps: [
          { f: 'u', t: 'sp', k: 'req', l: 'GET /app (no session)', title: 'Reach the app', d: 'You open a SAML-protected app with no existing session.', data: { 'GET': 'https://app/dashboard', session: 'none' } },
          { f: 'sp', t: 'u', k: 'res', l: 'redirect with AuthnRequest', title: 'App issues an AuthnRequest', d: 'The SP builds a (usually signed) <code>&lt;AuthnRequest&gt;</code> and redirects your browser to the IdP\'s SSO endpoint, encoding the request in the URL or a form.', data: { 'AuthnRequest': '<samlp:AuthnRequest Issuer=app …>', binding: 'HTTP-Redirect', relayState: 'where to return after login' } },
          { f: 'u', t: 'idp', k: 'req', l: 'deliver AuthnRequest + log in', title: 'Authenticate at the IdP', d: 'The browser delivers the request to the IdP, where you log in (password + MFA) if you don\'t already have an IdP session.', data: { endpoint: 'idp/sso', login: 'password + MFA', idp_session: 'created/reused' }, enc: true },
          { f: 'idp', t: 'idp', k: 'int', l: 'build + sign assertion', title: 'IdP mints a signed assertion', d: 'The IdP creates an <code>&lt;Assertion&gt;</code> stating who you are and your attributes, then signs it with its private key using XML-DSig. Conditions pin the audience and a short validity window.', data: { subject: 'NameID sakitha@company.com', attributes: 'role=editor, dept=eng', signature: 'XML-DSig (IdP private key)', conditions: 'Audience=app, NotOnOrAfter=+5min' } },
          { f: 'idp', t: 'u', k: 'res', l: 'auto-POST SAMLResponse', title: 'Assertion returned via browser', d: 'The IdP returns an auto-submitting HTML form that POSTs the <code>SAMLResponse</code> (the signed assertion) to the app\'s ACS URL. SAML routes through the browser — the IdP and SP never talk directly.', data: { binding: 'HTTP-POST', target: 'app/acs (Assertion Consumer Service)', transport: 'through the browser only' } },
          { f: 'u', t: 'sp', k: 'req', l: 'POST SAMLResponse → ACS', title: 'App verifies and logs you in', d: 'The app verifies the XML signature against the IdP\'s certificate, checks the audience, timestamps and a not-seen-before ID, maps attributes to roles, and creates a local session.', data: { verify: 'signature valid (IdP cert) ✓', audience: 'this app ✓', notOnOrAfter: 'still valid ✓', result: 'local session + role=editor' }, ok: 'Logged in via SAML assertion' },
        ],
      },
      attack: {
        name: 'XML signature wrapping (XSW)', summary: 'SAML\'s notorious class of attacks: manipulate the XML so the signature validates over a legitimate element while the app reads attacker-controlled data from another. Strict, position-aware verification is the defence.',
        steps: [
          { f: 'u', t: 'sp', k: 'atk', l: 'intercept a valid SAMLResponse', title: 'Start from a genuine assertion', d: 'The attacker has a validly signed assertion (their own, or captured). They can\'t alter the signed bytes without breaking the signature — so instead they restructure the XML around it.', data: { have: 'genuinely signed <Assertion> for attacker', goal: 'be seen as admin without re-signing' } },
          { f: 'u', t: 'sp', k: 'atk', l: 'wrap: add forged assertion, move signed one', title: 'Wrap the signature', d: 'They craft a response containing a <em>forged</em> assertion (role=admin) plus the original signed one tucked elsewhere, exploiting the gap between <em>what gets signature-checked</em> and <em>what the app actually reads</em>.', data: { document: 'forged <Assertion role=admin> + original signed one relocated', bet: 'verifier checks the signed node, app reads the forged node' } },
          { f: 'sp', t: 'sp', k: 'int', l: 'weak verifier: signature "valid"', title: 'The vulnerable case', d: 'A loose implementation verifies <em>a</em> signature successfully (over the genuine element) but then extracts identity from the attacker\'s unsigned element — granting admin. This is XML Signature Wrapping.', data: { signature_check: 'passes (on the genuine node)', data_used: 'the FORGED node', outcome_if_vulnerable: 'privilege escalation' }, fail: 'Vulnerable libraries have granted admin this way' },
          { f: 'sp', t: 'sp', k: 'int', l: 'fix: verify then read the SAME node', title: 'Correct verification', d: 'A correct verifier ensures the signature covers exactly the element whose data it uses, rejects extra/relocated assertions, resolves references strictly, and pins the schema. Maintained libraries do this — rolling your own SAML is how teams get breached.', data: { rule: 'signed element == consumed element', also: 'reject multiple assertions, strict XML parsing, check audience+timestamps', advice: 'use a vetted library, never hand-roll' }, ok: 'Defended: strict, position-aware signature validation' },
        ],
      },
    },
    basics: `
      <p>SAML (Security Assertion Markup Language) 2.0 is the long-standing standard for web SSO, especially in enterprises and government. It predates OIDC and is built entirely on <strong>XML</strong>. The unit of trust is a signed <b>assertion</b>: an XML document in which the IdP states who you are and your attributes, sealed with an <b>XML signature</b>.</p>
      <p>It uses the same IdP/SP roles as general <a href="#sso">SSO</a>. Two flows exist:</p>
      <ul>
        <li><b>SP-initiated</b> (most common) — you hit the app first; it bounces you to the IdP (shown in the diagram).</li>
        <li><b>IdP-initiated</b> — you start at the IdP's dashboard and click into an app; the IdP pushes an unsolicited assertion. Convenient but more prone to abuse, so it's discouraged.</li>
      </ul>
      <p>Crucially, SAML runs <em>through the browser</em> using "bindings" (HTTP-Redirect for the request, HTTP-POST for the response). The IdP and SP never call each other directly — the browser relays signed documents between them.</p>
      <div class="callout"><b>SAML vs OIDC in one line</b>Same job (federated SSO), different envelope: SAML is heavyweight signed XML built for the enterprise web; OIDC is lightweight signed JSON (JWT) built for modern web, mobile and APIs. New integrations usually pick OIDC; SAML persists for the vast installed base.</div>`,
    deep: `
      <h3>Anatomy of a SAML response</h3>
      <p>The <code>&lt;Response&gt;</code> wraps an <code>&lt;Assertion&gt;</code> containing:</p>
      <ul>
        <li><b>Subject / NameID</b> — the user identifier (email, a persistent opaque ID, etc.).</li>
        <li><b>Conditions</b> — <code>Audience</code> (which SP this is for) and <code>NotBefore</code>/<code>NotOnOrAfter</code> (a short validity window).</li>
        <li><b>AuthnStatement</b> — how and when the user authenticated.</li>
        <li><b>AttributeStatement</b> — attributes like role, department, groups, that the SP maps to its own authorization.</li>
        <li><b>Signature</b> — XML-DSig over the assertion (and/or the response), the thing that makes it trustworthy.</li>
      </ul>
      <h3>Why XML signatures are dangerous</h3>
      <p>XML-DSig is far more flexible than a JWT's flat signature: it can sign <em>parts</em> of a document, reference elements by ID, and allow transforms. That flexibility is the problem. <b>XML Signature Wrapping (XSW)</b> attacks exploit the gap between the element a verifier checks and the element the application then reads. A whole family of real CVEs across many SAML libraries came from this. The lesson every interviewer wants: <b>never implement SAML yourself; use a maintained, hardened library,</b> and ensure it verifies that the signed element is exactly the one consumed.</p>
      <h3>Metadata and trust setup</h3>
      <p>SP and IdP establish trust by exchanging <b>metadata</b> XML — endpoints (SSO URL, ACS URL), the signing certificate, and NameID formats. A frequent real-world outage: the IdP's signing certificate <b>expires</b> and every SAML login breaks at once, because the SP can no longer validate signatures. Certificate rotation is an operational must.</p>
      <h3>RelayState</h3>
      <p><code>RelayState</code> carries "where to send the user after login" through the round trip. It must be treated as untrusted input — an open-redirect or injection vector if the SP echoes it back carelessly.</p>`,
    howto: `
      <p>The overriding rule: integrate with a trusted library/IdP, configure strictly, and rotate certificates.</p>
      ${C('text', `
        Checklist for a SAML SP:
        • Use a maintained SAML library; never parse/verify XML signatures by hand.
        • Verify the signature covers the SAME assertion you read (XSW defence).
        • Reject responses with more than one assertion; enforce strict schema parsing.
        • Check Audience == your entityID, and NotBefore/NotOnOrAfter windows.
        • Track used assertion IDs (InResponseTo) to prevent replay.
        • Prefer SP-initiated; be wary of IdP-initiated (unsolicited) responses.
        • Monitor and rotate the IdP signing certificate BEFORE it expires.
        • Treat RelayState as untrusted (no open redirects).
      `, 'SAML service-provider hardening checklist')}
      <p>See the SAML-vs-OIDC format comparison below to feel the difference in envelopes.</p>`,
    tool: 'samloidc',
    pros: ['Mature, universally supported in enterprise/government', 'Rich attribute passing for complex org structures', 'Browser-based — works with plain web apps, no client secret needed at the SP', 'Strong installed base and vendor tooling', 'Assertions are self-contained and signed'],
    cons: ['Verbose XML — heavy and awkward for mobile/SPA/API clients', 'XML-DSig is complex and historically riddled with signature-wrapping CVEs', 'Easy to misconfigure; must not be hand-rolled', 'Certificate expiry causes fleet-wide outages', 'Single Logout is clumsy; IdP-initiated flow is risky'],
    history: [
      ['2002', 'SAML 1.0/1.1 standardise web SSO assertions at OASIS.'],
      ['2005', 'SAML 2.0 released — the version everyone means by "SAML" — unifying earlier efforts and Shibboleth.'],
      ['2012', 'Research formalises XML Signature Wrapping; waves of CVEs hit SAML implementations.'],
      ['2014', 'OIDC arrives as the lighter alternative; new projects start preferring it.'],
      ['2018', 'Duo discloses an XML-comment canonicalisation flaw across many SAML libraries that let attackers log in as other users — another reason not to hand-roll SAML.'],
      ['2020s', 'SAML remains entrenched in enterprises while OIDC takes new integrations.'],
    ],
    hidden: [
      ['XML Signature Wrapping is SAML\'s signature flaw', 'Because XML-DSig can sign a fragment and reference elements loosely, attackers slip a forged assertion beside a genuinely signed one so the verifier checks one node while the app reads another. It has produced real admin-escalation CVEs across many products.'],
      ['An expired IdP cert breaks everyone at once', 'SAML trust rests on the IdP\'s signing certificate. When it quietly expires, every SP rejects every login simultaneously — one of the most common SAML outages, entirely preventable with rotation monitoring.'],
      ['SAML never phones home', 'Unlike a token-introspection call, the SP validates the assertion locally via the browser-delivered signature. The IdP and SP exchange documents only through the user\'s browser, which is why bindings and RelayState exist.'],
      ['IdP-initiated SSO is a soft spot', 'An unsolicited assertion (no AuthnRequest to correlate) is easier to replay or inject, so modern guidance prefers SP-initiated flows and treats IdP-initiated with care.'],
    ],
    attacks: [
      ['XML Signature Wrapping (XSW)', 'Restructure the XML so the signature validates over one element while the app reads attacker-controlled data from another.', 'Verify the signed element is exactly the consumed one; reject multiple assertions; strict parsing; use a vetted library.'],
      ['Assertion replay', 'Reuse a captured, still-valid assertion.', 'Short NotOnOrAfter windows; track used IDs/InResponseTo; TLS.'],
      ['Certificate expiry/compromise', 'Expired cert breaks logins; stolen key forges assertions.', 'Monitor and rotate certs; protect IdP keys; alert on anomalies.'],
      ['Open redirect via RelayState', 'Abuse the post-login redirect target.', 'Validate/whitelist RelayState; never trust it as a redirect URL.'],
      ['IdP-initiated injection', 'Inject an unsolicited assertion into a victim session.', 'Prefer SP-initiated with InResponseTo correlation; restrict IdP-initiated.'],
    ],
    interview: [
      ['What is a SAML assertion and how is it trusted?', '<p>It\'s an XML document in which the IdP states who the user is and their attributes (role, groups), wrapped with conditions (audience, validity window) and sealed with an <b>XML signature</b> (XML-DSig) made with the IdP\'s private key. The service provider trusts it by verifying that signature against the IdP\'s certificate and checking the audience and timestamps — no direct call back to the IdP; the assertion is self-contained and browser-delivered.</p>', 'mid'],
      ['Walk through SP-initiated SAML SSO.', '<p>The user hits the app (SP) with no session; the SP builds an <code>AuthnRequest</code> and redirects the browser to the IdP. The user authenticates at the IdP (or reuses an IdP session). The IdP creates a signed <code>Assertion</code> and returns it via an auto-submitting form that POSTs the <code>SAMLResponse</code> to the SP\'s ACS URL. The SP verifies the signature, checks audience/timestamps/ID, maps attributes to roles, and creates a local session. Everything flows through the browser; IdP and SP never talk directly.</p>', 'mid'],
      ['What is XML Signature Wrapping and why is it SAML-specific?', '<p>XSW exploits XML-DSig\'s flexibility: a signature can cover a fragment and reference elements loosely, so an attacker can place a <b>forged</b> assertion in the document while relocating the genuinely signed one, such that a loose verifier validates the real signature but the application then reads the forged element — often escalating to admin. It\'s SAML-specific because it stems from XML signatures\' structural flexibility (a JWT\'s flat signature covers the whole token). The defence is strict, position-aware validation ensuring the signed element is exactly the consumed one — which is why you use a hardened library, never hand-rolled XML.</p>', 'senior'],
      ['SAML vs OIDC — when would you still choose SAML?', '<p>Choose SAML when you must integrate with an existing enterprise/government IdP or legacy app that only speaks SAML, or when rich XML attribute exchange is already established. For anything new — especially mobile, SPAs, or APIs — OIDC is lighter (JSON/JWT, simple redirects, discovery/JWKS) and easier to secure. Most orgs run both: SAML for the installed base, OIDC for new integrations.</p>', 'senior'],
    ],
    quiz: [
      { q: 'A SAML assertion is encoded as…', o: ['A JSON web token', 'Signed XML (XML-DSig)', 'A base64 cookie', 'A binary blob'], a: 1, e: 'SAML is XML-based; the assertion is sealed with an XML signature. That envelope is the main contrast with OIDC\'s JWT.' },
      { q: 'In SAML SSO, how do the IdP and SP communicate?', o: ['Directly over a back channel', 'Through the user\'s browser via bindings', 'Over SSH', 'They share a database'], a: 1, e: 'SAML routes signed documents through the browser (HTTP-Redirect/POST). The SP validates locally; the parties don\'t call each other directly.' },
      { q: 'XML Signature Wrapping works by…', o: ['Guessing the IdP password', 'Making the signature validate on one element while the app reads another', 'Brute-forcing the certificate', 'Expiring the token early'], a: 1, e: 'XSW exploits the gap between the signed element and the consumed element. Strict, position-aware verification and vetted libraries prevent it.' },
      { q: 'A very common real-world SAML outage is caused by…', o: ['Too many users', 'The IdP signing certificate expiring', 'Weak passwords', 'Browser updates'], a: 1, e: 'When the IdP\'s signing cert expires, every SP rejects every assertion at once. Monitoring and rotating it is essential.' },
    ],
    related: ['sso', 'oidc', 'oauth', 'kerberos'],
  });

  /* ---------------- Kerberos ---------------- */
  HS.add({
    id: 'kerberos', group: 'ent', short: 'Kerberos', icon: 'ticket', port: '88',
    title: 'Kerberos',
    tagline: 'The ticket-based protocol behind Windows Active Directory logins — when you sign into a domain PC and everything "just works", that\'s Kerberos. A beautiful 1980s design whose tickets, KDC and famous attacks still come up for infrastructure roles.',
    level: 'Advanced', kind: 'Ticket-based SSO',
    spec: [['Origin', 'MIT Project Athena (1980s)'], ['Port', 'TCP/UDP 88 (KDC)'], ['Core idea', 'Tickets, not passwords'], ['Requires', 'Synchronised clocks']],
    analogy: `<p>Kerberos is a theme park with a central ticket office. You prove your identity once at the office and get a <em>master pass</em> (the TGT). You never show ID at a ride; instead you take the master pass back to a booth to get a <em>ride-specific ticket</em>, which only that ride can read. Each ride trusts the ticket office's seal. Your actual ID (your password) stays at the gate — the rides never see it, so a nosy ride operator learns nothing they could reuse elsewhere.</p>`,
    flow: {
      nodes: [
        { id: 'c', label: 'Client', sub: 'domain PC', icon: 'terminal', x: 95, y: 150 },
        { id: 'as', label: 'AS', sub: 'KDC: auth', icon: 'idp', x: 330, y: 70 },
        { id: 'tgs', label: 'TGS', sub: 'KDC: tickets', icon: 'idp', x: 330, y: 230 },
        { id: 'svc', label: 'File server', sub: 'service', icon: 'server', x: 565, y: 150 },
      ],
      order: ['c', 'as', 'tgs', 'svc'],
      normal: {
        name: 'Tickets, not passwords', summary: 'Authenticate once to the KDC for a Ticket-Granting Ticket, then trade it for per-service tickets. Each ticket is encrypted so only its intended service can read it; your password never travels.',
        steps: [
          { f: 'c', t: 'as', k: 'req', l: 'AS-REQ: timestamp encrypted with pw-key', title: 'Prove identity once (AS-REQ)', d: 'The client encrypts a timestamp with a key derived from your password and sends it to the Authentication Server. Decrypting it proves you know the password — without sending the password.', data: { 'AS-REQ': 'user + enc(timestamp, pw-derived key)', password_sent: 'never' } },
          { f: 'as', t: 'c', k: 'res', l: 'AS-REP: TGT + session key', title: 'Receive the TGT (AS-REP)', d: 'The KDC returns a <b>Ticket-Granting Ticket</b> (encrypted with the KDC\'s own secret, so it\'s opaque to you) plus a session key encrypted for you. You just hold the TGT; you can\'t read inside it.', data: { TGT: 'enc(your identity + session key, KDC secret) — opaque to you', session_key: 'enc(for you)' }, enc: true, ok: 'Logged into the domain (hold TGT)' },
          { f: 'c', t: 'tgs', k: 'req', l: 'TGS-REQ: TGT + "I want the file server"', title: 'Request a service ticket (TGS-REQ)', d: 'To use a service, you present the TGT to the Ticket-Granting Server and name the target, authenticating with the session key — not your password.', data: { 'TGS-REQ': 'TGT + target=cifs/fileserver', authenticator: 'enc(timestamp, session key)' }, enc: true },
          { f: 'tgs', t: 'c', k: 'res', l: 'TGS-REP: service ticket', title: 'Get a service ticket (TGS-REP)', d: 'The TGS issues a <b>service ticket</b> encrypted with the <em>file server\'s</em> key, plus a fresh session key for talking to it. Only the file server can open this ticket.', data: { service_ticket: 'enc(your identity + svc session key, FILE SERVER key)', note: 'useless to anyone but that service' }, enc: true },
          { f: 'c', t: 'svc', k: 'req', l: 'AP-REQ: present service ticket', title: 'Present the ticket (AP-REQ)', d: 'You send the service ticket to the file server. It decrypts it with its own key, finds your identity and a session key vouched for by the KDC, and checks the timestamp.', data: { 'AP-REQ': 'service ticket + authenticator', decrypt: 'with file server key', finds: 'identity + session key from KDC' }, enc: true },
          { f: 'svc', t: 'c', k: 'res', l: 'access granted', title: 'Access granted', d: 'The file server trusts the KDC\'s vouching and grants access — having never seen your password, and without calling the KDC itself. That\'s ticket-based SSO.', data: { result: 'access to the share', kdc_contacted_by_service: 'no', password_seen_by_service: 'never' }, ok: 'Service access via ticket' },
        ],
      },
      attack: {
        name: 'Kerberoasting', summary: 'A famous AD attack: any authenticated user can request a service ticket and crack it offline to recover a service account\'s password. Strong passwords and modern encryption blunt it.',
        steps: [
          { f: 'c', t: 'tgs', k: 'atk', l: 'request ticket for a service account (SPN)', title: 'Request a service ticket', d: 'Any <em>already-authenticated</em> domain user can ask the TGS for a ticket to any service account (identified by its SPN). This is normal Kerberos behaviour — no alarm is raised.', data: { request: 'service ticket for MSSQLSvc SPN', privilege_needed: 'any valid domain user' } },
          { f: 'tgs', t: 'c', k: 'atk', l: 'ticket encrypted with svc-account pw hash', title: 'Ticket is encrypted with the account\'s key', d: 'The returned service ticket is encrypted with a key derived from the <em>service account\'s password</em>. The attacker now holds ciphertext whose key is that password hash.', data: { ticket: 'enc(…, key derived from service-account password)', insight: 'crack the key → recover the password' } },
          { f: 'c', t: 'c', k: 'atk', l: 'crack offline (no further requests)', title: 'Offline cracking', d: 'Offline and undetected, the attacker guesses passwords, derives each candidate key, and tries to decrypt the ticket. A weak service-account password falls quickly. No more network traffic means no detection from failed logins.', data: { method: 'offline guessing against the ticket', weak_pw: 'cracked fast', detection: 'none during cracking' } },
          { f: 'tgs', t: 'tgs', k: 'int', l: 'defenses', title: 'How to defend', d: 'Give service accounts long random passwords (or use group Managed Service Accounts that rotate automatically), enforce AES encryption (not legacy RC4), and monitor for anomalous bulk ticket requests. The attack relies on weak account passwords.', data: { fixes: 'gMSA / 25+ char random pw · AES only · disable RC4 · alert on bulk TGS requests', root_cause: 'weak service-account passwords' }, ok: 'Mitigated: strong rotated keys + AES + monitoring' },
        ],
      },
    },
    basics: `
      <p>Kerberos is a network authentication protocol built around <strong>tickets</strong> and a trusted third party, the <b>Key Distribution Center (KDC)</b>. Its guiding principle: your password should be proven <em>once</em> and never travel the network, and services should never need to see it.</p>
      <p>The cast:</p>
      <ul>
        <li><b>KDC</b> — the trusted authority, with two parts: the <b>Authentication Server (AS)</b> that verifies your initial login, and the <b>Ticket-Granting Server (TGS)</b> that issues per-service tickets.</li>
        <li><b>TGT (Ticket-Granting Ticket)</b> — your "master pass" after login, used to request service tickets without re-entering your password.</li>
        <li><b>Service ticket</b> — a per-service pass, encrypted so only that service can read it.</li>
      </ul>
      <p>The elegance: each ticket is encrypted with the key of its intended recipient, so a ticket is useless to anyone else, and every party trusts the KDC's seal rather than contacting it repeatedly. This is what makes a Windows domain login flow seamlessly into file shares, email and intranet apps.</p>
      <div class="callout"><b>Why "Kerberos"?</b>Named after Cerberus, the three-headed dog guarding Hades — a nod to the three parties involved: client, service, and KDC.</div>`,
    deep: `
      <h3>Why it needs synchronised clocks</h3>
      <p>Kerberos uses <b>timestamps</b> inside authenticators to prevent replay — a captured authenticator is only valid for a few minutes. That means every machine's clock must be roughly in sync (default tolerance ~5 minutes). A classic real-world symptom: fix a server's wrong clock and mysterious "access denied" errors vanish. Time sync (NTP) is effectively a dependency of Kerberos.</p>
      <h3>Mutual authentication and no password on the wire</h3>
      <p>Two properties interviewers like: Kerberos can authenticate <em>both</em> the client to the service <em>and</em> the service to the client (so you know the file server is genuine), and the user's long-term secret (password-derived key) is used only to decrypt the AS reply — it never crosses the network. Compare that to Basic auth sending the password each time.</p>
      <h3>Active Directory: Kerberos in the wild</h3>
      <p>Microsoft Active Directory is the overwhelmingly dominant deployment. Domain controllers are KDCs; logging into a domain-joined PC triggers the AS exchange, and accessing shares, Exchange or intranet sites uses service tickets transparently. That ubiquity makes Kerberos attacks a core topic in enterprise security:</p>
      <ul>
        <li><b>Kerberoasting</b> — request a service ticket and crack it offline for the service account password (see the attack flow). Mitigate with strong/rotated service passwords and AES.</li>
        <li><b>Pass-the-ticket</b> — steal a TGT/service ticket from a compromised machine's memory and reuse it. Mitigate with credential guard, least privilege, and limiting where privileged tickets appear.</li>
        <li><b>Golden ticket</b> — if an attacker steals the KDC's own master key (the <code>krbtgt</code> account hash), they can forge TGTs for <em>anyone</em>, indefinitely. This is domain-wide game-over and is why protecting and periodically rotating <code>krbtgt</code> matters.</li>
        <li><b>Silver ticket</b> — forge a service ticket for one service using that service's key; stealthier, scoped to one service.</li>
      </ul>
      <h3>Delegation</h3>
      <p>Kerberos <b>delegation</b> lets a service act on your behalf to a further service (e.g. a web app reaching a database as you). Unconstrained delegation is dangerous (the front-end holds your TGT); constrained and resource-based constrained delegation tighten this. It\'s an advanced but frequently probed AD topic.</p>`,
    howto: `
      <p>You rarely "call" Kerberos directly — the OS does it when you log into a domain. What you manage is configuration and hygiene:</p>
      ${C('bash', `
        # Linux: obtain a TGT, list tickets, then access a Kerberized service
        kinit sakitha@COMPANY.COM      # authenticate to the KDC → TGT
        klist                          # show cached TGT and service tickets
        # SSO to services then works without re-entering the password
      `, 'Getting and listing Kerberos tickets')}
      <ul>
        <li><b>Keep clocks in sync</b> (NTP) — the most common cause of Kerberos failures.</li>
        <li><b>Use AES, disable RC4/DES</b> encryption types to blunt Kerberoasting.</li>
        <li><b>Strong, rotated service-account passwords</b>, ideally group Managed Service Accounts (gMSA).</li>
        <li><b>Protect and periodically rotate the <code>krbtgt</code> key</b> to limit golden-ticket exposure.</li>
      </ul>
      <p>Step through the ticket exchange in the playground below.</p>`,
    tool: 'kerberos',
    pros: ['Password never crosses the network and services never see it', 'Seamless SSO across an entire domain', 'Mutual authentication (client and service both verified)', 'Tickets are short-lived and replay-resistant via timestamps', 'Mature, fast, and deeply integrated into Windows/AD'],
    cons: ['Centralised KDC is a single point of failure and a top target', 'Requires tight clock synchronisation', 'Complex; many AD-specific attacks (Kerberoast, golden/silver/pass-the-ticket)', 'Awkward across the open internet/NAT; really a LAN/domain protocol', 'krbtgt compromise is catastrophic and domain-wide'],
    history: [
      ['1980s', 'Developed at MIT\'s Project Athena to secure campus network services.'],
      ['1993', 'Kerberos v5 published (RFC 1510), the version still in use.'],
      ['2000', 'Microsoft adopts Kerberos as the default authentication for Active Directory domains.'],
      ['2005', 'RFC 4120 updates Kerberos v5.'],
      ['2014→', 'Kerberoasting, golden/silver tickets and pass-the-ticket become headline AD attack techniques.'],
    ],
    hidden: [
      ['A wrong clock breaks everything', 'Because authenticators rely on timestamps (default ±5 min), a machine with a skewed clock silently fails Kerberos with confusing "access denied" errors. Fixing NTP is the classic cure.'],
      ['The golden ticket is domain apocalypse', 'Steal the KDC\'s own krbtgt key and you can forge valid TGTs for any user, with any privileges, that bypass normal checks — persistent, domain-wide compromise. It\'s why the krbtgt password should be rotated (twice) after any DC compromise.'],
      ['Services never call the KDC', 'A service validates your ticket by decrypting it with its own key — no round trip to the KDC per request. That offline verification is what makes Kerberos fast at scale.'],
      ['Kerberoasting needs only a normal user', 'The unsettling part: any ordinary authenticated account can pull a service ticket and crack it offline. There\'s no privileged step and no failed logins to alert on — defence is strong service passwords and AES, not detection of the request itself.'],
    ],
    attacks: [
      ['Kerberoasting', 'Any user requests a service ticket and cracks it offline for the service-account password.', 'Long random/rotated service passwords (gMSA), AES only (no RC4), alert on bulk ticket requests.'],
      ['Pass-the-ticket', 'Steal a TGT/service ticket from memory and reuse it elsewhere.', 'Credential Guard, least privilege, limit where admin tickets appear, short lifetimes.'],
      ['Golden ticket', 'Forge TGTs using the stolen krbtgt key — total domain compromise.', 'Protect domain controllers; rotate krbtgt (twice) after compromise; monitor anomalies.'],
      ['Silver ticket', 'Forge a service ticket with a stolen service key; stealthy, scoped to one service.', 'Protect service keys, AES, monitor for tickets not issued by the KDC.'],
      ['Clock-skew / replay', 'Replay authenticators where time isn\'t enforced.', 'Enforce NTP and the skew window; short authenticator validity.'],
    ],
    interview: [
      ['What problem does Kerberos solve and how, at a high level?', '<p>It provides network SSO while ensuring the user\'s password never travels and services never see it. You authenticate once to the KDC and receive a <b>Ticket-Granting Ticket</b>; you then exchange that TGT for per-service <b>service tickets</b>, each encrypted with the target service\'s key so only it can read it. Services trust the KDC\'s seal and verify tickets offline, enabling seamless access across a domain.</p>', 'mid'],
      ['Why does Kerberos require synchronised clocks?', '<p>Authenticators include a <b>timestamp</b> to prevent replay — a captured one is valid only within a small window (default ~5 minutes). If a client and server clocks differ by more than the allowed skew, authentication fails. So NTP/time sync is effectively a dependency, and clock drift is one of the most common causes of mysterious Kerberos "access denied" errors.</p>', 'mid'],
      ['Explain Kerberoasting and how to defend against it.', '<p>Any authenticated domain user can request a service ticket for a service account (by its SPN). That ticket is encrypted with a key derived from the <b>service account\'s password</b>, so the attacker takes it offline and brute-forces the password — undetectably, with no further network activity. Defences target the root cause, weak service passwords: use long random or group-Managed Service Account passwords that rotate automatically, enforce AES (disable RC4), and monitor for anomalous bulk ticket requests. You can\'t easily block the request itself, so strong keys are the real fix.</p>', 'senior'],
      ['What is a golden ticket and why is it so severe?', '<p>If an attacker obtains the KDC\'s own master key — the <code>krbtgt</code> account\'s hash — they can <b>forge TGTs for any user with any privileges</b>, valid for as long as they like and bypassing normal authentication. It\'s full, persistent, domain-wide compromise, because every service trusts tickets that trace back to the KDC. Recovery requires rotating the <code>krbtgt</code> password twice, and it\'s the reason domain controllers are the crown jewels of an AD environment.</p>', 'senior'],
    ],
    quiz: [
      { q: 'In Kerberos, what does a client get after the initial authentication?', o: ['A service ticket', 'A Ticket-Granting Ticket (TGT)', 'A JWT', 'A password hash'], a: 1, e: 'The AS returns a TGT (plus a session key). The TGT is then exchanged at the TGS for per-service tickets.' },
      { q: 'A Kerberos service ticket is encrypted with…', o: ['The user\'s password', 'The target service\'s key, so only it can read it', 'The client\'s public key', 'A shared global secret'], a: 1, e: 'Each service ticket is encrypted with the intended service\'s key — useless to anyone else — and the service verifies it offline.' },
      { q: 'Kerberos authentication commonly fails when…', o: ['Passwords are too long', 'Machine clocks are out of sync', 'TLS is enabled', 'There are too few users'], a: 1, e: 'Timestamps guard against replay within a small window; clock skew beyond tolerance breaks authentication. NTP is essentially required.' },
      { q: 'A "golden ticket" attack requires the attacker to steal…', o: ['A single user password', 'The KDC\'s krbtgt key', 'A TLS certificate', 'An API key'], a: 1, e: 'With the krbtgt key an attacker forges TGTs for anyone — total, persistent domain compromise.' },
    ],
    related: ['sso', 'ldap', 'saml', 'tls'],
  });

  /* ---------------- LDAP ---------------- */
  HS.add({
    id: 'ldap', group: 'ent', short: 'LDAP / AD', icon: 'dir', port: '389/636',
    title: 'LDAP & Active Directory',
    tagline: 'The directory — the central phone book of users, groups and devices that most enterprise auth ultimately reads from. "Bind" to authenticate, query to authorize. The identity backbone behind Active Directory.',
    level: 'Intermediate', kind: 'Directory service',
    spec: [['Protocol', 'LDAP (RFC 4511)'], ['Ports', '389 (LDAP), 636 (LDAPS)'], ['Authenticates via', 'Bind operation'], ['Structure', 'Hierarchical tree (DIT)']],
    analogy: `<p>LDAP is the company's master directory — a giant, organised phone book of every person, group and resource. "Authenticating" is simply trying to <em>sign in to a directory entry</em> with its password (a <b>bind</b>): if the directory accepts, you are who you claim. "Authorizing" is then <em>looking up</em> that entry to see which groups it belongs to. One book answers both "is this really you?" and "what teams are you on?"</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'User', sub: 'login form', icon: 'user', x: 95, y: 150 },
        { id: 'app', label: 'App', sub: 'web server', icon: 'server', x: 330, y: 150 },
        { id: 'dir', label: 'Directory', sub: 'AD / OpenLDAP', icon: 'dir', x: 565, y: 150 },
      ],
      order: ['u', 'app', 'dir'],
      normal: {
        name: 'Bind to authenticate, query to authorize', summary: 'The app finds the user\'s directory entry, attempts a bind with their password to authenticate, then reads group memberships to authorize.',
        steps: [
          { f: 'u', t: 'app', k: 'req', l: 'login: sakitha / password', title: 'User submits credentials', d: 'The user logs into an app that defers to the corporate directory.', data: { username: 'sakitha', password: '•••••••• (over TLS)' }, enc: true, port: 'TLS 443' },
          { f: 'app', t: 'dir', k: 'req', l: 'service bind + search for user DN', title: 'Find the user entry', d: 'The app first binds with a service account and searches for the user to get their full <b>Distinguished Name</b> (their unique path in the tree). You rarely know your own DN; the app resolves it from your username.', data: { search_base: 'ou=people,dc=company,dc=com', filter: '(uid=sakitha)', found_dn: 'uid=sakitha,ou=people,dc=company,dc=com' }, enc: true },
          { f: 'app', t: 'dir', k: 'req', l: 'BIND as user DN + password', title: 'Authenticate: the bind', d: 'The app performs a second bind <em>as the user\'s DN</em> using the submitted password. A successful bind means the password is correct — that\'s LDAP authentication.', data: { operation: 'BIND', dn: 'uid=sakitha,ou=people,…', credential: 'submitted password', result: 'success = authenticated' }, enc: true },
          { f: 'dir', t: 'app', k: 'res', l: 'bind OK + group attributes', title: 'Read groups to authorize', d: 'With identity confirmed, the app reads the entry\'s attributes — notably group memberships — to decide what the user may do inside the app.', data: { bind: 'success ✓', memberOf: 'cn=editors, cn=eng-team', maps_to: 'app role = editor' }, ok: 'Authenticated; groups → roles' },
          { f: 'app', t: 'u', k: 'res', l: 'logged in as editor', title: 'Access granted', d: 'The directory answered both questions — who you are (bind) and what groups you\'re in (query) — and the app grants the matching access.', data: { identity: 'sakitha', role: 'editor', source_of_truth: 'the directory' }, ok: 'Login complete' },
        ],
      },
      attack: {
        name: 'LDAP injection & anonymous bind', summary: 'Unsanitised input can smuggle LDAP filter syntax to bypass authentication; misconfigured anonymous binds leak the directory. Parameterised filters and disabled anonymous access are the fixes.',
        steps: [
          { f: 'u', t: 'app', k: 'atk', l: 'username: *)(uid=*))(|(uid=*', title: 'Malicious filter input', d: 'If the app builds its LDAP search by string-concatenating user input, an attacker injects filter metacharacters — the LDAP equivalent of SQL injection.', data: { input: '*)(uid=*))(|(uid=*', naive_filter: '(uid=*)(uid=*))…)', effect: 'alters the query logic' } },
          { f: 'app', t: 'dir', k: 'atk', l: 'filter matches any/first user', title: 'Authentication bypass', d: 'The crafted filter can match every entry or always evaluate true, potentially letting the attacker authenticate as someone else or enumerate users.', data: { result: 'filter always true / matches admin', risk: 'auth bypass or data disclosure' }, fail: 'LDAP injection — like SQL injection for directories' },
          { f: 'app', t: 'app', k: 'int', l: 'fix: escape input, never build filters as strings', title: 'Defence 1: safe filters', d: 'Escape special characters and use the LDAP library\'s safe filter construction, never string concatenation. The injected metacharacters become literal text.', data: { safe: 'ldap.filter.escape(input)', rule: 'never concatenate user input into filters' }, ok: 'Injection neutralised' },
          { f: 'dir', t: 'dir', k: 'int', l: 'fix: disable anonymous bind + LDAPS', title: 'Defence 2: lock down access', d: 'Disable anonymous bind so the directory can\'t be browsed without credentials, and require LDAPS (TLS) so binds aren\'t sniffed. Plain LDAP binds send the password in the clear.', data: { anonymous_bind: 'disabled', transport: 'LDAPS (636) / StartTLS — never plain 389 for auth', least_priv: 'service account read-only' }, ok: 'Directory hardened' },
        ],
      },
    },
    basics: `
      <p>LDAP (Lightweight Directory Access Protocol) is how applications read and authenticate against a <strong>directory</strong> — a hierarchical database of people, groups, computers and other resources. It's not really an auth protocol so much as the <em>source of truth</em> that auth systems consult. <b>Active Directory</b> is Microsoft's directory, which speaks LDAP (and pairs with <a href="#kerberos">Kerberos</a> for the actual domain login).</p>
      <p>The data is a tree (the Directory Information Tree). Every entry has a <b>Distinguished Name (DN)</b> — a unique path like <code>uid=sakitha,ou=people,dc=company,dc=com</code> — built from components such as <code>dc</code> (domain component), <code>ou</code> (organizational unit) and <code>cn</code>/<code>uid</code> (the entry name).</p>
      <p>Two operations do the auth work:</p>
      <ul>
        <li><b>Bind</b> = authenticate. Supplying a DN and password; success means the credentials are valid.</li>
        <li><b>Search/query</b> = read attributes (like group membership) to authorize.</li>
      </ul>
      <div class="callout warn"><b>Use LDAPS, never plain LDAP for auth</b>A <em>simple bind</em> over port 389 sends the password in cleartext. Always use LDAPS (port 636) or StartTLS so binds are encrypted.</div>`,
    deep: `
      <h3>The directory as the identity backbone</h3>
      <p>Most enterprise auth ultimately resolves to the directory. SSO systems, VPNs, Wi-Fi, email and in-house apps all read users and groups from AD/LDAP. That centralisation is the value — one place to add, disable or regroup a user — and the risk: compromise the directory and you potentially own every system that trusts it.</p>
      <h3>Group-based authorization</h3>
      <p>Authorization in LDAP-backed systems is overwhelmingly <b>group membership</b>. An entry's <code>memberOf</code> attributes (or a group's <code>member</code> list) map to application roles. This is RBAC sourced from the directory (see <a href="#authz-models">authorization models</a>), and the usual enterprise pitfall is <em>group sprawl</em> — thousands of nested groups nobody fully understands, leading to over-permissioned users.</p>
      <h3>Bind types</h3>
      <ul>
        <li><b>Anonymous bind</b> — no credentials; should generally be disabled, or it lets anyone browse the directory.</li>
        <li><b>Simple bind</b> — DN + password; must be over TLS.</li>
        <li><b>SASL bind</b> — pluggable stronger mechanisms (e.g. GSSAPI/Kerberos), common in AD so the directory check rides on Kerberos tickets rather than a password.</li>
      </ul>
      <h3>LDAP injection</h3>
      <p>Because search filters are built from strings like <code>(uid=INPUT)</code>, unsanitised input that includes filter metacharacters (<code>*</code>, <code>(</code>, <code>)</code>, <code>\\</code>) can rewrite the query — directory-flavoured injection, with the same root cause and fix as SQL injection: never concatenate user input; escape and use parameterised filter APIs.</p>
      <h3>A note on the infamous Log4Shell</h3>
      <p>The 2021 Log4Shell catastrophe abused a feature that made Log4j fetch and execute code from an attacker-controlled <em>LDAP</em> (JNDI) URL. LDAP wasn't the flaw, but its ability to return references to remote objects was the vehicle — a good reminder that directories can hand back more than plain data.</p>`,
    howto: `
      ${C('bash', `
        # search the directory (over TLS) for a user, then verify by binding
        ldapsearch -H ldaps://dc.company.com:636 \\
          -D "cn=svc-reader,ou=svc,dc=company,dc=com" -w "$SVC_PW" \\
          -b "ou=people,dc=company,dc=com" "(uid=sakitha)" memberOf

        # a successful bind AS the user proves their password
        ldapwhoami -H ldaps://dc.company.com:636 \\
          -D "uid=sakitha,ou=people,dc=company,dc=com" -W
      `, 'Searching and binding against a directory')}
      <ul>
        <li>Always LDAPS/StartTLS; disable anonymous bind.</li>
        <li>Use a least-privilege read-only service account for searches.</li>
        <li>Escape all user input in filters — treat LDAP injection like SQL injection.</li>
        <li>Map groups to roles deliberately; audit for group sprawl and stale membership.</li>
      </ul>`,
    uses: [
      ['Corporate login everywhere', 'Email, VPN, Wi-Fi, intranet and apps all authenticate and read groups from AD/LDAP.'],
      ['SSO/IdP backing store', 'Okta/Entra and SAML/OIDC providers often sync from or front an LDAP directory.'],
      ['Linux/Unix auth', 'SSSD/PAM can authenticate Linux logins against LDAP/AD centrally.'],
      ['Application RBAC', 'Apps map LDAP groups (memberOf) to in-app roles and permissions.'],
    ],
    pros: ['Single source of truth for users, groups and devices', 'Central provisioning/deprovisioning across the whole org', 'Group-based authorization maps cleanly to RBAC', 'Fast reads, mature, standardised, widely integrated', 'Backs most enterprise SSO and OS login'],
    cons: ['Plain LDAP sends passwords in cleartext — TLS essential', 'Prone to LDAP injection if filters are built from raw input', 'Anonymous/misconfigured binds leak directory data', 'Group sprawl leads to over-permissioned accounts', 'A compromised directory is an org-wide catastrophe'],
    history: [
      ['1988', 'X.500 directory standards defined (heavyweight, OSI-based).'],
      ['1993', 'LDAP created as a lightweight TCP/IP front-end to X.500 directories.'],
      ['1997', 'LDAPv3 (RFC 2251, later 4511) becomes the enduring standard.'],
      ['2000', 'Microsoft Active Directory ships, combining LDAP with Kerberos and DNS — enterprise identity\'s backbone.'],
      ['2021', 'Log4Shell weaponises JNDI/LDAP lookups, a landmark reminder of directory-reference risks.'],
    ],
    hidden: [
      ['"Authentication" in LDAP is literally a login attempt', 'There\'s no special auth protocol — you authenticate by <em>binding</em> (logging in) as the user\'s DN. Success = correct password. It\'s a neat example of reusing the directory\'s own access as the auth check.'],
      ['Group sprawl quietly over-permissions everyone', 'Years of nested groups and "just add them to this group" leave users with access nobody intended. Periodic access reviews exist precisely because directories accumulate permissions.'],
      ['Log4Shell rode an LDAP feature', 'The worst vulnerability of 2021 abused Log4j fetching objects from an attacker LDAP URL via JNDI. The directory\'s power to return remote references, not a password flaw, was the vector.'],
      ['AD is LDAP + Kerberos + DNS', 'People say "we auth against AD" loosely. Under the hood the login is usually Kerberos, the lookups are LDAP, and locating services is DNS — three protocols working together.'],
    ],
    attacks: [
      ['LDAP injection', 'Filter metacharacters in user input rewrite the search, bypassing auth or leaking data.', 'Escape input, use parameterised filter APIs, never string-concatenate.'],
      ['Cleartext bind sniffing', 'Simple bind over port 389 exposes passwords on the wire.', 'Require LDAPS (636) or StartTLS for all binds.'],
      ['Anonymous bind enumeration', 'Browse users/groups without credentials.', 'Disable anonymous bind; restrict read access with least-privilege accounts.'],
      ['Over-permissioned groups', 'Group sprawl grants unintended access.', 'Regular access reviews, least privilege, flatten/clean up nested groups.'],
      ['Directory compromise', 'Owning AD/LDAP yields org-wide access.', 'Harden/monitor DCs, tiered admin, MFA for admins, offline backups.'],
    ],
    interview: [
      ['How does authentication actually work in LDAP?', '<p>By the <b>bind</b> operation. The app resolves the user\'s Distinguished Name (often via a service-account search on the username), then attempts a bind as that DN with the submitted password. A successful bind means the credentials are valid — that\'s the authentication. Authorization then comes from <b>searching</b> the entry\'s attributes, typically group memberships (<code>memberOf</code>), which map to application roles.</p>', 'mid'],
      ['What is LDAP injection and how do you prevent it?', '<p>It\'s the directory analogue of SQL injection: when an app builds a search filter by concatenating user input, an attacker supplies filter metacharacters (<code>*</code>, <code>(</code>, <code>)</code>) to rewrite the query — potentially always-true filters that bypass authentication or enumerate users. Prevention is identical in spirit to SQLi: never concatenate raw input into filters; escape special characters and use the LDAP library\'s safe filter-construction APIs.</p>', 'mid'],
      ['What\'s the relationship between LDAP, Active Directory and Kerberos?', '<p><b>LDAP</b> is the protocol for reading/authenticating against a directory. <b>Active Directory</b> is Microsoft\'s directory service that speaks LDAP for queries, uses <b>Kerberos</b> for the actual domain login (ticket-based SSO), and relies on DNS for service location. So "we authenticate against AD" usually means Kerberos does the login while LDAP supplies the user and group data — they\'re complementary, not alternatives.</p>', 'senior'],
      ['Why must LDAP authentication use TLS?', '<p>A <b>simple bind</b> sends the DN and password to the directory; over plain LDAP (port 389) that password travels in cleartext and can be sniffed. Requiring <b>LDAPS</b> (port 636) or <b>StartTLS</b> encrypts the bind so credentials aren\'t exposed. You should also disable anonymous bind so the directory can\'t be browsed without credentials. These are table-stakes hardening for any directory exposed to a network.</p>', 'mid'],
    ],
    quiz: [
      { q: 'In LDAP, you authenticate a user by…', o: ['Sending a JWT', 'Performing a bind as their DN with their password', 'Issuing a ticket', 'Reading their memberOf attribute'], a: 1, e: 'A successful bind confirms the password. Reading memberOf is the authorization step, not authentication.' },
      { q: 'A Distinguished Name (DN) is…', o: ['A password hash', 'The unique path identifying an entry in the directory tree', 'A session token', 'An encryption key'], a: 1, e: 'The DN (e.g. uid=sakitha,ou=people,dc=company,dc=com) uniquely locates an entry in the hierarchical directory.' },
      { q: 'LDAP injection has the same root cause as…', o: ['Rainbow tables', 'SQL injection — concatenating untrusted input into a query', 'Clock skew', 'Weak TLS ciphers'], a: 1, e: 'Building filters from raw user input lets metacharacters rewrite the query. Escape input and use parameterised filters.' },
      { q: 'Why require LDAPS or StartTLS for authentication?', o: ['It speeds up searches', 'A simple bind otherwise sends the password in cleartext', 'It enables anonymous access', 'It compresses the directory'], a: 1, e: 'Simple binds transmit the password; without TLS it\'s sniffable. LDAPS (636)/StartTLS encrypts the bind.' },
    ],
    related: ['kerberos', 'sso', 'radius', 'authz-models'],
  });

  /* ---------------- RADIUS ---------------- */
  HS.add({
    id: 'radius', group: 'ent', short: 'RADIUS', icon: 'net', port: '1812',
    title: 'RADIUS',
    tagline: 'The protocol that decides whether your laptop gets on the Wi-Fi or VPN. The original "AAA" server — Authentication, Authorization and Accounting — for network access. Quietly running behind enterprise Wi-Fi, VPNs and ISPs worldwide.',
    level: 'Advanced', kind: 'Network access (AAA)',
    spec: [['Defined in', 'RFC 2865 / 2866'], ['Ports', 'UDP 1812 (auth), 1813 (acct)'], ['The three A\'s', 'Authn, Authz, Accounting'], ['Modern use', '802.1X enterprise Wi-Fi, VPN']],
    analogy: `<p>RADIUS is the security desk for the building's <em>network</em>. When your device knocks on the door (connects to Wi-Fi or dials the VPN), the door itself (the access point) doesn't judge you — it phones the central security desk (the RADIUS server), which checks your credentials, decides which floor you may reach (which VLAN), and logs your entry and exit time for the records. The access point just relays and then obeys.</p>`,
    flow: {
      nodes: [
        { id: 'd', label: 'Device', sub: 'laptop', icon: 'user', x: 95, y: 150 },
        { id: 'nas', label: 'Access point', sub: 'NAS / switch', icon: 'net', x: 330, y: 150 },
        { id: 'srv', label: 'RADIUS', sub: 'AAA server', icon: 'server', x: 540, y: 75 },
        { id: 'dir', label: 'Directory', sub: 'AD/LDAP', icon: 'dir', x: 540, y: 235 },
      ],
      order: ['d', 'nas', 'srv', 'dir'],
      normal: {
        name: '802.1X Wi-Fi login (AAA)', summary: 'The access point (NAS) relays your credentials to the RADIUS server, which authenticates you against the directory, authorizes a network profile (VLAN), and logs the session.',
        steps: [
          { f: 'd', t: 'nas', k: 'req', l: 'connect to enterprise Wi-Fi', title: 'Device connects (802.1X)', d: 'Your laptop associates with the enterprise SSID. The access point blocks all traffic except the authentication exchange until you pass.', data: { ssid: 'CORP-WIFI', state: 'port blocked pending auth (802.1X)', supplicant: 'your device' } },
          { f: 'nas', t: 'srv', k: 'req', l: 'Access-Request (identity + EAP)', title: 'NAS asks RADIUS', d: 'The access point — the Network Access Server (NAS) — forwards your identity and credentials to the RADIUS server in an <code>Access-Request</code>, using EAP inside (often with a TLS tunnel so the password is protected).', data: { 'Access-Request': 'user + EAP credentials', from: 'NAS (the AP)', protection: 'EAP (PEAP/EAP-TLS) tunnel' } },
          { f: 'srv', t: 'dir', k: 'req', l: 'verify against AD/LDAP', title: 'Authenticate (1st A)', d: 'The RADIUS server checks the credentials against the identity store (often <a href="#ldap">AD/LDAP</a>), or validates a client certificate for EAP-TLS.', data: { check: 'bind/verify against directory', method: 'EAP-TLS (cert) or PEAP (password)' }, enc: true },
          { f: 'dir', t: 'srv', k: 'res', l: 'valid + group = Engineering', title: 'Authorize (2nd A)', d: 'On success, the server decides the network <em>authorization</em>: which VLAN, bandwidth, or ACLs apply — often from the user\'s group. It returns these as RADIUS attributes.', data: { identity: 'valid ✓', group: 'Engineering', authz_attrs: 'VLAN=20, session-timeout=8h' } },
          { f: 'srv', t: 'nas', k: 'res', l: 'Access-Accept + VLAN 20', title: 'Access-Accept', d: 'The RADIUS server tells the NAS to admit the device and apply the profile. The access point opens the port onto VLAN 20.', data: { 'Access-Accept': 'admit device', apply: 'VLAN 20, 8h session', alternative: 'Access-Reject would deny' }, ok: 'On the network, correct VLAN' },
          { f: 'nas', t: 'srv', k: 'req', l: 'Accounting-Start / Stop', title: 'Account (3rd A)', d: 'The NAS sends accounting records — session start, data used, session stop — so the server logs who was on the network, when, and how much. That\'s the often-forgotten third "A".', data: { 'Accounting-Start': 'session begins', 'Accounting-Stop': 'duration + bytes', purpose: 'audit, billing, forensics' }, ok: 'Session authenticated, authorized, accounted' },
        ],
      },
      attack: {
        name: 'Weak shared secret & legacy EAP', summary: 'RADIUS\'s old UDP design leans on a shared secret and weak hashing; weak EAP methods expose credentials. Strong secrets, EAP-TLS and RADSEC are the modern fixes.',
        steps: [
          { f: 'nas', t: 'srv', k: 'atk', l: 'capture Access-Request packets', title: 'Sniff the RADIUS traffic', d: 'Classic RADIUS runs over UDP and only obscures the password with an MD5-based scheme keyed by a shared secret between NAS and server. An attacker who can sniff this traffic targets that secret.', data: { transport: 'UDP, not natively encrypted', password_hiding: 'MD5-based with shared secret', target: 'the NAS↔server shared secret' } },
          { f: 'srv', t: 'srv', k: 'atk', l: 'weak shared secret → offline crack', title: 'Crack a weak secret', d: 'If the shared secret is short or reused, it can be brute-forced offline, undermining the protection of every password that crossed that link.', data: { weak_secret: 'short/default → crackable', impact: 'exposes credentials relying on it' }, fail: 'Weak secret undermines RADIUS protection' },
          { f: 'd', t: 'nas', k: 'atk', l: 'legacy EAP (e.g. EAP-MD5) leaks creds', title: 'Weak EAP method', d: 'Old inner methods like EAP-MD5 or unprotected MSCHAPv2 can be captured and cracked, or fall to rogue access points that trick devices into revealing credentials.', data: { weak_eap: 'EAP-MD5 / bare MSCHAPv2', evil_twin: 'rogue AP harvests credentials' } },
          { f: 'srv', t: 'srv', k: 'int', l: 'fix: EAP-TLS + strong secret + RADSEC', title: 'Modern hardening', d: 'Use <b>EAP-TLS</b> (client certificates — no password to steal), long random shared secrets, and <b>RADSEC</b> (RADIUS over TLS) to encrypt the whole exchange. Validate server certs on devices to defeat evil-twin APs.', data: { auth: 'EAP-TLS (certificates)', secret: 'long random, unique per NAS', transport: 'RADSEC (RADIUS over TLS)', device: 'validate RADIUS server cert' }, ok: 'Hardened: EAP-TLS + RADSEC + strong secrets' },
        ],
      },
    },
    basics: `
      <p>RADIUS (Remote Authentication Dial-In User Service) is the classic <strong>AAA</strong> server for <em>network</em> access. Its three jobs give the acronym:</p>
      <ul>
        <li><b>Authentication</b> — is this user/device who they claim?</li>
        <li><b>Authorization</b> — what network access do they get (which VLAN, bandwidth, ACLs)?</li>
        <li><b>Accounting</b> — log the session: who connected, when, for how long, how much data. (This is the "A" the other pages rarely cover — RADIUS is where it lives.)</li>
      </ul>
      <p>The key architectural idea: the device trying to connect talks to a <b>NAS (Network Access Server)</b> — a Wi-Fi access point, switch or VPN gateway — which does <em>not</em> decide anything itself. It relays the request to the central RADIUS server and enforces whatever the server replies. This centralises network-access policy in one place for an entire organisation or ISP.</p>
      <p>Replies are simple: <code>Access-Accept</code>, <code>Access-Reject</code>, or <code>Access-Challenge</code> (ask for more, e.g. an OTP — this is how RADIUS supports MFA).</p>`,
    deep: `
      <h3>802.1X and EAP — how enterprise Wi-Fi really logs in</h3>
      <p>When you join corporate Wi-Fi with your own username (not a shared password), that's <b>802.1X</b>: the access point blocks the port until a RADIUS server authenticates you, and the credentials are carried in <b>EAP</b> (Extensible Authentication Protocol), which is a framework for many methods:</p>
      <ul>
        <li><b>EAP-TLS</b> — client <em>certificates</em> on both ends. The strongest and increasingly standard choice: there's no password to phish, and it resists evil-twin access points.</li>
        <li><b>PEAP / EAP-TTLS</b> — build a TLS tunnel first, then send a password inside it. Common, but only safe if the device validates the server's certificate.</li>
        <li><b>EAP-MD5</b> and bare MSCHAPv2 — legacy and weak; avoid.</li>
      </ul>
      <h3>RADIUS vs TACACS+</h3>
      <p>An interview favourite for network roles. Both are AAA, but:</p>
      <ul>
        <li><b>RADIUS</b> — UDP, combines authentication and authorization, only encrypts the password portion. Ubiquitous for <em>network access</em> (Wi-Fi, VPN, ISP).</li>
        <li><b>TACACS+</b> (Cisco) — TCP, <em>separates</em> the three A's, and encrypts the <em>entire</em> payload. Preferred for <em>device administration</em> (logging into routers/switches), with fine-grained per-command authorization.</li>
      </ul>
      <h3>The shared-secret weakness and RADSEC</h3>
      <p>Classic RADIUS predates ubiquitous TLS. It protects passwords with an MD5-based construction keyed by a <b>shared secret</b> between NAS and server, and leaves most of the packet in the clear. A weak or reused shared secret is a real vulnerability (and the 2024 "BlastRADIUS" research showed protocol-level MD5 weaknesses). The modern answer is <b>RADSEC</b> — RADIUS over TLS/DTLS — which encrypts the whole exchange and is increasingly deployed, especially across untrusted links and in roaming federations like eduroam.</p>
      <h3>Where accounting matters</h3>
      <p>Accounting is why RADIUS persists: ISPs bill by it, enterprises use it for forensics ("which user had IP X at 2am?"), and compliance regimes require it. It's the concrete home of the AAA model's third pillar that the <a href="#concepts">concepts page</a> introduced.</p>`,
    howto: `
      <p>You configure NAS devices to point at a RADIUS server (e.g. FreeRADIUS) and define clients and policies there:</p>
      ${C('text', `
        # FreeRADIUS: clients.conf — each NAS needs a STRONG unique shared secret
        client ap-floor-3 {
            ipaddr = 10.0.3.5
            secret = <long-random-unique-secret>   # never a default/short value
        }

        # Prefer EAP-TLS (certificates) for 802.1X; validate the server cert on devices.
        # Map directory groups → RADIUS reply attributes (e.g. Tunnel-Private-Group-Id = VLAN).
        # Enable RADSEC (RADIUS over TLS) for links you don't fully trust.
      `, 'RADIUS server configuration essentials')}
      <ul>
        <li>Long, unique shared secrets per NAS; rotate them.</li>
        <li>Prefer EAP-TLS; if using PEAP, enforce server-certificate validation on clients (stops evil-twin APs).</li>
        <li>Use RADSEC for roaming/untrusted transport.</li>
        <li>Back RADIUS with your directory (AD/LDAP) so identities and groups stay central.</li>
      </ul>`,
    pros: ['Centralises network-access AAA for the whole org/ISP', 'Includes accounting — session audit, billing, forensics', 'Supports MFA via Access-Challenge', 'Works with 802.1X/EAP for per-user enterprise Wi-Fi and VPN', 'Mature, universally supported by network gear'],
    cons: ['Legacy UDP design; only the password is obscured (MD5-based)', 'Security hinges on strong, unique shared secrets', 'Weak EAP methods (EAP-MD5) and unvalidated PEAP expose credentials', 'Not natively encrypted end-to-end without RADSEC', 'Complex to deploy well (certs, VLAN mapping, device config)'],
    history: [
      ['1991', 'RADIUS created by Livingston Enterprises for dial-up ISP access.'],
      ['1997→2000', 'First standardised as RFC 2058 (1997); the current RFC 2865, with accounting in RFC 2866, follows in 2000.'],
      ['2001', '802.1X + EAP bring RADIUS to port-based network access and enterprise Wi-Fi.'],
      ['2010s', 'eduroam and similar federations use RADIUS hierarchies for global roaming access.'],
      ['2012/2024', 'RADSEC (RFC 6614) encrypts RADIUS over TLS; "BlastRADIUS" (2024) exposes MD5-based protocol weaknesses, pushing RADSEC adoption.'],
    ],
    hidden: [
      ['RADIUS is where the third "A" actually lives', 'The concepts page introduces AAA, but <em>accounting</em> rarely appears elsewhere. RADIUS is its natural home — session logs for billing, audit and "who had this IP when?" forensics.'],
      ['The access point decides nothing', 'A core idea people miss: the Wi-Fi AP/switch (the NAS) is just a relay and enforcer. All the policy lives centrally in RADIUS, which is exactly why it scales to ISPs and campuses.'],
      ['Evil-twin Wi-Fi beats careless PEAP', 'If devices don\'t validate the RADIUS server\'s certificate, a rogue access point with the same SSID can harvest credentials. EAP-TLS (certs, no password) sidesteps this entirely.'],
      ['BlastRADIUS (2024) revived old worries', 'Decades-old MD5 use in the protocol was shown exploitable under certain conditions, accelerating the shift to RADSEC — a reminder that "it\'s worked since 1991" isn\'t the same as "it\'s secure".'],
    ],
    attacks: [
      ['Weak/shared secret cracking', 'Sniff UDP traffic and brute-force a weak NAS↔server secret.', 'Long random unique secrets per NAS; rotate; use RADSEC.'],
      ['Legacy EAP credential capture', 'EAP-MD5 / unprotected MSCHAPv2 is captured and cracked.', 'Use EAP-TLS (certificates); disable weak EAP methods.'],
      ['Evil-twin access point', 'Rogue AP with the same SSID harvests credentials via PEAP.', 'Enforce server-certificate validation on devices; prefer EAP-TLS.'],
      ['Protocol MD5 weakness (BlastRADIUS)', 'Manipulate responses exploiting MD5-based integrity.', 'Apply Message-Authenticator fixes; adopt RADSEC (RADIUS over TLS).'],
      ['Accounting tampering', 'Forge or suppress accounting records.', 'Protect transport (RADSEC), secure logging, integrity checks.'],
    ],
    interview: [
      ['What do the three A\'s in RADIUS stand for?', '<p><b>Authentication</b> (verify the user/device), <b>Authorization</b> (decide the network access — VLAN, bandwidth, ACLs), and <b>Accounting</b> (log the session: who, when, how long, how much data). RADIUS is the canonical AAA server for network access; accounting is the piece unique to this space, used for billing, audit and forensics.</p>', 'mid'],
      ['In enterprise Wi-Fi, what role does the access point play versus the RADIUS server?', '<p>The access point is the <b>NAS (Network Access Server)</b> and makes no decisions itself — under 802.1X it blocks the port and relays the device\'s credentials (carried in EAP) to the RADIUS server in an <code>Access-Request</code>. The RADIUS server authenticates (often against AD/LDAP), authorizes a profile (e.g. a VLAN based on group), and replies <code>Access-Accept</code>/<code>Reject</code>. The AP simply enforces that answer. This centralises policy for the whole network.</p>', 'mid'],
      ['RADIUS vs TACACS+ — when would you use each?', '<p>Both are AAA, but RADIUS (UDP, auth+authz combined, only the password encrypted) is the standard for <b>network access</b> — Wi-Fi, VPN, ISP dial-in. TACACS+ (Cisco, TCP, separates all three A\'s, encrypts the entire payload, supports per-command authorization) is preferred for <b>device administration</b> — controlling and logging exactly what each admin can do on routers and switches. So: RADIUS to get <em>onto</em> the network, TACACS+ to <em>manage</em> the network gear.</p>', 'senior'],
      ['Why is EAP-TLS considered the gold standard for 802.1X, and what\'s the risk with PEAP?', '<p>EAP-TLS uses <b>client certificates</b> on both ends, so there\'s no password to phish, steal, or crack, and it inherently authenticates the server too — defeating evil-twin access points. PEAP/EAP-TTLS instead build a TLS tunnel and send a password inside; that\'s only safe if the device <b>validates the RADIUS server\'s certificate</b>. If validation is misconfigured, a rogue AP with the same SSID can present its own cert and harvest credentials. So EAP-TLS removes the weakest link (the password) entirely.</p>', 'senior'],
    ],
    quiz: [
      { q: 'The three A\'s of RADIUS are…', o: ['Access, Audit, Alert', 'Authentication, Authorization, Accounting', 'Authentication, Auditing, Allowlisting', 'Authorization, Availability, Accounting'], a: 1, e: 'RADIUS is the classic AAA server: it authenticates, authorizes network access, and accounts (logs) the session.' },
      { q: 'In 802.1X Wi-Fi, the access point (NAS)…', o: ['Decides access itself', 'Relays credentials to the RADIUS server and enforces its answer', 'Stores all passwords', 'Issues certificates'], a: 1, e: 'The NAS is a relay and enforcer; the RADIUS server makes the authentication/authorization decision centrally.' },
      { q: 'Which EAP method uses client certificates and has no password to steal?', o: ['EAP-MD5', 'PEAP', 'EAP-TLS', 'MSCHAPv2'], a: 2, e: 'EAP-TLS authenticates both ends with certificates — the strongest 802.1X option and resistant to evil-twin APs.' },
      { q: 'Compared with RADIUS, TACACS+ is typically preferred for…', o: ['Getting laptops onto Wi-Fi', 'Administering network devices with per-command control', 'Issuing TLS certificates', 'Storing user passwords'], a: 1, e: 'TACACS+ separates the A\'s, encrypts the whole payload and does per-command authorization — ideal for device administration.' },
    ],
    related: ['ldap', 'kerberos', 'mfa', 'sso'],
  });
})();
