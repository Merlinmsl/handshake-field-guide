/* Reference pages: home (learning path), compare + decision helper, interview bank, glossary */
(function () {
  'use strict';
  const HS = window.HS, esc = HS.esc, icon = HS.icon;

  const stStr = (id) => { const c = HS.stCls(id); return c === 'd' ? 'd' : c === 'v' ? 'v' : ''; };

  /* ---------------- HOME ---------------- */
  HS.pages.home = {
    group: 'start', short: 'Overview',
    render(main) {
      const path = [
        { stage: 'Foundations', sub: 'the vocabulary', ids: ['concepts', 'passwords'] },
        { stage: 'Core web', sub: 'every backend', ids: ['basic-auth', 'sessions', 'api-keys', 'jwt'] },
        { stage: 'Delegation', sub: 'logging in with others', ids: ['oauth', 'oidc'] },
        { stage: 'Transport & access', sub: 'the secure channel', ids: ['tls', 'mtls', 'ssh'] },
        { stage: 'Enterprise', sub: 'federation & networks', ids: ['sso', 'saml', 'kerberos', 'ldap', 'radius'] },
        { stage: 'Modern & MFA', sub: 'phishing resistance', ids: ['mfa', 'totp', 'webauthn', 'magic-links', 'hmac-sig'] },
        { stage: 'Authorization', sub: 'what you may do', ids: ['authz-models', 'oauth-scopes', 'opa'] },
      ];
      const card = (id) => {
        const t = HS.byId[id]; if (!t) return '';
        // first sentence only; split on ". " so version numbers like "OAuth 2.0" survive
        const first = t.tagline.split(/\.(?:\s|$)/)[0];
        return `<a class="station" href="#${id}"><b>${icon(t.icon || 'key')} ${esc(t.short || t.title)}<span class="st ${stStr(id)}"></span></b><span>${esc(first)}.</span></a>`;
      };
      main.innerHTML = `<div class="page">
        <header class="hero">
          <p class="eyebrow"><b>Interactive field guide</b> · ${HS.topics.length} methods · animated packet flows · playgrounds</p>
          <h1>Every way systems prove who you are — and what you may do</h1>
          <p class="lede">From passwords to passkeys, SSH to SAML, JWTs to Zanzibar. Each method is built up from first principles with a step-by-step animated diagram of packets moving across the wire, an attack mode, a hands-on playground, and interview prep. Follow the path, or jump to any topic.</p>
        </header>

        <div class="cols" style="margin-bottom:26px">
          <div class="pc"><h4>${icon('net')} Watch the packets move</h4><p class="muted" style="margin:0">Every topic has a player showing requests, responses and encrypted channels travelling between nodes, with a synced sequence diagram and a packet inspector. Hit play or step through.</p></div>
          <div class="pc"><h4>${icon('attacker')} Flip on attack mode</h4><p class="muted" style="margin:0">Each diagram has an attacker scenario — replay, token theft, MITM, phishing — showing how the attack is attempted and what defence stops it.</p></div>
          <div class="pc"><h4>${icon('key')} Break it in the playground</h4><p class="muted" style="margin:0">Decode a JWT, generate a live TOTP code, watch one byte shatter an HMAC, see why a passkey can't be phished. Real crypto in your browser.</p></div>
        </div>

        <div class="btn-row" style="margin-bottom:8px">
          <a class="btn" href="#concepts">Start from the beginning</a>
          <a class="btn ghost" href="#compare">Compare all methods</a>
          <a class="btn ghost" href="#decide">Which should I use?</a>
          <a class="btn ghost" href="#interview">Interview question bank</a>
        </div>

        <h2 style="margin-top:34px">The learning path</h2>
        <p class="muted" style="max-width:68ch">Ordered from the ground up. Each dot fills as you open a topic and turns green when you pass its quiz. You can always skip around using the sidebar.</p>
        <div class="path">
          ${path.map((row, i) => `<div class="stage-row">
            <h3>${esc(row.stage)}<small>${esc(row.sub)}</small></h3>
            <div class="stations">${row.ids.map(card).join('')}</div>
          </div>`).join('')}
        </div>

        <div class="pager"><a class="nx" href="#concepts" style="grid-column:2"><span>Begin</span><b>Authentication vs Authorization →</b></a></div>
      </div>`;
    },
  };

  /* ---------------- COMPARE ---------------- */
  HS.pages.compare = {
    group: 'ref', short: 'Compare methods',
    render(main) {
      const rows = [
        ['Password', 'Human login', 'Knowledge', 'None / server session', 'Weak — phishable, reused', 'passwords'],
        ['HTTP Basic', 'Scripts, internal tools', 'Knowledge', 'None (stateless)', 'OK inside TLS only', 'basic-auth'],
        ['Session cookie', 'Traditional web apps', 'Reference token', 'Server-side', 'Good; needs CSRF defence', 'sessions'],
        ['API key', 'Server-to-server', 'Bearer secret', 'Long-lived', 'OK; leak-prone, scope it', 'api-keys'],
        ['JWT', 'Stateless APIs, SPAs', 'Self-contained token', 'Until expiry', 'Good; hard to revoke', 'jwt'],
        ['OAuth 2.0', 'Delegated access', 'Access/refresh tokens', 'Short + refresh', 'Strong (authZ, not login)', 'oauth'],
        ['OIDC', 'Federated login', 'id_token (JWT)', 'Short', 'Strong', 'oidc'],
        ['TLS', 'All traffic', 'Server certificate', 'Per session', 'Essential baseline', 'tls'],
        ['mTLS', 'Service-to-service', 'Both certificates', 'Short-lived certs', 'Very strong', 'mtls'],
        ['SSH keys', 'Server access', 'Key pair', 'Until revoked', 'Strong (protect the key)', 'ssh'],
        ['SAML', 'Enterprise SSO', 'Signed XML assertion', 'Short window', 'Strong; XSW risk', 'saml'],
        ['Kerberos', 'AD domains', 'Tickets', 'Short-lived', 'Strong on-LAN', 'kerberos'],
        ['LDAP/AD', 'Directory lookups', 'Bind (directory)', 'N/A', 'Needs TLS; injection risk', 'ldap'],
        ['RADIUS', 'Network access (Wi-Fi/VPN)', 'AAA exchange', 'Session', 'Strong with EAP-TLS', 'radius'],
        ['TOTP', '2nd factor', 'One-time code', '30s window', 'Good; phishable', 'totp'],
        ['Passkey (FIDO2)', 'Passwordless login', 'Key pair (origin-bound)', 'Per login', 'Strongest; phishing-proof', 'webauthn'],
        ['Magic link', 'Low-friction login', 'Emailed token', 'Minutes', 'Only as strong as email', 'magic-links'],
        ['HMAC signing', 'API/webhook requests', 'Shared secret (signs)', 'Per request', 'Strong integrity + auth', 'hmac-sig'],
      ];
      main.innerHTML = `<article class="page">
        <header class="t-head"><div class="eyebrow"><b>Reference</b><span>side by side</span></div>
        <h1>Compare every method</h1>
        <p class="lede">The whole guide on one screen. Filter by group or search, then click through to the full topic. Use this to revise quickly before an interview.</p></header>
        <div class="filters">
          <input id="cmp-q" type="search" placeholder="Filter methods…" style="flex:1;min-width:160px">
          <select id="cmp-g"><option value="">All groups</option>${HS.GROUPS.filter((g) => g.id !== 'start' && g.id !== 'ref').map((g) => `<option value="${g.id}">${esc(g.name)}</option>`).join('')}</select>
        </div>
        <div class="tbl-wrap"><table class="t"><thead><tr><th>Method</th><th>Typical use</th><th>What it is</th><th>Lifetime</th><th>Security in a nutshell</th></tr></thead>
        <tbody id="cmp-body">${rows.map((r) => `<tr data-id="${r[5]}" data-g="${HS.byId[r[5]] ? HS.byId[r[5]].group : ''}"><td><a href="#${r[5]}">${esc(r[0])}</a></td><td>${esc(r[1])}</td><td>${esc(r[2])}</td><td>${esc(r[3])}</td><td>${esc(r[4])}</td></tr>`).join('')}</tbody></table></div>
        <p class="muted">Security notes are deliberately terse — open a topic for the real nuance, pros/cons and attacks.</p>
      </article>`;
      const q = main.querySelector('#cmp-q'), g = main.querySelector('#cmp-g');
      const filter = () => {
        const term = q.value.toLowerCase(), grp = g.value;
        main.querySelectorAll('#cmp-body tr').forEach((tr) => {
          const okText = tr.textContent.toLowerCase().includes(term);
          const okGrp = !grp || tr.dataset.g === grp;
          tr.hidden = !(okText && okGrp);
        });
      };
      q.addEventListener('input', filter); g.addEventListener('change', filter);
    },
  };

  /* ---------------- DECISION HELPER ---------------- */
  HS.pages.decide = {
    group: 'ref', short: 'Which should I use?',
    render(main) {
      const tree = {
        q: 'What are you building authentication for?',
        opts: [
          { l: 'Human users logging into my app', to: 'human' },
          { l: 'One service/program calling another', to: 'machine' },
          { l: 'Letting a third-party app access user data', to: 'delegate' },
          { l: 'Access to servers or the corporate network', to: 'infra' },
        ],
      };
      const nodes = {
        human: { q: 'What matters most for your user login?', opts: [
          { l: 'Strongest security, passwordless', rec: 'webauthn', why: 'Passkeys are phishing-resistant by construction and remove passwords entirely — the best choice for new consumer or enterprise login.' },
          { l: 'Lowest friction to sign up', rec: 'magic-links', why: 'Magic links need no password, but remember their security rests entirely on the user\'s email account.' },
          { l: 'Traditional app, full server control', rec: 'sessions', why: 'Server-side sessions give instant revocation and simple mental models; pair with CSRF defence and add MFA.' },
          { l: 'Reuse an existing identity (Google/corp)', rec: 'oidc', why: 'OIDC lets users log in with an identity they already have; you store no passwords.' },
        ] },
        machine: { q: 'What\'s the relationship between the services?', opts: [
          { l: 'Simple, I control both ends', rec: 'api-keys', why: 'An API key is the simplest option — just scope it, store it hashed, and rotate it.' },
          { l: 'Need tamper-proof, replay-proof requests', rec: 'hmac-sig', why: 'HMAC request signing proves the caller holds the secret without sending it, and protects request integrity.' },
          { l: 'Mutual identity, zero-trust mesh', rec: 'mtls', why: 'mTLS gives both ends cryptographic identity with no shared secret — ideal for service meshes.' },
          { l: 'Stateless identity across many services', rec: 'jwt', why: 'A signed JWT carries identity and is verifiable locally by any service without a lookup.' },
        ] },
        delegate: { q: 'Do you need to know who the user is, or just access their data?', opts: [
          { l: 'Just access some of their data', rec: 'oauth', why: 'OAuth 2.0 issues scoped, revocable tokens so an app acts on the user\'s behalf without their password.' },
          { l: 'Actually log the user in (identity)', rec: 'oidc', why: 'OIDC adds the id_token on top of OAuth so you reliably learn who the user is.' },
          { l: 'Limit exactly what the app can do', rec: 'oauth-scopes', why: 'Scopes express least privilege — request only what each feature needs, and enforce object-level authZ too.' },
        ] },
        infra: { q: 'Which kind of access?', opts: [
          { l: 'Logging into servers', rec: 'ssh', why: 'SSH key pairs beat passwords: the private key never travels and can\'t be phished.' },
          { l: 'Corporate Wi-Fi / VPN', rec: 'radius', why: 'RADIUS (with EAP-TLS) is the standard AAA for network access, including per-user enterprise Wi-Fi.' },
          { l: 'Windows domain single sign-on', rec: 'kerberos', why: 'Kerberos tickets give seamless domain SSO without sending passwords; it underpins Active Directory.' },
          { l: 'One login across many corporate apps', rec: 'sso', why: 'SSO via SAML/OIDC centralises login at an IdP — one strong, MFA-protected login for everything.' },
        ] },
      };
      let hist = [];
      function renderNode(node) {
        main.querySelector('.wiz').innerHTML = `<p class="q" style="font:700 20px var(--f-display)">${esc(node.q)}</p>` +
          node.opts.map((o, i) => `<button class="opt" data-i="${i}"><b>${esc(o.l)}</b></button>`).join('') +
          (hist.length ? `<div class="btn-row"><button class="btn ghost" id="wiz-back">← Back</button><button class="btn ghost" id="wiz-reset">Start over</button></div>` : '');
        main.querySelectorAll('.opt').forEach((b) => b.addEventListener('click', () => {
          const o = node.opts[+b.dataset.i];
          hist.push(node);
          if (o.rec) showRec(o);
          else renderNode(nodes[o.to]);
        }));
        const back = main.querySelector('#wiz-back'); if (back) back.addEventListener('click', () => renderNode(hist.pop()));
        const rs = main.querySelector('#wiz-reset'); if (rs) rs.addEventListener('click', () => { hist = []; renderNode(tree); });
      }
      function showRec(o) {
        const t = HS.byId[o.rec];
        main.querySelector('.wiz').innerHTML = `<div class="rec"><p class="eyebrow"><b>Suggested starting point</b></p>
          <h2 style="margin:4px 0 6px">${icon(t.icon || 'key')} ${esc(t.title)}</h2>
          <p>${o.why}</p>
          <div class="btn-row"><a class="btn" href="#${o.rec}">Open ${esc(t.short || t.title)}</a><button class="btn ghost" id="wiz-back">← Back</button><button class="btn ghost" id="wiz-reset">Start over</button></div>
          <p class="muted" style="margin-top:8px">This is a starting point, not gospel — real systems combine methods. Read the topic\'s pros, cons and attacks before committing.</p></div>`;
        main.querySelector('#wiz-back').addEventListener('click', () => renderNode(hist.pop()));
        main.querySelector('#wiz-reset').addEventListener('click', () => { hist = []; renderNode(tree); });
      }
      main.innerHTML = `<article class="page">
        <header class="t-head"><div class="eyebrow"><b>Reference</b><span>decision helper</span></div>
        <h1>Which method should I use?</h1>
        <p class="lede">Answer a couple of questions and get a sensible starting point, with a one-line rationale and a link to the full topic. Real systems mix several — this just points you at the right chapter.</p></header>
        <div class="wiz"></div>
      </article>`;
      renderNode(tree);
    },
  };

  /* ---------------- INTERVIEW BANK ---------------- */
  HS.pages.interview = {
    group: 'ref', short: 'Interview bank',
    render(main) {
      const all = [];
      HS.topics.forEach((t) => (t.interview || []).forEach(([q, a, lvl]) => all.push({ q, a, lvl: lvl || 'mid', topic: t.id, topicName: t.short || t.title })));
      const counts = { junior: all.filter((x) => x.lvl === 'junior').length, mid: all.filter((x) => x.lvl === 'mid').length, senior: all.filter((x) => x.lvl === 'senior').length };
      main.innerHTML = `<article class="page">
        <header class="t-head"><div class="eyebrow"><b>Reference</b><span>${all.length} questions</span></div>
        <h1>Interview question bank</h1>
        <p class="lede">Every interview question from across the guide in one place — ${all.length} of them, drawn from real auth interview themes. Filter by level or topic, try to answer out loud, then reveal the model answer.</p></header>
        <div class="filters">
          <input id="iv-q" type="search" placeholder="Search questions…" style="flex:1;min-width:160px">
          <select id="iv-l"><option value="">All levels</option><option value="junior">Junior (${counts.junior})</option><option value="mid">Mid (${counts.mid})</option><option value="senior">Senior (${counts.senior})</option></select>
          <select id="iv-t"><option value="">All topics</option>${HS.topics.filter((t) => t.interview).map((t) => `<option value="${t.id}">${esc(t.short || t.title)}</option>`).join('')}</select>
        </div>
        <p class="muted" id="iv-count"></p>
        <div class="qa" id="iv-list"></div>
      </article>`;
      const list = main.querySelector('#iv-list'), qel = main.querySelector('#iv-q'), lel = main.querySelector('#iv-l'), tel = main.querySelector('#iv-t'), cnt = main.querySelector('#iv-count');
      function draw() {
        const term = qel.value.toLowerCase(), lv = lel.value, tp = tel.value;
        const shown = all.filter((x) => (!lv || x.lvl === lv) && (!tp || x.topic === tp) && (!term || (x.q + x.a).toLowerCase().includes(term)));
        cnt.textContent = `Showing ${shown.length} of ${all.length} questions`;
        list.innerHTML = shown.map((x) => `<details><summary><span>${x.q}</span><span class="lvl ${x.lvl}">${x.lvl}</span></summary><div class="ans">${x.a}<p style="margin-top:10px"><a href="#${x.topic}">→ ${esc(x.topicName)}</a></p></div></details>`).join('') || '<p class="muted">No questions match.</p>';
      }
      [qel, lel, tel].forEach((e) => e.addEventListener('input', draw));
      draw();
    },
  };

  /* ---------------- GLOSSARY ---------------- */
  HS.pages.glossary = {
    group: 'ref', short: 'Glossary',
    render(main) {
      const terms = [
        ['Access token', 'A credential (often a JWT) that grants an app access to an API, carrying scopes and a short expiry.', 'oauth'],
        ['ACL', 'Access Control List — a per-object list of who may do what. Simple, doesn\'t scale.', 'authz-models'],
        ['AAA', 'Authentication, Authorization, Accounting — the network-access security model, embodied by RADIUS.', 'radius'],
        ['ABAC', 'Attribute-Based Access Control — decisions computed from attributes of user, resource and context.', 'authz-models'],
        ['Assertion', 'A signed statement from an IdP about a user, in SAML (XML) or as a token.', 'saml'],
        ['Attestation', 'A WebAuthn authenticator optionally proving what kind of device it is.', 'webauthn'],
        ['Audience (aud)', 'A token claim naming the intended recipient; must be checked to prevent cross-service replay.', 'jwt'],
        ['Authentication', 'Proving who you are. Comes before authorization.', 'concepts'],
        ['Authorization', 'Deciding what you may do, once your identity is known.', 'concepts'],
        ['Bearer token', 'A credential where mere possession grants access — "whoever bears it, uses it".', 'api-keys'],
        ['Bind (LDAP)', 'The directory operation that authenticates a user by logging in as their entry.', 'ldap'],
        ['CSRF', 'Cross-Site Request Forgery — abusing a browser\'s auto-attached cookies to forge authenticated requests.', 'sessions'],
        ['Certificate Authority (CA)', 'A trusted issuer that signs certificates binding a public key to an identity.', 'tls'],
        ['Claim', 'A statement inside a token about the subject (e.g. email, role), especially in JWT/OIDC.', 'jwt'],
        ['Constant-time compare', 'Comparing secrets so response timing doesn\'t leak how many bytes matched.', 'passwords'],
        ['Diffie–Hellman', 'A method for two parties to derive a shared secret over a public channel.', 'tls'],
        ['Distinguished Name (DN)', 'The unique path identifying an entry in an LDAP directory tree.', 'ldap'],
        ['EAP', 'Extensible Authentication Protocol — the framework (EAP-TLS, PEAP) used over 802.1X and RADIUS.', 'radius'],
        ['Federation', 'Extending trust across organisations so one login works elsewhere.', 'sso'],
        ['FIDO2', 'The standard behind passkeys: public-key, phishing-resistant authentication.', 'webauthn'],
        ['Forward secrecy', 'Property where stealing a long-term key later can\'t decrypt past recorded sessions.', 'tls'],
        ['Golden ticket', 'A forged Kerberos TGT made with a stolen krbtgt key — total domain compromise.', 'kerberos'],
        ['HMAC', 'A keyed hash proving integrity and authenticity using a shared secret.', 'hmac-sig'],
        ['HOTP', 'HMAC-based One-Time Password using an event counter.', 'totp'],
        ['HSTS', 'A header forcing HTTPS and removing the "proceed anyway" bypass.', 'tls'],
        ['id_token', 'An OIDC JWT asserting who the user is — for the app, not for APIs.', 'oidc'],
        ['IdP', 'Identity Provider — the service that authenticates users and vouches for them.', 'sso'],
        ['IDOR / BOLA', 'Reaching another user\'s object by changing an ID — a broken-authorization flaw.', 'authz-models'],
        ['JWKS', 'JSON Web Key Set — a published endpoint of public keys used to verify tokens.', 'jwt'],
        ['JWT', 'JSON Web Token — a signed, self-contained token of claims.', 'jwt'],
        ['KDC', 'Key Distribution Center — the trusted Kerberos authority (AS + TGS).', 'kerberos'],
        ['Kerberoasting', 'Requesting a Kerberos service ticket and cracking it offline for the account password.', 'kerberos'],
        ['mTLS', 'Mutual TLS — both client and server authenticate with certificates.', 'mtls'],
        ['Magic link', 'A one-time login URL emailed to the user; the inbox becomes the credential.', 'magic-links'],
        ['MFA', 'Multi-Factor Authentication — proof from two or more different factor categories.', 'mfa'],
        ['Nonce', 'A number used once, to bind a request/token and prevent replay.', 'oidc'],
        ['OAuth 2.0', 'A framework for delegated authorization — scoped access without sharing passwords.', 'oauth'],
        ['OIDC', 'OpenID Connect — an authentication layer on top of OAuth adding the id_token.', 'oidc'],
        ['OPA', 'Open Policy Agent — a policy engine evaluating authorization rules written in Rego.', 'opa'],
        ['Passkey', 'A user-friendly FIDO2 credential; phishing-resistant, often synced across devices.', 'webauthn'],
        ['PEP / PDP', 'Policy Enforcement Point (enforces) vs Policy Decision Point (decides).', 'authz-models'],
        ['Pepper', 'A site-wide secret, stored outside the DB, mixed into password hashing.', 'passwords'],
        ['PKCE', 'Proof Key for Code Exchange — binds an OAuth code to the client that started the flow.', 'oauth'],
        ['RBAC', 'Role-Based Access Control — permissions granted via roles.', 'authz-models'],
        ['RADIUS', 'The AAA server for network access (Wi-Fi, VPN).', 'radius'],
        ['ReBAC', 'Relationship-Based Access Control — permissions follow a graph of relationships (Zanzibar).', 'authz-models'],
        ['Refresh token', 'A long-lived token used to obtain new short-lived access tokens.', 'oauth'],
        ['Rego', 'The declarative policy language used by OPA.', 'opa'],
        ['Relying Party (RP)', 'In OIDC/WebAuthn, the application relying on the identity provider/authenticator.', 'oidc'],
        ['Replay attack', 'Re-sending a captured valid message; defeated by nonces/timestamps.', 'hmac-sig'],
        ['Salt', 'A unique random value per password, defeating rainbow tables; not secret.', 'passwords'],
        ['SAML', 'An XML standard for enterprise SSO using signed assertions.', 'saml'],
        ['Scope', 'An OAuth permission describing what an app may do on the user\'s behalf.', 'oauth-scopes'],
        ['Session', 'Server-side state keyed by an opaque ID held in a cookie.', 'sessions'],
        ['SIM swapping', 'Hijacking a phone number to intercept SMS codes.', 'mfa'],
        ['SNI', 'Server Name Indication — the hostname in the TLS handshake enabling shared IPs.', 'tls'],
        ['SSO', 'Single Sign-On — authenticate once, access many apps.', 'sso'],
        ['SSH', 'Secure Shell — encrypted remote access, usually with key pairs.', 'ssh'],
        ['Step-up auth', 'Requiring an extra factor only for risky or sensitive actions.', 'mfa'],
        ['TGT', 'Ticket-Granting Ticket — the Kerberos "master pass" obtained after login.', 'kerberos'],
        ['TLS', 'Transport Layer Security — encrypts and authenticates connections (HTTPS).', 'tls'],
        ['TOTP', 'Time-based One-Time Password — authenticator-app codes from HMAC of the clock.', 'totp'],
        ['WebAuthn', 'The browser API for public-key, phishing-resistant login (passkeys).', 'webauthn'],
        ['XML Signature Wrapping', 'A SAML attack validating a signature on one element while reading another.', 'saml'],
        ['Zanzibar', 'Google\'s planet-scale ReBAC system; inspired OpenFGA and SpiceDB.', 'authz-models'],
      ];
      main.innerHTML = `<article class="page">
        <header class="t-head"><div class="eyebrow"><b>Reference</b><span>${terms.length} terms</span></div>
        <h1>Glossary</h1>
        <p class="lede">Every acronym and term in the guide, defined in a line, each linking to where it\'s explained in full. The fast way to look something up mid-revision.</p></header>
        <div class="filters"><input id="gl-q" type="search" placeholder="Search terms…" style="flex:1;min-width:160px"></div>
        <dl class="gloss" id="gl-list"></dl>
      </article>`;
      const list = main.querySelector('#gl-list'), q = main.querySelector('#gl-q');
      const draw = () => {
        const term = q.value.toLowerCase();
        const shown = terms.filter((t) => (t[0] + ' ' + t[1]).toLowerCase().includes(term)).sort((a, b) => a[0].localeCompare(b[0]));
        list.innerHTML = shown.map(([name, def, id]) => `<div><dt>${esc(name)}</dt><dd>${esc(def)} ${HS.byId[id] ? `<a href="#${id}">→ ${esc(HS.byId[id].short || HS.byId[id].title)}</a>` : ''}</dd></div>`).join('') || '<p class="muted">No terms match.</p>';
      };
      q.addEventListener('input', draw); draw();
    },
  };
})();
