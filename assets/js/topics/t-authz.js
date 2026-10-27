/* Authorization: models (ACL/RBAC/ABAC/ReBAC), OAuth scopes, policy engines (OPA) */
(function () {
  'use strict';
  const HS = window.HS, C = window.C;

  /* ---------------- Authorization models ---------------- */
  HS.add({
    id: 'authz-models', group: 'authz', short: 'Authorization models', icon: 'policy',
    title: 'Authorization Models: ACL, RBAC, ABAC, ReBAC',
    tagline: 'Once you know who someone is, how do you decide what they may do? The four dominant models — from simple lists to Google-scale relationship graphs — with the trade-offs interviewers love and the "role explosion" war story every senior engineer has.',
    level: 'Intermediate', kind: 'Access control',
    spec: [['ACL', 'Per-object allow lists'], ['RBAC', 'Permissions via roles'], ['ABAC', 'Rules over attributes'], ['ReBAC', 'Relationships in a graph']],
    analogy: `<p>Four ways a building controls doors. <b>ACL</b>: each door has a taped list of names allowed through it. <b>RBAC</b>: your badge says "Engineer", and doors open for badge-types, not names. <b>ABAC</b>: the lock reads conditions — "Engineers, on weekdays, from the building network". <b>ReBAC</b>: the door asks "is this person on the <em>team that owns this room</em>, or did the owner share it with them?" — following relationships rather than a fixed list. Each adds expressiveness and cost.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'User', sub: 'request', icon: 'user', x: 90, y: 150 },
        { id: 'app', label: 'App', sub: 'PEP', icon: 'server', x: 300, y: 150 },
        { id: 'pdp', label: 'Decision point', sub: 'PDP', icon: 'policy', x: 520, y: 75 },
        { id: 'data', label: 'Resource', sub: 'object', icon: 'db', x: 520, y: 235 },
      ],
      order: ['u', 'app', 'pdp', 'data'],
      normal: {
        name: 'An authorization decision (RBAC)', summary: 'The app (enforcement point) asks a decision point whether this subject may take this action on this object. RBAC answers from the user\'s roles.',
        steps: [
          { f: 'u', t: 'app', k: 'req', l: 'DELETE /docs/42', title: 'Authenticated request arrives', d: 'The user is already authenticated (we know who they are). Now they attempt an action on a specific object.', data: { subject: 'user_8842 (role: editor)', action: 'delete', object: 'doc:42' } },
          { f: 'app', t: 'pdp', k: 'req', l: 'may editor delete doc:42?', title: 'Ask the decision point', d: 'The app is the <b>Policy Enforcement Point (PEP)</b>. It asks a <b>Policy Decision Point (PDP)</b> for a verdict rather than scattering if-statements everywhere.', data: { query: 'can(user_8842, delete, doc:42)?', model: 'RBAC', input: 'role = editor' } },
          { f: 'pdp', t: 'pdp', k: 'int', l: 'role → permissions lookup', title: 'Evaluate the policy', d: 'Under RBAC the PDP maps the role to its permission set: editors may read and update, but deletion is reserved for admins.', data: { role: 'editor', grants: 'read, update', 'delete?': 'no (admin only)' } },
          { f: 'pdp', t: 'app', k: 'res', l: 'DENY', title: 'Decision returned', d: 'The PDP returns DENY. The PEP enforces it and never touches the resource.', data: { decision: 'DENY', reason: 'editor lacks delete permission' }, fail: '403 — role lacks the permission' },
          { f: 'app', t: 'u', k: 'res', l: '403 Forbidden', title: 'Enforced at the app', d: 'The user is refused. Separating decision (PDP) from enforcement (PEP) keeps policy consistent and auditable across the system.', data: { status: 403, pattern: 'PEP enforces, PDP decides' }, fail: 'Action blocked' },
        ],
      },
      attack: {
        name: 'Role explosion → over-permissioning', summary: 'RBAC\'s classic failure mode isn\'t a hack — it\'s drift. Coarse roles force a choice between too much access or an unmanageable sprawl of roles, quietly leaving users over-privileged.',
        steps: [
          { f: 'app', t: 'pdp', k: 'atk', l: 'need: edit only EU finance docs', title: 'A requirement roles can\'t express', d: 'Business asks: "Let this user edit finance docs, but only for the EU region, only during audits." Roles are coarse — they grant a whole permission set, not conditional slices.', data: { need: 'edit finance docs WHERE region=EU AND context=audit', rbac_can_express: 'edit finance docs (all of them)' } },
          { f: 'pdp', t: 'pdp', k: 'atk', l: 'option A: broad role (too much)', title: 'The over-grant temptation', d: 'The quick fix is to give the existing "Finance Editor" role, which also exposes non-EU and non-audit documents. The user is now over-permissioned — a standing risk auditors flag.', data: { choice: 'reuse broad role', result: 'access to docs they shouldn\'t see', risk: 'violates least privilege' }, fail: 'Over-permissioning — the common real-world outcome' },
          { f: 'pdp', t: 'pdp', k: 'atk', l: 'option B: new narrow role × N', title: 'Role explosion', d: 'The "correct" RBAC fix is a new precise role — but every region × department × context combination spawns another, yielding thousands of near-duplicate roles nobody can audit.', data: { choice: 'mint "EU-Finance-Editor-Audit" role', scaled: '× regions × depts × contexts = thousands', result: 'role explosion, ungovernable' }, fail: 'Role explosion — unmanageable sprawl' },
          { f: 'pdp', t: 'pdp', k: 'int', l: 'fix: ABAC/ReBAC for conditions', title: 'Where ABAC/ReBAC come in', d: 'Attribute rules (<code>region==EU && context==audit</code>) or relationships (<code>member-of EU-finance-team</code>) express the condition directly — one policy instead of a thousand roles. This is exactly why the richer models exist.', data: { abac: 'rule over attributes: region, context', rebac: 'relationship: member of EU-finance-team', outcome: 'one policy, least privilege, auditable' }, ok: 'Conditions → ABAC/ReBAC, not more roles' },
        ],
      },
    },
    basics: `
      <p>Authorization (authZ) is deciding what an authenticated subject may do. Every model answers the same question — <em>can subject S perform action A on object O?</em> — but differs in how it expresses the rules. Two architectural terms recur:</p>
      <ul>
        <li><b>PEP (Policy Enforcement Point)</b> — where the decision is <em>enforced</em> (your app/gateway).</li>
        <li><b>PDP (Policy Decision Point)</b> — where the decision is <em>made</em> (a policy engine or your authZ code).</li>
      </ul>
      <p>The four dominant models, in order of increasing expressiveness:</p>
      <ul>
        <li><b>ACL (Access Control List)</b> — each object carries a list of who may do what. Simple and precise; doesn\'t scale to many users/objects. Unix file permissions and S3 bucket ACLs are ACLs.</li>
        <li><b>RBAC (Role-Based)</b> — users get <em>roles</em>; roles carry <em>permissions</em>. You manage a handful of roles instead of per-user grants. The enterprise default.</li>
        <li><b>ABAC (Attribute-Based)</b> — decisions are computed from <em>attributes</em> of the user, resource, action and environment ("editors in EU, during business hours"). Flexible, context-aware, harder to reason about.</li>
        <li><b>ReBAC (Relationship-Based)</b> — permissions follow <em>relationships</em> in a graph ("you can edit this doc because you\'re on the team that owns the folder it\'s in"). Powers Google Drive-style sharing via <a href="#oauth-scopes">Zanzibar</a>.</li>
      </ul>
      <p>Try the same request under RBAC, ABAC and ReBAC in the playground — watch how each needs different information to decide.</p>`,
    deep: `
      <h3>RBAC and the role-explosion problem</h3>
      <p>RBAC is popular because roles match how organisations think ("admin", "editor", "viewer") and are easy to audit. Its Achilles heel is granularity: as soon as access needs <em>conditions</em> ("only their own department", "only during business hours", "only EU data"), roles can\'t express them. Teams respond either by over-granting a broad role (insecure) or by minting ever more specific roles until there are thousands of near-duplicates nobody understands — <b>role explosion</b>. Recognising this and reaching for ABAC/ReBAC is a senior-level signal.</p>
      <h3>ABAC: power and peril</h3>
      <p>ABAC evaluates a policy over attributes: <code>subject.dept == resource.dept && env.time in businessHours</code>. It expresses fine-grained, contextual rules in a few policies and underlies cloud IAM (AWS IAM conditions, XACML). The downside is <em>analysability</em>: with enough attributes and rules it becomes hard to answer "who can access this?" or to prove no rule grants unintended access. Policy testing and tooling become essential.</p>
      <h3>ReBAC and Google Zanzibar</h3>
      <p>ReBAC models permissions as a graph of relationships: <code>user:sakitha is editor of doc:42</code>, <code>doc:42 is in folder:specs</code>, <code>group:eng is viewer of folder:specs</code>. Authorization becomes a graph traversal: "is there a path from this user to this object granting this action?" Google\'s <b>Zanzibar</b> paper (2019) described doing this at planet scale for Drive, YouTube and more, inspiring open systems like <b>OpenFGA</b> and <b>SpiceDB</b>. ReBAC shines for sharing and hierarchy ("inherit access from the parent folder", "anyone my manager manages"), which RBAC models awkwardly.</p>
      <h3>Choosing a model</h3>
      <div class="tbl-wrap"><table class="t"><thead><tr><th>Use when</th><th>Model</th><th>Watch out for</th></tr></thead><tbody>
        <tr><td>Few objects, explicit per-object access</td><td>ACL</td><td>Doesn\'t scale with users/objects</td></tr>
        <tr><td>Access maps cleanly to job functions</td><td>RBAC</td><td>Role explosion when conditions appear</td></tr>
        <tr><td>Access depends on context/attributes</td><td>ABAC</td><td>Hard to audit "who can do what"</td></tr>
        <tr><td>Access follows ownership/sharing/hierarchy</td><td>ReBAC</td><td>Infrastructure complexity; consistency</td></tr>
      </tbody></table></div>
      <p>In practice, real systems <b>combine</b> them: RBAC for coarse roles, ABAC conditions for context, ReBAC for sharing. The question is rarely "which one" but "which where".</p>
      <h3>Principles that cut across all models</h3>
      <ul>
        <li><b>Least privilege</b> — grant the minimum needed; the antidote to over-permissioning.</li>
        <li><b>Deny by default</b> — absence of an explicit allow is a deny.</li>
        <li><b>Separation of duties</b> — no single role should, e.g., both create and approve a payment.</li>
        <li><b>Enforce on every object</b> — the fix for the BOLA/IDOR bug from the <a href="#concepts">concepts page</a>.</li>
      </ul>`,
    howto: `
      <p>Keep authorization decisions out of scattered if-statements and centralise the policy:</p>
      ${C('text', `
        • Separate PEP (enforce) from PDP (decide); don't sprinkle role checks everywhere.
        • Default-deny: only an explicit rule grants access.
        • Start with RBAC; add ABAC conditions when you hit "only their own / only when…".
        • Reach for ReBAC (OpenFGA/SpiceDB) when sharing and hierarchy dominate.
        • Check authorization on EVERY object access (stops IDOR/BOLA), not just at login.
        • Make policy testable: write tests for "who can / can't" and review on change.
      `, 'Designing authorization')}
      <p>Experiment with the three models side by side below.</p>`,
    tool: 'authz',
    pros: ['A model for every scale: ACL (simple) → ReBAC (planet-scale sharing)', 'RBAC is intuitive, auditable and ubiquitous', 'ABAC expresses rich, contextual rules compactly', 'ReBAC models sharing and hierarchy naturally', 'Separating PEP/PDP keeps policy consistent and testable'],
    cons: ['RBAC suffers role explosion once conditions appear', 'ABAC can become unauditable ("who can access X?")', 'ReBAC needs real infrastructure and consistency guarantees', 'ACLs don\'t scale with users/objects', 'Most breaches are broken authZ — easy to under-enforce'],
    history: [
      ['1970s', 'Access Control Lists and the access-matrix model formalise early authorization.'],
      ['1992', 'RBAC formalised (Ferraiolo & Kuhn); becomes the enterprise standard.'],
      ['2004', 'NIST RBAC standard; XACML brings policy-based ABAC to the enterprise.'],
      ['2011', 'AWS IAM reaches general availability, bringing JSON policies with conditions to cloud scale.'],
      ['2019', 'Google\'s Zanzibar paper describes ReBAC at global scale; OpenFGA and SpiceDB follow.'],
    ],
    hidden: [
      ['"Role explosion" is a rite of passage', 'Nearly every growing company hits the moment RBAC can\'t express a conditional requirement and roles multiply uncontrollably. Naming this in an interview signals you\'ve lived real authZ, not just read definitions.'],
      ['Most breaches are authZ, not authN', 'Broken access control tops the OWASP risks. Logging in is easy to get right; consistently checking permission on every object is where systems fail — the IDOR/BOLA family.'],
      ['Google runs authZ as its own global service', 'Zanzibar treats "can X do Y to Z?" as a massive, consistent, low-latency lookup service across all of Google\'s products — an eye-opening reframing of authorization as core infrastructure.'],
      ['Models compose; the real skill is placement', 'Mature systems don\'t pick one model — they use RBAC for coarse roles, ABAC for conditions, ReBAC for sharing. "Which model where" is the senior question, not "which model".'],
    ],
    attacks: [
      ['Broken object-level authZ (IDOR/BOLA)', 'Access another user\'s object by changing an ID; the app checked login but not ownership.', 'Enforce an authZ check on every object access, comparing owner/relationship to the caller.'],
      ['Privilege escalation via role sprawl', 'Over-broad or stale roles grant more than intended.', 'Least privilege, periodic access reviews, prefer conditions over broad roles.'],
      ['Policy misconfiguration (ABAC)', 'A subtle rule interaction grants unintended access.', 'Policy testing, static analysis, default-deny, review changes.'],
      ['Confused deputy', 'Trick a privileged component into acting on the attacker\'s behalf.', 'Pass and check the original caller\'s identity; don\'t authorize on the deputy\'s privilege.'],
      ['Missing separation of duties', 'One actor both initiates and approves a sensitive action.', 'Model SoD constraints; require distinct roles/approvers.'],
    ],
    interview: [
      ['Explain RBAC vs ABAC.', '<p><b>RBAC</b> grants permissions through <em>roles</em>: a user has roles, roles carry permissions, and you manage the roles. It\'s simple and auditable but coarse — it can\'t express conditions. <b>ABAC</b> computes decisions from <em>attributes</em> of the subject, resource, action and environment (e.g. "editors, in the EU, during business hours"), so it handles fine-grained, contextual rules compactly. The trade-off: ABAC is harder to audit — answering "who can access this?" is easy in RBAC and hard in ABAC. Many systems use RBAC for coarse access and ABAC conditions on top.</p>', 'mid'],
      ['What is "role explosion" and how do you avoid it?', '<p>Role explosion is when RBAC can\'t express a conditional requirement ("only their own department", "only EU data"), so teams create ever more specific roles — region × department × context — until there are thousands of near-duplicate, unauditable roles. You avoid it by not forcing conditions into roles: use <b>ABAC</b> attribute rules or <b>ReBAC</b> relationships to express the condition directly, keeping a small set of coarse roles for the rest. Recognising the symptom and reaching for the right model is the key.</p>', 'senior'],
      ['What is ReBAC and when would you choose it?', '<p><b>Relationship-Based Access Control</b> models permissions as a graph of relationships — "user is editor of doc", "doc is in folder", "group is viewer of folder" — and authorizes by traversing it ("is there a granting path from this user to this object?"). You choose it when access is naturally about <b>ownership, sharing and hierarchy</b> — Google Drive-style "share this folder with my team, and sub-items inherit it". Google\'s <b>Zanzibar</b> pioneered it at scale; OpenFGA and SpiceDB are open implementations. It handles inheritance and sharing that RBAC models awkwardly, at the cost of running real graph-authorization infrastructure.</p>', 'senior'],
      ['Where should authorization be enforced in a system, and why?', '<p>Separate the <b>Policy Enforcement Point</b> (where you enforce — the app/service/gateway) from the <b>Policy Decision Point</b> (where the rule is evaluated — a policy engine or shared authZ service), so policy stays consistent and auditable instead of scattered as ad-hoc <code>if role ==</code> checks. Critically, enforce on <b>every object access</b>, not just at login — checking "are you allowed to touch <em>this specific record</em>?" is what prevents IDOR/BOLA. In microservices, each service should enforce on its own data (defence in depth) rather than trusting an upstream to have done it.</p>', 'mid'],
    ],
    quiz: [
      { q: 'In RBAC, permissions are attached to…', o: ['Individual users directly', 'Roles, which users are assigned', 'Resource attributes', 'Network locations'], a: 1, e: 'Users get roles; roles carry permissions. You manage a few roles instead of per-user grants.' },
      { q: '"Role explosion" happens because RBAC struggles to express…', o: ['Many users', 'Conditional/contextual access (only EU, only owners)', 'Encryption', 'Login'], a: 1, e: 'Roles are coarse; conditions force either over-granting or endless specific roles. ABAC/ReBAC express conditions directly.' },
      { q: 'Which model decides access by traversing relationships in a graph?', o: ['ACL', 'RBAC', 'ABAC', 'ReBAC'], a: 3, e: 'ReBAC follows relationships ("editor of", "member of", "parent folder"), as in Google\'s Zanzibar — ideal for sharing and hierarchy.' },
      { q: 'Checking permission on every object access primarily prevents…', o: ['Rainbow tables', 'IDOR/BOLA (reaching another user\'s object)', 'Clock skew', 'Replay attacks'], a: 1, e: 'Per-object authorization stops users from accessing records that aren\'t theirs by changing an ID — the top API risk.' },
    ],
    related: ['concepts', 'oauth-scopes', 'opa', 'oauth'],
  });

  /* ---------------- OAuth scopes ---------------- */
  HS.add({
    id: 'oauth-scopes', group: 'authz', short: 'OAuth scopes', icon: 'policy',
    title: 'OAuth Scopes & Delegated Authorization',
    tagline: 'The consent screen\'s "this app wants to read your contacts" is authorization in action. Scopes are how OAuth expresses least privilege — and the difference between a scope and a real permission check trips up even experienced engineers.',
    level: 'Intermediate', kind: 'Delegated permissions',
    spec: [['Defined by', 'OAuth 2.0'], ['Carried in', 'The access token'], ['Express', 'What an app may do, not who'], ['Principle', 'Least privilege']],
    analogy: `<p>Scopes are the checkboxes on a permission slip. When a parent signs a school trip form, they tick "may go on the bus" and "may swim" but leave "may leave the group unsupervised" unticked. The slip delegates <em>specific</em> permissions to the teacher, not blanket authority. An OAuth scope is each checkbox — the app gets exactly the ones you consented to, and the resource server enforces that the app can\'t do the unticked things.</p>`,
    flow: {
      nodes: [
        { id: 'app', label: 'App', sub: 'client', icon: 'browser', x: 95, y: 150 },
        { id: 'as', label: 'Auth server', sub: 'consent', icon: 'idp', x: 335, y: 90 },
        { id: 'rs', label: 'API', sub: 'resource server', icon: 'cloud', x: 560, y: 150 },
      ],
      order: ['app', 'as', 'rs'],
      normal: {
        name: 'Scoped consent, enforced access', summary: 'The app requests specific scopes; the user consents; the token carries those scopes; the resource server enforces them on every call.',
        steps: [
          { f: 'app', t: 'as', k: 'req', l: 'authorize scope=contacts.read', title: 'App requests specific scopes', d: 'The app asks only for what it needs — here, read-only contacts. Requesting the minimum is least privilege in practice.', data: { requested_scope: 'contacts.read', not_requested: 'contacts.write, mail.send' } },
          { f: 'as', t: 'app', k: 'res', l: 'consent screen → user approves', title: 'User consents to those scopes', d: 'The authorization server shows the human-readable scopes ("read your contacts") and the user approves or declines. Consent is per-scope.', data: { consent: 'Allow "read your contacts"?', user: 'approves', granted: 'contacts.read' } },
          { f: 'as', t: 'app', k: 'res', l: 'access_token (scope=contacts.read)', title: 'Token carries the granted scopes', d: 'The issued access token encodes exactly the granted scopes — no more. Even if the app later tries to do more, the token says what it may do.', data: { access_token: 'Bearer …', scope: 'contacts.read', ttl: '1h' }, ok: 'Scoped token issued' },
          { f: 'app', t: 'rs', k: 'req', l: 'GET /contacts  Bearer token', title: 'App calls within scope', d: 'The app reads contacts. The resource server checks the token\'s scope allows this operation.', data: { 'GET': '/contacts', scope_needed: 'contacts.read', token_scope: 'contacts.read ✓' }, ok: 'Allowed — in scope' },
          { f: 'app', t: 'rs', k: 'req', l: 'DELETE /contacts/5 (out of scope)', title: 'App tries beyond its scope', d: 'If the app attempts to delete a contact, the resource server sees the token lacks <code>contacts.write</code> and refuses — the enforcement that makes scopes meaningful.', data: { 'DELETE': '/contacts/5', scope_needed: 'contacts.write', token_scope: 'contacts.read → 403' }, fail: '403 insufficient_scope — enforced by the API' },
        ],
      },
      attack: {
        name: 'Scope ≠ permission check', summary: 'A dangerous misconception: scopes limit what the app may do on the user\'s behalf, but the API must still enforce the user\'s own permissions on specific objects. Scope alone is not object-level authZ.',
        steps: [
          { f: 'app', t: 'rs', k: 'atk', l: 'token scope=documents.read', title: 'A broadly-scoped read token', d: 'An app holds a valid token with <code>documents.read</code> — the user consented to it reading documents.', data: { token_scope: 'documents.read', meaning: 'app may read documents on the user\'s behalf' } },
          { f: 'app', t: 'rs', k: 'atk', l: 'GET /documents/9999 (not the user\'s)', title: 'Request another user\'s object', d: 'The app requests document 9999, which belongs to a <em>different</em> user. The scope check passes — it\'s a read — so a naive API returns it.', data: { 'GET': '/documents/9999', scope_check: 'documents.read ✓ (passes!)', owner: 'a different user' } },
          { f: 'rs', t: 'rs', k: 'int', l: 'scope OK but ownership NOT checked', title: 'The gap', d: 'Scope says "this app may read documents" — it says nothing about <em>which</em> documents. If the API stops at the scope check, it leaks other users\' data. Scope is app-level; object ownership is user-level.', data: { scope: 'documents.read (app permission) ✓', missing: 'does this doc belong to the token\'s user?', result_if_naive: 'data leak (BOLA)' }, fail: 'Scope passed, ownership unchecked → data leak' },
          { f: 'rs', t: 'rs', k: 'int', l: 'fix: enforce user ownership too', title: 'Both checks are required', d: 'The API must check <em>both</em>: the token has the right scope <b>and</b> the target object belongs to (or is shared with) the token\'s user. Scopes complement object-level authZ; they don\'t replace it.', data: { check_1: 'token scope allows read ✓', check_2: 'doc.owner == token.user ✓', rule: 'scope AND object authorization' }, ok: 'Scope + ownership both enforced' },
        ],
      },
    },
    basics: `
      <p><strong>Scopes</strong> are OAuth\'s mechanism for <em>delegated</em> authorization: they say what an app is permitted to do <em>on your behalf</em>. When you see "This app wants to: read your contacts, send email as you", each item is a scope you consent to. The granted scopes ride inside the <a href="#oauth">access token</a>, and the <a href="#api-keys">resource server</a> enforces them on every request.</p>
      <p>Scopes exist to enforce <b>least privilege</b>: an app should request the narrowest set it needs. A calendar widget that only reads events should ask for <code>calendar.read</code>, not <code>calendar.read_write</code> — so even if the app is compromised, the damage is bounded by what you consented to.</p>
      <div class="callout warn"><b>The crucial subtlety: a scope is not a permission check</b>A scope says "this <em>app</em> may read documents on the user\'s behalf". It does <em>not</em> say "this app may read document #9999". The resource server must still check that the specific object belongs to — or is shared with — the token\'s user. Confusing the two causes real data-leak bugs (the BOLA/IDOR family from the <a href="#authz-models">authZ models</a> page). Scopes are coarse app-level permissions; they sit <em>on top of</em> normal object-level authorization, not instead of it.</div>`,
    deep: `
      <h3>Scope design in practice</h3>
      <p>Well-designed scopes are:</p>
      <ul>
        <li><b>Granular enough to be useful</b> — separate read from write (<code>repo.read</code> vs <code>repo.write</code>), and separate sensitive capabilities (<code>admin</code>, <code>billing</code>).</li>
        <li><b>Coarse enough to be understandable</b> — users must comprehend the consent screen; a hundred micro-scopes is as bad as one god-scope.</li>
        <li><b>Named for the user, not the system</b> — "Read your calendar", not "GET /v3/cal/*".</li>
      </ul>
      <p>Over-broad scopes are a recurring real-world problem: apps request <code>read_write_all</code> "to be safe", users click through, and a later breach of that app exposes everything. The OAuth ideal is incremental/"downscoped" consent — ask for more only when a feature needs it.</p>
      <h3>Scopes vs claims vs roles</h3>
      <p>An interview-sharpening distinction:</p>
      <ul>
        <li><b>Scopes</b> (OAuth) — what the <em>app</em> may do on the user\'s behalf. Consented by the user, enforced by the resource server.</li>
        <li><b>Roles/permissions</b> (your authZ model) — what the <em>user</em> may do, independent of any app. Enforced by your application.</li>
        <li><b>Claims</b> (OIDC id_token) — facts about <em>who the user is</em> (email, name), not what they can do.</li>
      </ul>
      <p>A request can be in-scope for the app yet forbidden for the user (they lack the role) or forbidden on the object (not theirs). All layers apply.</p>
      <h3>Consent and transparency</h3>
      <p>Scopes power the consent and audit experience: the screen that lists what you\'re granting, the ability to review and revoke app access later, and the ability to grant a subset. This user-facing authorization is a big part of why OAuth replaced "give the app your password" — you can see and limit exactly what you delegate.</p>`,
    howto: `
      ${C('text', `
        Scope hygiene:
        • Request the minimum scopes a feature needs — least privilege.
        • Use incremental consent: ask for more only when the user reaches that feature.
        • Name scopes for humans; keep the consent screen understandable.
        • Resource server: check the token scope AND the user's object-level permission.
        • Separate read/write and sensitive capabilities into distinct scopes.
        • Let users review and revoke granted scopes/apps.
      `, 'Working with scopes')}
      <div class="callout"><b>Enforce both layers</b>On every API call: (1) does the token\'s scope permit this <em>operation</em>? and (2) is the <em>specific object</em> owned by or shared with the token\'s user? Skipping (2) is a classic breach.</div>
      <p>The authorization-models playground shows object-level checks that scopes must sit alongside.</p>`,
    tool: 'authz',
    pros: ['Enforce least privilege for third-party apps', 'User sees and consents to exactly what\'s delegated', 'Granted scopes travel in the token and are enforced per-request', 'Users can review and revoke app access', 'Bounds the blast radius if an app is compromised'],
    cons: ['Easily confused with user permissions — scope ≠ object authZ', 'Over-broad scopes undermine least privilege', 'Too many micro-scopes make consent incomprehensible', 'Users click through consent without reading', 'Inconsistent scope naming across providers'],
    history: [
      ['2012', 'OAuth 2.0 defines scopes for delegated authorization.'],
      ['2014', 'OpenID Connect adds the openid/profile/email scopes on top.'],
      ['2016→', 'Incremental authorization (ask for scopes as needed) spreads among major providers.'],
      ['2018', 'High-profile over-permissioned third-party apps (and data misuse) push providers toward granular scopes and app review.'],
    ],
    hidden: [
      ['Scope is app-level, not object-level', 'The single most common OAuth authZ bug: trusting a scope check alone. "This app may read documents" is not "this app may read <em>that</em> document". You still need ownership checks — scopes and object authZ are different layers.'],
      ['Users almost never read consent', 'Studies consistently show people click "Allow" without reading scopes, which is why providers push <em>minimal</em> requests and app review rather than relying on user vigilance.'],
      ['"Just ask for everything" is a real anti-pattern', 'Apps requesting broad scopes "to avoid asking again" turned minor app breaches into major data exposures — the reason incremental, least-privilege consent exists.'],
      ['Scopes, roles and claims are three different things', 'Scope = app permission (OAuth), role = user permission (your app), claim = user identity fact (OIDC). Mixing them up is a frequent interview stumble.'],
    ],
    attacks: [
      ['Scope-only enforcement (BOLA)', 'API checks the scope but not object ownership, leaking other users\' data.', 'Enforce scope AND per-object user authorization.'],
      ['Over-broad scope abuse', 'A compromised app with wide scopes exposes everything consented.', 'Least privilege, incremental consent, provider app review.'],
      ['Consent phishing', 'Trick users into granting a malicious app broad scopes.', 'Clear consent UX, app verification, admin consent controls, revocation.'],
      ['Scope upgrade / confused token use', 'Use a token beyond its granted scope or for the wrong audience.', 'Validate scope and aud on every request; downscope tokens.'],
    ],
    interview: [
      ['What is an OAuth scope?', '<p>A scope expresses <b>what an app may do on the user\'s behalf</b> — the items on the consent screen ("read your contacts", "send email as you"). The user consents per-scope, the granted scopes are carried in the access token, and the resource server enforces them on each request. Scopes are OAuth\'s way of implementing <b>least privilege</b> for delegated access: the app gets exactly what was approved, no more.</p>', 'junior'],
      ['Why is "the token has the right scope" not sufficient authorization?', '<p>Because a scope is <b>app-level</b>, not <b>object-level</b>. <code>documents.read</code> means "this app may read documents on behalf of its user" — it says nothing about <em>which</em> document. If the API returns document #9999 just because the scope permits reading, it leaks another user\'s data (a BOLA/IDOR bug). The resource server must check <b>both</b>: the token\'s scope allows the operation, <em>and</em> the specific object belongs to or is shared with the token\'s user. Scopes complement object-level authorization; they don\'t replace it.</p>', 'senior'],
      ['Distinguish scopes, roles and claims.', '<p><b>Scopes</b> (OAuth) are what the <em>app</em> may do on the user\'s behalf — consented and enforced by the resource server. <b>Roles/permissions</b> (your authZ model) are what the <em>user</em> may do, independent of any app, enforced by your application. <b>Claims</b> (OIDC id_token) are facts about <em>who the user is</em> — email, name, sub. A request can be in-scope for the app yet denied because the user\'s role doesn\'t permit it, or because the object isn\'t theirs. They\'re separate layers that all apply.</p>', 'mid'],
      ['How do you apply least privilege with scopes?', '<p>Request the <b>narrowest scopes a feature actually needs</b>, separating read from write and isolating sensitive capabilities (admin, billing) into their own scopes. Use <b>incremental/downscoped consent</b> — ask for additional scopes only when the user reaches the feature that requires them, rather than demanding everything up front. Name scopes for humans so consent is meaningful, and let users review and revoke. This bounds the blast radius: if the app is compromised, an attacker is limited to what the user actually granted.</p>', 'mid'],
    ],
    quiz: [
      { q: 'An OAuth scope expresses…', o: ['Who the user is', 'What an app may do on the user\'s behalf', 'The user\'s password', 'The server\'s TLS version'], a: 1, e: 'Scopes are delegated app permissions, consented by the user and enforced by the resource server.' },
      { q: 'A token with documents.read lets an app read documents — but the API must ALSO check…', o: ['The TLS cipher', 'That the specific document belongs to or is shared with the token\'s user', 'The user\'s password', 'The app\'s client secret'], a: 1, e: 'Scope is app-level; object ownership is user-level. Checking scope alone leaks other users\' data (BOLA).' },
      { q: 'Scopes implement which security principle?', o: ['Forward secrecy', 'Least privilege', 'Non-repudiation', 'Perfect forward secrecy'], a: 1, e: 'Scopes bound what an app can do to the minimum the user consented to — least privilege for delegated access.' },
      { q: 'Scopes, roles and claims differ in that…', o: ['They are identical', 'Scope = app permission, role = user permission, claim = identity fact', 'Only roles are in OAuth', 'Claims decide access'], a: 1, e: 'Scope (OAuth, app-level), role/permission (your app, user-level), claim (OIDC, who the user is) are distinct layers that all apply.' },
    ],
    related: ['oauth', 'authz-models', 'oidc', 'opa'],
  });

  /* ---------------- OPA / policy engines ---------------- */
  HS.add({
    id: 'opa', group: 'authz', short: 'Policy engines (OPA)', icon: 'policy',
    title: 'Policy Engines & Open Policy Agent',
    tagline: 'Pull authorization logic out of your code and into declarative policy that any service can query. OPA and its Rego language are how modern platforms keep "who can do what" consistent, testable and auditable across microservices, APIs and Kubernetes.',
    level: 'Advanced', kind: 'Policy-as-code',
    spec: [['OPA', 'Open Policy Agent (CNCF)'], ['Language', 'Rego (declarative)'], ['Pattern', 'Decouple decision (PDP) from enforcement (PEP)'], ['Used for', 'App authZ, Kubernetes, APIs']],
    analogy: `<p>Instead of every bouncer at every door inventing their own rules, a venue writes one rulebook and installs an identical "rules computer" at each door. Each bouncer just asks the computer "can this person enter with this ticket right now?" and obeys the yes/no. Update the rulebook once and every door enforces it consistently. OPA is that rules computer; Rego is the rulebook language; your services are the bouncers.</p>`,
    flow: {
      nodes: [
        { id: 'svc', label: 'Service', sub: 'PEP', icon: 'server', x: 110, y: 150 },
        { id: 'opa', label: 'OPA', sub: 'PDP engine', icon: 'policy', x: 360, y: 90 },
        { id: 'data', label: 'Policy + data', sub: 'Rego + context', icon: 'db', x: 565, y: 150 },
      ],
      order: ['svc', 'opa', 'data'],
      normal: {
        name: 'Query the policy engine', summary: 'A service sends the decision input (who, what, which object, context) to OPA; OPA evaluates the Rego policy against current data and returns allow/deny; the service enforces it.',
        steps: [
          { f: 'svc', t: 'opa', k: 'req', l: 'input: {user, action, resource, ctx}', title: 'Service asks for a decision', d: 'The service (the enforcement point) packages the decision input — the subject, action, target object and context — and queries OPA. It contains no policy logic itself.', data: { input: '{ user: {id, roles}, action: "delete", resource: {owner}, time }', note: 'service holds NO authZ rules' } },
          { f: 'opa', t: 'data', k: 'req', l: 'load Rego policy + any extra data', title: 'OPA evaluates policy', d: 'OPA runs the declarative <b>Rego</b> policy against the input and any additional data it holds (roles, relationships, org structure).', data: { policy: 'package authz; default allow := false …', data: 'role grants, ownership, hierarchy' } },
          { f: 'data', t: 'opa', k: 'res', l: 'rules evaluate → decision', title: 'Rules produce a verdict', d: 'The policy is default-deny; a decision is allowed only if a rule explicitly grants it (e.g. admin, or owner, during business hours).', data: { 'default allow': 'false', matched_rule: 'allow if input.user.id == input.resource.owner', decision: 'allow := true' } },
          { f: 'opa', t: 'svc', k: 'res', l: '{"allow": true}', title: 'Decision returned, service enforces', d: 'OPA returns a simple JSON decision. The service enforces it. Change the policy centrally and every service\'s behaviour updates — without redeploying application code.', data: { response: '{ "allow": true }', benefit: 'policy changes without code changes', consistency: 'same engine everywhere' }, ok: 'Consistent, centralised decision; local enforcement' },
        ],
      },
      attack: {
        name: 'Policy as attack surface', summary: 'Centralising authorization is powerful but concentrates risk: a buggy or unsafe policy, or a non-default-deny rule, can open everything. Testing, default-deny and safe failure modes are essential.',
        steps: [
          { f: 'svc', t: 'opa', k: 'atk', l: 'policy bug: overly broad allow', title: 'A subtle policy mistake', d: 'A refactor introduces a rule that accidentally evaluates true too often — e.g. a missing condition — granting access far beyond intent. One line now affects every service that queries OPA.', data: { bad_rule: 'allow if input.user.roles[_]  // any role!', blast_radius: 'every service using this policy' }, fail: 'One broad rule can over-grant everywhere' },
          { f: 'opa', t: 'opa', k: 'int', l: 'default-deny + unit tests', title: 'Default-deny and testing', d: 'OPA policies start <code>default allow := false</code>, so only explicit grants pass. Rego is testable — you write policy unit tests ("admin can delete", "stranger cannot") and run them in CI before any policy ships.', data: { 'default allow': 'false', tests: 'opa test — who can / cannot', ci: 'policy reviewed + tested like code' } },
          { f: 'svc', t: 'opa', k: 'atk', l: 'OPA unreachable mid-request', title: 'Fail-open vs fail-closed', d: 'If the PDP is unavailable, what should the PEP do? Fail-open (allow) is a security hole; fail-closed (deny) is the safe default, so an outage denies rather than exposes.', data: { pdp_down: 'network/engine failure', wrong: 'fail-open → allow (insecure)', right: 'fail-closed → deny' } },
          { f: 'svc', t: 'svc', k: 'int', l: 'fail-closed + local eval + audit', title: 'Resilient, auditable design', d: 'Run OPA as a sidecar/library for low latency and availability, default to deny on failure, and log every decision for audit. Centralised policy becomes a strength — consistent, testable, observable — rather than a single point of failure.', data: { deploy: 'sidecar/embedded → low latency, resilient', fail_mode: 'closed (deny)', audit: 'every decision logged' }, ok: 'Centralised, tested, fail-closed, audited' },
        ],
      },
    },
    basics: `
      <p>As systems grow, authorization logic scattered as <code>if user.role == "admin"</code> across dozens of services becomes inconsistent, untestable and impossible to audit. <strong>Policy engines</strong> fix this by making authorization <b>policy-as-code</b>: rules live in one declarative place, and services <em>query</em> for decisions instead of hard-coding them.</p>
      <p><b>Open Policy Agent (OPA)</b> is the CNCF-graduated standard for this. It cleanly implements the PEP/PDP split from the <a href="#authz-models">authZ models</a> page:</p>
      <ul>
        <li>Your service is the <b>PEP</b> — it gathers the decision input and enforces the answer.</li>
        <li>OPA is the <b>PDP</b> — it evaluates the policy and returns allow/deny.</li>
      </ul>
      <p>Policies are written in <b>Rego</b>, a declarative query language. A request sends JSON input ("user X wants to delete resource Y, context Z"); OPA returns a JSON decision ("allow: false"). Because the policy is data, you can version it in Git, unit-test it, review it in pull requests, and update it without redeploying application code.</p>`,
    deep: `
      <h3>Why decouple policy from code?</h3>
      <ul>
        <li><b>Consistency</b> — one policy evaluated the same way by every service, instead of each team\'s ad-hoc checks.</li>
        <li><b>Auditability</b> — "what can an admin do?" is answerable by reading one policy, and every decision can be logged.</li>
        <li><b>Agility</b> — security/compliance can change rules without a code deploy; developers stop reimplementing authZ.</li>
        <li><b>Testability</b> — Rego policies have unit tests; you prove "a stranger cannot delete" in CI.</li>
      </ul>
      <h3>A tiny Rego example</h3>
      ${C('rego', `
        package authz
        default allow := false                    # deny by default

        # admins can do anything
        allow if input.user.roles[_] == "admin"

        # owners can modify their own resource during business hours
        allow if {
          input.action in {"update", "delete"}
          input.user.id == input.resource.owner
          input.time.hour >= 9
          input.time.hour < 18
        }
      `, 'A Rego authorization policy (OPA 1.0 syntax, ABAC-style)')}
      <p>Notice it expresses RBAC (the admin rule) and ABAC (owner + time conditions) together — policy engines don\'t pick a model, they let you encode whichever fits, which is exactly the "models compose" point from the authZ-models page.</p>
      <h3>Where OPA runs — and fail-closed</h3>
      <p>For low latency and availability OPA is typically deployed as a <b>sidecar</b> next to each service or embedded as a library, with policies distributed to all instances. Two design imperatives:</p>
      <ul>
        <li><b>Default-deny</b> in the policy (<code>default allow := false</code>) so only explicit grants pass.</li>
        <li><b>Fail-closed</b> at the enforcement point: if the engine is unavailable, deny rather than allow. Fail-open is a classic, dangerous mistake.</li>
      </ul>
      <h3>Beyond app authZ</h3>
      <p>OPA is general-purpose policy. Its best-known use is <b>Kubernetes admission control</b> (via Gatekeeper) — "no container may run as root", "every namespace must have an owner label" — enforced as policy across the cluster. The same engine governs API gateways, Terraform/infra validation, and CI checks. Alternatives and complements include <b>Cedar</b> (AWS, used by Amazon Verified Permissions), and ReBAC-focused systems like <b>OpenFGA</b>/<b>SpiceDB</b> (the Zanzibar lineage from the authZ-models page) for relationship-heavy authorization.</p>`,
    howto: `
      ${C('text', `
        Adopting policy-as-code:
        • Pick the engine for the job: OPA/Rego (general, k8s), Cedar (AWS), OpenFGA/SpiceDB (ReBAC).
        • Keep policy in version control; review and unit-test it like application code.
        • default allow := false — deny by default; grant only explicit rules.
        • PEP gathers input and ENFORCES; PDP (engine) only DECIDES.
        • Deploy as sidecar/embedded for latency; fail CLOSED if the engine is unreachable.
        • Log every decision for audit; monitor allow-rate for anomalies.
      `, 'Introducing a policy engine')}
      <div class="callout"><b>Separate decision from enforcement, always</b>The engine answers "may this happen?"; your service still has to actually not do the thing on a deny. The PEP/PDP split is the whole pattern — and the enforcement point must fail closed.</div>
      <p>The authorization-models playground shows the kinds of decisions such a policy encodes.</p>`,
    tool: 'authz',
    pros: ['One consistent, auditable source of authorization truth', 'Policy-as-code: versioned, reviewed, unit-tested in CI', 'Change rules without redeploying application code', 'Decouples decision (PDP) from enforcement (PEP) cleanly', 'General-purpose: app authZ, Kubernetes, APIs, infra'],
    cons: ['Rego has a real learning curve', 'Centralised policy concentrates risk — a bad rule affects everything', 'Adds an evaluation dependency; must handle latency and failure', 'Fail-open misconfiguration is a serious hole', 'Operational overhead of distributing and versioning policy'],
    history: [
      ['2016', 'Open Policy Agent created by Styra to unify policy across the cloud-native stack.'],
      ['2018', 'OPA joins the CNCF; Gatekeeper brings OPA to Kubernetes admission control.'],
      ['2021', 'OPA graduates in the CNCF — a signal of broad production adoption.'],
      ['2023', 'AWS open-sources Cedar and launches Verified Permissions, popularising dedicated authZ-as-a-service.'],
      ['2020s', 'Zanzibar-inspired OpenFGA/SpiceDB and policy engines converge on "authorization as a service".'],
    ],
    hidden: [
      ['Authorization is becoming its own service', 'The industry trend: pull authZ out of every app into a dedicated, consistent policy/relationship service (OPA, Cedar, OpenFGA). It mirrors how authentication moved to IdPs — a strong talking point about where the field is heading.'],
      ['Fail-open is the catastrophic default to avoid', 'If the policy engine is down and the service "allows to keep working", you\'ve disabled authorization during an outage. Fail-closed (deny) is the only safe choice — a favourite interview gotcha.'],
      ['Rego thinks in queries, not loops', 'Rego trips up newcomers because it\'s declarative — you describe what makes something allowed, and the engine evaluates, rather than writing imperative checks. The mental shift is the main cost of adoption.'],
      ['OPA guards far more than app logins', 'Its biggest footprint is Kubernetes admission control (Gatekeeper) — enforcing cluster rules like "no root containers". Same engine, same language, a completely different authorization problem.'],
    ],
    attacks: [
      ['Overly broad / buggy policy', 'A mistaken rule grants access everywhere it\'s queried.', 'Default-deny, policy unit tests in CI, peer review, least privilege.'],
      ['Fail-open on engine outage', 'Enforcement allows when the PDP is unreachable.', 'Fail-closed (deny) at the PEP; local/sidecar eval for availability.'],
      ['Stale policy/data', 'Decisions made on outdated roles/relationships.', 'Reliable policy/data distribution, freshness checks, revocation handling.'],
      ['Unaudited decisions', 'No record of who was allowed what.', 'Log every decision with input; monitor allow-rate anomalies.'],
      ['PEP bypass', 'Reaching the resource without going through enforcement.', 'Ensure all paths enforce; defence in depth; network controls.'],
    ],
    interview: [
      ['What problem does a policy engine like OPA solve?', '<p>It stops authorization logic from being scattered and inconsistent across services. Instead of each service hard-coding <code>if role ==</code> checks, rules live in one declarative place (Rego policy) and services <b>query</b> for decisions. This gives consistency (one policy, evaluated the same everywhere), auditability (read one policy to know who can do what; log every decision), agility (change rules without redeploying code), and testability (unit-test policies in CI). It cleanly implements the PEP/PDP split: the service enforces, OPA decides.</p>', 'mid'],
      ['What does the PEP/PDP separation mean in an OPA deployment?', '<p>The <b>Policy Decision Point</b> (OPA) evaluates the policy and returns allow/deny; the <b>Policy Enforcement Point</b> (your service) gathers the decision input and actually enforces the answer — it contains no rules itself. This decoupling lets you change policy centrally without touching application code, and keeps decisions consistent across many services. The critical caveat: the PEP must still <em>act</em> on a deny, and must <b>fail closed</b> if the PDP is unreachable.</p>', 'senior'],
      ['Should a policy check fail open or fail closed, and why?', '<p><b>Fail closed</b> — deny when the engine is unavailable or errors. Fail-open (allowing to "keep things working") effectively disables authorization during an outage, exactly when you\'re most exposed, and is a classic, severe misconfiguration. You combine fail-closed with resilient deployment (OPA as a sidecar or embedded library so it\'s highly available and low-latency) and default-deny policies, so both the normal and failure paths default to denial.</p>', 'senior'],
      ['Is OPA RBAC or ABAC? And what else is it used for?', '<p>Neither exclusively — OPA is model-agnostic. Rego can encode RBAC (role → permission rules), ABAC (conditions over attributes), and even relationship checks, often in the same policy, which reflects how real systems compose models. Beyond application authorization, OPA\'s largest use is <b>Kubernetes admission control</b> (via Gatekeeper) — enforcing cluster policies like "no root containers" or "images only from our registry" — plus API-gateway authorization and infrastructure/CI validation. It\'s general-purpose policy-as-code, not a fixed model.</p>', 'mid'],
    ],
    quiz: [
      { q: 'In the OPA pattern, the policy engine is the ____ and your service is the ____.', o: ['PEP; PDP', 'PDP (decides); PEP (enforces)', 'IdP; SP', 'client; server'], a: 1, e: 'OPA decides (Policy Decision Point); your service enforces the answer (Policy Enforcement Point) and holds no rules itself.' },
      { q: 'A core benefit of policy-as-code is that you can…', o: ['Encrypt traffic', 'Version, review and unit-test authorization rules, and change them without redeploying code', 'Avoid authentication', 'Skip object-level checks'], a: 1, e: 'Policy lives in one declarative place: testable, auditable, and updatable without application code changes.' },
      { q: 'If the policy engine is unreachable mid-request, a secure PEP should…', o: ['Fail open (allow)', 'Fail closed (deny)', 'Cache the last yes', 'Skip the check'], a: 1, e: 'Fail-closed denies during an outage. Fail-open would silently disable authorization exactly when you\'re exposed.' },
      { q: 'OPA policies written in Rego are typically…', o: ['Imperative loops', 'Default-allow', 'Declarative and default-deny', 'Written per user'], a: 2, e: 'Rego is declarative; good policies start with default allow := false so only explicit rules grant access.' },
    ],
    related: ['authz-models', 'oauth-scopes', 'concepts', 'mtls'],
  });
})();
