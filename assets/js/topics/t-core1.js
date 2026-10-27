/* Start-here concepts + first transport topics */
(function () {
  'use strict';
  const HS = window.HS, C = window.C;

  /* ---------------- Authentication vs Authorization ---------------- */
  HS.add({
    id: 'concepts', group: 'start', short: 'AuthN vs AuthZ', icon: 'key',
    title: 'Authentication vs Authorization',
    tagline: 'Two words that start with "auth", mean completely different things, and get mixed up in nearly every interview. Get these straight first — every other page builds on them.',
    level: 'Foundations', kind: 'Concept',
    spec: [['Authentication', 'Who are you?'], ['Authorization', 'What may you do?'], ['Order', 'AuthN first, then AuthZ'], ['HTTP codes', '401 vs 403']],
    analogy: `<p><b>Authentication (AuthN)</b> is showing your passport at the airport desk — proving you are who you claim. <b>Authorization (AuthZ)</b> is the boarding pass that says you may sit in seat 14C on <em>this</em> flight. The passport proves identity; the boarding pass grants access to a specific thing.</p><p>You authenticate once, then the system authorizes you over and over for each thing you try to touch.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'Client', sub: 'you', icon: 'user', x: 95, y: 150 },
        { id: 's', label: 'Server', sub: 'app', icon: 'server', x: 360, y: 90 },
        { id: 'authz', label: 'Policy', sub: 'access rules', icon: 'policy', x: 360, y: 225 },
        { id: 'db', label: 'Resource', sub: 'the data', icon: 'db', x: 565, y: 150 },
      ],
      order: ['u', 's', 'authz', 'db'],
      normal: {
        name: 'Identify, then decide', summary: 'One login proves identity (authentication); every action afterward is a separate authorization decision.',
        steps: [
          { f: 'u', t: 's', k: 'req', l: 'login: user + proof', title: 'Authentication request', d: 'The client sends a credential — a password, a token, a certificate — to prove who it is.', data: { 'POST': '/login', username: 'sakitha', proof: 'password / token / cert' }, port: 'HTTPS 443' },
          { f: 's', t: 's', k: 'int', l: 'verify identity', title: 'Server checks the proof', d: 'The server validates the credential. If it checks out, it now knows <em>who</em> the caller is. This is the whole of authentication.', data: { step: 'compare credential', result: 'identity = user_8842 (sakitha)' } },
          { f: 's', t: 'u', k: 'res', l: 'session / token', title: 'Identity established', d: 'The server issues a session or token the client will present on later requests, so it need not log in again each time.', data: { 'Set-Cookie': 'sid=…; HttpOnly', or: 'Authorization: Bearer …' }, ok: 'Authenticated — identity known' },
          { f: 'u', t: 's', k: 'req', l: 'DELETE /reports/9', title: 'Now an action', d: 'Authenticated, the client asks to do something specific. Knowing who they are does not yet mean they are allowed.', data: { 'DELETE': '/reports/9', identity: 'user_8842' } },
          { f: 's', t: 'authz', k: 'req', l: 'may user_8842 delete report 9?', title: 'Authorization check', d: 'The server asks its policy layer whether <em>this identity</em> may perform <em>this action</em> on <em>this object</em>.', data: { subject: 'user_8842', action: 'delete', object: 'report:9', role: 'editor' } },
          { f: 'authz', t: 's', k: 'res', l: 'DENY — editors can\'t delete', title: 'Policy answers', d: 'The policy says editors may update but not delete. Authentication succeeded; authorization failed.', data: { decision: 'DENY', reason: 'role editor lacks delete' }, fail: '403 Forbidden — identity known, action not allowed' },
        ],
      },
      attack: {
        name: 'The classic confusion bug', summary: 'A developer checks that you are logged in but forgets to check whether you own the thing. This is "Broken Object Level Authorization" — the #1 item on the OWASP API Top 10.',
        steps: [
          { f: 'u', t: 's', k: 'req', l: 'GET /invoices/1001 (mine)', title: 'A normal request', d: 'Logged-in user requests their own invoice. Works fine.', data: { 'GET': '/invoices/1001', identity: 'user_8842' } },
          { f: 's', t: 'u', k: 'res', l: '200 OK — your invoice', title: 'Returned correctly', d: 'The server confirms you are authenticated and returns invoice 1001, which happens to be yours.', data: { status: 200, owner: 'user_8842' }, ok: 'Fine so far' },
          { f: 'u', t: 's', k: 'atk', l: 'GET /invoices/1002', title: 'Change one digit', d: 'The same logged-in user simply asks for the next invoice number — one belonging to someone else.', data: { 'GET': '/invoices/1002', identity: 'user_8842', note: 'not their invoice' } },
          { f: 's', t: 's', k: 'int', l: 'is user logged in? yes → serve', title: 'The missing check', d: 'The buggy server only verified <em>authentication</em> ("are you logged in?") and never asked <em>authorization</em> ("is this invoice yours?").', data: { checked: 'authenticated = true', 'NOT checked': 'owner == caller' } },
          { f: 's', t: 'u', k: 'atk', l: '200 OK — someone else\'s invoice', title: 'Data leak', d: 'The server leaks another customer\'s invoice. The fix is an authorization check on every object: compare the resource owner to the caller.', data: { leaked: 'invoice 1002', ownedBy: 'user_9001' }, fail: 'Broken Object Level Authorization (BOLA)' },
        ],
      },
    },
    basics: `
      <p><strong>Authentication</strong> answers <em>"who are you?"</em> You prove an identity. <strong>Authorization</strong> answers <em>"what are you allowed to do?"</em> The system decides access.</p>
      <p>The order is always the same: authenticate first, then authorize. You cannot decide what someone may do until you know who they are. A rare exception is anonymous access, where the identity is simply "the public" and authorization still runs against that.</p>
      <p>HTTP even gives them separate status codes, and interviewers love this detail:</p>
      <ul>
        <li><code>401 Unauthorized</code> — despite the name, this is an <em>authentication</em> failure. "I don't know who you are. Log in." The response should include a <code>WWW-Authenticate</code> header.</li>
        <li><code>403 Forbidden</code> — an <em>authorization</em> failure. "I know exactly who you are, and you may not do this." Logging in again won't help.</li>
      </ul>
      <p>A third word you will hear is <strong>identification</strong> — simply <em>claiming</em> an identity (typing a username) without yet proving it. Authentication is the proof step.`,
    deep: `
      <h3>The three (or four) factors</h3>
      <p>Authentication proof comes in categories called <em>factors</em>:</p>
      <ul>
        <li><b>Something you know</b> — password, PIN, security answer.</li>
        <li><b>Something you have</b> — phone, hardware key, smart card.</li>
        <li><b>Something you are</b> — fingerprint, face, iris.</li>
        <li>Sometimes added: <b>somewhere you are</b> (location) and <b>something you do</b> (typing rhythm).</li>
      </ul>
      <p>Multi-factor authentication (MFA) means combining factors from <em>different</em> categories. Two passwords is not MFA; a password plus a phone code is. Covered in depth on the <a href="#mfa">MFA page</a>.</p>
      <h3>Accounting — the forgotten third A</h3>
      <p>Security textbooks talk about <strong>AAA</strong>: Authentication, Authorization and <strong>Accounting</strong> (also called auditing). Accounting is the log of who did what, when. It is how you detect and investigate abuse after the fact, and it is a real interview topic for infrastructure roles — see <a href="#radius">RADIUS</a>, which was built around AAA.</p>
      <h3>Where identity "lives"</h3>
      <p>After authentication the proven identity has to travel with later requests. The whole rest of this guide is essentially different answers to "how do we carry proven identity around safely?" — cookies, tokens, tickets, certificates. Keep that lens as you read.`,
    uses: [
      ['Logging into anything', 'The password/passkey step is authentication; what you then see and can edit is authorization.'],
      ['Bank app', 'AuthN: biometric unlock. AuthZ: you can view your own accounts but not transfer above a limit without extra approval.'],
      ['Cloud consoles (AWS/GCP)', 'AuthN: your account login. AuthZ: IAM policies deciding which buckets and VMs you may touch.'],
      ['Office building', 'AuthN: your badge identifies you. AuthZ: the badge opens the 3rd floor but not the data centre.'],
    ],
    history: [
      ['1960s', 'Time-sharing systems (CTSS, then Multics) introduce per-user passwords — the first real need to tell users apart on one machine.'],
      ['1962', 'The first documented password theft: a researcher prints CTSS\'s password file at MIT to get extra computer time — a year after passwords were introduced.'],
      ['2000', 'RFCs 2903–2904 describe a generic "AAA" architecture (authentication, authorization, accounting), the model RADIUS had popularised for network access.'],
      ['2003→2021', 'OWASP publishes its first Top 10 in 2003; by the 2021 edition, broken access control has risen to the #1 web application risk.'],
    ],
    hidden: [
      ['401 is misnamed forever', 'HTTP\'s <code>401 Unauthorized</code> is really an authentication error. The spec authors admitted the name is wrong but it can never change. Use the right word in interviews even though the code lies.'],
      ['AuthZ is where breaches live', 'Authentication gets the glamour, but most real-world breaches are broken <em>authorization</em> — a logged-in user reaching data that isn\'t theirs. Checking identity is easy; checking permission on every object is where teams slip.'],
      ['"Confused deputy"', 'A program with more privilege than its caller can be tricked into misusing that privilege on the caller\'s behalf. OAuth, CSRF and SSRF are all variants of this one classic authorization problem.'],
    ],
    interview: [
      ['Explain the difference between authentication and authorization in one sentence each.', '<p>Authentication proves <em>who</em> you are; authorization decides <em>what</em> you are allowed to do. Authentication always comes first, because you cannot make an access decision about an unknown party.</p>', 'junior'],
      ['What is the difference between HTTP 401 and 403?', '<p><code>401</code> means not authenticated — the server doesn\'t know who you are and invites you to log in (and should send <code>WWW-Authenticate</code>). <code>403</code> means authenticated but not authorized — it knows who you are and refuses anyway, so re-logging-in won\'t help. A subtlety: some apps deliberately return 404 instead of 403 to avoid revealing that a resource exists.</p>', 'mid'],
      ['A user changes the ID in a URL from their own order to someone else\'s and sees it. What went wrong and what class of bug is it?', '<p>The server authenticated the user but failed to authorize them against that specific object — it never checked that the order belongs to the caller. This is <b>Broken Object Level Authorization (BOLA)</b>, also called IDOR, the top item on the OWASP API Security Top 10. The fix is an ownership/permission check on every object access, not just a login check, and ideally not relying on unguessable IDs alone.</p>', 'mid'],
      ['Where do you enforce authorization in a microservices system?', '<p>Authentication can happen once at the edge (gateway) and be passed inward as a signed token, but authorization should be enforced by each service on its own data, because only that service knows its objects and relationships. A common pattern is a central policy decision point (e.g. OPA) that each service queries, keeping policy consistent while enforcement stays local. Never trust an upstream service to have done the check for you — defence in depth.</p>', 'senior'],
    ],
    quiz: [
      { q: 'You receive HTTP 403 Forbidden. What does it tell you?', o: ['Your credentials are wrong; log in again', 'The server knows who you are but won\'t let you do this', 'The page doesn\'t exist', 'The server is down'], a: 1, e: '403 is an authorization failure — identity is known, action is refused. 401 is the one that means "log in".' },
      { q: 'Which pairing is true multi-factor authentication?', o: ['A password and a PIN', 'A fingerprint and a face scan', 'A password and a code from your phone', 'Two different passwords'], a: 2, e: 'MFA requires factors from different categories. Password (know) + phone code (have) qualifies; two of the same category does not.' },
      { q: 'A logged-in user reads another user\'s record by changing an ID. This is primarily a failure of…', o: ['Authentication', 'Authorization', 'Encryption', 'Accounting'], a: 1, e: 'Authentication succeeded (they were logged in). Authorization failed — no ownership check on the object. This is BOLA/IDOR.' },
      { q: 'What does the "accounting" in AAA mean?', o: ['Billing the user', 'Recording who did what and when', 'Counting failed logins', 'Balancing server load'], a: 1, e: 'Accounting (auditing) is the record of actions — essential for detecting and investigating misuse after the fact.' },
    ],
    related: ['passwords', 'sessions', 'authz-models', 'jwt'],
  });

  /* ---------------- Passwords & credential storage ---------------- */
  HS.add({
    id: 'passwords', group: 'start', short: 'Passwords & hashing', icon: 'lock',
    title: 'Passwords & Credential Storage',
    tagline: 'The oldest method, still everywhere, and the one whose failures make the news. The interesting engineering is not the login — it is how the server stores the secret so that a database theft is survivable.',
    level: 'Foundations', kind: 'Knowledge factor',
    spec: [['Factor', 'Something you know'], ['Store as', 'Salted slow hash'], ['Never store', 'Plaintext / fast hash'], ['Algorithms', 'Argon2, scrypt, bcrypt']],
    analogy: `<p>A password is a shared secret between you and the service. The naive mistake is for the service to keep a copy of the secret itself — like a hotel storing a photocopy of every guest's house key. If the filing cabinet is stolen, every home is exposed.</p><p>Good systems instead keep a <em>one-way fingerprint</em> of the key: enough to recognise the real key when you present it, but not enough to recreate it. And they make taking each fingerprint deliberately slow, so a thief with the cabinet still can't test guesses quickly.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'Browser', sub: 'user', icon: 'browser', x: 95, y: 150 },
        { id: 's', label: 'Auth server', sub: 'login', icon: 'server', x: 355, y: 150 },
        { id: 'db', label: 'User store', sub: 'hashes only', icon: 'db', x: 565, y: 150 },
      ],
      order: ['u', 's', 'db'],
      normal: {
        name: 'Registration & login', summary: 'At registration the server stores only a salted slow hash. At login it repeats the computation and compares — it never needs the plaintext again.',
        steps: [
          { f: 'u', t: 's', k: 'req', l: 'sign up: pw="hunter2"', title: 'User sets a password', d: 'Over TLS, the browser sends the chosen password once. This is the only time the server sees the plaintext.', data: { 'POST': '/register', password: 'hunter2 (over HTTPS)' }, enc: true, port: 'TLS 443' },
          { f: 's', t: 's', k: 'int', l: 'salt + Argon2id(pw)', title: 'Hash with a random salt', d: 'The server generates a unique random salt, then runs a slow hash (Argon2/bcrypt/scrypt) over salt+password. The cost parameter makes this take ~100–250 ms on purpose.', data: { salt: 'a7f3c901… (random, per user)', algorithm: 'argon2id, t=3, m=64MB', output: 'store salt + hash' } },
          { f: 's', t: 'db', k: 'req', l: 'store {salt, hash}', title: 'Persist the fingerprint', d: 'Only the salt and hash are written. The plaintext is discarded from memory. There is now no copy of the password anywhere.', data: { user: 'sakitha', salt: 'a7f3c901…', hash: '$argon2id$v=19$…', plaintext: 'NOT stored' }, ok: 'Password unrecoverable by design' },
          { f: 'u', t: 's', k: 'req', l: 'login: pw="hunter2"', title: 'Later: login attempt', d: 'On login the browser sends the password again over TLS.', data: { 'POST': '/login', password: 'hunter2' }, enc: true },
          { f: 's', t: 'db', k: 'req', l: 'fetch salt + hash for user', title: 'Load the stored values', d: 'The server fetches the stored salt and hash for that username.', data: { lookup: 'sakitha', got: 'salt a7f3c901…, hash $argon2id$…' } },
          { f: 's', t: 's', k: 'int', l: 'recompute & compare', title: 'Constant-time compare', d: 'It recomputes Argon2id(salt+entered password) and compares to the stored hash using a constant-time comparison (so timing can\'t leak how many bytes matched).', data: { recomputed: '$argon2id$…', match: 'true', compare: 'constant-time' }, ok: 'Match → authenticated' },
        ],
      },
      attack: {
        name: 'Database theft: fast hash vs salted slow hash', summary: 'The attacker has stolen the entire user table. What they can do with it depends entirely on how it was stored.',
        steps: [
          { f: 'db', t: 'db', k: 'atk', l: 'table exfiltrated', title: 'The breach', d: 'An attacker dumps the user table. If passwords are plaintext, it is game over immediately — and people reuse passwords across sites.', data: { stolen: 'all usernames + stored secrets', goal: 'recover plaintext passwords' } },
          { f: 'db', t: 'db', k: 'int', l: 'case A: unsalted SHA-256', title: 'Fast unsalted hash', d: 'A fast hash with no salt is barely a speed bump. Identical passwords share a hash, and precomputed <em>rainbow tables</em> reverse common ones instantly; GPUs test billions of guesses per second.', data: { 'hunter2': 'f52fbd32… (same for every user who chose it)', rate: '~10,000,000,000 guesses/sec on a GPU', rainbow: 'common passwords reversed instantly' }, fail: 'Most passwords cracked within hours' },
          { f: 'db', t: 'db', k: 'int', l: 'case B: per-user salt', title: 'Salt kills the shortcut', d: 'A unique salt per user means identical passwords store differently, so one precomputed table can no longer crack many accounts at once. The attacker must attack each account separately.', data: { 'user A': 'salt a7f3 → 9c01…', 'user B': 'salt 91c0 → 2f88…', effect: 'rainbow tables useless; no bulk cracking' } },
          { f: 'db', t: 'db', k: 'int', l: 'case C: slow cost factor', title: 'Slowness makes guessing uneconomic', d: 'A deliberately slow algorithm (Argon2 with real memory/time cost) turns 10 billion guesses/sec into a few thousand. Strong unique passwords become infeasible to crack; only weak ones remain at risk.', data: { rate: '~a few thousand guesses/sec', strong_pw: 'centuries to crack', weak_pw: 'still at risk → enforce length + breach checks' }, ok: 'Breach is survivable for good passwords' },
        ],
      },
    },
    basics: `
      <p>A password is a <em>knowledge factor</em>: a secret both sides share. The security question is not really "is the password strong?" — it is "what does the server keep, and what happens when that store is stolen?" Assume it <em>will</em> be stolen and design backwards from there.</p>
      <p>The rules, in order of importance:</p>
      <ol>
        <li><b>Never store plaintext.</b> A stolen plaintext table is an instant, total breach.</li>
        <li><b>Never store a plain fast hash</b> (MD5, SHA-1, SHA-256 alone). Fast hashes are for integrity, not passwords; GPUs reverse them en masse.</li>
        <li><b>Add a unique random salt per user.</b> This defeats precomputed rainbow tables and stops identical passwords from looking identical.</li>
        <li><b>Use a deliberately slow, memory-hard algorithm:</b> Argon2id (first choice today), scrypt, or bcrypt. Tune the cost so one hash takes ~100–250 ms.</li>
        <li><b>Compare in constant time</b> so response timing can't leak information.</li>
      </ol>
      <div class="callout"><b>Salt vs pepper</b>Salt is random, per-user, and stored next to the hash — its job is uniqueness, not secrecy. A <em>pepper</em> is a single site-wide secret kept <em>outside</em> the database (e.g. in an HSM or app config) and mixed in too, so a database-only breach still can't verify guesses. Peppering is optional; salting is mandatory.</div>`,
    deep: `
      <h3>Why "slow" and "memory-hard"?</h3>
      <p>Fast hashes were designed to be fast — great for checksums, terrible for passwords, because the attacker gets that speed too. Password hashes invert the goal: each evaluation should cost real time <em>and</em> real memory, so an attacker can't just throw a warehouse of cheap GPUs or ASICs at the problem. Argon2id is memory-hard precisely to blunt specialised hardware. bcrypt (1999) is still acceptable; scrypt and Argon2 are stronger against custom hardware.</p>
      <h3>Modern NIST guidance (the stuff that overturns old advice)</h3>
      <ul>
        <li><b>Length over complexity.</b> Allow long passphrases (64+ chars, spaces, emoji). Forced "1 uppercase, 1 symbol" rules produce predictable patterns like <code>Password1!</code> and are discouraged.</li>
        <li><b>No forced periodic rotation.</b> Routine 90-day expiry makes people pick weaker, incrementing passwords. Rotate only on evidence of compromise.</li>
        <li><b>Check against breach lists.</b> Reject passwords found in known breach corpora (e.g. via a k-anonymity range query to a service like Have I Been Pwned, so the full password never leaves the client).</li>
        <li><b>No hints, no knowledge-based "security questions"</b> — your mother's maiden name is not a secret.</li>
      </ul>
      <h3>Rate limiting & lockout</h3>
      <p>Storage protects against offline cracking after a breach. Against <em>online</em> guessing you also need throttling: exponential backoff, CAPTCHAs after N failures, and alerting. Beware lockout as a denial-of-service vector — an attacker who knows a username can lock a victim out by failing on purpose. Prefer throttling and MFA over hard lockouts.`,
    howto: `
      <p>In practice you almost never implement this yourself — you call a vetted library. The point of knowing the internals is to use the library correctly and to read incident reports intelligently.</p>
      ${C('python', `
        # Python — use a maintained library, not hashlib
        from argon2 import PasswordHasher
        ph = PasswordHasher(time_cost=3, memory_cost=64*1024, parallelism=4)

        # at registration
        stored = ph.hash(user_password)   # includes algorithm, params and salt
        # -> "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"

        # at login
        try:
            ph.verify(stored, submitted_password)   # constant-time, raises on mismatch
            if ph.check_needs_rehash(stored):        # params upgraded since? re-hash
                stored = ph.hash(submitted_password)
        except Exception:
            reject()  # do not reveal whether user or password was wrong
      `, 'Hashing a password with Argon2id')}
      <div class="callout warn"><b>Don't leak which part was wrong</b>Return the same generic error for "no such user" and "wrong password", and take the same time in both cases, or you hand attackers a way to enumerate valid usernames.</div>
      <p>Try the storage comparison below to see a breach play out under each choice.</p>`,
    tool: 'pwstore',
    pros: ['Universally understood — zero user training needed', 'No hardware, works on any device', 'Cheap to implement with mature libraries', 'Easy to reset/recover when forgotten'],
    cons: ['Reused across sites, so one breach cascades everywhere', 'Phishable — users type them into fake pages', 'Weak human-chosen passwords are guessable', 'Put the entire burden of secrecy on the user', 'Breaches are routine and high-impact'],
    history: [
      ['1961', 'MIT\'s CTSS introduces per-user passwords on a shared machine.'],
      ['1979', 'Morris and Thompson\'s Unix crypt adds a 12-bit salt and a deliberately slowed DES-based hash — salting enters the mainstream.'],
      ['1999', 'bcrypt introduces a tunable cost factor, so hashing can be made slower as hardware speeds up.'],
      ['2009', 'scrypt adds memory-hardness to resist custom cracking hardware.'],
      ['2015', 'Argon2 wins the Password Hashing Competition; Argon2id becomes the modern default.'],
      ['2017→2025', 'NIST flips decades of advice (SP 800-63B, culminating in Revision 4, 2025): favour length, forbid forced composition rules and routine rotation, require breach-list screening.'],
    ],
    hidden: [
      ['The salt is not secret', 'A common misconception is that salts must be hidden. They don\'t — a salt stored in plaintext beside the hash still does its job, because its purpose is uniqueness, not secrecy. The secret, optional defence is the pepper.'],
      ['bcrypt silently truncates at 72 bytes', 'bcrypt ignores everything past 72 bytes of input. Very long passphrases can collide, and pre-hashing with SHA-256 before bcrypt (to shorten them) can introduce null-byte bugs. Argon2 avoids this.'],
      ['"Hashing" ≠ "encryption"', 'Interviewers probe this. Encryption is reversible with a key; hashing is one-way. Passwords are hashed, not encrypted — there should be no key that turns the stored value back into the password.'],
      ['Timing attacks on comparison', 'A normal <code>==</code> on hashes can return early on the first differing byte, leaking match length through timing. Always use a constant-time comparison; good libraries do this for you.'],
    ],
    attacks: [
      ['Credential stuffing', 'Attacker replays username/password pairs leaked from <em>other</em> sites, betting on reuse.', 'MFA, breach-list screening, device fingerprinting, rate limiting per account and IP.'],
      ['Brute force / dictionary', 'Systematically guess passwords, online or offline against a stolen hash table.', 'Slow memory-hard hashing, long minimum length, online throttling and backoff.'],
      ['Rainbow tables', 'Precomputed hash→password lookups reverse unsalted fast hashes instantly.', 'A unique per-user salt makes precomputation useless.'],
      ['Phishing', 'A fake login page captures the typed password directly.', 'Phishing-resistant factors (<a href="#webauthn">passkeys</a>), password managers that refuse wrong domains.'],
      ['Shoulder-surfing / keylogging', 'The secret is observed as it is entered.', 'MFA so a stolen password alone is insufficient; hardware keys.'],
    ],
    interview: [
      ['Why can\'t you store passwords with SHA-256?', '<p>SHA-256 is a <em>fast</em> hash — exactly the wrong property. GPUs compute billions per second, so an attacker with the hash table cracks weak and common passwords quickly, and without a salt, rainbow tables reverse them outright. Password storage needs a <b>slow, salted, memory-hard</b> algorithm (Argon2id/scrypt/bcrypt). SHA-256 is for integrity, not secrets.</p>', 'junior'],
      ['What is a salt and what attack does it stop?', '<p>A salt is a unique random value per password, stored alongside the hash and mixed in before hashing. It stops <b>precomputed (rainbow table)</b> attacks and prevents identical passwords from producing identical hashes, so an attacker can\'t crack many accounts with one effort or spot shared passwords. It doesn\'t need to be secret — uniqueness is the point.</p>', 'junior'],
      ['Salt vs pepper — what\'s the difference?', '<p>Both are mixed into the password before hashing. A <b>salt</b> is random, per-user, and stored with the hash; its job is uniqueness. A <b>pepper</b> is a single site-wide secret kept <em>outside</em> the database (app config or an HSM); its job is to make a database-only breach insufficient to verify guesses. Salting is mandatory; peppering is an optional extra layer.</p>', 'mid'],
      ['Should you force users to change passwords every 90 days?', '<p>Current NIST guidance (SP 800-63B, Revision 4 in 2025) says no — routine rotation drives weaker, predictable passwords (<code>Spring2026!</code> → <code>Summer2026!</code>). Rotate only on evidence of compromise. Rev 4 also forbids forced composition rules and requires breach-list screening. Better investments are length, screening and MFA. Being able to cite the shift in 800-63B signals you follow modern practice rather than cargo-culted rules.</p>', 'mid'],
      ['How would you design login to resist both offline cracking and online guessing?', '<p>Two different threats, two defences. <b>Offline</b> (stolen DB): salted memory-hard hashing tuned to ~100–250 ms, optional pepper in an HSM. <b>Online</b> (live guessing): per-account and per-IP rate limiting with exponential backoff, CAPTCHA after repeated failures, generic constant-time error responses to avoid username enumeration, anomaly detection, and MFA to make a correct password alone insufficient. Add breach-list screening at set-time to reject known-compromised passwords.</p>', 'senior'],
    ],
    quiz: [
      { q: 'Why is a unique salt per user important?', o: ['It encrypts the password', 'It makes identical passwords hash differently and defeats rainbow tables', 'It hides the username', 'It speeds up hashing'], a: 1, e: 'Salts provide uniqueness, defeating precomputed tables and masking shared passwords. They aren\'t secret and don\'t encrypt anything.' },
      { q: 'Which is the best modern choice for password storage?', o: ['SHA-256', 'MD5 with a salt', 'Argon2id', 'AES encryption'], a: 2, e: 'Argon2id is slow and memory-hard — the current first choice. Fast hashes (SHA-256/MD5) are wrong even salted, and passwords are hashed, not encrypted.' },
      { q: 'What does current NIST guidance say about forced 90-day password changes?', o: ['Do them monthly instead', 'Avoid routine rotation; change only on compromise', 'Always required for compliance', 'Only for admins'], a: 1, e: 'Routine expiry leads to weaker, incrementing passwords. Modern guidance favours length, breach screening and MFA over scheduled rotation.' },
      { q: 'Hashing differs from encryption because…', o: ['Hashing is faster', 'Hashing is one-way with no key to reverse it', 'Encryption can\'t use a salt', 'They are the same thing'], a: 1, e: 'Encryption is reversible with a key; hashing is a one-way fingerprint. Passwords are hashed so there is no key that recovers them.' },
    ],
    related: ['concepts', 'mfa', 'webauthn', 'basic-auth'],
  });

  /* ---------------- HTTP Basic & Digest ---------------- */
  HS.add({
    id: 'basic-auth', group: 'core', short: 'HTTP Basic & Digest', icon: 'lock', port: 'HTTP',
    title: 'HTTP Basic & Digest Authentication',
    tagline: 'Authentication built straight into the HTTP protocol. Rarely the right choice for a modern user-facing app, but it shows up constantly in internal tools, scripts and APIs — and the 401/WWW-Authenticate handshake underpins everything else.',
    level: 'Beginner', kind: 'HTTP-native',
    spec: [['Defined in', 'RFC 7617 / 7616'], ['Carries', 'Authorization header'], ['Basic', 'base64(user:pass)'], ['Needs', 'TLS (for Basic)']],
    analogy: `<p>HTTP Basic is like writing your name and password on a sticky note and attaching it to <em>every</em> letter you send. Anyone who intercepts a letter reads both — so you must send it inside a sealed, opaque envelope (TLS). Digest is a cleverer version from before everyone had TLS: instead of the password, you send proof that you know it, computed against a one-time number the server gave you, so the password itself never rides along.</p>`,
    flow: {
      nodes: [
        { id: 'c', label: 'Client', sub: 'browser/curl', icon: 'browser', x: 100, y: 150 },
        { id: 's', label: 'Server', sub: 'protected site', icon: 'server', x: 440, y: 150 },
      ],
      order: ['c', 's'],
      normal: {
        name: 'The 401 challenge (Basic)', summary: 'The defining HTTP auth handshake: request with no credentials → 401 + WWW-Authenticate challenge → resend with an Authorization header.',
        steps: [
          { f: 'c', t: 's', k: 'req', l: 'GET /admin (no auth)', title: 'Request a protected resource', d: 'The client asks for a protected page without any credentials.', data: { 'GET': '/admin', 'Authorization': '(none)' } },
          { f: 's', t: 'c', k: 'res', l: '401 + WWW-Authenticate', title: 'Server challenges', d: 'The server refuses and names the scheme and <em>realm</em> it wants. This <code>WWW-Authenticate</code> header is what triggers the browser\'s username/password popup.', data: { status: '401 Unauthorized', 'WWW-Authenticate': 'Basic realm="Admin Area"' }, fail: '401 — authenticate, please' },
          { f: 'c', t: 's', k: 'req', l: 'GET /admin + Authorization', title: 'Resend with credentials', d: 'The client Base64-encodes <code>user:password</code> and puts it in the <code>Authorization</code> header. Base64 is encoding, not encryption — so this must be inside TLS.', data: { 'GET': '/admin', 'Authorization': 'Basic c2FraXRoYTpodW50ZXIy', note: 'decodes to sakitha:hunter2' }, enc: true, port: 'TLS 443' },
          { f: 's', t: 's', k: 'int', l: 'decode & verify', title: 'Server verifies', d: 'The server decodes the header, checks the credentials against its user store (ideally a salted hash compare), and if valid, serves the page.', data: { decoded: 'sakitha:hunter2', check: 'hash compare', result: 'valid' } },
          { f: 's', t: 'c', k: 'res', l: '200 OK + page', title: 'Access granted', d: 'The resource is returned. Crucially, the client must attach that same header on <em>every</em> subsequent request — Basic auth is stateless and has no session.', data: { status: '200 OK', note: 'client caches creds, resends every request' }, ok: 'Authenticated for this request' },
        ],
      },
      attack: {
        name: 'Basic without TLS', summary: 'Base64 is trivially reversible. Over plain HTTP, Basic auth hands the password to anyone on the network path.',
        steps: [
          { f: 'c', t: 's', k: 'req', l: 'GET /admin  Authorization: Basic …', title: 'Credentials over plain HTTP', d: 'A script hits an internal tool over <code>http://</code>, attaching the Basic header as usual.', data: { 'Authorization': 'Basic c2FraXRoYTpodW50ZXIy', channel: 'http:// — NOT encrypted' } },
          { f: 'c', t: 's', k: 'atk', l: 'passive sniff on the wire', title: 'Anyone on the path reads it', d: 'A party on the same network, a compromised router, or a rogue proxy captures the request. The "Basic" value is just Base64.', data: { captured: 'Basic c2FraXRoYTpodW50ZXIy', 'base64-decode': 'sakitha:hunter2' } },
          { f: 's', t: 's', k: 'int', l: 'decode → full password', title: 'Full password recovered', d: 'Base64 reverses in one step with no key — the attacker now has the reusable plaintext password, which is probably reused elsewhere too.', data: { recovered: 'sakitha:hunter2', reuse_risk: 'high' }, fail: 'Password disclosed — Basic REQUIRES TLS' },
        ],
      },
    },
    basics: `
      <p>HTTP has authentication built into the protocol itself, defined by two headers:</p>
      <ul>
        <li>Server → client: <code>WWW-Authenticate</code> on a <code>401</code> response, naming the scheme and a <em>realm</em> (a label for the protection space).</li>
        <li>Client → server: <code>Authorization</code> carrying the credentials, resent on every request.</li>
      </ul>
      <p><strong>Basic</strong> puts <code>base64(username:password)</code> in that header. Base64 is <em>encoding</em>, not encryption — it exists to make binary safe for headers, and it reverses with no key. So Basic is only acceptable inside TLS. It is dead simple, which is why scripts, internal dashboards, and machine-to-machine calls still use it.</p>
      <p><strong>Digest</strong> was designed so the password never travels even over plain HTTP. The server sends a random <em>nonce</em>; the client returns a hash of the username, password, nonce, HTTP method and URI. The server, knowing the password, recomputes the same hash. An eavesdropper sees only the hash, and the nonce stops simple replay.</p>`,
    deep: `
      <h3>Why Digest still loses to "Basic over TLS"</h3>
      <p>Digest sounds better — the password never crosses the wire — but it has crippling problems that make modern practice prefer plain Basic <em>wrapped in TLS</em>:</p>
      <ul>
        <li>To recompute the hash, the server must know the password or a password-equivalent, which <b>forces weak, often unsalted storage</b> (an MD5 of <code>user:realm:password</code>). That's worse than a properly salted hash.</li>
        <li>It historically used <b>MD5</b>, now broken for collision resistance.</li>
        <li>It's complex, with many optional modes that implementations get wrong, and it doesn't protect the response body at all.</li>
      </ul>
      <p>Once TLS is ubiquitous, the channel already provides confidentiality and integrity, so the elaborate Digest dance buys little. The industry consensus: <b>use Basic over TLS, or a token scheme — not Digest.</b></p>
      <h3>The realm and the browser popup</h3>
      <p>That native "Sign in" dialog your browser shows is driven purely by the <code>WWW-Authenticate</code> header and its <code>realm</code>. The browser caches the credentials per realm and resends them automatically for the rest of the session — there is no logout button, which is one reason Basic is awkward for human-facing apps (you often have to close the browser to "log out").</p>
      <h3>Statelessness</h3>
      <p>Basic/Digest keep <em>no server session</em>. Every request re-authenticates from scratch. That's elegant for APIs and scripts (nothing to store or expire) but means the credential is transmitted constantly, widening exposure, and there's no easy per-session revocation.</p>`,
    howto: `
      <p>You'll most often meet Basic auth from the client side, in scripts and health checks:</p>
      ${C('bash', `
        # curl builds the Authorization: Basic header for you
        curl -u sakitha:hunter2 https://internal.example.com/metrics

        # equivalently, by hand
        AUTH=$(printf 'sakitha:hunter2' | base64)
        curl -H "Authorization: Basic $AUTH" https://internal.example.com/metrics
      `, 'Calling a Basic-protected endpoint')}
      <div class="callout warn"><b>Never put credentials in the URL</b><code>https://user:pass@host/</code> still works in some tools but leaks the password into logs, browser history and the <code>Referer</code> header. Use the <code>Authorization</code> header instead, always over <code>https://</code>.</div>
      <p>On the server, prefer your framework's middleware, make sure TLS is enforced (redirect or reject plain HTTP), and store credentials as salted slow hashes — see <a href="#passwords">Passwords</a>. Use the API-key playground to see how the header looks beside other schemes.</p>`,
    tool: 'apikey',
    pros: ['Built into HTTP — no libraries, works everywhere', 'Stateless: nothing to store or expire server-side', 'Trivial for scripts, cron jobs and machine-to-machine calls', 'The 401/WWW-Authenticate pattern is the basis for other schemes'],
    cons: ['Basic sends reusable credentials on every request — TLS is mandatory', 'No real logout or session management in the browser', 'No built-in MFA, rate limiting or lockout', 'Digest forces weak server-side password storage and uses broken MD5', 'Credentials cached by the browser per realm, easy to forget they\'re live'],
    history: [
      ['1996', 'HTTP/1.0 (RFC 1945) defines Basic authentication.'],
      ['1997', 'RFC 2069 introduces Digest to avoid sending passwords in the clear on the pre-TLS web.'],
      ['1999', 'RFC 2617 refines Digest with qop (quality of protection) and client nonces.'],
      ['2015', 'RFCs 7616/7617 modernise both; Digest gains SHA-256, but adoption stays low.'],
      ['Today', 'Basic-over-TLS survives for internal and machine use; Digest is effectively legacy.'],
    ],
    hidden: [
      ['Base64 fools people constantly', 'Treating Base64 as "sort of encrypted" is a recurring real-world bug. It\'s a reversible encoding with no key. If you can read these words you can decode a Basic header.'],
      ['There\'s no logout', 'Because the browser caches realm credentials, Basic auth has no clean logout. Apps resort to tricks like returning 401 deliberately or changing the realm to force re-prompt.'],
      ['Proxy-Authenticate is the twin', 'The same handshake exists for proxies via <code>407 Proxy Authentication Required</code> and <code>Proxy-Authorization</code> — handy to know when debugging corporate proxies.'],
      ['Digest nonces are an early anti-replay design', 'Digest\'s server nonce + client nonce + request counter is a neat, pre-OAuth example of the challenge–response pattern you\'ll see again in Kerberos and WebAuthn.'],
    ],
    attacks: [
      ['Passive sniffing', 'On plain HTTP, Base64 credentials are read directly off the wire.', 'Mandatory TLS; reject or redirect any plain-HTTP request to protected paths.'],
      ['Credential replay', 'A captured Basic header works forever since it never changes.', 'TLS prevents capture; move to short-lived tokens if replay is a concern.'],
      ['Brute force', 'No built-in throttling, so attackers can hammer the endpoint.', 'Add rate limiting, backoff and lockout at the server or gateway.'],
      ['Downgrade to MD5 (Digest)', 'Force the weaker MD5 mode of Digest.', 'Disable legacy modes; prefer Basic-over-TLS or tokens.'],
    ],
    interview: [
      ['Is HTTP Basic authentication secure?', '<p>Only inside TLS. Basic sends <code>base64(user:password)</code>, which is reversible encoding, not encryption — over plain HTTP anyone on the path reads the password. Over HTTPS the channel protects it, and Basic becomes an acceptable, simple choice for internal tools and machine-to-machine calls, though it still lacks sessions, logout and MFA.</p>', 'junior'],
      ['Walk me through what happens when a browser hits a Basic-protected page.', '<p>The browser requests the page with no credentials; the server responds <code>401</code> with <code>WWW-Authenticate: Basic realm="…"</code>. That header makes the browser show its native login dialog. The browser then resends the request with <code>Authorization: Basic base64(user:pass)</code>, and caches it to resend automatically on every later request to that realm. The server decodes and verifies on each request — it\'s stateless, with no session.</p>', 'mid'],
      ['Why do we generally prefer "Basic over TLS" to Digest, even though Digest never sends the password?', '<p>Because Digest\'s advantage disappears once TLS is everywhere, and it carries real costs: to verify the hash the server must store a password-equivalent, forcing weak (often unsalted MD5) storage; it historically relies on broken MD5; and it\'s complex with error-prone optional modes that don\'t protect the body. TLS already gives confidentiality and integrity, so plain Basic inside it is simpler and lets you store properly salted hashes. Hence the consensus to avoid Digest.</p>', 'senior'],
    ],
    quiz: [
      { q: 'What does HTTP Basic put in the Authorization header?', o: ['An encrypted password', 'base64(username:password)', 'A signed JWT', 'A session cookie'], a: 1, e: 'Basic sends Base64-encoded user:password — reversible encoding, so it must travel inside TLS.' },
      { q: 'Which header triggers the browser\'s native login popup?', o: ['Authorization', 'Set-Cookie', 'WWW-Authenticate on a 401', 'Content-Type'], a: 2, e: 'The server\'s WWW-Authenticate header on a 401 response names the scheme/realm and makes the browser prompt.' },
      { q: 'Why is Digest usually avoided today despite never sending the password?', o: ['It is slower than TLS', 'It forces weak server-side password storage and uses MD5', 'Browsers don\'t support it', 'It requires a database'], a: 1, e: 'To recompute the hash the server must store a password-equivalent (often unsalted MD5), which is worse than a salted hash. TLS makes the elaborate dance unnecessary.' },
      { q: 'A key downside of Basic auth for human users is…', o: ['It can\'t use TLS', 'There is no clean logout and no session', 'It needs a hardware token', 'It only works in Chrome'], a: 1, e: 'The browser caches realm credentials and resends them; there\'s no real logout or session management built in.' },
    ],
    related: ['passwords', 'sessions', 'api-keys', 'tls'],
  });
})();
