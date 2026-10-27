/* Modern & MFA: MFA overview, TOTP/HOTP, WebAuthn/passkeys, magic links, HMAC signing */
(function () {
  'use strict';
  const HS = window.HS, C = window.C;

  /* ---------------- MFA ---------------- */
  HS.add({
    id: 'mfa', group: 'modern', short: 'MFA / 2FA', icon: 'phone',
    title: 'Multi-Factor Authentication',
    tagline: 'Requiring more than one kind of proof, so a stolen password alone is not enough. The single highest-impact control in everyday security — but not all second factors are equal, and knowing why phishing-resistant MFA matters is a strong interview signal.',
    level: 'Intermediate', kind: 'Layered authentication',
    spec: [['Combines', 'Different factor categories'], ['Factors', 'Know / have / are'], ['Strongest', 'Phishing-resistant (passkeys)'], ['Weakest', 'SMS codes']],
    analogy: `<p>A bank vault doesn't open with one control. It needs a key <em>and</em> a combination <em>and</em> a manager present — different <em>kinds</em> of safeguard, so defeating one isn't enough. MFA applies that to logins: even if a thief learns your password (one safeguard), they still lack your phone or your fingerprint (another kind). The trick is that the factors must be genuinely <em>different</em> — two keys to the same lock add nothing.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'User', sub: 'logging in', icon: 'user', x: 95, y: 150 },
        { id: 's', label: 'Server', sub: 'auth logic', icon: 'server', x: 340, y: 90 },
        { id: 'dev', label: 'Phone / key', sub: '2nd factor', icon: 'phone', x: 560, y: 150 },
      ],
      order: ['u', 's', 'dev'],
      normal: {
        name: 'Password + second factor', summary: 'The password proves "something you know"; a second, different factor proves "something you have", so a leaked password alone can\'t get in.',
        steps: [
          { f: 'u', t: 's', k: 'req', l: 'username + password', title: 'First factor (knowledge)', d: 'The user submits their password — "something you know". On its own, modern systems treat this as necessary but not sufficient.', data: { factor_1: 'password (something you know)', status: 'necessary, not sufficient' }, enc: true, port: 'TLS 443' },
          { f: 's', t: 's', k: 'int', l: 'password valid → demand 2nd factor', title: 'Server requires a second factor', d: 'The password checks out, but the server doesn\'t grant access yet. It challenges for a second factor from a <em>different category</em>.', data: { password: 'valid ✓', decision: 'require factor 2 (possession)' } },
          { f: 's', t: 'dev', k: 'req', l: 'challenge the possession factor', title: 'Challenge the second factor', d: 'The server triggers the possession factor — e.g. expects a TOTP code, sends a push, or asks the hardware key to sign a challenge.', data: { prompt: 'enter 6-digit code / approve push / tap key', factor_2: 'something you have' } },
          { f: 'dev', t: 's', k: 'res', l: 'proof of possession', title: 'User provides the second proof', d: 'The user supplies the code or approves on their device. The server verifies it. Only now, with two different factors satisfied, is the login complete.', data: { provided: 'valid TOTP / approved push / key signature', both_factors: 'know ✓ + have ✓' }, ok: 'Access granted — two factors satisfied' },
        ],
      },
      attack: {
        name: 'Phishing a one-time code', summary: 'Not all MFA stops phishing. A real-time relay proxy can forward an OTP; only phishing-resistant factors (passkeys) truly defeat it.',
        steps: [
          { f: 'u', t: 's', k: 'atk', l: 'user enters creds on fake site', title: 'Victim phished', d: 'The user is lured to a convincing fake login that sits in front of the real site (an adversary-in-the-middle proxy). They type their password.', data: { site: 'evil-proxy (looks real)', captured: 'password' } },
          { f: 's', t: 'dev', k: 'atk', l: 'real site demands OTP → relayed', title: 'OTP challenge relayed', d: 'The proxy forwards the password to the real site, which asks for the OTP. The proxy relays that prompt to the victim.', data: { real_site: 'asks for 6-digit code', proxy: 'relays prompt to victim' } },
          { f: 'u', t: 's', k: 'atk', l: 'victim types OTP → proxy forwards', title: 'The code is phishable', d: 'The victim enters the current TOTP/SMS code; the proxy immediately forwards it to the real site within its 30-second window. SMS and app codes don\'t bind to the site, so they\'re relayable.', data: { otp: 'valid for ~30s', proxy_action: 'forwards instantly', weakness: 'code not bound to the real origin' }, fail: 'OTP MFA can be phished via real-time relay' },
          { f: 's', t: 's', k: 'int', l: 'passkey binds to real origin → relay fails', title: 'Phishing-resistant MFA wins', d: 'A <a href="#webauthn">passkey/FIDO2</a> signs the <em>actual origin</em> the browser is on. On the phishing domain the signature is bound to the wrong origin, so the real site rejects it — the relay simply can\'t work.', data: { passkey: 'signs origin = evil-proxy', real_site_expects: 'its own origin → REJECT', result: 'relay impossible' }, ok: 'Passkeys defeat real-time phishing' },
        ],
      },
    },
    basics: `
      <p>Multi-factor authentication requires proof from <em>two or more different categories</em>. The categories (from the <a href="#concepts">concepts page</a>):</p>
      <ul>
        <li><b>Something you know</b> — password, PIN.</li>
        <li><b>Something you have</b> — phone, authenticator app, hardware security key.</li>
        <li><b>Something you are</b> — fingerprint, face, iris.</li>
      </ul>
      <p>The defining rule: the factors must come from <em>different</em> categories. A password plus a security question is <b>not</b> MFA — both are "something you know". A password plus a code from your phone <em>is</em>, because it adds "something you have". ("2FA" just means exactly two factors.)</p>
      <p>Why it matters so much: the overwhelming majority of account takeovers start with a stolen or reused password. Adding a second factor means a leaked password is no longer enough — which is why MFA is consistently cited as blocking the vast majority of automated and bulk attacks.</p>
      <div class="callout warn"><b>Not all MFA is equal</b>SMS codes are far weaker than a hardware passkey. The hierarchy, weakest to strongest: SMS → app-based TOTP → push with number-matching → phishing-resistant (FIDO2/passkeys). Saying "we have MFA" isn't the whole story; <em>which</em> factor matters enormously.</div>`,
    deep: `
      <h3>The second-factor hierarchy</h3>
      <ul>
        <li><b>SMS one-time codes</b> — better than nothing, but vulnerable to <b>SIM-swapping</b> (attacker ports your number), SS7 interception, and phishing relay. NIST discourages SMS for anything sensitive.</li>
        <li><b>TOTP apps</b> (Google Authenticator, Authy) — codes generated offline from a shared secret and the clock (<a href="#totp">TOTP page</a>). No SMS network to attack, but still <em>phishable</em>: a user can be tricked into typing the code into a fake site.</li>
        <li><b>Push notifications</b> — "approve this login?" Convenient, but prone to <b>MFA fatigue</b> (spamming prompts until someone taps approve). <b>Number-matching</b> (type the number shown on screen into the app) mitigates this.</li>
        <li><b>Phishing-resistant: FIDO2 / WebAuthn / passkeys</b> — the gold standard. The credential signs the real site's origin, so it <em>cannot</em> be relayed to a phishing page. See <a href="#webauthn">WebAuthn</a>.</li>
      </ul>
      <h3>Why "phishing-resistant" is the key phrase</h3>
      <p>Every code-based factor shares one flaw: the code isn't tied to <em>where</em> it's entered, so a real-time adversary-in-the-middle proxy can forward it. Phishing-resistant factors bind the proof to the exact origin cryptographically, breaking the relay. This is why major providers and governments are mandating FIDO2/passkeys for high-value access — it's a categorical improvement, not an incremental one.</p>
      <h3>Step-up and adaptive MFA</h3>
      <p>You don't have to prompt for a second factor on every action. <b>Step-up authentication</b> asks for it only when risk rises — a new device, a large transfer, accessing admin settings. <b>Adaptive/risk-based</b> MFA scores signals (location, device, behaviour) and challenges only anomalies, balancing security and friction. These appear constantly in system-design interviews.</p>
      <h3>Recovery is the soft underbelly</h3>
      <p>The hardest part of MFA isn't the happy path — it's account recovery. Backup codes, a second key, or a fallback factor are necessary, but each is also a bypass an attacker can target (social-engineering the help desk is a classic). A strong MFA design is only as strong as its weakest recovery path.</p>`,
    uses: [
      ['Consumer accounts', 'Email, banking and social apps offer (and increasingly require) a second factor.'],
      ['Enterprise SSO', 'MFA is enforced once at the IdP (see SSO) and covers every connected app.'],
      ['Admin & privileged access', 'Cloud consoles and servers require strong MFA, often hardware keys, for high-privilege actions.'],
      ['Step-up on risk', 'Payments, password changes and new-device logins trigger an extra challenge.'],
    ],
    howto: `
      <p>As a builder, prefer the strongest factor you can and design recovery carefully:</p>
      ${C('text', `
        Priority order for adding MFA:
        1. Support passkeys / FIDO2 (phishing-resistant) as the primary strong option.
        2. Offer TOTP authenticator apps as a widely-compatible fallback.
        3. Use push WITH number-matching; avoid plain "tap to approve".
        4. Treat SMS as a last resort, not the default; warn about SIM-swap risk.
        5. Issue backup codes; allow a second security key. Secure the recovery flow
           as strongly as login (it's the favourite bypass).
        6. Consider step-up: require the factor on risky actions, not every click.
      `, 'Designing MFA well')}
      <p>The TOTP playground shows a live rolling code; the <a href="#webauthn">WebAuthn</a> demo shows why a passkey can't be phished.</p>`,
    tool: 'totp',
    pros: ['Blocks the vast majority of password-based account takeovers', 'A leaked or reused password alone becomes insufficient', 'Phishing-resistant options (passkeys) defeat real-time phishing', 'Flexible: step-up and risk-based reduce friction', 'Standardised and widely supported'],
    cons: ['Weak factors (SMS) give false confidence — SIM-swap, relay', 'Adds user friction; can hurt adoption and support load', 'MFA fatigue attacks exploit push approvals', 'Recovery/backup paths are a common bypass', 'Lost devices can lock users out without good recovery'],
    history: [
      ['1986', 'Security Dynamics\' SecurID tokens (later RSA SecurID) popularise time-based one-time passwords for enterprises.'],
      ['2004–2011', 'The OATH initiative drives open OTP standards: HOTP (RFC 4226, 2005) and TOTP (RFC 6238, 2011).'],
      ['2011', 'High-profile breaches push consumer services toward 2FA.'],
      ['2016–2017', 'NIST\'s SP 800-63B drafts deprecate SMS as a second factor; the final version marks it "restricted".'],
      ['2013→2022', 'FIDO (U2F → FIDO2/WebAuthn) delivers phishing-resistant MFA; passkeys bring it mainstream.'],
    ],
    hidden: [
      ['Two passwords is not MFA', 'A password plus a "security question" is still one factor (knowledge). Interviewers use this to check you understand factors must be from <em>different</em> categories.'],
      ['SMS is the weakest common factor', 'SIM-swapping — social-engineering a carrier into moving your number to the attacker\'s SIM — defeats SMS 2FA entirely. NIST has discouraged it for years, yet it remains the most deployed.'],
      ['MFA fatigue is a human exploit', 'Attackers with a valid password spam push prompts at 3am until the tired user taps "approve". Number-matching (type the on-screen digits) turns a reflex tap into a deliberate action.'],
      ['Phishing-resistant is a category jump', 'The leap from TOTP to FIDO2 isn\'t incremental: codes can always be relayed, passkeys structurally cannot. That\'s why "phishing-resistant MFA" is the phrase regulators now use.'],
      ['Recovery is where MFA is actually broken', 'Most real MFA bypasses target the backup path — help-desk social engineering, weak backup codes, an SMS fallback on an otherwise-strong setup. Security equals the weakest enabled factor.'],
    ],
    attacks: [
      ['SIM swapping', 'Hijack the phone number to intercept SMS codes.', 'Avoid SMS; use app TOTP or passkeys; carrier port-out locks.'],
      ['Real-time phishing (AiTM)', 'Proxy relays the password and OTP to the real site live.', 'Phishing-resistant FIDO2/passkeys that bind to origin.'],
      ['MFA fatigue / push bombing', 'Spam approval prompts until the user accepts.', 'Number-matching, limit prompts, alert on repeated denials.'],
      ['Weak recovery bypass', 'Attack backup codes or help-desk recovery instead of login.', 'Harden recovery to login\'s level; verify identity rigorously; monitor.'],
      ['Malware/token theft', 'Steal session tokens or TOTP seeds from a compromised device.', 'Device security, hardware-bound keys, short sessions, token binding.'],
    ],
    interview: [
      ['Is a password plus a security question multi-factor authentication?', '<p>No. Both are "<b>something you know</b>", so they\'re the same factor category — defeating one (phishing, data breach) tends to defeat the other. True MFA combines <em>different</em> categories, e.g. a password (know) plus a phone or security key (have), or a biometric (are). The categories being distinct is the whole point.</p>', 'junior'],
      ['Why is SMS considered a weak second factor?', '<p>Because the number can be hijacked and the code can be relayed. <b>SIM-swapping</b> lets an attacker social-engineer a carrier into moving your number to their SIM, intercepting all codes; SS7 network weaknesses allow interception; and like any code, it can be phished through a real-time proxy. It still beats no MFA, but NIST discourages it for sensitive accounts in favour of app-based TOTP or, better, passkeys.</p>', 'mid'],
      ['What does "phishing-resistant MFA" mean and why does it matter?', '<p>It means the authentication proof is cryptographically bound to the <b>real site\'s origin</b>, so it can\'t be forwarded to a fake one. Code-based factors (SMS, TOTP, push) share a fatal flaw: the code isn\'t tied to where it\'s entered, so an adversary-in-the-middle proxy relays it in real time. <b>FIDO2/WebAuthn passkeys</b> sign the actual origin the browser is on, so on a phishing domain the signature is for the wrong origin and the real server rejects it. That\'s a categorical defeat of phishing, not an incremental improvement — hence the regulatory push toward it.</p>', 'senior'],
      ['How would you reduce MFA friction without weakening security?', '<p>Use <b>risk-based / step-up</b> authentication: don\'t prompt on every action, prompt when risk rises — a new device or location, a sensitive action (password change, large transfer, admin access), or anomalous behaviour. Score signals (device, geo, velocity) and challenge only outliers, while keeping a strong factor (passkey) for the challenges that do fire. Also remember session length and device trust: a long-lived trusted device needs fewer prompts than a fresh browser.</p>', 'senior'],
      ['What is an MFA fatigue attack and how do you stop it?', '<p>An attacker who already has the password repeatedly triggers push "approve login?" prompts, betting the user eventually taps approve out of annoyance or confusion (often late at night). Defences: <b>number-matching</b> (the user must type a number shown on the login screen into the app, turning a reflex into a deliberate step), rate-limiting and capping prompts, alerting/locking after repeated denials, and ultimately moving to passkeys where there\'s no approvable prompt to spam.</p>', 'mid'],
    ],
    quiz: [
      { q: 'Which combination is genuine multi-factor authentication?', o: ['Password + PIN', 'Password + security question', 'Password + hardware security key', 'Two different passwords'], a: 2, e: 'A password (know) + hardware key (have) spans two categories. PINs and security questions are both "know", so they don\'t count.' },
      { q: 'The strongest, phishing-resistant form of MFA is…', o: ['SMS codes', 'TOTP apps', 'FIDO2 / passkeys', 'Email codes'], a: 2, e: 'Passkeys sign the real origin, so a relay to a phishing site fails. Codes of any kind can be relayed in real time.' },
      { q: 'Why can a real-time phishing proxy defeat TOTP but not a passkey?', o: ['TOTP codes never expire', 'TOTP codes aren\'t bound to the site, so they can be forwarded; passkeys sign the origin', 'Passkeys are longer', 'TOTP uses SMS'], a: 1, e: 'A TOTP code is just digits with no notion of where it\'s typed, so a proxy relays it. A passkey\'s signature is bound to the actual origin, breaking the relay.' },
      { q: 'An MFA fatigue attack is best mitigated by…', o: ['Longer passwords', 'Number-matching on push approvals', 'Disabling MFA', 'Using SMS'], a: 1, e: 'Number-matching forces a deliberate action (type the shown digits) instead of a reflexive tap, defeating prompt-spamming.' },
    ],
    related: ['totp', 'webauthn', 'passwords', 'sso'],
  });

  /* ---------------- TOTP / HOTP ---------------- */
  HS.add({
    id: 'totp', group: 'modern', short: 'TOTP / HOTP', icon: 'phone',
    title: 'TOTP & HOTP (Authenticator Codes)',
    tagline: 'The 6-digit codes in Google Authenticator. A beautiful use of HMAC and a shared clock to produce the same one-time number on two devices with no network between them. Simple enough to implement from scratch — and we do, in the playground.',
    level: 'Intermediate', kind: 'One-time passwords',
    spec: [['Standards', 'HOTP RFC 4226, TOTP RFC 6238'], ['Basis', 'HMAC of a counter'], ['TOTP counter', 'Current 30-second window'], ['Seed sharing', 'QR / Base32 secret']],
    analogy: `<p>Imagine you and a friend own identical code-wheel toys and set them to the same secret pattern. Every 30 seconds the wheel shows a new number — and because the toys are identical and started the same way, you both see the <em>same</em> number at the same moment, without ever speaking. To prove you're really you, you just read off the current number. That's TOTP: a shared secret plus the shared clock generates matching codes on your phone and the server.</p>`,
    flow: {
      nodes: [
        { id: 'ph', label: 'Phone', sub: 'authenticator', icon: 'phone', x: 95, y: 150 },
        { id: 'u', label: 'You', sub: 'login form', icon: 'user', x: 330, y: 150 },
        { id: 's', label: 'Server', sub: 'same secret', icon: 'server', x: 565, y: 150 },
      ],
      order: ['ph', 'u', 's'],
      normal: {
        name: 'Enrolment then login', summary: 'Setup shares one secret (via QR). Afterward, phone and server independently compute HMAC(secret, current 30s window) and take 6 digits — matching with no messages exchanged.',
        steps: [
          { f: 's', t: 'ph', k: 'res', l: 'enrol: QR encodes the shared secret', title: 'One-time secret sharing', d: 'At setup the server generates a random secret and shows it as a QR code; your authenticator app scans and stores it. This is the <em>only</em> moment the secret is transmitted.', data: { secret: 'JBSWY3DPEHPK3PXP (Base32)', delivery: 'QR code, scanned once', stored: 'on phone AND server' } },
          { f: 'ph', t: 'ph', k: 'int', l: 'code = HMAC(secret, time/30)', title: 'Phone computes a code', d: 'Every 30 seconds the app computes <code>HMAC-SHA1(secret, floor(unixtime/30))</code> and extracts 6 digits — entirely offline. No signal needed; it works on a plane.', data: { counter: 'floor(now/30)', hmac: 'HMAC-SHA1(secret, counter)', truncate: '→ 6 digits', network: 'none' } },
          { f: 'u', t: 's', k: 'req', l: 'password + 6-digit code', title: 'You submit the current code', d: 'At login you enter your password plus whatever 6 digits the app currently shows.', data: { factor_1: 'password', factor_2: 'e.g. 492013 (TOTP)' }, enc: true, port: 'TLS 443' },
          { f: 's', t: 's', k: 'int', l: 'server computes the same code', title: 'Server independently recomputes', d: 'The server does the identical HMAC with its stored copy of the secret and the current window, and compares. It also checks the previous window to tolerate clock drift.', data: { server_code: 'HMAC(secret, floor(now/30)) → 492013', match: 'true', drift: 'also accepts previous 30s window' }, ok: 'Codes match → authenticated' },
        ],
      },
      attack: {
        name: 'Codes are phishable + seed theft', summary: 'TOTP resists network interception but not a user typing the code into a fake site, nor theft of the shared seed. Those limits are exactly why passkeys exist.',
        steps: [
          { f: 'u', t: 's', k: 'atk', l: 'user types code into phishing site', title: 'Real-time phishing', d: 'A TOTP code is just 6 digits with no idea <em>where</em> it\'s entered. A fake login page relays the password and the freshly-typed code to the real site inside the 30-second window.', data: { entered_on: 'fake site', relayed: 'to real site in <30s', weakness: 'code not bound to origin' }, fail: 'TOTP can be relayed to the real site' },
          { f: 'ph', t: 'ph', k: 'atk', l: 'shared secret can be stolen/duplicated', title: 'Seed theft', d: 'Because the <em>same</em> secret sits on both phone and server, malware on either side (or a breached server storing seeds in plaintext) can clone it and generate codes forever.', data: { risk: 'secret on phone AND server', if_stolen: 'attacker generates valid codes indefinitely', server_store: 'must be encrypted at rest' } },
          { f: 's', t: 's', k: 'int', l: 'mitigations: rate-limit, encrypt seeds', title: 'Partial mitigations', d: 'Limit code attempts (brute-forcing 6 digits), store seeds encrypted (ideally in an HSM), and keep the drift window tight. These harden TOTP but can\'t fix the phishability.', data: { 'rate limit': 'few attempts per code', storage: 'seeds encrypted / HSM', window: 'minimal drift tolerance' } },
          { f: 's', t: 's', k: 'int', l: 'real fix: move to passkeys', title: 'The categorical fix', d: 'TOTP\'s phishability is inherent to shared-secret codes. The structural fix is <a href="#webauthn">WebAuthn/passkeys</a>, where the proof is bound to the origin and nothing reusable is shared. TOTP remains a solid, widely-compatible fallback.', data: { limitation: 'phishable by design', upgrade: 'FIDO2/passkeys bind to origin', role: 'TOTP = good fallback, not the ceiling' }, ok: 'Understand TOTP\'s ceiling → passkeys above it' },
        ],
      },
    },
    basics: `
      <p>HOTP and TOTP are algorithms for generating <strong>one-time passwords</strong> — short codes valid only briefly or once. Both are built on <b>HMAC</b> (a keyed hash; see <a href="#hmac-sig">HMAC signing</a>) of a counter, using a secret shared between your device and the server.</p>
      <ul>
        <li><b>HOTP (HMAC-based OTP, RFC 4226)</b> — the counter is an <em>event counter</em> that increments each time you generate a code. Phone and server must stay in sync on the count.</li>
        <li><b>TOTP (Time-based OTP, RFC 6238)</b> — the counter is simply the <em>current time</em> divided into 30-second windows. No event sync needed; both sides just need a roughly correct clock. This is what nearly every authenticator app uses.</li>
      </ul>
      <p>The elegant part: after a one-time secret exchange (usually a QR code at setup), <b>no messages are ever exchanged to produce a code</b>. Both sides compute <code>truncate(HMAC(secret, counter))</code> and get the same 6 digits. That's why your authenticator works with no signal.</p>
      <p>Build the exact computation and watch the code roll over in the playground below.</p>`,
    deep: `
      <h3>How 6 digits come out of a hash</h3>
      <p>The HMAC output is 20 bytes. "Dynamic truncation" uses the last nibble as an offset to pick 4 bytes from the hash, masks off the top bit (to avoid sign issues), and takes that number modulo 10⁶ to get 6 digits. It's deterministic, so the same secret and counter always yield the same code — which is the whole point.</p>
      <h3>Why TOTP beat HOTP in practice</h3>
      <p>HOTP's event counter drifts: press the button on your token a few times without logging in, and the counter on your side runs ahead of the server's, causing failures until a resync. TOTP sidesteps this by using time, which both sides share for free. The cost is needing clocks within tolerance — servers typically accept the current and adjacent windows (±1 step) to absorb drift and the user typing the code as it rolls over.</p>
      <h3>The two inherent weaknesses</h3>
      <ul>
        <li><b>Phishable.</b> A code carries no information about <em>where</em> it's entered, so a real-time proxy relays it. This is the ceiling TOTP can't pass, and the reason the industry is moving to passkeys.</li>
        <li><b>Shared secret.</b> The same seed lives on both the device and the server. A server that stores seeds in plaintext turns a breach into permanent code generation for every user, so seeds must be encrypted at rest (ideally in an HSM). Malware on the phone can likewise exfiltrate the seed.</li>
      </ul>
      <h3>Good hygiene</h3>
      <p>Rate-limit verification (only a handful of guesses per code — otherwise 6 digits is brute-forceable), keep the drift window tight, encrypt stored seeds, and provide backup codes for lost devices. TOTP remains an excellent, phishing-aware <em>fallback</em> and a huge upgrade over SMS — just not the strongest option available.</p>`,
    howto: `
      <p>The server generates a secret, shows a QR (an <code>otpauth://</code> URI), and later verifies codes:</p>
      ${C('python', `
        import pyotp
        # enrolment: create and store a secret, show it as a QR
        secret = pyotp.random_base32()                      # store encrypted!
        uri = pyotp.TOTP(secret).provisioning_uri(
            name="sakitha@company.com", issuer_name="MyApp")  # -> QR code

        # verification at login
        totp = pyotp.TOTP(secret)
        ok = totp.verify(submitted_code, valid_window=1)      # ±1 step for drift
      `, 'Server-side TOTP with a library')}
      <ul>
        <li>Store the secret encrypted (HSM/KMS), never plaintext.</li>
        <li>Rate-limit code attempts; 6 digits falls fast to unthrottled guessing.</li>
        <li>Offer backup codes and a second enrolment for device loss.</li>
        <li>Prefer passkeys where you can; keep TOTP as a compatible fallback over SMS.</li>
      </ul>`,
    tool: 'totp',
    pros: ['Works fully offline — no SMS network or signal needed', 'Free, open standard; dozens of compatible apps', 'Far stronger than SMS (no SIM-swap, no interception)', 'Simple to implement and understand', 'No per-use cost to the service'],
    cons: ['Phishable — a user can type the code into a fake site', 'Shared secret lives on both sides; seed theft = lasting compromise', '6 digits need rate-limiting to resist brute force', 'Clock drift can cause failures; needs a tolerance window', 'Device loss locks users out without backup codes'],
    history: [
      ['2005', 'OATH publishes HOTP (RFC 4226), an open event-based OTP.'],
      ['2010', 'Google Authenticator (released September 2010) popularises app-based OTP for consumers.'],
      ['2011', 'TOTP standardised (RFC 6238), making time the counter — the now-ubiquitous form.'],
      ['2013→', 'TOTP becomes the default "authenticator app" 2FA across the web.'],
      ['2020s', 'Passkeys begin displacing TOTP for phishing resistance, but TOTP persists as a fallback.'],
    ],
    hidden: [
      ['No network is used to make a code', 'A surprise to many: generating a TOTP involves zero communication. Phone and server independently compute the same HMAC from the shared secret and clock — which is why it works in airplane mode.'],
      ['It\'s just HMAC of the time', 'TOTP is HOTP with the counter set to floor(unixtime/30). Understanding that one substitution demystifies the whole thing — and you can implement it in a dozen lines.'],
      ['Servers accept more than one code', 'To tolerate clock skew and the user typing as it changes, servers usually accept the previous window too. That slightly widens the valid period — a deliberate usability/security trade-off.'],
      ['Plaintext seed storage is a time bomb', 'If a service stores TOTP seeds unencrypted and gets breached, attackers can generate valid codes for every user forever. Seeds deserve the same protection as private keys.'],
    ],
    attacks: [
      ['Real-time phishing', 'User enters the code on a fake site that relays it live.', 'Move to phishing-resistant passkeys; user vigilance; short windows.'],
      ['Seed theft (server or device)', 'Steal the shared secret to generate codes indefinitely.', 'Encrypt seeds at rest (HSM/KMS); device security; re-enrol on suspicion.'],
      ['Brute force', 'Guess the 6-digit code without throttling.', 'Strict rate-limiting and lockout on repeated failures.'],
      ['Clock-skew exploitation / wide windows', 'Overly generous drift windows extend a code\'s validity.', 'Keep the tolerance minimal (±1 step); sync server time via NTP.'],
    ],
    interview: [
      ['How does a TOTP code end up the same on your phone and the server without any network between them?', '<p>Both sides share a secret (exchanged once at enrolment via QR) and both read the same clock. Each independently computes <code>HMAC-SHA1(secret, floor(unixtime/30))</code> and truncates it to 6 digits. Because the inputs are identical, the outputs match — no messages are exchanged to generate the code, which is why it works offline. The server just recomputes and compares at login, allowing an adjacent window for clock drift.</p>', 'mid'],
      ['What\'s the difference between HOTP and TOTP?', '<p>Both HMAC a counter with a shared secret; they differ in the counter. <b>HOTP</b> uses an <em>event counter</em> that increments per code, so the device and server must stay in sync on the count (it can drift if you generate codes without using them). <b>TOTP</b> uses the <em>current time window</em> (e.g. floor(unixtime/30)) as the counter, which both sides share automatically — no event sync, just roughly aligned clocks. TOTP\'s convenience is why authenticator apps use it.</p>', 'mid'],
      ['What are TOTP\'s security limitations and what addresses them?', '<p>Two inherent ones. First, codes are <b>phishable</b>: a code carries no binding to the site it\'s entered on, so a real-time adversary-in-the-middle proxy forwards it to the real server — the limitation passkeys fix by signing the origin. Second, it\'s a <b>shared secret</b>: the same seed sits on device and server, so a plaintext-seed breach or phone malware yields permanent code generation; mitigate by encrypting seeds (HSM), rate-limiting, and tight drift windows. TOTP is a strong SMS replacement and good fallback, but FIDO2/passkeys are the ceiling above it.</p>', 'senior'],
      ['Why does the server often accept more than the single current code?', '<p>To absorb <b>clock skew</b> between the device and server and the case where the user reads a code just as it rolls over. Servers typically accept the current window plus one adjacent step (±30s). It\'s a deliberate usability trade-off — too wide a window lengthens how long each code is valid, so you keep the tolerance minimal and keep server time synced via NTP.</p>', 'senior'],
    ],
    quiz: [
      { q: 'A TOTP code is computed from…', o: ['A random server message each time', 'HMAC of a shared secret and the current time window', 'The user\'s password hash', 'An SMS the server sends'], a: 1, e: 'TOTP = truncate(HMAC(secret, floor(time/30))). Both sides compute it independently — no message is exchanged to make the code.' },
      { q: 'The main difference between HOTP and TOTP is…', o: ['HOTP is encrypted', 'The counter: an event count (HOTP) vs the current time (TOTP)', 'TOTP needs the internet', 'HOTP uses SMS'], a: 1, e: 'Both HMAC a counter; HOTP increments per event (can drift), TOTP uses time windows so both sides share the counter automatically.' },
      { q: 'Why is TOTP still phishable?', o: ['The code is too short', 'The code isn\'t bound to the site, so it can be relayed to the real server', 'It uses MD5', 'It expires too slowly'], a: 1, e: 'A code is just digits with no notion of origin, so a real-time proxy forwards it. Passkeys fix this by signing the origin.' },
      { q: 'Why must TOTP seeds be stored encrypted on the server?', o: ['To make codes longer', 'A breach of plaintext seeds lets attackers generate valid codes forever', 'To speed up HMAC', 'To avoid clock drift'], a: 1, e: 'The same secret generates all future codes, so a leaked plaintext seed is a permanent compromise. Encrypt seeds like private keys.' },
    ],
    related: ['mfa', 'webauthn', 'hmac-sig', 'passwords'],
  });

  /* ---------------- WebAuthn / Passkeys ---------------- */
  HS.add({
    id: 'webauthn', group: 'modern', short: 'WebAuthn / Passkeys', icon: 'key',
    title: 'WebAuthn & Passkeys (FIDO2)',
    tagline: 'The passwordless future, shipping now. Public-key login built into browsers and phones, where the secret never leaves your device and the login is bound to the real site — making it structurally impossible to phish. The single most important modern auth topic.',
    level: 'Advanced', kind: 'Passwordless / phishing-resistant',
    spec: [['Standards', 'W3C WebAuthn + FIDO2 CTAP'], ['Secret', 'Private key never leaves device'], ['Bound to', 'The site\'s origin (RP ID)'], ['Phishing', 'Structurally resistant']],
    analogy: `<p>A passkey is a wax seal that only <em>you</em> can stamp, and that automatically embosses the name of the building you're actually standing in. When the real bank asks you to seal a document, your stamp works. When a forger lures you to a fake bank with the same façade, your stamp embosses the <em>forger's</em> address — and the real bank rejects it because the address is wrong. You never hand over the stamp, and it can't be fooled into sealing for the wrong place. That origin-binding is why passkeys can't be phished.</p>`,
    flow: {
      nodes: [
        { id: 'auth', label: 'Authenticator', sub: 'phone / key', icon: 'key', x: 95, y: 150 },
        { id: 'b', label: 'Browser', sub: 'checks origin', icon: 'browser', x: 335, y: 150 },
        { id: 's', label: 'Server (RP)', sub: 'stores public key', icon: 'server', x: 565, y: 150 },
      ],
      order: ['auth', 'b', 's'],
      normal: {
        name: 'Register, then sign in', summary: 'Registration stores your public key on the server; the private key never leaves your device. Login proves possession by signing a challenge together with the real origin.',
        steps: [
          { f: 's', t: 'b', k: 'res', l: 'register: challenge + rpId', title: 'Registration begins', d: 'When you create a passkey, the server sends a challenge and its identity (the <code>rpId</code>, e.g. <code>bank.com</code>).', data: { challenge: 'random bytes', rpId: 'bank.com', user: 'sakitha' } },
          { f: 'b', t: 'auth', k: 'req', l: 'make credential (biometric unlock)', title: 'Device generates a key pair', d: 'Your authenticator (phone secure element, laptop TPM, or a hardware key), after a local biometric/PIN, generates a <em>new key pair just for this site</em>. The private key stays locked in hardware.', data: { generated: 'new key pair for bank.com', private_key: 'stays in secure hardware — never exported', user_gesture: 'Face/Touch/PIN' } },
          { f: 'auth', t: 's', k: 'res', l: 'send PUBLIC key only', title: 'Server stores the public key', d: 'Only the <b>public</b> key goes to the server, bound to your account. There is no shared secret and nothing phishable to store — a server breach leaks public keys, which are useless to an attacker.', data: { stored_on_server: 'PUBLIC key only', shared_secret: 'none', breach_value: 'public keys are not sensitive' }, ok: 'Passkey registered' },
          { f: 's', t: 'b', k: 'res', l: 'login: challenge', title: 'Login challenge', d: 'To sign in, the server sends a fresh random challenge. The browser supplies the <em>real</em> origin it\'s connected to — the user can\'t override this.', data: { challenge: 'fresh random bytes', origin: 'https://bank.com (set by browser)' } },
          { f: 'b', t: 'auth', k: 'req', l: 'sign {challenge, origin}', title: 'Device signs challenge + origin', d: 'After a local gesture, the authenticator signs the challenge <em>together with the origin the browser reports</em>, using the private key. The origin is baked into what gets signed.', data: { signs: '{ challenge, origin=bank.com }', with: 'private key (never leaves device)', gesture: 'biometric/PIN' }, enc: true },
          { f: 'auth', t: 's', k: 'res', l: 'signature → verify with public key', title: 'Server verifies', d: 'The server verifies the signature with the stored public key and checks the origin matches its own. Valid → logged in. No password, no code, nothing reusable ever transmitted.', data: { verify: 'signature valid (public key) ✓', origin_check: 'bank.com == expected ✓', transmitted_secret: 'none' }, ok: 'Signed in — passwordless' },
        ],
      },
      attack: {
        name: 'Why phishing simply fails', summary: 'Every passkey is scoped to one site. The browser checks the real address before the authenticator is even asked, and the server checks the origin inside the signed data. The relay that beats passwords and OTP codes has nothing to work with.',
        steps: [
          { f: 'b', t: 'b', k: 'atk', l: 'user lured to bank-secure.com', title: 'Victim on a look-alike site', d: 'A phishing page on <code>bank-secure.com</code> imitates the bank and tries the relay trick that works against passwords and OTP codes.', data: { page: 'https://bank-secure.com', wants: 'a login it can replay at bank.com' } },
          { f: 'b', t: 'b', k: 'int', l: 'browser: bank.com passkey not allowed here', title: 'The browser refuses', d: 'The user\'s passkey is scoped to the RP ID <code>bank.com</code>. The browser compares that with the page\'s real address, <code>bank-secure.com</code>, which is neither bank.com nor a subdomain of it, so it refuses the request. The page can\'t fake its own address and the user can\'t override the check.', data: { rp_id: 'bank.com', page_origin: 'https://bank-secure.com', result: 'request refused before the authenticator is asked' } },
          { f: 'b', t: 'auth', k: 'int', l: 'nothing to sign', title: 'Authenticator never involved', d: 'Because the browser refused, the authenticator is never asked and signs nothing. There is no code to type and no shared secret to steal, so the user has nothing to hand over even if fully fooled.', data: { signature: 'none produced', shared_secret: 'does not exist' } },
          { f: 's', t: 's', k: 'int', l: 'second layer: server checks origin', title: 'Defence in depth at the server', d: 'Even a response produced some other way would carry the wrong origin in its signed client data and the wrong RP ID hash. The real server compares both with its own values and rejects any mismatch.', data: { expected_origin: 'https://bank.com', expected_rp_id_hash: 'SHA-256("bank.com")', mismatch: 'reject' }, ok: 'Phishing fails by construction' },
        ],
      },
    },
    basics: `
      <p>WebAuthn (a W3C browser API) plus FIDO2/CTAP (how browsers talk to authenticators) let you log in with <strong>public-key cryptography</strong> instead of a password. A <b>passkey</b> is the user-friendly name for a FIDO2 credential — a key pair where:</p>
      <ul>
        <li>The <b>private key</b> never leaves your device's secure hardware (phone secure enclave, laptop TPM, or a hardware security key). It's unlocked by a local gesture — Face ID, Touch ID, Windows Hello, or a PIN.</li>
        <li>The <b>public key</b> is stored by the website. That's all the server keeps — there's no shared secret and nothing worth stealing in a breach.</li>
      </ul>
      <p>You've met this model already in <a href="#ssh">SSH keys</a> and <a href="#tls">TLS</a>; WebAuthn brings it to web login with two superpowers: the key is <b>bound to the site's origin</b>, and the private key is <b>non-exportable hardware-backed</b>.</p>
      <div class="callout ok"><b>Why this is a big deal</b>Passwords can be guessed, reused, breached and phished. TOTP codes can be phished via relay. Passkeys remove the password entirely <em>and</em> are <b>phishing-resistant by construction</b> — the single biggest security upgrade most users can make.</div>
      <p>See exactly why phishing fails in the origin-binding playground below.</p>`,
    deep: `
      <h3>The origin binding — the whole game</h3>
      <p>Every code-based factor shares a fatal flaw: the proof isn't tied to <em>where</em> it's used, so a proxy relays it. WebAuthn fixes this at the root. When you sign in, the authenticator signs the challenge <em>plus the origin the browser is connected to</em> — and the <b>browser</b> supplies that origin; neither the user nor a malicious page can forge it. Each credential is scoped to an RP ID such as <code>bank.com</code>, and the browser will only use it on <code>bank.com</code> or its subdomains. On a look-alike domain the browser refuses the request outright, so nothing is signed. As a second layer, the server checks the origin and RP ID hash inside the signed data. There is simply nothing to relay. That's what "phishing-resistant" means concretely.</p>
      <h3>Passkeys: device-bound vs synced</h3>
      <ul>
        <li><b>Device-bound</b> (original FIDO2, hardware keys like YubiKey) — the private key never leaves one device. Maximum security; lose the device and you need a backup registered.</li>
        <li><b>Synced passkeys</b> (the mainstream 2022+ model) — the private key is end-to-end encrypted and synced across your devices via your platform keychain (Apple, Google, Microsoft). This solved the adoption-killing problem of "what if I lose my only key?" at a small, debated trade-off: your cloud account's security now backs your passkeys.</li>
      </ul>
      <h3>Attestation and discoverable credentials</h3>
      <ul>
        <li><b>Attestation</b> lets the authenticator optionally prove <em>what kind</em> of device it is (e.g. a certified hardware key), which enterprises use to require specific authenticators. Consumer flows often skip it for privacy.</li>
        <li><b>Discoverable credentials (resident keys)</b> store enough on the authenticator to enable truly usernameless login — you just pick an account and authenticate.</li>
      </ul>
      <h3>WebAuthn as a second factor vs passwordless</h3>
      <p>WebAuthn can be a phishing-resistant <em>second factor</em> (password + security key) or the <em>sole</em> factor (passwordless passkey, where the local biometric/PIN provides a second factor on-device: something you have — the device — plus something you are/know — the gesture). The direction of travel is full passwordless.</p>
      <h3>Why it took so long</h3>
      <p>The cryptography is decades old; the blocker was always usability and recovery. Synced passkeys and OS-level support (2022–2023) finally made passwordless practical for ordinary users, which is why this is the hot topic now.</p>`,
    howto: `
      <p>You call the browser API (or a library/provider that wraps it). The essentials:</p>
      ${C('javascript', `
        // Registration (simplified) — browser + authenticator create the key pair
        const cred = await navigator.credentials.create({
          publicKey: {
            challenge, rp: { id: "bank.com", name: "Bank" },
            user: { id, name: "sakitha", displayName: "Sakitha" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
            authenticatorSelection: { userVerification: "required" }
          }
        });
        // send cred.response.publicKey to the server to store

        // Login — authenticator signs {challenge, origin}; server verifies
        const assertion = await navigator.credentials.get({
          publicKey: { challenge, rpId: "bank.com", userVerification: "required" }
        });
        // server verifies signature with the stored public key AND checks origin == bank.com
      `, 'WebAuthn in the browser')}
      <ul>
        <li>Use a maintained server library to verify signatures, origin, challenge and sign-count.</li>
        <li>Let users register <b>more than one</b> passkey (e.g. phone + hardware key) for recovery.</li>
        <li>Offer passkeys as the strong default; keep a fallback during the transition.</li>
      </ul>`,
    tool: 'webauthn',
    pros: ['Phishing-resistant by construction — origin is signed, not typed', 'No password to reuse, guess, breach or forget', 'Private key never leaves secure hardware; server stores only public keys', 'A server breach leaks nothing reusable', 'Fast, smooth UX via biometrics; synced passkeys solve device loss'],
    cons: ['Account recovery / lost-device flows still need careful design', 'Synced passkeys tie security to your cloud account', 'Enterprise attestation and policy add complexity', 'Legacy systems and some browsers lag; needs a fallback', 'User mental model ("where is my passkey?") is still maturing'],
    history: [
      ['2013', 'FIDO Alliance forms to kill the password; U2F security keys follow.'],
      ['2018', 'WebAuthn becomes a W3C candidate standard; FIDO2 pairs it with CTAP.'],
      ['2019', 'WebAuthn reaches W3C Recommendation; browsers ship support.'],
      ['2022', 'Apple, Google and Microsoft announce synced <b>passkeys</b>, solving device-loss and driving mainstream adoption.'],
      ['2023→', 'Major consumer and enterprise services roll out passwordless passkey login.'],
    ],
    hidden: [
      ['The browser, not the user, asserts the origin', 'This is the crux: because the browser supplies the origin that gets signed, a phishing page literally cannot make your authenticator claim the real site. No amount of user mistake relays the login. It\'s security that doesn\'t depend on the human spotting the fake.'],
      ['A server breach leaks only public keys', 'Unlike password hashes or TOTP seeds, what the server stores (public keys) is useless to an attacker. There\'s genuinely nothing sensitive to steal from the authentication store.'],
      ['Synced passkeys were the adoption unlock', 'The technology worked for years; what changed in 2022 was syncing private keys (E2E-encrypted) across your devices, so losing your phone no longer locks you out. That single UX fix is why passkeys suddenly went mainstream.'],
      ['Passwordless is still "multi-factor" on-device', 'A passkey login looks like one step, but it combines something you <em>have</em> (the device holding the key) with something you <em>are</em> or <em>know</em> (the biometric/PIN that unlocks it) — satisfying MFA locally without a second prompt.'],
      ['It\'s the same crypto as SSH and TLS', 'Passkeys aren\'t exotic — they\'re the public-key challenge-response you already met in SSH and TLS client certs, finally wrapped in a browser API with great UX.'],
    ],
    attacks: [
      ['Phishing / AiTM relay', 'Relay a login through a fake site (defeats passwords and OTP).', 'Fails by construction — the signed origin won\'t match the real server.'],
      ['Server credential breach', 'Steal the stored authentication data.', 'Only public keys are stored; they\'re not sensitive or reusable.'],
      ['Lost/stolen device', 'Attacker gets physical access to an authenticator.', 'Local biometric/PIN gates use; register backups; remote-revoke the credential.'],
      ['Cloud account compromise (synced passkeys)', 'Breach the platform account that syncs keys.', 'Strong protection on the cloud account (itself a passkey), device-bound keys for highest assurance.'],
      ['Downgrade to weaker fallback', 'Force the user back to password/OTP during transition.', 'Phase out weak fallbacks; require phishing-resistant factors for sensitive actions.'],
    ],
    interview: [
      ['Why are passkeys considered phishing-resistant when TOTP isn\'t?', '<p>Because the authentication is <b>bound to the origin</b>, and the <em>browser</em> — not the user — supplies that origin to be signed. A passkey is scoped to <code>bank.com</code>, so on a look-alike domain the browser won\'t even offer it — nothing gets signed — and the server separately checks the origin recorded in the signed data. A TOTP code, by contrast, is just digits with no notion of where it\'s entered, so an adversary-in-the-middle proxy relays it. Passkeys remove the relay by construction, so the user can\'t be tricked into authenticating to the wrong site.</p>', 'mid'],
      ['What does the server store for a passkey, and why is a breach less dangerous?', '<p>Only the user\'s <b>public key</b> (plus metadata like a sign counter). There\'s no password hash and no shared secret. A public key is useless to an attacker — they can\'t derive the private key or forge signatures with it — so breaching the authentication store leaks nothing reusable. That\'s a fundamental improvement over password hashes (crackable) and TOTP seeds (directly reusable).</p>', 'mid'],
      ['Explain device-bound versus synced passkeys and the trade-off.', '<p><b>Device-bound</b> keys (hardware security keys, original FIDO2) never leave a single device\'s secure element — highest assurance, but losing the device means relying on a pre-registered backup. <b>Synced</b> passkeys E2E-encrypt the private key and sync it across your devices via a platform keychain (Apple/Google/Microsoft), which solved the adoption-killing "lost my only key" problem. The trade-off is that your passkeys\' security now also depends on your cloud account\'s security. High-security contexts may still require device-bound hardware keys; consumer flows favour synced for recoverability.</p>', 'senior'],
      ['How is a single-tap passkey login still multi-factor?', '<p>It combines <b>something you have</b> — the device holding the non-exportable private key — with <b>something you are or know</b> — the biometric or PIN that unlocks the authenticator locally. Both are satisfied on-device in one gesture, so there\'s no separate second prompt, yet two distinct factors are involved. That\'s why passwordless passkeys count as strong MFA rather than single-factor.</p>', 'senior'],
      ['What\'s the hardest part of deploying passkeys?', '<p><b>Recovery and account lifecycle</b>, not the crypto. You must let users register multiple authenticators (phone + hardware key), handle lost devices without opening a weak reset path (the favourite attacker target), decide on synced vs device-bound policy, and manage a transition where weaker fallbacks (password/OTP) still exist and could be downgraded to. The authentication itself is robust; the surrounding enrolment, backup and recovery design is where real deployments succeed or fail.</p>', 'senior'],
    ],
    quiz: [
      { q: 'With a passkey, what leaves your device during login?', o: ['The private key', 'A signature over the challenge and origin', 'Your biometric data', 'A shared secret'], a: 1, e: 'The private key stays in secure hardware; only a signature is sent. Your biometric never leaves the device either — it just unlocks the key locally.' },
      { q: 'Passkeys resist phishing because…', o: ['The codes are longer', 'The browser signs the real origin, so a fake site\'s signature is rejected', 'They use SMS', 'The server stores the private key'], a: 1, e: 'The origin is signed and supplied by the browser, not the user. A phishing domain yields a signature for the wrong origin, which the real server refuses.' },
      { q: 'What does the server store for a registered passkey?', o: ['A password hash', 'The user\'s public key', 'The private key encrypted', 'A TOTP seed'], a: 1, e: 'Only the public key — useless to an attacker. A breach of the auth store leaks nothing reusable.' },
      { q: 'A synced passkey differs from a device-bound one in that…', o: ['It uses a password', 'Its private key is E2E-encrypted and synced across your devices', 'It can be phished', 'It needs no biometric'], a: 1, e: 'Synced passkeys replicate the key across devices (solving device loss), trading off some assurance to your cloud account\'s security.' },
      { q: 'A single-tap passkey login is still multi-factor because it combines…', o: ['Two passwords', 'The device you have + the biometric/PIN you are or know', 'SMS and email', 'Two servers'], a: 1, e: 'Possession of the device (have) plus the local gesture (are/know) are two distinct factors satisfied on-device.' },
    ],
    related: ['mfa', 'totp', 'ssh', 'passwords'],
  });

  /* ---------------- Magic links ---------------- */
  HS.add({
    id: 'magic-links', group: 'modern', short: 'Magic links', icon: 'mail',
    title: 'Magic Links & Email OTP',
    tagline: 'Passwordless login by clicking a link (or entering a code) emailed to you. Loved for its simplicity and zero-password UX — but it quietly makes your email inbox the master key to everything.',
    level: 'Beginner', kind: 'Passwordless / possession',
    spec: [['Factor', 'Control of an inbox'], ['Token', 'Single-use, short-lived'], ['No', 'Password to store'], ['Risk', 'Email = master key']],
    analogy: `<p>A magic link is like a hotel mailing a one-time room key to your home address. Anyone who can reach your mailbox can get the key — so the security of your room now depends entirely on the security of your mailbox. Convenient (no key to remember), but you've moved the whole problem to "how safe is my post?" For magic links, that mailbox is your email account.</p>`,
    flow: {
      nodes: [
        { id: 'u', label: 'User', sub: 'browser', icon: 'user', x: 95, y: 150 },
        { id: 's', label: 'Server', sub: 'app', icon: 'server', x: 335, y: 90 },
        { id: 'mail', label: 'Inbox', sub: 'email', icon: 'mail', x: 560, y: 150 },
      ],
      order: ['u', 's', 'mail'],
      normal: {
        name: 'Click to log in', summary: 'The server emails a single-use, short-lived, random token. Clicking it proves you control the inbox tied to the account, so the inbox becomes the credential.',
        steps: [
          { f: 'u', t: 's', k: 'req', l: 'enter email → "send me a link"', title: 'Request a link', d: 'The user types only their email address — no password. They ask the app to send a login link.', data: { 'POST': '/auth/magic', email: 'sakitha@example.com', password: 'none' }, enc: true },
          { f: 's', t: 's', k: 'int', l: 'mint single-use token, store hash', title: 'Generate a one-time token', d: 'The server creates a long random token, stores its <em>hash</em> with a short expiry (e.g. 10 min) and single-use flag, and builds a URL containing the token.', data: { token: '128-bit random', stored: 'hash + exp(+10m) + used=false', url: 'https://app/magic?t=…' } },
          { f: 's', t: 'mail', k: 'req', l: 'email the link', title: 'Send the link to the inbox', d: 'The link is emailed. From here, security rests on the user controlling that inbox — the app has delegated authentication to the email provider.', data: { to: 'sakitha@example.com', contains: 'one-time login URL', trust: 'control of inbox = identity' } },
          { f: 'mail', t: 'u', k: 'res', l: 'user opens email, clicks link', title: 'User clicks', d: 'The user opens the email and clicks the link, which hits the app with the token.', data: { action: 'click link', carries: 'the one-time token' } },
          { f: 'u', t: 's', k: 'req', l: 'GET /magic?t=… ', title: 'Redeem the token', d: 'The app looks up the token hash, checks it\'s unexpired and unused, marks it used, and creates a session. The token is now dead.', data: { lookup: 'hash matches', checks: 'not expired, not used', then: 'mark used → create session' }, ok: 'Logged in; token consumed' },
        ],
      },
      attack: {
        name: 'Email compromise & link interception', summary: 'Magic links are only as strong as the inbox and the link\'s handling. Single-use short-lived tokens, and treating email as a single point of failure, are the key mitigations.',
        steps: [
          { f: 'mail', t: 'mail', k: 'atk', l: 'attacker controls the inbox', title: 'The inbox is the master key', d: 'If an attacker has access to the user\'s email (phished, reused password, session theft), they can request and click magic links for <em>every</em> service that uses them — and for password resets everywhere else too.', data: { compromised: 'email account', unlocks: 'every magic-link app + all password resets', nature: 'single point of failure' }, fail: 'Email compromise = account takeover across services' },
          { f: 's', t: 'mail', k: 'atk', l: 'link leaks (forward, proxy, logs)', title: 'Link leakage', d: 'Links can leak via forwarded emails, shared screens, corporate mail scanners that pre-fetch URLs, or server logs. A leaked <em>reusable</em> link would be disastrous.', data: { leak_paths: 'forwarding · URL-scanners pre-click · logs · Referer', risk: 'if token is reusable/long-lived' } },
          { f: 's', t: 's', k: 'int', l: 'single-use + short expiry + bind', title: 'Core mitigations', d: 'Make tokens single-use and short-lived (minutes), so a pre-fetched or leaked link is likely already dead. Store only the hash. Optionally bind redemption to the same browser/session that requested it.', data: { 'single-use': 'dead after first click', expiry: '~10 min', storage: 'hash only', binding: 'same device/session (optional)' }, ok: 'Leaked/old links are useless' },
          { f: 'mail', t: 'mail', k: 'int', l: 'protect the inbox: MFA on email', title: 'Secure the real dependency', d: 'Because email is the credential, the highest-leverage defence is strong MFA (ideally passkeys) on the email account itself, plus phishing awareness. Treat magic links as convenience, not high-assurance auth for sensitive systems.', data: { priority: 'strong MFA on email', also: 'phishing-resistant factors for high-value apps', framing: 'magic link = low-friction, not high-assurance' }, ok: 'Dependency (email) hardened' },
        ],
      },
    },
    basics: `
      <p>A <strong>magic link</strong> logs you in by emailing you a one-time URL to click; <strong>email OTP</strong> does the same with a code you type. Both are <em>passwordless</em> and rest on a single idea: if you can read a secret sent to your inbox, you must control that inbox, and the app treats that as proof of identity.</p>
      <p>The appeal is real: no password for users to choose, forget, reuse or have breached, and nothing (password-equivalent) for the app to store. Onboarding is frictionless — type your email, click, done.</p>
      <p>But notice what happened: the app <strong>delegated authentication to your email provider</strong>. Your inbox is now the credential — and since email is <em>already</em> the recovery channel for most of your other accounts, it was arguably the master key anyway. Magic links make that dependency explicit.</p>
      <div class="callout warn"><b>The token must be single-use and short-lived</b>Treat the emailed token like a one-time password: long random value, stored hashed, expires in minutes, invalidated after one use. A reusable or long-lived link sitting in an inbox is a standing key.</div>`,
    deep: `
      <h3>Security properties, honestly</h3>
      <ul>
        <li><b>Strength = inbox security.</b> Magic links are exactly as strong as the user's email account. If that has weak or reused credentials and no MFA, the magic-link app inherits that weakness. If the email has a passkey, the app effectively borrows that strength.</li>
        <li><b>Phishable.</b> Like any code or link not bound to origin, a user can be tricked into entering an email OTP on a fake site, or an attacker can trigger a link and socially-engineer the user into clicking/forwarding it.</li>
        <li><b>Link handling pitfalls.</b> Corporate mail security scanners often <em>pre-fetch</em> URLs, which can consume a single-use link before the user clicks (a real UX bug). Links also leak via forwarding, shared screens and logs.</li>
      </ul>
      <h3>Hardening checklist</h3>
      <ul>
        <li>Cryptographically random token (≥128 bits), stored <b>hashed</b>, never logged.</li>
        <li>Short expiry (minutes) and strict <b>single use</b>.</li>
        <li>Rate-limit requests per email/IP to prevent spamming someone\'s inbox.</li>
        <li>Consider <b>binding</b> redemption to the same browser/session that requested it, so a forwarded link alone can\'t log someone else in.</li>
        <li>Email OTP (type a code) can be more robust against URL pre-fetching than clickable links.</li>
        <li>Clear messaging so users don\'t forward the email.</li>
      </ul>
      <h3>Where it fits</h3>
      <p>Magic links shine for low-friction, lower-risk consumer products, infrequent logins, and as a passwordless on-ramp. For sensitive systems (finance, admin, healthcare) they\'re usually too dependent on email security to stand alone — there, <a href="#webauthn">passkeys</a> or strong MFA are the better fit. A common pattern: magic link to establish the account, then prompt to add a passkey.</p>`,
    howto: `
      ${C('text', `
        Magic-link checklist:
        • Token: ≥128-bit random, stored HASHED, single-use, expires in ~10 min.
        • Never log the token or the full link; rate-limit send requests.
        • Optionally bind redemption to the requesting browser/session.
        • Expect URL pre-fetching by mail scanners — email OTP avoids that pitfall.
        • Encourage (or require) MFA on the email account for sensitive apps.
        • Don't use magic links alone for high-assurance systems — add passkeys.
      `, 'Implementing magic links safely')}
      <div class="callout"><b>The highest-leverage control isn\'t in your app</b>Since the inbox is the credential, pushing users toward strong MFA/passkeys on their email does more for magic-link security than almost anything you can do server-side.</div>`,
    pros: ['No password for users to create, forget, reuse, or get breached', 'Nothing password-equivalent for the app to store', 'Very low onboarding friction — email and click', 'Naturally verifies the email address at the same time', 'Simple to implement with one-time tokens'],
    cons: ['Security is only as strong as the user\'s email account', 'Makes email an explicit single point of failure', 'Phishable; links leak via forwarding, logs, URL scanners', 'Mail scanners can pre-consume single-use links (UX breakage)', 'Latency/deliverability of email; poor fit for high-assurance systems'],
    history: [
      ['2010s', 'Slack, Medium and others popularise magic-link login for frictionless onboarding.'],
      ['2015→', 'Email OTP codes spread as a password alternative and step-up factor.'],
      ['2019', 'Passwordless UX gains traction; magic links become a common default for consumer apps.'],
      ['2022→', 'Passkeys offer a stronger passwordless option, repositioning magic links as a low-friction/fallback choice.'],
    ],
    hidden: [
      ['Your inbox was already the master key', 'Even with passwords, "reset via email" means whoever controls your inbox controls most of your accounts. Magic links just make that dependency honest and visible.'],
      ['Mail scanners click your links', 'Enterprise email security products often pre-fetch URLs to check them — which can silently consume a single-use magic link before the human clicks, causing "link already used" errors. Email OTP sidesteps this.'],
      ['A forwarded email can be a login', 'If redemption isn\'t bound to the requesting session, a helpfully-forwarded "here\'s my login email" hands someone else a session. Session binding mitigates it.'],
      ['It quietly verifies the email too', 'A nice side effect: successful magic-link login proves the address works and belongs to the user, folding email verification into authentication.'],
    ],
    attacks: [
      ['Email account compromise', 'Control of the inbox grants login to every magic-link app.', 'Strong MFA/passkeys on email; treat email as critical infrastructure.'],
      ['Link leakage / forwarding', 'Links exposed via forwarding, logs, screenshots.', 'Single-use, short expiry, hashed storage, session binding.'],
      ['URL pre-fetch consumption', 'Mail scanners click the link first, breaking or exposing it.', 'Prefer email OTP; design for one pre-fetch; confirm-click pages.'],
      ['Phishing (email OTP)', 'User enters the code on a fake site.', 'Phishing-resistant factors for sensitive flows; clear anti-phishing cues.'],
      ['Request flooding', 'Spamming login emails to harass or mask attacks.', 'Rate-limit per email/IP; captcha on abuse.'],
    ],
    interview: [
      ['What is the core security dependency of magic-link login?', '<p>The user\'s <b>email account</b>. Clicking an emailed one-time link proves control of the inbox, so the app effectively delegates authentication to the email provider. The magic-link app is therefore exactly as strong — or weak — as that inbox\'s protection. The highest-leverage defence is strong MFA/passkeys on the email account itself, which is outside the app\'s control.</p>', 'junior'],
      ['How should the magic-link token be designed?', '<p>Like a one-time password: a cryptographically random value (≥128 bits), stored <b>hashed</b> (never plaintext, never logged), <b>single-use</b> (invalidated after first redemption), and <b>short-lived</b> (minutes). Optionally bind redemption to the browser/session that requested it so a forwarded link alone can\'t log someone in. These ensure a leaked or pre-fetched link is almost certainly already dead.</p>', 'mid'],
      ['Why might email OTP be more robust than a clickable magic link in enterprises?', '<p>Because enterprise email security gateways often <b>pre-fetch URLs</b> to scan them, which can silently consume a single-use magic link before the human clicks — producing confusing "link already used" failures. A typed email <b>OTP code</b> has no URL to pre-click, so it avoids that consumption problem while keeping the same "control of inbox" model. The trade-off is slightly more user effort.</p>', 'senior'],
      ['When would you not use magic links?', '<p>For <b>high-assurance systems</b> — finance, healthcare, admin consoles — because their security floor is the user\'s email account, which you don\'t control and which is commonly phished. They\'re also a poor fit where login latency matters (email deliverability) or where offline/airgapped access is needed. For those, phishing-resistant <b>passkeys</b> or strong MFA are better. A sensible pattern is magic link for low-friction signup, then nudging the user to add a passkey for ongoing, stronger auth.</p>', 'mid'],
    ],
    quiz: [
      { q: 'A magic link proves identity by showing that the user…', o: ['Knows their password', 'Controls the email inbox it was sent to', 'Has a hardware key', 'Is on a trusted network'], a: 1, e: 'Reading the emailed secret demonstrates control of the inbox, so the inbox becomes the credential.' },
      { q: 'A magic-link token should be…', o: ['Reusable and long-lived for convenience', 'Single-use, short-lived, and stored hashed', 'Stored in plaintext for lookups', 'The user\'s email address itself'], a: 1, e: 'Treat it like a one-time password: random, hashed, single-use, expiring in minutes, so leaked links are already dead.' },
      { q: 'A real UX pitfall specific to clickable magic links is…', o: ['They\'re too long', 'Mail security scanners pre-fetch the URL and consume the single-use token', 'They require a password', 'They can\'t be emailed'], a: 1, e: 'Corporate URL scanners can click the link first, breaking single-use flows. Email OTP codes avoid this.' },
      { q: 'The biggest structural weakness of magic links is that…', o: ['They use TLS', 'They make the email account a single point of failure', 'They store passwords', 'They need a hardware token'], a: 1, e: 'Whoever controls the inbox can log in everywhere magic links (and password resets) are used — so email security is paramount.' },
    ],
    related: ['passwords', 'webauthn', 'mfa', 'totp'],
  });

  /* ---------------- HMAC request signing ---------------- */
  HS.add({
    id: 'hmac-sig', group: 'modern', short: 'HMAC signing', icon: 'key',
    title: 'HMAC Request Signing',
    tagline: 'How AWS and payment webhooks authenticate requests without ever sending the secret. Instead of transmitting a key, you prove you hold it by signing each request — defeating tampering and, with a timestamp, replay. The grown-up alternative to a bare API key.',
    level: 'Advanced', kind: 'Message authentication',
    spec: [['Primitive', 'HMAC (keyed hash)'], ['Secret', 'Never transmitted'], ['Protects', 'Integrity + authenticity'], ['Example', 'AWS SigV4, Stripe webhooks']],
    analogy: `<p>Think of a wax seal pressed from a signet ring only you own. You send your letter openly, but across the flap you press your unique seal computed from the letter's exact words. The recipient, who has a matching reference, can confirm the seal is yours and that not a single word changed — yet you never mailed them the ring. Alter any word and the seal no longer fits. HMAC is that seal: proof of the secret and of integrity, without ever sending the secret.</p>`,
    flow: {
      nodes: [
        { id: 'c', label: 'Client', sub: 'has secret', icon: 'server', x: 110, y: 150 },
        { id: 's', label: 'Server', sub: 'same secret', icon: 'server', x: 455, y: 150 },
      ],
      order: ['c', 's'],
      normal: {
        name: 'Sign, send, verify', summary: 'The client computes HMAC(secret, request + timestamp) and sends the signature — not the secret. The server recomputes it over the received request and compares.',
        steps: [
          { f: 'c', t: 'c', k: 'int', l: 'build canonical string + timestamp', title: 'Canonicalise the request', d: 'The client assembles a precise, agreed string from the request — method, path, body hash, and a current timestamp/nonce. Both sides must build it identically.', data: { canonical: 'POST\\n/refunds\\nbody-sha256\\nts=1730000000', timestamp: 'included to stop replay' } },
          { f: 'c', t: 'c', k: 'int', l: 'signature = HMAC(secret, canonical)', title: 'Sign with the secret', d: 'The client computes an HMAC of that string using the shared secret. The secret is used, never sent.', data: { signature: 'HMAC-SHA256(secret, canonical)', secret_transmitted: 'NO' } },
          { f: 'c', t: 's', k: 'req', l: 'send request + signature + timestamp', title: 'Send request + signature', d: 'The request goes out with the signature and timestamp in headers. An eavesdropper sees the request and the signature but not the secret.', data: { 'POST': '/refunds', 'X-Signature': 'HMAC-SHA256=9c01…', 'X-Timestamp': '1730000000', body: 'amount=20.00' }, enc: true, port: 'TLS 443' },
          { f: 's', t: 's', k: 'int', l: 'check timestamp fresh', title: 'Reject stale requests', d: 'The server first checks the timestamp is within a small window (e.g. ±5 min) and the nonce is unseen — so a captured request can\'t be replayed later.', data: { timestamp: 'within ±5 min ✓', nonce: 'not seen before ✓', else: 'reject (replay)' } },
          { f: 's', t: 's', k: 'int', l: 'recompute HMAC, constant-time compare', title: 'Recompute & compare', d: 'The server rebuilds the same canonical string from what it received and computes HMAC with its copy of the secret. It compares in constant time. Any tampering changes the body hash and breaks the match.', data: { recomputed: 'HMAC(secret, canonical)', compare: 'constant-time == client signature', tamper: 'any change → mismatch → reject' }, ok: 'Signature valid → authentic & untampered' },
        ],
      },
      attack: {
        name: 'Tamper & replay attempts', summary: 'HMAC signing defeats request tampering outright; adding a timestamp/nonce defeats replay. What it doesn\'t do is hide the request contents — that\'s TLS\'s job.',
        steps: [
          { f: 'c', t: 's', k: 'atk', l: 'attacker edits amount 20 → 2000', title: 'Tampering attempt', d: 'A man-in-the-middle (or malicious client) intercepts the request and changes the amount, hoping the server honours it.', data: { original: 'amount=20.00', altered: 'amount=2000.00', signature: 'still the old one' } },
          { f: 's', t: 's', k: 'int', l: 'recomputed HMAC ≠ sent signature', title: 'Integrity check fails', d: 'The server\'s recomputed HMAC over the altered body no longer matches the signature (which was over the original). The request is rejected — the attacker can\'t forge a new signature without the secret.', data: { recomputed: 'HMAC(secret, altered) ≠ sent sig', result: 'REJECT', why: 'no secret → no valid signature' }, ok: 'Tampering blocked' },
          { f: 'c', t: 's', k: 'atk', l: 'replay the original signed request', title: 'Replay attempt', d: 'Foiled on tampering, the attacker instead resends the <em>original</em>, validly-signed request verbatim — hoping to trigger the refund twice.', data: { resent: 'exact original request + valid signature', goal: 'duplicate the action' } },
          { f: 's', t: 's', k: 'int', l: 'timestamp too old / nonce seen → reject', title: 'Timestamp & nonce stop replay', d: 'The server sees the timestamp is outside the freshness window (or the nonce was already used) and rejects it. This is why a signature alone isn\'t enough — you must bind it to time.', data: { timestamp: 'expired / nonce reused', result: 'REJECT', lesson: 'sign a timestamp+nonce, not just the body' }, ok: 'Replay blocked (timestamp + nonce)' },
        ],
      },
    },
    basics: `
      <p><strong>HMAC</strong> (Hash-based Message Authentication Code) takes a secret key and a message and produces a fixed-length tag. It gives you two guarantees at once:</p>
      <ul>
        <li><b>Integrity</b> — if the message changes by even one byte, the tag changes completely (the <a href="#tls">avalanche effect</a>; try it in the HMAC playground).</li>
        <li><b>Authenticity</b> — only someone with the secret key could have produced a tag that verifies, so a valid tag proves the sender holds the key.</li>
      </ul>
      <p>Request signing applies this to API calls. Instead of sending a bearer <a href="#api-keys">API key</a> (which anyone who captures it can reuse), the client <em>signs</em> each request with the secret and sends the <b>signature</b>. The server, sharing the secret, recomputes the signature over the received request and checks it matches. The secret never travels.</p>
      <div class="callout"><b>HMAC ≠ encryption, and ≠ hashing alone</b>HMAC doesn\'t hide the message (use TLS for that) and it isn\'t just a hash — a plain hash anyone can recompute, but an HMAC requires the secret, so it proves <em>who</em> made it. It\'s symmetric: both sides share the same secret.</div>`,
    deep: `
      <h3>Why sign instead of sending the key?</h3>
      <p>A bare API key is a bearer token: capture it once and you can make any request forever. A signed request is different:</p>
      <ul>
        <li>The <b>secret never crosses the wire</b>, so capturing traffic doesn\'t reveal it.</li>
        <li>The signature <b>covers the request contents</b>, so a man-in-the-middle can\'t alter the amount, path or parameters without invalidating it.</li>
        <li>With a <b>timestamp and/or nonce</b> folded into the signed string, each request is fresh — a captured request can\'t be replayed later.</li>
      </ul>
      <p>This is exactly why AWS uses <b>Signature Version 4</b> for API calls: every request is signed over a canonical form including headers and a timestamp, so AWS authenticates the caller and rejects tampering and replay — without your secret access key ever leaving your machine.</p>
      <h3>Canonicalisation — the fiddly, crucial part</h3>
      <p>Both sides must build the <em>exact same string</em> to sign. Differences in header order, casing, URL encoding, or trailing whitespace produce different signatures and mysterious failures. That\'s why signing is usually done by an SDK: defining and reproducing the "canonical request" precisely is error-prone by hand. Most real-world signing bugs are canonicalisation mismatches, not crypto flaws.</p>
      <h3>Webhooks: the other big use case</h3>
      <p>When Stripe, GitHub or Slack call <em>your</em> server with an event, how do you know it\'s really them and not a forgery? They <b>HMAC-sign the payload</b> with a secret you both share and send the signature in a header (e.g. <code>Stripe-Signature</code>). You recompute the HMAC over the raw body and compare. Two rules people get wrong: sign/verify the <b>raw bytes</b> (not re-serialised JSON), and use a <b>constant-time</b> comparison.</p>
      <h3>HMAC vs digital signatures (asymmetric)</h3>
      <p>HMAC is <em>symmetric</em>: both parties share one secret, so either could have produced the tag — fine when both are trusted (you and AWS). A <b>digital signature</b> (RSA/ECDSA, as in <a href="#jwt">JWT RS256</a> or <a href="#tls">TLS</a>) is <em>asymmetric</em>: the signer uses a private key and anyone can verify with the public key, giving <b>non-repudiation</b> (only the signer could have signed). Choose HMAC for speed and shared-secret scenarios; choose asymmetric signatures when verifiers shouldn\'t be able to forge, or when you need to prove origin to third parties.</p>`,
    howto: `
      <p>Use the provider\'s SDK for signing (canonicalisation is the trap). For webhooks you verify:</p>
      ${C('javascript', `
        import crypto from "crypto";

        // Verifying an incoming webhook (e.g. Stripe/GitHub style)
        function verify(rawBody, signatureHeader, secret, timestamp) {
          // 1. reject stale requests (replay defence)
          if (Math.abs(Date.now()/1000 - Number(timestamp)) > 300) return false;

          // 2. recompute HMAC over the signed payload (RAW bytes!)
          const expected = crypto
            .createHmac("sha256", secret)
            .update(timestamp + "." + rawBody)   // match the provider's scheme
            .digest("hex");

          // 3. constant-time compare
          const a = Buffer.from(expected), b = Buffer.from(signatureHeader);
          return a.length === b.length && crypto.timingSafeEqual(a, b);
        }
      `, 'Verifying an HMAC-signed webhook')}
      <ul>
        <li>Always verify over the <b>raw request body</b>, before any JSON parsing/re-serialisation.</li>
        <li>Include and check a <b>timestamp</b> (and ideally a nonce) to stop replay.</li>
        <li>Use a <b>constant-time</b> comparison (<code>timingSafeEqual</code>), never <code>==</code>.</li>
        <li>Rotate shared secrets; support two valid secrets during rotation.</li>
      </ul>
      <p>The HMAC playground shows how one changed byte shatters the signature.</p>`,
    tool: 'hmac',
    pros: ['Secret never transmitted — capturing traffic doesn\'t reveal it', 'Signature covers contents, so tampering is detected', 'With a timestamp/nonce, defeats replay', 'Fast and lightweight (symmetric, just a hash)', 'Ideal for server-to-server APIs and webhook verification'],
    cons: ['Symmetric — both sides share the secret; no non-repudiation', 'Canonicalisation is fiddly; most bugs live here', 'Doesn\'t provide confidentiality (still need TLS)', 'Secret distribution and rotation must be managed', 'Replay protection requires explicit timestamp/nonce handling'],
    history: [
      ['1996', 'HMAC introduced by Bellare, Canetti and Krawczyk; later RFC 2104.'],
      ['2002', 'HMAC standardised in FIPS 198, cementing it for government and industry.'],
      ['2010s', 'AWS Signature Version 4 makes HMAC request signing a daily reality for cloud developers.'],
      ['2015→', 'Webhook providers (Stripe, GitHub, Slack) standardise HMAC payload signatures for authenticity.'],
    ],
    hidden: [
      ['The secret never leaves home', 'The whole trick: you prove you hold the key by using it, not by sending it. Capturing a signed request reveals the signature and the message, but not the key that made them — unlike a bare API key, which is the thing you capture.'],
      ['A signature without a timestamp is replayable', 'HMAC proves authenticity and integrity but says nothing about <em>freshness</em>. Without a signed timestamp or nonce, an attacker can resend a valid request. This is the most common HMAC-signing design mistake.'],
      ['Canonicalisation causes more pain than crypto', 'Nearly all "my signature doesn\'t match" bugs are mismatched canonical strings — header order, URL-encoding, trailing newlines — not broken HMAC. It\'s why you lean on the SDK.'],
      ['Verify the raw body, not parsed JSON', 'Re-serialising JSON can reorder keys or change spacing, breaking the signature. Webhook verification must run over the exact bytes received, which trips up many first implementations.'],
      ['HMAC can\'t prove it wasn\'t you', 'Because both sides share the secret, either could have produced a given tag — so HMAC gives no non-repudiation. If you need to prove a specific party signed something (to a third party), you need an asymmetric digital signature.'],
    ],
    attacks: [
      ['Request tampering', 'Alter the body/parameters in transit.', 'HMAC over the contents — any change breaks the signature.'],
      ['Replay', 'Resend a captured valid signed request.', 'Sign a timestamp and nonce; reject stale/seen requests.'],
      ['Timing attack on comparison', 'Learn the signature byte-by-byte via response timing.', 'Constant-time comparison (timingSafeEqual).'],
      ['Canonicalisation confusion', 'Exploit ambiguity so signer and verifier disagree on the signed string.', 'Strict, well-specified canonical form; use the vetted SDK.'],
      ['Secret leakage', 'The shared secret is exposed in code/logs.', 'Secret managers, rotation, never log secrets; dual-secret rollover.'],
    ],
    interview: [
      ['What does HMAC request signing give you that sending an API key doesn\'t?', '<p>Three things. The <b>secret never crosses the wire</b> — you send a signature computed with it, not the key itself, so capturing traffic doesn\'t reveal the credential (a bare API key is the very thing captured). The signature <b>covers the request contents</b>, so tampering (changing an amount or path) invalidates it. And by signing a <b>timestamp/nonce</b>, each request is fresh, defeating replay. A bare bearer key offers none of these — capture it once and reuse it forever.</p>', 'mid'],
      ['Does HMAC provide confidentiality?', '<p>No. HMAC provides <b>integrity</b> (detects changes) and <b>authenticity</b> (proves the sender holds the secret), but it does not hide the message — the request contents are still visible. Confidentiality is TLS\'s job. You use HMAC signing <em>in addition to</em> TLS: TLS encrypts the channel, HMAC authenticates the specific request and proves it wasn\'t altered.</p>', 'mid'],
      ['How do you stop a validly-signed request from being replayed?', '<p>Fold a <b>timestamp</b> (and ideally a unique <b>nonce</b>) into the signed string, and have the server reject requests whose timestamp is outside a small window (e.g. ±5 minutes) or whose nonce it has already seen. HMAC alone proves authenticity and integrity but says nothing about freshness, so without this an attacker can resend a captured valid request verbatim — the single most common HMAC-signing design gap.</p>', 'senior'],
      ['HMAC vs an asymmetric digital signature — when would you pick each?', '<p><b>HMAC</b> is symmetric: both parties share one secret, it\'s fast, and it\'s perfect when both ends are trusted and co-operating (you ↔ AWS, you ↔ your webhook sender). Its limitation is <b>no non-repudiation</b> — since both hold the secret, either could have produced the tag. An <b>asymmetric signature</b> (RSA/ECDSA) uses a private key to sign and a public key to verify, so verifiers can\'t forge and you can prove to third parties that a specific party signed — at higher computational cost. Choose HMAC for speed and shared-secret integrity; choose asymmetric when verifiers must not be able to sign, or you need provable origin.</p>', 'senior'],
      ['Why must webhook signatures be verified over the raw body?', '<p>Because the sender computed the HMAC over the exact bytes they transmitted. If you parse the JSON and re-serialise it before verifying, key ordering, whitespace or encoding can change, producing a different string and a signature mismatch even for a legitimate request. So you must capture and verify the <b>raw request body</b> before any parsing — and compare in constant time. This is a frequent real-world bug in webhook integrations.</p>', 'senior'],
    ],
    quiz: [
      { q: 'In HMAC request signing, what is sent over the network?', o: ['The secret key', 'A signature computed with the secret, plus the request', 'The key encrypted', 'Nothing'], a: 1, e: 'The signature travels, not the secret. The server recomputes it with its own copy of the secret and compares.' },
      { q: 'HMAC provides integrity and authenticity but NOT…', o: ['A fixed-length output', 'Confidentiality (hiding the message)', 'Determinism', 'Speed'], a: 1, e: 'HMAC detects tampering and proves the sender holds the secret, but doesn\'t hide contents — that\'s TLS\'s job.' },
      { q: 'To stop replay of a validly-signed request you must…', o: ['Use a longer key', 'Include and verify a timestamp/nonce in the signed data', 'Encrypt the signature', 'Send the key too'], a: 1, e: 'HMAC says nothing about freshness. Signing a timestamp/nonce and rejecting stale or reused ones defeats replay.' },
      { q: 'Compared with an RSA digital signature, HMAC…', o: ['Provides non-repudiation', 'Is symmetric — both sides share the secret, so neither can prove the other signed', 'Is slower', 'Uses a public key to verify'], a: 1, e: 'HMAC is symmetric and fast but gives no non-repudiation. Asymmetric signatures let anyone verify with a public key and prove origin.' },
    ],
    related: ['api-keys', 'jwt', 'tls', 'totp'],
  });
})();
