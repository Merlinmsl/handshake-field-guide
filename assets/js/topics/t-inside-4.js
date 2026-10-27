/* "How it works inside" + "Solved example" for: MFA, TOTP, WebAuthn, Magic links, HMAC signing,
   Authorization models, OAuth scopes, OPA. Short, simple sentences.
   TOTP, HMAC and SHA-256 values were computed with real code (TOTP uses the RFC 6238 vector). */
(function () {
  'use strict';
  const HS = window.HS, C = window.C, T = HS.tbl;
  const IN = (id, d) => { const t = HS.byId[id]; if (!t) return; t.inside = d.inside; t.example = d.example; };

  /* ================= MFA ================= */
  IN('mfa', {
    inside: [
      ['The three kinds of factor', `
        ${T(['Kind', 'You prove that you…', 'Examples', 'What the server stores'], [
          ['Knowledge', 'know something', 'Password, PIN', 'A slow hash (bcrypt / Argon2)'],
          ['Possession', 'have something', 'Phone app (TOTP), security key, SIM', 'TOTP secret (encrypted), passkey public key, phone number'],
          ['Inherence', 'are something', 'Fingerprint, face', 'Nothing! The match happens on your device. It only unlocks the key.'],
        ])}
        <p>Two passwords are still one factor. MFA means <b>different kinds</b>. Then one stolen thing is not enough.</p>`],
      ['The half-logged-in state', `
        <p>After the password is correct, the server does <b>not</b> make a full session yet. It makes a short "pending" record:</p>
        ${C('json', `
          { "sid": "p_Hq81…", "userId": 42, "state": "mfa_pending",
            "factorsDone": ["password"], "attempts": 0, "expiresIn": 300 }
        `, 'Valid for 5 minutes, and only for the MFA page')}
        <p>Only after the second factor passes does it become a full session (<code>"state": "active"</code>). And the server <b>makes a new session ID</b> at that moment.</p>
        <p>A common bug: the app already gives a working session after step 1, and only the page hides the rest. Attackers skip the MFA page and call the API directly.</p>`],
      ['Limits that make guessing useless', `
        <ul>
          <li>Count wrong codes on the pending record. Lock after about 5.</li>
          <li>Make each code single-use. Remember the last time step used.</li>
          <li>Keep the pending record short-lived (minutes).</li>
          <li>Store recovery codes as hashes, like passwords. Each one works once.</li>
        </ul>`],
      ['Push approval and number matching', `
        <p>Simple push says "Approve sign-in?" An attacker with your password can send 50 pushes at 2 a.m. You might tap Approve just to stop it. This is <b>MFA fatigue</b>.</p>
        <p><b>Number matching</b> fixes this. The login screen shows a number, like <b>47</b>. The phone asks you to type that number. If you did not start the login, you do not know the number.</p>`],
    ],
    example: {
      title: 'What is the chance of guessing a 6-digit code?',
      problem: `
        <p>An attacker already has the user's password. The second factor is a 6-digit TOTP code. The server:</p>
        <ul>
          <li>accepts the current code <b>and</b> the codes one step before and after (3 valid codes at any moment),</li>
          <li>locks the login after <b>5</b> wrong tries.</li>
        </ul>
        <p>What is the chance the attacker gets in before the lock? What if there were no lock and they could try 10 codes per second for one hour?</p>`,
      steps: [
        ['Count all possible codes', `<div class="math">000000 to 999999 → 10⁶ = 1,000,000 codes</div>`],
        ['Chance of one guess', `<div class="math">valid ÷ possible = 3 ÷ 1,000,000 = 0.000003</div>`],
        ['Chance with 5 guesses', `
          <div class="math">5 × 0.000003 = 0.000015 = 0.0015 %   (about 1 in 66,667)</div>
          <p>(Adding is fine here because the numbers are tiny.)</p>`],
        ['Without a lock', `
          <div class="math">10 tries/s × 3,600 s = 36,000 tries
36,000 × 3 ÷ 1,000,000 = 0.108</div>
          <p>That is roughly a 10% chance per hour. Over a full day (864,000 tries) it climbs to about 92%.</p>`],
      ],
      answer: `
        <p><b>With the lock: about 0.0015 % (1 in 66,667).</b> Without a lock: about 10 % per hour.</p>
        <p>The 6 digits alone are not what protects you. The <b>attempt limit</b> does. Always count failures on the server.</p>`,
    },
  });

  /* ================= TOTP / HOTP ================= */
  IN('totp', {
    inside: [
      ['The setup QR code', `
        <p>When you turn on 2FA, the server makes a random secret (usually 20 bytes). It shows it as a QR code. The QR code holds this URI:</p>
        ${C('text', `
          otpauth://totp/SLIIT:sakitha?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=SLIIT&algorithm=SHA1&digits=6&period=30
        `)}
        ${T(['Part', 'Meaning'], [
          ['<code>secret</code>', 'The shared key, in Base32'],
          ['<code>algorithm</code>', 'Hash used inside HMAC (SHA1 is the default and still OK here)'],
          ['<code>digits</code>', 'Code length (6)'],
          ['<code>period</code>', 'Seconds per code (30)'],
        ])}
        <p>After this, the phone and the server both hold the same secret. They never talk again. That is why codes work in airplane mode.</p>`],
      ['Why Base32?', `
        <p>Base32 uses only <code>A–Z</code> and <code>2–7</code>. No <code>0/O</code> or <code>1/l</code> confusion. So a human can type it if the camera fails.</p>
        <p>Each character carries 5 bits. Example: the secret bytes start with <code>"1"</code> (0x31 = <code>00110001</code>) and <code>"2"</code> (0x32 = <code>00110010</code>).</p>
        <div class="math">00110 | 00100 | 11001 | 0…
  6       4      25
  G       E      Z      → "GEZ…"</div>`],
      ['The algorithm, step by step', `
        <div class="math">T       = floor( unix_time ÷ 30 )               the time step
msg     = T as 8 bytes, big-endian
h       = HMAC-SHA1( secret, msg )             20 bytes
offset  = last byte of h AND 0x0F              a number 0–15
code32  = 4 bytes of h starting at offset, with the top bit cleared
code    = code32 mod 10⁶                       → 6 digits, with leading zeros</div>
        <p>The "offset" trick is called <b>dynamic truncation</b>. It picks a different place in the hash each time. Clearing the top bit avoids negative numbers in some languages.</p>`],
      ['How the server checks a code', `
        <ol>
          <li>Compute T from its own clock.</li>
          <li>Compute codes for T−1, T and T+1. This allows about 30 seconds of clock drift.</li>
          <li>If the typed code matches one of them, and that step is newer than the last one used → accept. Save that step.</li>
          <li>Otherwise count a failure.</li>
        </ol>`],
      ['HOTP: the counter version', `
        <p>HOTP is the same math, but <code>msg</code> is a <b>counter</b>, not time. Each button press adds 1. The server keeps the counter. If you press the button without logging in, the counters drift apart. So the server looks ahead a few values (for example the next 10) and then jumps forward.</p>`],
      ['Where the secret lives', `
        ${T(['Place', 'Holds', 'Note'], [
          ['Authenticator app', 'Secret, in the phone\'s secure storage', 'Some apps sync it to the cloud'],
          ['Server database', 'Same secret, <b>encrypted</b> with a key from a KMS', 'Cannot be hashed — the server must use the real value'],
          ['QR code', 'The secret, once', 'Never email it or keep a screenshot'],
        ])}`],
    ],
    example: {
      title: 'Compute a TOTP code by hand (RFC 6238 test vector)',
      problem: `
        <p>Secret (ASCII): <code>12345678901234567890</code> (Base32: <code>GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ</code>).</p>
        <p>Unix time: <b>59</b> seconds. Period 30. Hash SHA-1.</p>
        <p>Find the 8-digit code (the RFC value) and the 6-digit code an app would show.</p>`,
      steps: [
        ['Find the time step', `
          <div class="math">T = floor(59 ÷ 30) = 1</div>
          <p>As 8 bytes: <code>00 00 00 00 00 00 00 01</code></p>`],
        ['Compute the HMAC', `
          <div class="math">h = HMAC-SHA1("12345678901234567890", 00…01)
  = 75 a4 8a 19 d4 cb e1 00 64 4e 8a c1 39 7e ea 74 7a 2d 33 ab</div>
          <p>That is 20 bytes. Number them 0 to 19.</p>`],
        ['Find the offset', `
          <p>The last byte (number 19) is <code>0xab</code> = <code>1010 1011</code>.</p>
          <div class="math">0xab AND 0x0f = 0x0b = 11</div>
          <p>So start at byte 11.</p>`],
        ['Take 4 bytes and clear the top bit', `
          <p>Bytes 11, 12, 13, 14 are <code>c1 39 7e ea</code>.</p>
          <div class="math">0xc1 AND 0x7f = 0x41
code32 = 0x41397eea = 1,094,287,082</div>`],
        ['Cut to the number of digits', `
          <div class="math">1,094,287,082 mod 10⁸ = 94,287,082
1,094,287,082 mod 10⁶ =    287,082</div>`],
      ],
      answer: `
        <p><b>8 digits: 94287082</b> — this is exactly the value in RFC 6238, Appendix B. <b>6 digits: 287082.</b></p>
        <p>The test suite of this site checks the TOTP playground against this same vector. Try it below: the playground uses the current time, so its code changes every 30 seconds.</p>`,
    },
  });

  /* ================= WebAuthn / Passkeys ================= */
  IN('webauthn', {
    inside: [
      ['Registration: a new key pair for each site', `
        <ol>
          <li>The server sends a random <b>challenge</b> and its <b>RP ID</b> (<code>bank.com</code>).</li>
          <li>The authenticator (phone chip, laptop TPM, security key) makes a <b>new</b> key pair, usually ECDSA P-256. This key is only for <code>bank.com</code>.</li>
          <li>The private key stays inside the hardware (or in your encrypted passkey sync).</li>
          <li>The server receives: a <b>credential ID</b> and the <b>public key</b>.</li>
        </ol>
        ${T(['Server stores', 'Example', 'Secret?'], [
          ['credential ID', '<code>Kx9_r2…</code> (random bytes)', 'No'],
          ['public key (COSE format)', 'P-256 point (x, y)', 'No'],
          ['sign count', '7', 'No'],
          ['user handle', 'random ID, not the email', 'No'],
        ])}
        <p>Nothing on the server can log you in by itself. A database leak gives the attacker only public keys.</p>`],
      ['Login: what gets signed', `
        <p>The browser builds <b>clientDataJSON</b>. The page cannot fake these fields. The browser fills them in:</p>
        ${C('json', `
          { "type": "webauthn.get",
            "challenge": "q7Ld9w3V0aZ…",        // the server's random value
            "origin": "https://bank.com",       // the real address bar
            "crossOrigin": false }
        `)}
        <p>The authenticator builds <b>authenticatorData</b>:</p>
        ${T(['Bytes', 'Field', 'Meaning'], [
          ['0–31', 'rpIdHash', 'SHA-256 of the RP ID'],
          ['32', 'flags', 'bit 0 = UP (user present), bit 2 = UV (user verified, e.g. fingerprint), bit 3/4 = backup (synced passkey)'],
          ['33–36', 'signCount', 'A counter that goes up each use (often 0 for synced passkeys)'],
        ])}
        <div class="math">signature = ECDSA-sign( privateKey, authenticatorData ‖ SHA-256(clientDataJSON) )</div>`],
      ['What the server checks', `
        <ol>
          <li><code>type</code> is <code>webauthn.get</code>.</li>
          <li><code>challenge</code> is the one it just sent (and not used before).</li>
          <li><code>origin</code> is exactly <code>https://bank.com</code>.</li>
          <li><code>rpIdHash</code> = SHA-256("bank.com").</li>
          <li>The UP flag is set. If the site needs it, UV is set too.</li>
          <li>The signature verifies with the stored public key.</li>
          <li>signCount is bigger than the stored one (if not 0). Then save the new count.</li>
        </ol>`],
      ['ECDSA in simple words', `
        <p>Like Ed25519 in SSH, ECDSA uses a curve. The private key is a big number <b>d</b>. The public key is the point <b>Q = d · G</b>. To sign, the device picks a fresh random number k and makes two numbers (r, s) from k, d and the message hash. Anyone with Q can check (r, s). Nobody can make (r, s) without d.</p>`],
      ['Why phishing fails', `
        <p>On <code>bank-secure.com</code> the browser puts <b>that</b> origin in clientDataJSON. The RP ID <code>bank.com</code> is not allowed there at all. So either the browser refuses, or the signature covers the wrong origin and wrong rpIdHash. The real bank rejects it. You cannot "type the passkey" into a fake site.</p>`],
    ],
    example: {
      title: 'Check three passkey logins at bank.com',
      problem: `
        <p>The server has this saved for Sakitha's security key: public key Q, <b>signCount = 7</b>, RP ID <code>bank.com</code>. It requires UV.</p>
        <p>Three login attempts arrive. All signatures verify with Q (the math is fine). Should the server accept each one?</p>
        ${T(['', 'Attempt 1', 'Attempt 2', 'Attempt 3'], [
          ['origin', 'https://bank.com', 'https://bank-secure.com', 'https://bank.com'],
          ['rpIdHash', 'c2f75c03…4bef1ce5', 'a0b40e39…e796a1c6', 'c2f75c03…4bef1ce5'],
          ['flags', '0x05', '0x05', '0x05'],
          ['signCount', '8', '9', '5'],
          ['challenge', 'matches', 'matches (relayed)', 'matches'],
        ])}`,
      steps: [
        ['Work out the correct rpIdHash', `
          <div class="math">SHA-256("bank.com")        = c2f75c03697e1731530ad93a2067ea85145d565e6084b65051669f074bef1ce5
SHA-256("bank-secure.com") = a0b40e391a42b74cd2b41847146541b91d5b4199a142d92ac4ed5d4fe796a1c6</div>`],
        ['Decode the flags byte', `
          <div class="math">0x05 = 0000 0101
bit 0 (UP) = 1   user touched the key
bit 2 (UV) = 1   user did PIN / fingerprint</div>
          <p>UV is required and set. Pass for all three.</p>`],
        ['Attempt 1', `<p>Origin right, rpIdHash right, flags OK. Counter 8 &gt; 7. <b>Accept</b>, then save signCount = 8.</p>`],
        ['Attempt 2', `<p>Origin is <code>bank-secure.com</code>, not <code>bank.com</code>. rpIdHash is for <code>bank-secure.com</code>. A phishing site relayed the bank's challenge, but the signed data names the wrong site. <b>Reject.</b></p>`],
        ['Attempt 3', `<p>Everything matches except the counter. Stored is now 8, received is 5. A real key never counts backwards. This suggests the key was <b>cloned</b>. <b>Reject</b> (or flag the account and ask for review).</p>`],
      ],
      answer: `
        <p><b>Attempt 1: accept. Attempt 2: reject (wrong origin / RP). Attempt 3: reject (counter went backwards).</b></p>
        <p>Notice attempt 2. The challenge was correct and the user really touched their key. It still fails, because the browser wrote the true origin into what was signed. That is the phishing resistance in one line.</p>`,
    },
  });

  /* ================= Magic links ================= */
  IN('magic-links', {
    inside: [
      ['Making the token', `
        ${C('js', `
          const token = crypto.randomBytes(32).toString("base64url");
          // e.g. "Xk3p9LwQ2vT8nR5yB1cF7hJ0mD4sG6aZqE2uW9oP8iY"  → 43 chars, 256 random bits
        `)}
        <p>The email contains the raw token in a link:</p>
        ${C('text', `
          https://app.example/magic?t=Xk3p9LwQ2vT8nR5yB1cF7hJ0mD4sG6aZqE2uW9oP8iY
        `)}`],
      ['What the server stores', `
        ${T(['Column', 'Value'], [
          ['token_hash', '<code>daaa6132471754f33d53225e2deb3a4214a9a31c526a582eeb7e0788404de9fb</code> (SHA-256 of the token)'],
          ['user_id', '42'],
          ['expires_at', 'created + 10 minutes'],
          ['used_at', 'NULL until clicked'],
        ])}
        <p>Why store the hash? If the database leaks, the attacker cannot build working links. The token has 256 random bits, so plain SHA-256 is enough (no slow hash needed).</p>`],
      ['What happens on click', `
        <ol>
          <li>Hash the <code>t</code> value from the URL.</li>
          <li>Find the row with that hash. None → error page.</li>
          <li>Check <code>expires_at</code> &gt; now and <code>used_at</code> is empty.</li>
          <li>Set <code>used_at</code> = now <b>in the same database step</b> (for example <code>UPDATE … WHERE used_at IS NULL</code>). Two fast clicks cannot both win.</li>
          <li>Create a normal session cookie. Redirect to the app.</li>
        </ol>`],
      ['Two real-world traps', `
        <p><b>Email scanners.</b> Some company mail systems open every link to check for malware. That "click" would use up the token. Fix: the link opens a page with a "Sign in" button. Only the button (a POST) uses the token.</p>
        <p><b>Account guessing.</b> If the form says "No account with that email", attackers can test which emails exist. Fix: always say "If that email has an account, we sent a link."</p>`],
    ],
    example: {
      title: 'Follow two links through their life',
      problem: `
        <p>Rules: a link expires <b>10 minutes</b> after it is made. Each link works <b>once</b>.</p>
        ${T(['Time', 'Event'], [
          ['10:00', 'Sakitha requests a link → Link A'],
          ['10:04', 'She clicks Link A on her laptop'],
          ['10:06', 'Link A is clicked again (she forwarded the email to her phone)'],
          ['10:07', 'She requests another link → Link B'],
          ['10:20', 'She clicks Link B'],
        ])}
        <p>What happens at 10:04, 10:06 and 10:20?</p>`,
      steps: [
        ['Write down the expiry times', `
          <div class="math">Link A: 10:00 + 10 min = 10:10
Link B: 10:07 + 10 min = 10:17</div>`],
        ['10:04 — Link A', `<p>Hash found. 10:04 &lt; 10:10 → not expired. <code>used_at</code> is empty → not used. Mark used. Create session. <b>Logged in.</b></p>`],
        ['10:06 — Link A again', `<p>Hash found. Not expired. But <code>used_at</code> = 10:04. <b>Rejected</b> — "This link was already used. Request a new one."</p>`],
        ['10:20 — Link B', `<p>Hash found. 10:20 &gt; 10:17 → <b>expired. Rejected.</b></p>`],
      ],
      answer: `
        ${T(['Time', 'Result', 'Reason'], [
          ['10:04', 'Logged in', 'Valid, unused, not expired'],
          ['10:06', 'Rejected', 'Already used'],
          ['10:20', 'Rejected', 'Expired at 10:17'],
        ])}
        <p>Short life and single use make an old email harmless. If someone reads her inbox tomorrow, every link in it is dead.</p>`,
    },
  });

  /* ================= HMAC signing ================= */
  IN('hmac-sig', {
    inside: [
      ['The shared secret', `
        <p>Both sides hold the same secret key, for example a webhook secret <code>whsec_demo123</code>. The sender uses it to sign. The receiver uses it to check. It is never sent with the message.</p>
        ${T(['Side', 'Keeps the secret in'], [
          ['Sender (e.g. a payment provider)', 'Its own secret store, per customer endpoint'],
          ['Receiver (your server)', 'An environment variable or secret manager — never in Git'],
        ])}`],
      ['The HMAC formula', `
        <p>HMAC wraps a normal hash (SHA-256) in two layers:</p>
        <div class="math">K'    = key padded with zeros to 64 bytes
inner = SHA-256( (K' ⊕ ipad) ‖ message )      ipad = 0x36 repeated
HMAC  = SHA-256( (K' ⊕ opad) ‖ inner )        opad = 0x5c repeated</div>
        <p>Why not just <code>SHA-256(key ‖ message)</code>? With SHA-256 an attacker could add data to the end of the message and compute a valid hash without the key. This is a <b>length-extension</b> attack. The outer layer of HMAC blocks it.</p>`],
      ['Sign exactly the right bytes', `
        <p>The receiver must rebuild the <b>same bytes</b> the sender signed. One extra space breaks it. So each scheme defines a <b>canonical string</b>:</p>
        ${T(['Scheme', 'Signed string'], [
          ['Stripe-style webhooks', '<code>timestamp + "." + raw request body</code>'],
          ['GitHub webhooks', 'raw request body (header <code>X-Hub-Signature-256</code>)'],
          ['AWS SigV4', 'method, path, query, sorted headers, body hash, date, region and service — on separate lines'],
        ])}
        <p>Always verify against the <b>raw body</b>. If your framework parses the JSON and you re-serialize it, the bytes may change.</p>`],
      ['Stopping replay', `
        <p>A valid signed message can be copied and sent again. So the signed string includes a <b>timestamp</b>. The receiver rejects messages older than a window (often 5 minutes). For stricter systems add a <b>nonce</b> (a unique ID) and remember the ones already seen.</p>`],
      ['Compare safely', `
        <p>Use a constant-time compare (<code>crypto.timingSafeEqual</code>, <code>hmac.compare_digest</code>). A normal <code>==</code> stops at the first different character. The time difference can leak the right signature one character at a time.</p>`],
    ],
    example: {
      title: 'Sign and verify a webhook',
      problem: `
        <p>Secret: <code>whsec_demo123</code>. The sender sends this webhook:</p>
        ${C('http', `
          POST /webhooks/payments
          X-Signature: t=1700000000,v1=<signature>

          {"order":1042,"amount":500}
        `)}
        <p>The signed string is <code>timestamp + "." + body</code>. Tolerance: 300 seconds.</p>
        <ol>
          <li>Compute the signature.</li>
          <li>An attacker changes the amount to 5000 and keeps the signature. Result?</li>
          <li>An attacker replays the original, unchanged, when the receiver's clock says <code>1700000400</code>. Result?</li>
        </ol>`,
      steps: [
        ['Build the signed string', `<div class="math">1700000000.{"order":1042,"amount":500}</div>`],
        ['Look inside HMAC (first byte only)', `
          <p>The key's first byte is <code>w</code> = 0x77.</p>
          <div class="math">0x77 ⊕ 0x36 = 0x41   (first byte of the inner pad)
0x77 ⊕ 0x5c = 0x2b   (first byte of the outer pad)
inner = SHA-256(innerPad ‖ message) = c6c8f284c97035ee…cbeecbae</div>`],
        ['Get the final signature', `
          <div class="math">v1 = SHA-256(outerPad ‖ inner)
   = 2972e9cd81d5295cd01e4575a0f60a3df18c8fd28c9879e1bed2985922f69515</div>
          <p>The receiver computes the same thing with its copy of the secret and compares. Match → accept.</p>`],
        ['Tampered amount', `
          <div class="math">HMAC(secret, '1700000000.{"order":1042,"amount":5000}')
= cd35d2eb4b98debdb811c10284e15892145c23a435ab957d7ff6d45dec711fc4   ≠ 2972e9cd…</div>
          <p>One added zero changed the whole signature. The attacker cannot make the new one without the secret.</p>`],
        ['Replay', `
          <div class="math">now − t = 1700000400 − 1700000000 = 400 s  &gt;  300 s</div>
          <p>The signature is valid, but it is too old.</p>`],
      ],
      answer: `
        <p><b>Signature: 2972e9cd81d5295cd01e4575a0f60a3df18c8fd28c9879e1bed2985922f69515.</b></p>
        <p><b>Tampered:</b> rejected — signature mismatch. <b>Replay at +400 s:</b> rejected — outside the 300-second window.</p>
        <p>You can check the first result in the HMAC playground below: message <code>1700000000.{"order":1042,"amount":500}</code>, key <code>whsec_demo123</code>.</p>`,
    },
  });

  /* ================= Authorization models ================= */
  IN('authz-models', {
    inside: [
      ['RBAC: three tables and a join', `
        ${C('sql', `
          users(id, name)              -- 1 Sakitha, 2 Nimal
          roles(id, name)              -- 1 lecturer, 2 student
          user_roles(user_id, role_id) -- (1,1) (2,2)
          role_perms(role_id, perm)    -- (1,'marks:read') (1,'marks:write') (2,'marks:read_own')

          -- "Can user 2 do marks:write?"
          SELECT 1 FROM user_roles ur JOIN role_perms rp ON rp.role_id = ur.role_id
          WHERE ur.user_id = 2 AND rp.perm = 'marks:write';   -- no row → deny
        `)}
        <p>Users get roles. Roles get permissions. A check is one lookup. It is simple and easy to audit. It gets messy when rules depend on <b>which</b> object or <b>when</b>.</p>`],
      ['ABAC: a rule over attributes', `
        <p>ABAC looks at facts (attributes) at request time:</p>
        ${T(['Group', 'Example attributes'], [
          ['Subject (who)', 'role, department, year, clearance'],
          ['Resource (what)', 'owner, department, classification'],
          ['Action', 'read, write, delete'],
          ['Environment', 'time, IP address, device health'],
        ])}
        <div class="math">allow if  subject.dept == resource.dept
     and  action == "read"
     and  08:00 ≤ env.time &lt; 18:00</div>
        <p>Very flexible. But it is harder to answer "who can see this file?", because the answer depends on many attributes.</p>`],
      ['ReBAC: a graph of relationships', `
        <p>ReBAC stores <b>relationship tuples</b>: object, relation, subject.</p>
        ${C('text', `
          doc:cs3014-notes   #parent   @ folder:cs3014
          folder:cs3014      #viewer   @ group:cs3014-students#member
          group:cs3014-students #member @ user:nimal
        `)}
        <p>A rule says "viewers of the parent folder can view the doc". A check becomes a <b>graph search</b>: is there a path from the user to the object? This is how Google Zanzibar (Drive, YouTube) and OpenFGA / SpiceDB work.</p>`],
      ['Where the decision is made', `
        <ul>
          <li><b>PEP</b> (Policy Enforcement Point): the code that stops the request, e.g. API middleware.</li>
          <li><b>PDP</b> (Policy Decision Point): the code that answers yes/no, e.g. a function, OPA or OpenFGA.</li>
          <li><b>PIP</b> (Policy Information Point): where extra facts come from, e.g. the user directory.</li>
        </ul>
        <p>All three models share two rules: <b>default deny</b>, and check on <b>every request</b>.</p>`],
    ],
    example: {
      title: 'Decide the same kind of question with RBAC, ABAC and ReBAC',
      problem: `
        <p>Users: <b>Sakitha</b> (lecturer, dept CS), <b>Nimal</b> (student, dept CS), <b>Kamal</b> (student, dept IT).</p>
        <ol>
          <li><b>RBAC:</b> lecturer → <code>marks:read, marks:write</code>; student → <code>marks:read_own</code>. Can Nimal write marks?</li>
          <li><b>ABAC:</b> rule = "read the CS timetable if <code>user.dept == "CS"</code> and 08:00 ≤ time &lt; 18:00". Check Nimal at 10:00, Nimal at 20:30, Kamal at 10:00.</li>
          <li><b>ReBAC:</b> use the three tuples above. Can Nimal view <code>doc:cs3014-notes</code>? Can Kamal?</li>
        </ol>`,
      steps: [
        ['RBAC', `
          <p>Nimal → role student → permissions {<code>marks:read_own</code>}.</p>
          <p>Is <code>marks:write</code> in the set? No. → <b>Deny</b>.</p>`],
        ['ABAC — Nimal at 10:00', `<p>dept CS = CS ✓. 08:00 ≤ 10:00 &lt; 18:00 ✓. → <b>Allow</b>.</p>`],
        ['ABAC — Nimal at 20:30', `<p>dept ✓. 20:30 is not before 18:00 ✗. → <b>Deny</b>.</p>`],
        ['ABAC — Kamal at 10:00', `<p>dept IT ≠ CS ✗. → <b>Deny</b> (time does not matter; AND needs all).</p>`],
        ['ReBAC — Nimal', `
          <p>Start at the doc and walk the graph:</p>
          <div class="math">doc:cs3014-notes ─parent→ folder:cs3014
folder:cs3014 ─viewer→ group:cs3014-students#member
group:cs3014-students ─member→ user:nimal   ✓ path found</div>
          <p>→ <b>Allow</b>.</p>`],
        ['ReBAC — Kamal', `<p>No tuple links <code>user:kamal</code> to the group or the folder. No path. → <b>Deny</b>.</p>`],
      ],
      answer: `
        ${T(['Question', 'Answer'], [
          ['RBAC: Nimal writes marks', 'Deny'],
          ['ABAC: Nimal 10:00 / Nimal 20:30 / Kamal 10:00', 'Allow / Deny / Deny'],
          ['ReBAC: Nimal / Kamal view notes', 'Allow / Deny'],
        ])}
        <p>Pick the model by the question you need to answer. "What can a <b>role</b> do?" → RBAC. "Does this <b>situation</b> meet the rule?" → ABAC. "Is this user <b>connected</b> to this object?" → ReBAC. Real systems often mix them.</p>`,
    },
  });

  /* ================= OAuth scopes ================= */
  IN('oauth-scopes', {
    inside: [
      ['What a scope looks like', `
        <p>A scope is a short string. Several scopes are joined with spaces in the <code>scope</code> parameter:</p>
        ${C('text', `
          scope=openid email photos.read
          scope=https://www.googleapis.com/auth/calendar.readonly      (Google uses URLs)
          scope=repo read:user                                         (GitHub)
        `)}
        <p>The API owner decides the names. A good name says the resource and the action.</p>`],
      ['How the granted scopes are decided', `
        <div class="math">granted = requested ∩ allowed_for_this_client ∩ approved_by_user</div>
        <ul>
          <li><b>requested</b>: what the app asks for.</li>
          <li><b>allowed for this client</b>: what the admin let this app ever ask for.</li>
          <li><b>approved by user</b>: what the user ticked on the consent screen.</li>
        </ul>
        <p>The token reply tells the app what it really got: <code>"scope": "photos.read"</code>. The app must read this. It may be less than it asked for.</p>`],
      ['Where the scope travels', `
        ${C('json', `
          { "iss": "https://auth.example", "sub": "42", "aud": "photos-api",
            "scope": "photos.read", "exp": 1798762200 }
        `, 'Access token (JWT form). Opaque tokens give the same data through token introspection.')}`],
      ['How the API enforces it', `
        ${C('js', `
          const need = { "GET /photos": "photos.read", "POST /photos": "photos.write" };
          const granted = token.scope.split(" ");
          if (!granted.includes(need[route])) {
            res.set("WWW-Authenticate", 'Bearer error="insufficient_scope", scope="' + need[route] + '"');
            return res.status(403).end();
          }
        `)}
        <p>Scope is a <b>ceiling</b>, not a permission. The final check is:</p>
        <div class="math">allowed = token has the scope  AND  the user may do it anyway</div>
        <p>A token with <code>photos.write</code> still must not let Sakitha edit Nimal's photos.</p>`],
    ],
    example: {
      title: 'Work out the granted scopes and three API answers',
      problem: `
        <p>A photo-printing app asks for: <code>photos.read photos.write contacts.read</code>.</p>
        <ul>
          <li>The admin allows this app: <code>photos.read photos.write</code>.</li>
          <li>On the consent screen, the user ticks: <code>photos.read contacts.read</code>.</li>
        </ul>
        <p>Which scopes are in the token? What do these calls return: <code>GET /photos</code>, <code>POST /photos</code>, <code>GET /contacts</code>?</p>`,
      steps: [
        ['Intersect requested and client-allowed', `<div class="math">{read, write, contacts} ∩ {read, write} = {photos.read, photos.write}</div>`],
        ['Intersect with what the user approved', `
          <div class="math">{photos.read, photos.write} ∩ {photos.read, contacts.read} = {photos.read}</div>
          <p>The user ticked <code>contacts.read</code>, but the admin never allowed it for this app. So it drops out.</p>`],
        ['Check each call', `
          ${T(['Call', 'Needs', 'In token?', 'Result'], [
            ['GET /photos', 'photos.read', 'Yes', '<code>200 OK</code>'],
            ['POST /photos', 'photos.write', 'No', '<code>403</code> insufficient_scope'],
            ['GET /contacts', 'contacts.read', 'No', '<code>403</code> insufficient_scope'],
          ])}`],
      ],
      answer: `
        <p><b>Granted: <code>photos.read</code> only.</b> GET /photos → 200. POST /photos → 403. GET /contacts → 403.</p>
        <p>Every party can only <b>narrow</b> access, never widen it. That is the point of scopes: the app gets the smallest access that everyone agreed to.</p>`,
    },
  });

  /* ================= OPA ================= */
  IN('opa', {
    inside: [
      ['The four pieces', `
        ${T(['Piece', 'What it is', 'Example'], [
          ['Input', 'JSON the service sends for this request', '<code>{"user":"nimal","method":"POST","path":["grades"]}</code>'],
          ['Data', 'JSON OPA already holds', '<code>{"roles":{"sakitha":["lecturer"],"nimal":["student"]}}</code>'],
          ['Policy', 'Rules written in Rego', '<code>allow if { … }</code>'],
          ['Decision', 'JSON answer', '<code>{"result": false}</code>'],
        ])}`],
      ['How to read Rego', `
        <ul>
          <li><code>default allow := false</code> → if nothing matches, the answer is false.</li>
          <li>Inside one <code>allow if { … }</code> block, every line must be true. Lines are joined by <b>AND</b>.</li>
          <li>Two separate <code>allow</code> blocks are joined by <b>OR</b>. If any block is true, allow is true.</li>
          <li>There are no loops or if/else. You describe what must be true. OPA finds out if it is.</li>
        </ul>`],
      ['How a service asks', `
        ${C('http', `
          POST http://localhost:8181/v1/data/app/authz/allow
          Content-Type: application/json

          { "input": { "user": "nimal", "method": "POST", "path": ["grades"] } }
        `)}
        ${C('json', `{ "result": false }`, 'OPA replies. The service enforces it: 403.')}
        <p>OPA usually runs as a <b>sidecar</b> next to each service, so this call is local and fast (well under a millisecond for simple policies).</p>`],
      ['Where policies come from', `
        <p>Policies live in Git, like code. CI runs <code>opa test</code>. Then they are packed into a <b>bundle</b>. Each OPA downloads new bundles every few seconds or minutes. OPA can also send <b>decision logs</b> — a record of every yes/no — for audits.</p>`],
    ],
    example: {
      title: 'Evaluate a Rego policy for three requests',
      problem: `
        ${C('rego', `
          package app.authz
          import rego.v1

          default allow := false

          # rule 1: anyone may read grades
          allow if {
            input.method == "GET"
            input.path[0] == "grades"
          }

          # rule 2: lecturers may post grades
          allow if {
            input.method == "POST"
            input.path[0] == "grades"
            "lecturer" in data.roles[input.user]
          }
        `, 'policy.rego')}
        <p>Data: <code>{"roles": {"sakitha": ["lecturer"], "nimal": ["student"]}}</code></p>
        <p>What is <code>allow</code> for: (a) Nimal POST /grades, (b) Sakitha POST /grades, (c) Nimal GET /grades?</p>`,
      steps: [
        ['(a) Nimal POST /grades — rule 1', `<p><code>input.method == "GET"</code>? It is POST. ✗. Rule 1 is false. (OPA stops this rule at the first false line.)</p>`],
        ['(a) Nimal POST /grades — rule 2', `
          <p>method POST ✓. path[0] "grades" ✓.</p>
          <p><code>data.roles["nimal"]</code> = <code>["student"]</code>. Is "lecturer" in it? ✗. Rule 2 is false.</p>
          <p>No rule is true → the default is used → <b>false</b>.</p>`],
        ['(b) Sakitha POST /grades', `
          <p>Rule 1: method ✗.</p>
          <p>Rule 2: POST ✓, "grades" ✓, <code>data.roles["sakitha"]</code> = <code>["lecturer"]</code> contains "lecturer" ✓ → rule 2 true → <b>true</b>.</p>`],
        ['(c) Nimal GET /grades', `<p>Rule 1: GET ✓, "grades" ✓ → true. One true rule is enough (OR) → <b>true</b>.</p>`],
      ],
      answer: `
        ${T(['Request', 'Rule that matched', 'allow'], [
          ['(a) Nimal POST', 'none → default', '<b>false</b> → 403'],
          ['(b) Sakitha POST', 'rule 2', '<b>true</b>'],
          ['(c) Nimal GET', 'rule 1', '<b>true</b>'],
        ])}
        <p>Turn these three cases into <code>opa test</code> unit tests. Then a later policy change cannot silently let students post grades.</p>`,
    },
  });
})();
