/* "How it works inside" + "Solved example" for: AuthN vs AuthZ, Passwords, HTTP Basic,
   Sessions, API keys, JWT. Written in short, simple sentences on purpose.
   Every number in the solved examples was computed with real code (Node crypto). */
(function () {
  'use strict';
  const HS = window.HS, C = window.C, T = HS.tbl;
  const IN = (id, d) => { const t = HS.byId[id]; if (!t) return; t.inside = d.inside; t.example = d.example; };

  /* ================= AuthN vs AuthZ ================= */
  IN('concepts', {
    inside: [
      ['Two questions, in a fixed order', `
        <p>Every protected request asks two questions.</p>
        <ol>
          <li><b>Authentication (AuthN):</b> "Who are you?" The server checks a proof. The proof can be a password, a cookie, a token or a key.</li>
          <li><b>Authorization (AuthZ):</b> "Are you allowed to do this?" The server checks a rule.</li>
        </ol>
        <p>The order never changes. You cannot decide what someone may do before you know who they are.</p>`],
      ['What the server keeps after login', `
        <p>When authentication passes, the server does not keep the password. It keeps a small record of the person. This record is called the <b>principal</b> (or subject).</p>
        ${C('js', `
          // after the proof is checked, the server attaches the principal to the request
          req.user = { id: 42, name: "Sakitha", roles: ["editor"], dept: "CS" };
        `, 'The principal travels with the request inside the server')}
        <p>Every later check reads this object. Nobody checks the password again on that request.</p>`],
      ['Authorization is just a function', `
        <p>Inside the code, authorization is a function. It takes three inputs. It returns yes or no.</p>
        <div class="math">allow( subject, action, resource ) → true / false</div>
        ${C('js', `
          function allow(user, action, doc) {
            if (action === "read")   return user.roles.includes("viewer") || user.roles.includes("editor");
            if (action === "edit")   return user.roles.includes("editor");
            if (action === "delete") return doc.ownerId === user.id;   // only the owner
            return false;                                               // default: deny
          }
        `, 'A tiny authorization function')}
        <p>Look at the last line. If no rule says yes, the answer is no. This is called <b>default deny</b>.</p>`],
      ['How the answer reaches the client', `
        <p>HTTP has two different status codes. Each one matches one question.</p>
        ${T(['Code', 'Meaning', 'Which step failed', 'What the client should do'], [
          ['401 Unauthorized', 'I do not know who you are.', 'Authentication', 'Log in, or send a valid token.'],
          ['403 Forbidden', 'I know who you are. You still may not do this.', 'Authorization', 'Logging in again will not help. Ask for access.'],
          ['404 Not Found', 'Sometimes used instead of 403.', 'Authorization (hidden)', 'Used to hide that a private thing exists.'],
        ])}
        <p>The name "401 Unauthorized" is confusing. It really means "unauthenticated".</p>`],
      ['Where each part lives', `
        ${T(['Part', 'Where it lives', 'Example'], [
          ['Credential check', 'Login service or identity provider', 'Compare password hash, verify a token signature'],
          ['Proof of login', 'Client side (cookie or token)', '<code>sid=…</code> cookie, <code>Bearer eyJ…</code>'],
          ['Principal', 'Server memory, for one request', '<code>req.user</code>'],
          ['Rules (policy)', 'Code, a database table or a policy engine', '<code>allow()</code>, RBAC tables, OPA'],
          ['Object ownership', 'Next to the data', '<code>docs.owner_id</code> column'],
        ])}
        <p>Authentication usually happens once per login. Authorization happens on <b>every</b> request, for <b>every</b> object.</p>`],
    ],
    example: {
      title: 'Decide the status code for six requests',
      problem: `
        <p>A notes app has these rules:</p>
        <ul>
          <li>You must be logged in to do anything.</li>
          <li>Role <b>viewer</b> can read a note.</li>
          <li>Role <b>editor</b> can read and edit a note.</li>
          <li>Only the <b>owner</b> of a note can delete it.</li>
        </ul>
        <p>Note 7 is owned by Sakitha. The users are: Sakitha (editor), Nimal (viewer) and Kamal (editor). What does the server answer for each request?</p>
        ${T(['#', 'Request', 'Who sent it'], [
          ['A', 'GET /notes/7', 'No cookie, no token'],
          ['B', 'POST /login', 'Nimal, with a wrong password'],
          ['C', 'GET /notes/7', 'Nimal (viewer)'],
          ['D', 'PUT /notes/7', 'Nimal (viewer)'],
          ['E', 'DELETE /notes/7', 'Kamal (editor, not owner)'],
          ['F', 'DELETE /notes/7', 'Sakitha (editor, owner)'],
        ])}`,
      steps: [
        ['Ask question 1 for each request: who is it?', `
          <p>A has no proof at all. The server cannot find a principal. So A stops at authentication.</p>
          <p>B gives a proof, but the proof is wrong. B also stops at authentication.</p>
          <p>C, D, E and F carry a valid session. The server knows who they are. They move to question 2.</p>`],
        ['Ask question 2 for the rest: is this allowed?', `
          <p>C: Nimal wants to <b>read</b>. Viewers can read. Allowed.</p>
          <p>D: Nimal wants to <b>edit</b>. Only editors can edit. Nimal is a viewer. Not allowed.</p>
          <p>E: Kamal wants to <b>delete</b>. Being an editor is not enough. Only the owner can delete. Kamal is not the owner. Not allowed.</p>
          <p>F: Sakitha wants to <b>delete</b>. She is the owner. Allowed.</p>`],
        ['Turn each result into a status code', `
          <p>Failed at question 1 → <code>401</code>. Failed at question 2 → <code>403</code>. Passed both → <code>200</code> (or <code>204</code> for a delete with no body).</p>`],
      ],
      answer: `
        ${T(['#', 'Step that decided', 'Answer'], [
          ['A', 'Authentication (no proof)', '<code>401</code>'],
          ['B', 'Authentication (wrong proof)', '<code>401</code>'],
          ['C', 'Authorization: viewer may read', '<code>200 OK</code>'],
          ['D', 'Authorization: viewer may not edit', '<code>403</code>'],
          ['E', 'Authorization: not the owner', '<code>403</code>'],
          ['F', 'Authorization: owner may delete', '<code>204 No Content</code>'],
        ])}
        <p>Notice E. Kamal is logged in and is an editor. A bug that only checks "is logged in" would let him delete. That bug is called <b>broken access control</b>. It is number 1 in the OWASP Top 10.</p>`,
    },
  });

  /* ================= Passwords & hashing ================= */
  IN('passwords', {
    inside: [
      ['What a stored password really looks like', `
        <p>A good server never stores your password. It stores a <b>hash string</b>. Here is a real bcrypt hash of the password <code>sunshine</code>:</p>
        ${C('text', `
          $2a$12$gsXmj.Tn/xWLqhX.SLhwbOlBx17OG/3pKuTDVlelTKFgbPbWN63BW
        `, 'bcrypt output: 60 characters')}
        <p>The string has four parts. Each part is separated by <code>$</code>.</p>
        ${T(['Part', 'Value', 'Meaning'], [
          ['Algorithm', '<code>2a</code>', 'This is bcrypt.'],
          ['Cost', '<code>12</code>', 'Do 2<sup>12</sup> = 4,096 rounds of slow work.'],
          ['Salt', '<code>gsXmj.Tn/xWLqhX.SLhwbO</code>', '22 characters = 16 random bytes.'],
          ['Hash', '<code>lBx17OG/3pKuTDVlelTKFgbPbWN63BW</code>', '31 characters. The real result.'],
        ])}
        <p>Argon2id (the newest choice) looks similar. It also stores its settings inside the string:</p>
        ${C('text', `
          $argon2id$v=19$m=65536,t=3,p=4$ZT14/TIgiCM8zb/xFkujMg$VDt2yqSjEf1A1nxrQ4G0e92toy20XFbg3eRZOSybFLI
        `, 'm = memory in KiB (64 MiB), t = passes, p = threads, then salt, then hash')}
        <p>Because the settings live in the string, the server can raise the cost later. Old hashes still work.</p>`],
      ['How the salt is made', `
        <p>When you sign up, the server asks the operating system for random bytes. This uses a <b>CSPRNG</b> (a cryptographically secure random number generator). On Linux it reads from <code>/dev/urandom</code>.</p>
        ${C('js', `
          const salt = crypto.randomBytes(16);   // 16 random bytes, new for every user
        `)}
        <p>The salt is not a secret. It is stored next to the hash. Its only job is to make every hash different.</p>
        <p>Here is the proof. Two users both chose <code>sunshine</code>. bcrypt gave two very different strings:</p>
        ${C('text', `
          user A: $2a$12$gsXmj.Tn/xWLqhX.SLhwbOlBx17OG/3pKuTDVlelTKFgbPbWN63BW
          user B: $2a$12$OjsW9brWI8WXF63HX6sNMu5TCssyuPfiZsfksus6s4HG0omZzPWJi
        `)}
        <p>An attacker who steals the table cannot see that A and B share a password.</p>`],
      ['How login is checked', `
        <ol>
          <li>You type your password. It travels to the server inside TLS.</li>
          <li>The server loads your hash string from the database.</li>
          <li>It reads the algorithm, the cost and the salt <b>out of that string</b>.</li>
          <li>It hashes what you typed, with the same salt and the same cost.</li>
          <li>It compares the new hash with the stored hash. It uses a <b>constant-time</b> compare. That compare always takes the same time, so timing gives no clue.</li>
          <li>Same → login OK. Different → login fails.</li>
        </ol>
        <div class="math">stored  = bcrypt( cost, salt, "sunshine" )
login   = bcrypt( cost, salt, typed )
success = ( login == stored )</div>
        <p>The server never "decrypts" anything. A hash is one-way. It can only be recomputed and compared.</p>`],
      ['Why slow is good here', `
        <p>Normal hashes like SHA-256 are built to be fast. A gaming GPU can do about ten billion per second. That is great for files. It is terrible for passwords.</p>
        <p>bcrypt has a cost number. Each +1 doubles the work. Cost 12 is 2× cost 11 and 4× cost 10.</p>
        <p>Argon2id is slow in two ways. It needs time <b>and</b> memory. With <code>m=65536</code>, each guess needs 64 MiB of RAM. GPUs have many cores but little memory per core. So they cannot run many guesses at once.</p>
        <p>The goal: about 100–500 ms per login on your server. One user does not notice. An attacker making billions of guesses does.</p>`],
      ['Where each piece lives', `
        ${T(['Item', 'Lives in', 'Secret?'], [
          ['Your password', 'Only your head (or password manager)', 'Yes'],
          ['Salt', 'Database, inside the hash string', 'No'],
          ['Hash', 'Database', 'Should stay private, but built to survive a leak'],
          ['Pepper (optional)', 'Secret manager or app config, not the database', 'Yes. A DB-only leak then cannot test guesses.'],
          ['Cost settings', 'Inside the hash string + app config', 'No'],
        ])}`],
    ],
    example: {
      title: 'How long does it take to crack an 8-letter password?',
      problem: `
        <p>An attacker stole a user table. One password is 8 lowercase letters (a–z). The attacker has one GPU.</p>
        <p>Assume these speeds (round numbers, for practice):</p>
        <ul>
          <li>Plain SHA-256: <b>10,000,000,000</b> guesses per second.</li>
          <li>bcrypt cost 12: <b>1,000</b> guesses per second.</li>
        </ul>
        <p>How long does it take to try <b>every</b> possible password in each case?</p>`,
      steps: [
        ['Count the possible passwords', `
          <p>Each position has 26 choices. There are 8 positions.</p>
          <div class="math">26 × 26 × 26 × 26 × 26 × 26 × 26 × 26 = 26⁸ = 208,827,064,576</div>
          <p>That is about 209 billion passwords.</p>`],
        ['Divide by the fast speed (SHA-256)', `
          <div class="math">208,827,064,576 ÷ 10,000,000,000 ≈ 20.9 seconds</div>
          <p>Every 8-letter lowercase password falls in about 21 seconds.</p>`],
        ['Divide by the slow speed (bcrypt cost 12)', `
          <div class="math">208,827,064,576 ÷ 1,000 = 208,827,064.6 seconds</div>
          <p>Change seconds to years. One year is about 31,557,600 seconds.</p>
          <div class="math">208,827,064.6 ÷ 31,557,600 ≈ 6.6 years</div>`],
        ['Now add salt to the picture', `
          <p>Say the table has 1,000,000 users.</p>
          <p><b>No salt:</b> the attacker hashes each guess once. Then they compare it with all 1,000,000 rows. One pass cracks everyone with a weak password.</p>
          <p><b>With salt:</b> each user has a different salt. A guess must be hashed again for each user. The work becomes 1,000,000 times bigger.</p>`],
      ],
      answer: `
        <p><b>SHA-256: about 21 seconds. bcrypt cost 12: about 6.6 years.</b> The password is the same. Only the hash choice changed.</p>
        <p>Salt makes the attacker repeat this work for every user. A slow hash makes each try expensive. You need both.</p>
        <div class="callout warn"><b>But slow hashing has limits</b>A password from a common list (like <code>sunshine</code>) is tried in the first second, even with bcrypt. That is why sites also block known-breached passwords and add MFA.</div>`,
    },
  });

  /* ================= HTTP Basic & Digest ================= */
  IN('basic-auth', {
    inside: [
      ['What the header looks like', `
        <p>The browser joins the username and password with a colon. Then it Base64-encodes the result. Then it puts it in a header.</p>
        ${C('http', `
          GET /admin HTTP/1.1
          Host: example.com
          Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        `, 'username "Aladdin", password "open sesame" (the example from RFC 7617)')}
        <p>The browser sends this header again on <b>every</b> request to that site. There is no login session.</p>`],
      ['How Base64 works inside', `
        <p>Base64 turns any bytes into safe text. It works on groups of 3 bytes.</p>
        <ol>
          <li>Take 3 bytes. That is 3 × 8 = 24 bits.</li>
          <li>Cut the 24 bits into 4 pieces of 6 bits.</li>
          <li>Each 6-bit piece is a number from 0 to 63.</li>
          <li>Look up each number in the alphabet below. You get 4 characters.</li>
        </ol>
        ${T(['Numbers', 'Characters'], [
          ['0 – 25', '<code>A</code> to <code>Z</code>'],
          ['26 – 51', '<code>a</code> to <code>z</code>'],
          ['52 – 61', '<code>0</code> to <code>9</code>'],
          ['62, 63', '<code>+</code> and <code>/</code>'],
          ['(padding)', '<code>=</code> fills the end when the last group is short'],
        ])}
        <p>So 3 bytes always become 4 characters. Base64 text is about 33% longer than the input.</p>`],
      ['Base64 is not encryption', `
        <p>There is no key. Anyone can reverse it in one step. Try it in any terminal:</p>
        ${C('bash', `
          echo QWxhZGRpbjpvcGVuIHNlc2FtZQ== | base64 -d
          # Aladdin:open sesame
        `)}
        <p>So Basic auth is only safe inside HTTPS. TLS encrypts the whole request, header included.</p>`],
      ['How the server checks it', `
        <ol>
          <li>Read the <code>Authorization</code> header. Check it starts with <code>Basic </code>.</li>
          <li>Base64-decode the rest.</li>
          <li>Split at the <b>first</b> colon. Left = username. Right = password. (A password may contain colons. A username may not.)</li>
          <li>Find the user. Hash the password with the stored salt. Compare in constant time.</li>
          <li>Wrong or missing → reply <code>401</code> with <code>WWW-Authenticate: Basic realm="Admin"</code>. The browser then shows its login box.</li>
        </ol>`],
      ['How Digest hides the password (and why it is still weak)', `
        <p>Digest auth never sends the password. It sends an MD5 hash mixed with a fresh server number (the <b>nonce</b>).</p>
        <div class="math">HA1      = MD5( username : realm : password )
HA2      = MD5( method : uri )
response = MD5( HA1 : nonce : nc : cnonce : qop : HA2 )</div>
        <p>Here are the real values from the RFC 2617 example. User <code>Mufasa</code>, password <code>Circle Of Life</code>, realm <code>testrealm@host.com</code>:</p>
        ${C('text', `
          HA1      = 939e7578ed9e3c518a452acee763bce9
          HA2      = 39aff3a2bab6126f332b942af96d3366   (GET:/dir/index.html)
          response = 6629fae49393a05397450978507c4ef1
        `)}
        <p>The server does the same sum and compares. A new nonce makes every response different, so replay is hard.</p>
        <p>But look at HA1. The server must store it (or the plain password). HA1 works like a password. MD5 is also very fast to guess. That is why people now use Basic over TLS, or tokens, instead of Digest.</p>`],
    ],
    example: {
      title: 'Base64-encode a Basic auth header by hand',
      problem: `
        <p>Username <code>Aladdin</code>, password <code>open sesame</code>.</p>
        <ol>
          <li>Build the string the browser encodes.</li>
          <li>Encode the first 3 characters by hand.</li>
          <li>Work out how long the full Base64 text is, and why it ends with <code>==</code>.</li>
        </ol>`,
      steps: [
        ['Join username and password', `
          <div class="math">"Aladdin" + ":" + "open sesame" = "Aladdin:open sesame"</div>
          <p>Count the characters: 7 + 1 + 11 = <b>19 bytes</b>.</p>`],
        ['Turn the first 3 characters into bits', `
          <p>Take <code>A</code>, <code>l</code>, <code>a</code>. Look up their ASCII codes.</p>
          ${T(['Char', 'Hex', 'Binary (8 bits)'], [
            ['A', '0x41', '<code>01000001</code>'],
            ['l', '0x6C', '<code>01101100</code>'],
            ['a', '0x61', '<code>01100001</code>'],
          ])}
          <p>Put them side by side: <code>010000010110110001100001</code> (24 bits).</p>`],
        ['Cut into four 6-bit pieces', `
          ${T(['6 bits', 'Decimal', 'Base64 char'], [
            ['<code>010000</code>', '16', '<code>Q</code> (A=0, so 16 = Q)'],
            ['<code>010110</code>', '22', '<code>W</code>'],
            ['<code>110001</code>', '49', '<code>x</code> (49 − 26 = 23 → 24th lower-case letter)'],
            ['<code>100001</code>', '33', '<code>h</code> (33 − 26 = 7 → h)'],
          ])}
          <p>So <code>Ala</code> → <code>QWxh</code>.</p>`],
        ['Work out the length and the padding', `
          <p>19 bytes = 6 full groups of 3 (18 bytes) + <b>1 byte left over</b>.</p>
          <p>6 full groups → 6 × 4 = 24 characters.</p>
          <p>The last single byte (8 bits) needs 2 characters (12 bits, with 4 zero bits added). Then <code>==</code> fills the group to 4 characters.</p>
          <div class="math">24 + 2 + 2 ("==") = 28 characters</div>`],
      ],
      answer: `
        <div class="math">Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==</div>
        <p>It starts with <code>QWxh</code>, as we computed. It is 28 characters long and ends in <code>==</code>.</p>
        <p>The lesson: anyone who sees this header can decode the real password in one step. Always use Basic auth over HTTPS only.</p>`,
    },
  });

  /* ================= Sessions & cookies ================= */
  IN('sessions', {
    inside: [
      ['What a session ID looks like and how it is made', `
        <p>A session ID is just a long random string. It has no meaning inside. It is like a coat-check ticket number.</p>
        ${C('js', `
          const sid = crypto.randomBytes(16).toString("base64url");
          // e.g. "Zr3kQ8vN1pXy7Lb2Wc5Tgw"  → 22 characters, 128 random bits
        `, 'Made from the OS secure random generator')}
        <p>Never build it from the user ID, the time or a counter. Those can be guessed.</p>`],
      ['What is stored where', `
        ${T(['Place', 'What it holds', 'Example'], [
          ['Browser cookie jar', 'Only the ID', '<code>sid=Zr3kQ8vN1pXy7Lb2Wc5Tgw</code>'],
          ['Session store (Redis / DB)', 'The real data, keyed by the ID', '<code>sess:Zr3k… → {"userId":42,"role":"editor","csrf":"t9Lm…"}</code>, expires in 30 min'],
          ['App server memory', 'Nothing between requests', 'It looks up the store each time'],
        ])}
        <p>The important point: the <b>truth lives on the server</b>. The browser only holds a pointer. So the server can delete a session at any time. That is instant logout.</p>`],
      ['The Set-Cookie line, flag by flag', `
        ${C('http', `
          HTTP/1.1 302 Found
          Location: /dashboard
          Set-Cookie: sid=Zr3kQ8vN1pXy7Lb2Wc5Tgw; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=1800
        `)}
        ${T(['Flag', 'What it does', 'Attack it blocks'], [
          ['<code>HttpOnly</code>', 'JavaScript cannot read the cookie.', 'XSS stealing the session'],
          ['<code>Secure</code>', 'Sent only over HTTPS.', 'Sniffing on open Wi-Fi'],
          ['<code>SameSite=Lax</code>', 'Not sent on most requests started by other sites.', 'Most CSRF'],
          ['<code>Max-Age=1800</code>', 'Browser drops it after 30 minutes.', 'Old cookies living forever'],
          ['<code>Path=/</code>', 'Sent for the whole site.', '(scope, not security)'],
        ])}`],
      ['What happens on every request', `
        <ol>
          <li>The browser adds <code>Cookie: sid=Zr3k…</code> by itself.</li>
          <li>The server reads the ID and runs <code>GET sess:Zr3k…</code> in Redis.</li>
          <li>Not found or expired → treat as logged out (redirect to login or <code>401</code>).</li>
          <li>Found → put the data in <code>req.user</code>. Often the expiry is pushed forward ("sliding" expiry).</li>
        </ol>
        <p>This lookup is one fast key read. It is the price of easy revocation.</p>`],
      ['Signed cookies and ID rotation', `
        <p>Many frameworks also <b>sign</b> the cookie. Express does this:</p>
        ${C('text', `
          sid = s:Zr3kQ8vN1pXy7Lb2Wc5Tgw.Jq4c9vK…   →  "s:" + id + "." + HMAC-SHA256(secret, id)
        `)}
        <p>If anyone changes one letter of the ID, the HMAC no longer matches. The server rejects it before it even asks Redis.</p>
        <p>One more rule: <b>make a new ID at login</b>. If the old ID stays, an attacker who planted it before login now shares your session. This attack is called <b>session fixation</b>.</p>`],
    ],
    example: {
      title: 'Can an attacker guess a valid session ID?',
      problem: `
        <p>A site has <b>1,000</b> users logged in. An attacker sends guesses for the session cookie.</p>
        <ol>
          <li>Design 1: the session ID is a 6-digit number (000000–999999). The attacker can try <b>100</b> per second.</li>
          <li>Design 2: the session ID is 128 random bits. Now there are <b>1,000,000</b> active sessions, and the attacker can try <b>1,000,000,000</b> per second.</li>
        </ol>
        <p>About how long until the attacker hits some valid session?</p>`,
      steps: [
        ['Design 1: find the chance of one guess', `
          <p>There are 1,000,000 possible IDs. 1,000 of them are valid.</p>
          <div class="math">P(hit) = 1,000 ÷ 1,000,000 = 1 / 1,000</div>
          <p>So on average the attacker needs about <b>1,000</b> guesses.</p>`],
        ['Design 1: turn guesses into time', `
          <div class="math">1,000 guesses ÷ 100 per second = 10 seconds</div>`],
        ['Design 2: count the possible IDs', `
          <div class="math">2¹²⁸ ≈ 340,282,366,920,938,463,463,374,607,431,768,211,456 ≈ 3.4 × 10³⁸</div>
          <p>Valid IDs: 10⁶. Guesses needed on average:</p>
          <div class="math">3.4 × 10³⁸ ÷ 10⁶ = 3.4 × 10³²</div>`],
        ['Design 2: turn guesses into time', `
          <div class="math">3.4 × 10³² ÷ 10⁹ per second = 3.4 × 10²³ seconds</div>
          <div class="math">3.4 × 10²³ ÷ 31,557,600 (seconds in a year) ≈ 1.08 × 10¹⁶ years</div>
          <p>The universe is about 1.4 × 10¹⁰ years old.</p>`],
      ],
      answer: `
        <p><b>Design 1 falls in about 10 seconds. Design 2 needs about 10 million billion years</b> — even with a much faster attacker and many more sessions.</p>
        <p>This is why OWASP asks for at least 64 bits of randomness, and most frameworks use 128 bits or more. Session security comes from randomness, not from hiding the cookie name.</p>`,
    },
  });

  /* ================= API keys ================= */
  IN('api-keys', {
    inside: [
      ['What an API key looks like', `
        <p>Most modern keys have two parts: a readable <b>prefix</b> and a long <b>random</b> part.</p>
        ${C('text', `
          hfg_live_7Qm2Xc9TfV4kLp8ZrW3nYb6HsJ1dGa5E
          └──┬───┘└────────────── 32 random characters ─────────────┘
           prefix: product + environment
        `, 'Example key used on this page (not a real key)')}
        <p>Real examples: Stripe uses <code>sk_live_…</code>. GitHub uses <code>ghp_…</code>. The prefix helps people and secret scanners spot a leaked key. GitHub even puts a checksum in the last 6 characters, so scanners can reject random look-alikes.</p>`],
      ['How the key is made', `
        <p>The server picks each of the 32 characters at random from 62 options (A–Z, a–z, 0–9). It uses the secure random generator.</p>
        <div class="math">bits of randomness = 32 × log₂(62) = 32 × 5.954 ≈ 190 bits</div>
        <p>190 bits is far beyond any guessing attack. So the risk is not guessing. The risk is <b>leaking</b>.</p>`],
      ['What the server stores (and what it does not)', `
        <p>The server shows the full key <b>once</b>, at creation. Then it stores only a hash.</p>
        ${T(['Column', 'Value', 'Why'], [
          ['key_hash', '<code>4c76813bdd4cdf1c…4da15227</code> (SHA-256)', 'A database leak does not reveal usable keys'],
          ['prefix', '<code>hfg_live_7Qm2</code>', 'So the dashboard can show "key ending 7Qm2…"'],
          ['owner', '<code>acct_42</code>', 'Who pays and who is responsible'],
          ['scopes', '<code>orders:read</code>', 'Least privilege'],
          ['created / last_used / revoked', 'dates', 'Rotation and clean-up'],
        ])}
        <p>Why plain SHA-256 and not bcrypt? A password is weak, so it needs a slow hash. This key already has 190 random bits. A fast hash is enough, and it keeps every API call quick.</p>`],
      ['What happens on each request', `
        ${C('http', `
          GET /v1/orders HTTP/1.1
          Authorization: Bearer hfg_live_7Qm2Xc9TfV4kLp8ZrW3nYb6HsJ1dGa5E
        `)}
        <ol>
          <li>The gateway hashes the key it received with SHA-256.</li>
          <li>It looks up that hash in an index. One row or none.</li>
          <li>It checks: not revoked? Scope allows this endpoint? Under the rate limit?</li>
          <li>All yes → forward the request with the account ID attached.</li>
        </ol>`],
      ['Where the key should live', `
        ${T(['Place', 'OK?'], [
          ['A secret manager (Vault, AWS Secrets Manager) or CI secret', '<b>Yes</b>. Loaded at runtime.'],
          ['An environment variable on the server', 'OK for small setups'],
          ['Source code or a Git repo', '<b>No</b>. Bots scan GitHub within minutes.'],
          ['A mobile app or browser JavaScript', '<b>No</b>. Anyone can read it from the app.'],
        ])}`],
    ],
    example: {
      title: 'Store a new key and check two requests',
      problem: `
        <p>The server just created the key <code>hfg_live_7Qm2Xc9TfV4kLp8ZrW3nYb6HsJ1dGa5E</code> for account <code>acct_42</code>.</p>
        <ol>
          <li>What value goes into the database?</li>
          <li>Request 1 sends the exact key. Request 2 sends the same key with the <b>last letter changed</b> from <code>E</code> to <code>F</code>. What happens to each?</li>
        </ol>`,
      steps: [
        ['Hash the new key', `
          <div class="math">SHA-256("hfg_live_7Qm2Xc9TfV4kLp8ZrW3nYb6HsJ1dGa5E")
= 4c76813bdd4cdf1c23d304677cc5c06a4143baaeff23973fe4a566374da15227</div>
          <p>Store this hash with the owner and scopes. Show the full key to the user once. Then forget it.</p>`],
        ['Request 1: the exact key', `
          <p>The gateway hashes what it got. It gets <code>4c76813b…4da15227</code> again. The lookup finds the row for <code>acct_42</code>. Access is checked against its scopes.</p>`],
        ['Request 2: one letter different', `
          <div class="math">SHA-256("hfg_live_7Qm2Xc9TfV4kLp8ZrW3nYb6HsJ1dGa5F")
= 6b0fa21f3db4abad1bd2f33c7eb4ae56c60cfe559ee7a1598f441678cca9506b</div>
          <p>One input letter changed. The whole hash changed. This is the <b>avalanche effect</b>. The lookup finds no row.</p>`],
        ['Check the guessing risk', `
          <p>The random part has about 190 bits. Even at a trillion guesses per second, the expected time is far longer than the age of the universe. So the reply to bad keys can simply be <code>401</code>, plus a rate limit to stop noise.</p>`],
      ],
      answer: `
        <p><b>Database:</b> <code>4c76813bdd4cdf1c23d304677cc5c06a4143baaeff23973fe4a566374da15227</code> (never the key itself).</p>
        <p><b>Request 1:</b> hash matches → allowed (if the scope fits). <b>Request 2:</b> hash <code>6b0fa21f…</code> matches nothing → <code>401 Unauthorized</code>.</p>
        <p>If this database leaks, the attacker gets only hashes. They cannot turn a hash back into a working key.</p>`,
    },
  });

  /* ================= JWT ================= */
  IN('jwt', {
    inside: [
      ['What a JWT looks like', `
        <p>A JWT is three Base64url strings joined by dots.</p>
        <div class="math"><span class="hl1">HEADER</span> . <span class="hl2">PAYLOAD</span> . <span class="hl3">SIGNATURE</span></div>
        <ul>
          <li><b>Header</b>: which algorithm signed it, e.g. <code>{"alg":"HS256","typ":"JWT"}</code>.</li>
          <li><b>Payload</b>: the claims (who, roles, expiry).</li>
          <li><b>Signature</b>: proof that nobody changed the first two parts.</li>
        </ul>
        <p>The header and payload are <b>encoded, not encrypted</b>. Anyone can read them. Never put secrets inside.</p>`],
      ['Base64url, not plain Base64', `
        <p>Tokens go into URLs and headers. So JWT uses a URL-safe Base64:</p>
        <ul>
          <li><code>+</code> becomes <code>-</code></li>
          <li><code>/</code> becomes <code>_</code></li>
          <li>The <code>=</code> padding is removed.</li>
        </ul>`],
      ['How the signature is made', `
        <p>First build the <b>signing input</b>: header and payload, joined with a dot.</p>
        <div class="math">signing_input = base64url(header) + "." + base64url(payload)</div>
        <p><b>HS256</b> (shared secret). One secret both signs and checks:</p>
        <div class="math">signature = base64url( HMAC-SHA256( secret, signing_input ) )</div>
        <p><b>RS256</b> (key pair). The auth server signs with its private key. Every API checks with the public key:</p>
        <div class="math">signature = RSA-sign( privateKey, SHA-256(signing_input) )
valid?    = RSA-verify( publicKey, SHA-256(signing_input), signature )</div>
        <p>With RS256, APIs never hold anything that can create tokens. They only hold the public key. That is safer when many services verify.</p>`],
      ['How a server verifies (in this order)', `
        <ol>
          <li>Split on the dots. Exactly 3 parts, or reject.</li>
          <li>Decode the header. Read <code>kid</code> to choose the key.</li>
          <li><b>Use the algorithm you expect</b>, not the one in the header. (An attacker can write <code>"alg":"none"</code>.)</li>
          <li>Recompute or verify the signature. Compare in constant time.</li>
          <li>Only now trust the payload. Check <code>exp</code> (not expired), <code>nbf</code>, <code>iss</code> (right issuer) and <code>aud</code> (meant for me).</li>
        </ol>`],
      ['Where everything lives', `
        ${T(['Item', 'Lives on', 'Secret?'], [
          ['HS256 secret', 'Auth server + every verifier', 'Yes (that is its weakness)'],
          ['RS256 private key', 'Auth server only (ideally in a KMS/HSM)', 'Yes'],
          ['RS256 public key', 'Published at <code>/.well-known/jwks.json</code>', 'No'],
          ['The token', 'Client: memory or an HttpOnly cookie', 'Yes — it is a bearer credential'],
          ['Revocation list (optional)', 'Server cache, by <code>jti</code>', 'No'],
        ])}`],
    ],
    example: {
      title: 'Build and verify an HS256 JWT by hand',
      problem: `
        <p>Secret: <code>my-secret</code>. Header: <code>{"alg":"HS256","typ":"JWT"}</code>.</p>
        <p>Payload: <code>{"sub":"42","name":"Sakitha","role":"student","exp":1798761600}</code>.</p>
        <ol>
          <li>Build the full token.</li>
          <li>An attacker changes <code>"student"</code> to <code>"admin"</code> but keeps the old signature. Does the server accept it?</li>
        </ol>`,
      steps: [
        ['Encode the header', `
          <div class="math">base64url('{"alg":"HS256","typ":"JWT"}')
= eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9</div>
          <p>Tip: almost every JWT starts with <code>eyJ</code>. That is Base64 for <code>{"</code>.</p>`],
        ['Encode the payload', `
          <div class="math">base64url('{"sub":"42","name":"Sakitha","role":"student","exp":1798761600}')
= eyJzdWIiOiI0MiIsIm5hbWUiOiJTYWtpdGhhIiwicm9sZSI6InN0dWRlbnQiLCJleHAiOjE3OTg3NjE2MDB9</div>
          <p><code>exp</code> is Unix time. 1798761600 = 1 January 2027, 00:00 UTC.</p>`],
        ['Sign', `
          <div class="math">HMAC-SHA256( "my-secret", header + "." + payload )
→ base64url → IBiw7ql61bigzOtAxYB4UuXB9OHiPC4wTHLgkfbwXJM</div>`],
        ['Join the three parts', `
          ${C('text', `
            eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsIm5hbWUiOiJTYWtpdGhhIiwicm9sZSI6InN0dWRlbnQiLCJleHAiOjE3OTg3NjE2MDB9.IBiw7ql61bigzOtAxYB4UuXB9OHiPC4wTHLgkfbwXJM
          `, 'The finished token')}`],
        ['Check the tampered token', `
          <p>The attacker's new payload encodes to <code>eyJzdWIiOiI0MiIs…ImFkbWluIiwiZXhwIjoxNzk4NzYxNjAwfQ</code>. They keep the old signature <code>IBiw7ql6…</code>.</p>
          <p>The server recomputes HMAC over the <b>new</b> header.payload with its secret:</p>
          <div class="math">expected = OyIKy6qQeXUpd1LdNYlWd8iGr4j2EVAJnBg5lA1zgzU
received = IBiw7ql61bigzOtAxYB4UuXB9OHiPC4wTHLgkfbwXJM   → different</div>
          <p>The attacker cannot make the right value. That needs <code>my-secret</code>.</p>`],
      ],
      answer: `
        <p><b>Token:</b> <code>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi…MDB9.IBiw7ql61bigzOtAxYB4UuXB9OHiPC4wTHLgkfbwXJM</code></p>
        <p><b>Tampered token:</b> rejected with <code>401</code>, because the signature does not match.</p>
        <p>You can check this yourself in the JWT playground below. Paste the token and use the secret <code>my-secret</code>.</p>
        <div class="callout warn"><b>Real-world note</b><code>my-secret</code> is far too short for HS256. Use at least 32 random bytes. Short secrets can be brute-forced offline from one captured token.</div>`,
    },
  });
})();
