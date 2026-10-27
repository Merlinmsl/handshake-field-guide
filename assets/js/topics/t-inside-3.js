/* "How it works inside" + "Solved example" for: SSO, SAML, Kerberos, LDAP, RADIUS.
   Short, simple sentences. Hash and XOR values were computed with real code. */
(function () {
  'use strict';
  const HS = window.HS, C = window.C, T = HS.tbl;
  const IN = (id, d) => { const t = HS.byId[id]; if (!t) return; t.inside = d.inside; t.example = d.example; };

  /* ================= SSO ================= */
  IN('sso', {
    inside: [
      ['Two kinds of session, on different domains', `
        <p>SSO works because there are <b>two layers</b> of sessions.</p>
        ${T(['Cookie', 'Set on domain', 'Made when', 'Typical life'], [
          ['IdP session', '<code>login.sliit.lk</code>', 'You type your password (and MFA) at the IdP', '8–12 hours'],
          ['App A session', '<code>moodle.sliit.lk</code>', 'App A accepts a login from the IdP', '30–60 minutes'],
          ['App B session', '<code>mail.sliit.lk</code>', 'App B accepts a login from the IdP', '30–60 minutes'],
        ])}
        <p>Browsers only send a cookie to the domain that set it. So App A cannot see the IdP cookie. But the IdP can. That is the trick.</p>`],
      ['What happens when you open a second app', `
        <ol>
          <li>You open App B. It has no session for you.</li>
          <li>App B redirects your browser to the IdP with a login request.</li>
          <li>Your browser sends the <b>IdP cookie</b> with that request.</li>
          <li>The IdP sees a valid session. It does not ask for a password.</li>
          <li>It makes a signed assertion (SAML) or ID token (OIDC) for App B.</li>
          <li>It sends the browser back to App B with it. App B verifies the signature and creates its own session.</li>
        </ol>
        <p>All of this takes about one second. To you it looks like "I was already logged in".</p>`],
      ['How the trust is set up (once, by admins)', `
        ${T(['App knows about the IdP', 'IdP knows about the app'], [
          ['IdP login URL', 'App ID (Entity ID or client_id)'],
          ['IdP public signing key / certificate (or JWKS URL)', 'Where to send users back (ACS URL / redirect URI)'],
          ['Expected issuer name', 'Which user attributes the app may receive'],
        ])}
        <p>This exchange is called <b>metadata</b> (SAML) or <b>client registration</b> (OIDC). After it, no passwords are shared between systems.</p>`],
      ['Logging out is harder than logging in', `
        <ul>
          <li><b>Local logout</b>: App A deletes its cookie. The IdP session is still alive. Opening App A again logs you straight back in.</li>
          <li><b>IdP logout</b>: the IdP cookie is deleted. Apps that already have sessions keep them until they expire.</li>
          <li><b>Single Logout (SLO)</b>: the IdP tells every app to end your session — by browser redirects (front-channel) or server calls (back-channel). Back-channel is more reliable.</li>
        </ul>`],
    ],
    example: {
      title: 'Count the password prompts in one day',
      problem: `
        <p>Your university uses SSO. Rules:</p>
        <ul>
          <li>IdP session lasts <b>8 hours</b> from when you type your password.</li>
          <li>Each app session lasts <b>1 hour</b> from when it is created.</li>
        </ul>
        <p>Your day:</p>
        ${T(['Time', 'You open'], [
          ['09:00', 'Moodle (App A)'],
          ['09:30', 'Email (App B)'],
          ['10:15', 'Moodle again'],
          ['17:30', 'Email again'],
        ])}
        <p>How many times do you type your password? How many app logins happen?</p>`,
      steps: [
        ['09:00 — Moodle', `
          <p>Moodle session? No. Redirect to IdP. IdP session? No. → <b>Password prompt #1</b>.</p>
          <p>IdP session now valid until <b>17:00</b>. Moodle session valid until <b>10:00</b>.</p>`],
        ['09:30 — Email', `
          <p>Email session? No. Redirect to IdP. IdP session? Yes (until 17:00). → <b>No prompt</b>.</p>
          <p>Email session valid until <b>10:30</b>.</p>`],
        ['10:15 — Moodle again', `
          <p>Moodle session ended at 10:00. Redirect to IdP. IdP still valid. → <b>No prompt</b>.</p>
          <p>New Moodle session until <b>11:15</b>. You probably saw a quick page flash, nothing more.</p>`],
        ['17:30 — Email again', `
          <p>Email session ended at 10:30. Redirect to IdP. IdP session ended at 17:00. → <b>Password prompt #2</b>.</p>`],
      ],
      answer: `
        <p><b>2 password prompts. 4 app logins</b> (09:00, 09:30, 10:15, 17:30).</p>
        <p>Without SSO it would be 4 prompts, with possibly 2 different passwords. That is the whole value of SSO: one strong login, many apps.</p>
        <p>The flip side: anyone who steals your IdP session cookie at 12:00 gets into every app until 17:00. Protect that cookie and use MFA at the IdP.</p>`,
    },
  });

  /* ================= SAML 2.0 ================= */
  IN('saml', {
    inside: [
      ['The two messages', `
        <p><b>1. AuthnRequest (App → IdP).</b> A small XML message: "Please log this user in for me." It travels in the URL (HTTP-Redirect binding). To fit, it is compressed with DEFLATE, then Base64, then URL-encoded:</p>
        ${C('text', `
          https://idp.sliit.lk/sso?SAMLRequest=fZJNT8MwDIb%2FSpV7m7ZsFKJ1Utk0aRIHtLEDF%2BSlLo2UjxK…&RelayState=%2Fcourses
        `)}
        <p><b>2. Response (IdP → App).</b> A larger XML message with the <b>Assertion</b> inside. It is too big for a URL. So the IdP returns an HTML form that the browser auto-submits (HTTP-POST binding). The XML is Base64-encoded in a hidden field called <code>SAMLResponse</code>.</p>`],
      ['What an assertion looks like', `
        ${C('xml', `
          <saml:Assertion ID="_a1b2c3" IssueInstant="2026-10-27T10:00:00Z" Version="2.0">
            <saml:Issuer>https://idp.sliit.lk</saml:Issuer>
            <ds:Signature> … </ds:Signature>
            <saml:Subject>
              <saml:NameID>it24103215@my.sliit.lk</saml:NameID>
              <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="_req77"
                    Recipient="https://moodle.sliit.lk/saml/acs" NotOnOrAfter="2026-10-27T10:05:00Z"/>
              </saml:SubjectConfirmation>
            </saml:Subject>
            <saml:Conditions NotBefore="2026-10-27T09:59:30Z" NotOnOrAfter="2026-10-27T10:05:00Z">
              <saml:AudienceRestriction><saml:Audience>https://moodle.sliit.lk/saml</saml:Audience></saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AuthnStatement AuthnInstant="2026-10-27T09:59:58Z"/>
            <saml:AttributeStatement>
              <saml:Attribute Name="role"><saml:AttributeValue>student</saml:AttributeValue></saml:Attribute>
            </saml:AttributeStatement>
          </saml:Assertion>
        `, 'Shortened assertion. Each block answers one question.')}
        ${T(['Element', 'Question it answers'], [
          ['Issuer', 'Who made this?'],
          ['Subject / NameID', 'Who is the user?'],
          ['SubjectConfirmationData', 'Which request is this an answer to, and where must it be delivered?'],
          ['Conditions', 'When is it valid, and for which app (Audience)?'],
          ['AuthnStatement', 'When and how did the user log in?'],
          ['AttributeStatement', 'Extra facts: email, role, groups.'],
        ])}`],
      ['How the XML signature works', `
        <p>XML can be written in many equal ways (spaces, attribute order). So the signer first makes it <b>canonical</b> — one standard form. This is called <b>C14N</b>.</p>
        <ol>
          <li><b>Digest.</b> Canonicalize the Assertion (without the Signature element). Hash it with SHA-256. Base64 the result. That is the <code>DigestValue</code>.</li>
          <li><b>SignedInfo.</b> Build a small XML block. It names the algorithms, the element ID (<code>#_a1b2c3</code>) and the DigestValue.</li>
          <li><b>Signature.</b> Canonicalize SignedInfo. Sign it with the IdP's RSA private key. Base64 → <code>SignatureValue</code>.</li>
        </ol>
        <p>Example digest of a tiny assertion:</p>
        ${C('text', `
          input : <saml:Assertion ID="_a1b2c3" IssueInstant="2026-10-27T10:00:00Z"><saml:Issuer>https://idp.sliit.lk</saml:Issuer></saml:Assertion>
          SHA-256 → base64 : dZrR2yayZb99TbNEiPQBgwlZze+znXUm3TMTWldTboI=
        `)}
        <p>The app checks in reverse: verify SignatureValue with the IdP certificate from metadata → this proves SignedInfo is real → recompute the digest of the referenced element → it must equal DigestValue.</p>`],
      ['What lives where', `
        ${T(['Item', 'Lives on', 'Secret?'], [
          ['IdP signing private key', 'IdP only', '<b>Yes</b>. Steal it and you can log in as anyone (the "Golden SAML" attack).'],
          ['IdP signing certificate', 'Every app, from IdP metadata', 'No'],
          ['App Entity ID + ACS URL', 'IdP config', 'No'],
          ['Request IDs sent (e.g. _req77)', 'App, short-term cache', 'No. Used to match InResponseTo and stop replay.'],
        ])}`],
      ['The trap: check the element you actually use', `
        <p>An attacker can add a second, unsigned Assertion into a signed Response. A careless app verifies the signature on one element but reads the user from the other. This is <b>XML Signature Wrapping</b>.</p>
        <p>The fix: take the user only from the exact element the signature points to (by its ID). Use a well-tested SAML library. Do not parse it yourself.</p>`],
    ],
    example: {
      title: 'Validate a SAML assertion at the app',
      problem: `
        <p>Moodle (the SP) receives the assertion shown above. Facts on the Moodle side:</p>
        <ul>
          <li>Its Entity ID: <code>https://moodle.sliit.lk/saml</code></li>
          <li>Its ACS URL: <code>https://moodle.sliit.lk/saml/acs</code></li>
          <li>It sent request <code>_req77</code> a moment ago and has not used it yet.</li>
          <li>Allowed clock skew: <b>30 seconds</b>.</li>
          <li>Signature and digest check out with the IdP certificate.</li>
        </ul>
        <p>Q1: The browser posts it at <b>10:05:20</b> (Moodle's clock). Accept?<br>Q2: What if it arrives at <b>10:05:40</b>?<br>Q3: What if the same Response is posted again at 10:02?</p>`,
      steps: [
        ['Signature and Issuer', `<p>Signature valid. Issuer = <code>https://idp.sliit.lk</code>, which is the IdP in Moodle's metadata. Pass.</p>`],
        ['Audience and Recipient', `
          <p>Audience = <code>https://moodle.sliit.lk/saml</code> = Moodle's Entity ID. Pass.</p>
          <p>Recipient = <code>https://moodle.sliit.lk/saml/acs</code> = where it was posted. Pass.</p>`],
        ['InResponseTo', `<p><code>_req77</code> is in Moodle's list of open requests. Pass. Now remove it from the list, so it cannot be used again.</p>`],
        ['Time window, with skew (Q1)', `
          <p>Valid window: NotBefore − skew ≤ now &lt; NotOnOrAfter + skew.</p>
          <div class="math">09:59:30 − 30 s = 09:59:00
10:05:00 + 30 s = 10:05:30
09:59:00 ≤ 10:05:20 &lt; 10:05:30   ✓</div>`],
        ['Time window (Q2)', `<div class="math">10:05:40 &lt; 10:05:30 ?   ✗  → too late</div>`],
        ['Replay (Q3)', `<p>At 10:02 the time is fine. But <code>_req77</code> was already used and removed. The assertion ID <code>_a1b2c3</code> is also in the "seen" cache. Reject.</p>`],
      ],
      answer: `
        <p><b>Q1: accept</b> — the user becomes <code>it24103215@my.sliit.lk</code> with role <code>student</code>.</p>
        <p><b>Q2: reject</b> — it arrived 10 seconds after the window closed.</p>
        <p><b>Q3: reject</b> — a replay of an already used response.</p>
        <p>Keep the window short (a few minutes) and keep servers on NTP time. Most "SAML suddenly fails" tickets are clock drift.</p>`,
    },
  });

  /* ================= Kerberos ================= */
  IN('kerberos', {
    inside: [
      ['Three long-term keys', `
        <p>Kerberos is built on <b>symmetric</b> keys. A key can lock a box, and the same key opens it. The KDC (on a Windows domain controller) knows every key.</p>
        ${T(['Key', 'Known by', 'Made from'], [
          ['User key (K<sub>user</sub>)', 'You (from your password) + KDC', 'Your password'],
          ['krbtgt key (K<sub>tgs</sub>)', 'KDC only', 'Random, set by the domain'],
          ['Service key (K<sub>svc</sub>)', 'The file server + KDC', 'The service account\'s password / random'],
        ])}
        <p>Two more keys are made fresh for each login. They are called <b>session keys</b>: SK1 (you ↔ KDC) and SK2 (you ↔ service).</p>`],
      ['How your password becomes a key', `
        <p>Your PC never sends your password. It turns it into an AES key on your own machine:</p>
        <div class="math">salt  = REALM + username   e.g. "SLIIT.LKsakitha"
tmp   = PBKDF2-HMAC-SHA1( password, salt, 4096 rounds )
Kuser = one extra AES step on tmp   (AES-256 key, 32 bytes)</div>
        <p>The KDC stores the same key (not the password). So both sides hold K<sub>user</sub> without ever sending it.</p>`],
      ['Exchange 1: AS (get a TGT)', `
        <ol>
          <li>Your PC encrypts the current time with K<sub>user</sub>. This is <b>pre-authentication</b>. It proves you know the password.</li>
          <li>The KDC decrypts it with its copy of K<sub>user</sub>. Is the time within 5 minutes? Yes → you are real.</li>
          <li>The KDC makes SK1. It sends back two boxes:
            <ul>
              <li><b>TGT</b> = {your name, SK1, expiry} locked with K<sub>tgs</sub>. You cannot open it.</li>
              <li>{SK1} locked with K<sub>user</sub>. You open this one.</li>
            </ul></li>
        </ol>
        <p>From now on, your PC does not need your password key for tickets. It keeps the TGT and SK1 for about 10 hours.</p>`],
      ['Exchange 2: TGS (get a service ticket)', `
        <ol>
          <li>You want <code>cifs/files.sliit.lk</code>. You send the TGT plus an <b>authenticator</b> = {your name, time} locked with SK1.</li>
          <li>The KDC opens the TGT with K<sub>tgs</sub>. Inside it finds SK1. With SK1 it opens the authenticator. Names match, time is fresh.</li>
          <li>The KDC makes SK2. It sends back:
            <ul>
              <li><b>Service ticket</b> = {your name, groups (the PAC), SK2, expiry} locked with K<sub>svc</sub>.</li>
              <li>{SK2} locked with SK1.</li>
            </ul></li>
        </ol>`],
      ['Exchange 3: AP (use the service)', `
        <ol>
          <li>You send the service ticket plus a new authenticator locked with SK2.</li>
          <li>The file server opens the ticket with its own K<sub>svc</sub>. It finds SK2 and your groups. With SK2 it opens the authenticator.</li>
          <li>It checks the time (±5 minutes) and a replay cache. Then it grants access by your groups.</li>
        </ol>
        <p>The file server never talked to the KDC. It trusts the ticket because only the KDC (and itself) know K<sub>svc</sub>.</p>
        ${C('text', `
          C:\\> klist
          #0>  Client: sakitha @ SLIIT.LK
               Server: krbtgt/SLIIT.LK @ SLIIT.LK          ← your TGT
               KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
               End Time: 10/27/2026 20:00:00
          #1>  Client: sakitha @ SLIIT.LK
               Server: cifs/files.sliit.lk @ SLIIT.LK      ← a service ticket
        `, 'See your tickets on Windows (klist) or Linux (klist)')}`],
    ],
    example: {
      title: 'Who can open which box?',
      problem: `
        <p>During one Kerberos login these encrypted boxes are created. For each box, say <b>which key</b> locks it and <b>who can open it</b>:</p>
        <ol>
          <li>The pre-auth timestamp.</li>
          <li>The TGT.</li>
          <li>The copy of SK1 sent to you.</li>
          <li>The service ticket.</li>
          <li>The authenticator sent to the file server.</li>
        </ol>
        <p>Then: your PC clock says 10:03. The file server clock says 10:09. What happens at step 3 (AP)?</p>`,
      steps: [
        ['Box 1: pre-auth timestamp', `<p>Locked with K<sub>user</sub>. Opened by the <b>KDC</b> (it has your key). This proves you know the password, without sending it.</p>`],
        ['Box 2: TGT', `<p>Locked with K<sub>tgs</sub>. Only the <b>KDC</b> can open it. You carry it like a sealed envelope.</p>`],
        ['Box 3: your copy of SK1', `<p>Locked with K<sub>user</sub>. <b>You</b> open it. Now you and the KDC share SK1.</p>`],
        ['Box 4: service ticket', `<p>Locked with K<sub>svc</sub>. Only the <b>file server</b> (and the KDC) can open it. You carry it but cannot read or change it.</p>`],
        ['Box 5: authenticator to the file server', `<p>Locked with SK2. The <b>file server</b> opens it, after it got SK2 out of box 4. This proves the ticket is being used by the person it was issued to.</p>`],
        ['The clock problem', `
          <div class="math">10:09 − 10:03 = 6 minutes  &gt;  5 minutes allowed</div>
          <p>The server thinks the authenticator is too old. It could be a replay. It refuses.</p>`],
      ],
      answer: `
        ${T(['Box', 'Locked with', 'Opened by'], [
          ['1. Pre-auth timestamp', 'K<sub>user</sub>', 'KDC'],
          ['2. TGT', 'K<sub>tgs</sub>', 'KDC only'],
          ['3. SK1 for you', 'K<sub>user</sub>', 'You'],
          ['4. Service ticket', 'K<sub>svc</sub>', 'File server'],
          ['5. Authenticator', 'SK2', 'File server'],
        ])}
        <p>With a 6-minute difference the server returns <code>KRB_AP_ERR_SKEW</code>. Fix the clocks (domain machines sync time from the domain controller).</p>
        <p>Notice box 4. If an attacker steals K<sub>svc</sub>, they can make their own service tickets — a "Silver Ticket". If they steal K<sub>tgs</sub>, they can make TGTs for anyone — a "Golden Ticket".</p>`,
    },
  });

  /* ================= LDAP / AD ================= */
  IN('ldap', {
    inside: [
      ['The directory is a tree', `
        <p>LDAP stores entries in a tree, like folders. Every entry has a full path called a <b>DN</b> (Distinguished Name). Read a DN from right to left:</p>
        <div class="math">uid=sakitha , ou=students , dc=sliit , dc=lk
   person      folder        domain: sliit.lk</div>
        ${C('text', `
          dc=sliit,dc=lk
          ├── ou=students
          │   ├── uid=sakitha
          │   └── uid=nimal
          ├── ou=staff
          └── ou=groups
              └── cn=cs-y3
        `)}`],
      ['What one entry looks like (LDIF)', `
        ${C('text', `
          dn: uid=sakitha,ou=students,dc=sliit,dc=lk
          objectClass: inetOrgPerson
          uid: sakitha
          cn: Sakitha Loku Narangoda
          mail: sakitha@my.sliit.lk
          memberOf: cn=cs-y3,ou=groups,dc=sliit,dc=lk
          userPassword: {SSHA}pVM1m+a9asU+I4eOuJQ7BbpyJKWhssPU
        `, 'LDIF: one attribute per line')}`],
      ['How the password is stored', `
        <p>OpenLDAP often uses <b>SSHA</b> (salted SHA-1):</p>
        <div class="math">digest = SHA-1( password ‖ salt )
stored = "{SSHA}" + base64( digest ‖ salt )</div>
        <p>For password <code>secret</code> and salt bytes <code>a1 b2 c3 d4</code>:</p>
        ${C('text', `
          SHA-1("secret" ‖ a1b2c3d4) = a553359be6bd6ac53e23878eb8943b05ba7224a5
          base64(digest ‖ salt)      = pVM1m+a9asU+I4eOuJQ7BbpyJKWhssPU
          stored                     = {SSHA}pVM1m+a9asU+I4eOuJQ7BbpyJKWhssPU
        `)}
        <p>SHA-1 is fast, so this is weak against cracking if leaked. Modern setups use <code>{ARGON2}</code> or <code>{PBKDF2-SHA512}</code>. Active Directory stores an NT hash in <code>unicodePwd</code>. That attribute can never be read over LDAP.</p>`],
      ['Bind and search: the two main operations', `
        <p><b>Bind</b> = log in to the directory. A <b>simple bind</b> sends a DN and a password. The server compares it with the stored hash.</p>
        <p><b>Search</b> = find entries. It takes a base DN, a scope and a <b>filter</b>. Filters use prefix notation — the operator goes first:</p>
        ${T(['Filter', 'Means'], [
          ['<code>(uid=sakitha)</code>', 'uid equals sakitha'],
          ['<code>(&amp;(objectClass=person)(uid=sakitha))</code>', 'person AND uid = sakitha'],
          ['<code>(|(ou=staff)(ou=admins))</code>', 'staff OR admins'],
          ['<code>(!(accountDisabled=TRUE))</code>', 'NOT disabled'],
          ['<code>(mail=*)</code>', 'has any mail value'],
        ])}`],
      ['The search-then-bind login pattern', `
        <ol>
          <li>The app binds with its own <b>service account</b> (read-only).</li>
          <li>It searches for the user: <code>(&amp;(objectClass=person)(uid=sakitha))</code> → finds the DN.</li>
          <li>It binds again, as <b>that DN</b>, with the password the user typed. Success → password is correct.</li>
          <li>It reads <code>memberOf</code> to decide what the user may do.</li>
        </ol>
        <p>A simple bind sends the password in clear text. So always use <b>LDAPS</b> (port 636) or <b>StartTLS</b>.</p>
        <p>One more trap: a bind with an <b>empty password</b> is often treated as an anonymous bind and "succeeds". Always reject empty passwords in the app.</p>`],
    ],
    example: {
      title: 'Spot and fix an LDAP injection',
      problem: `
        <p>An old app checks logins with one search. It builds the filter by gluing strings:</p>
        ${C('js', `
          const filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
          // if the search returns an entry → "login OK"
        `)}
        <p>An attacker types <code>*</code> in both boxes. What happens? How do you fix it?</p>`,
      steps: [
        ['Build the filter the app makes', `
          <div class="math">(&amp;(uid=*)(userPassword=*))</div>`],
        ['Read it in plain words', `
          <p><code>*</code> means "any value". So the filter means: "any user that has any password". That is <b>every user</b>.</p>
          <p>The search returns entries. The app thinks the login worked. It usually logs the attacker in as the first entry — often an admin.</p>`],
        ['Fix 1: escape special characters', `
          <p>RFC 4515 says these characters must be escaped in filter values:</p>
          ${T(['Character', 'Escaped as'], [
            ['<code>*</code>', '<code>\\2a</code>'], ['<code>(</code>', '<code>\\28</code>'], ['<code>)</code>', '<code>\\29</code>'], ['<code>\\</code>', '<code>\\5c</code>'], ['NUL', '<code>\\00</code>'],
          ])}
          <div class="math">(&amp;(uid=\\2a)(userPassword=\\2a))</div>
          <p>Now it looks for a user literally named "*". There is none. Login fails.</p>`],
        ['Fix 2: stop comparing passwords in a filter', `
          <p>Use search-then-bind. Search for the user by escaped uid only. Then <b>bind</b> as that DN with the typed password. The server checks the hash. The password is never part of a filter.</p>`],
      ],
      answer: `
        <p>The input <code>*</code> / <code>*</code> makes the filter match <b>all users</b>, so the attacker logs in without a password.</p>
        <p>Fix it in two layers: escape every value put into a filter (<code>*</code> → <code>\\2a</code>), and check passwords with a <b>bind</b>, never with <code>(userPassword=…)</code>. Also reject empty passwords.</p>`,
    },
  });

  /* ================= RADIUS ================= */
  IN('radius', {
    inside: [
      ['The packet, field by field', `
        <p>RADIUS runs over UDP. Authentication uses port <b>1812</b>, accounting uses <b>1813</b>.</p>
        ${T(['Field', 'Size', 'Meaning'], [
          ['Code', '1 byte', '1 = Access-Request, 2 = Accept, 3 = Reject, 11 = Challenge'],
          ['Identifier', '1 byte', 'Matches a reply to its request'],
          ['Length', '2 bytes', 'Whole packet size'],
          ['Authenticator', '16 bytes', 'Request: random. Reply: a hash that proves the reply is real.'],
          ['Attributes', 'rest', 'A list of Type – Length – Value items'],
        ])}
        ${C('text', `
          Type 1  User-Name          "sakitha"
          Type 2  User-Password      2c 52 3b d8 0f 58 6f ef 29 64 4f 9e 1c 9c fb bb   (hidden)
          Type 4  NAS-IP-Address     10.0.5.12
          Type 30 Called-Station-Id  "CORP-WIFI"
        `, 'Attributes in an Access-Request')}`],
      ['The shared secret', `
        <p>The access point (the NAS) and the RADIUS server share one secret, typed into both configs. For example <code>testing123</code> (never use this in real life).</p>
        <p>The secret is <b>never sent</b>. It is only mixed into MD5 hashes. It does two jobs: hides the password, and proves replies are real.</p>`],
      ['How the password is hidden', `
        <ol>
          <li>Pad the password with zero bytes to 16 bytes.</li>
          <li>Compute <code>b1 = MD5( secret ‖ Request Authenticator )</code>.</li>
          <li>XOR the padded password with b1, byte by byte. That is the hidden value.</li>
          <li>For longer passwords: <code>b2 = MD5( secret ‖ c1 )</code> for the next 16 bytes, and so on.</li>
        </ol>
        <div class="math">c1 = p1 XOR MD5( S ‖ RA )
p1 = c1 XOR MD5( S ‖ RA )      ← the server reverses it the same way</div>
        <p>XOR is its own undo. Doing it twice with the same value gives back the original.</p>`],
      ['How the reply is proven', `
        <div class="math">Response Authenticator = MD5( Code ‖ ID ‖ Length ‖ Request Authenticator ‖ Attributes ‖ Secret )</div>
        <p>The access point recomputes this. A fake server without the secret cannot make it match.</p>
        <p>But MD5 is old. In 2024 the <b>BlastRADIUS</b> attack showed a man in the middle could forge an Accept using MD5 collisions. The fix: always require the <b>Message-Authenticator</b> attribute (HMAC-MD5 over the whole packet), and move to <b>RADIUS over TLS</b> (RadSec, port 2083).</p>`],
      ['Enterprise Wi-Fi: EAP inside RADIUS', `
        <p>For WPA2/WPA3-Enterprise the password is not put in User-Password. Instead, <b>EAP</b> messages travel inside RADIUS attributes.</p>
        <ul>
          <li><b>PEAP / EAP-TTLS</b>: a TLS tunnel is built to the RADIUS server first. The password goes inside the tunnel.</li>
          <li><b>EAP-TLS</b>: the device uses a certificate. No password at all. This is the strongest option.</li>
        </ul>
        <p>On Accept, the server also returns rules: <code>Tunnel-Private-Group-Id = 20</code> (put this user on VLAN 20), <code>Session-Timeout = 28800</code> (8 hours).</p>`],
    ],
    example: {
      title: 'Hide and recover a RADIUS password',
      problem: `
        <p>Shared secret: <code>testing123</code>. Password: <code>hello</code>.</p>
        <p>Request Authenticator (16 random bytes from the access point):</p>
        <div class="math">RA = 0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a</div>
        <p>What bytes go into the User-Password attribute? Show how the server gets <code>hello</code> back.</p>`,
      steps: [
        ['Pad the password to 16 bytes', `
          <p><code>h e l l o</code> in hex is <code>68 65 6c 6c 6f</code>. Add 11 zero bytes:</p>
          <div class="math">p1 = 68 65 6c 6c 6f 00 00 00 00 00 00 00 00 00 00 00</div>`],
        ['Make the mask with MD5', `
          <div class="math">b1 = MD5( "testing123" ‖ RA )
   = 44 37 57 b4 60 58 6f ef 29 64 4f 9e 1c 9c fb bb</div>`],
        ['XOR byte by byte', `
          <p>Look at the first byte in binary:</p>
          <div class="math">  0x68 = 0110 1000
⊕ 0x44 = 0100 0100
= 0x2c = 0010 1100</div>
          ${T(['Byte', '1', '2', '3', '4', '5', '6 … 16'], [
            ['p1', '68', '65', '6c', '6c', '6f', '00 …'],
            ['b1', '44', '37', '57', 'b4', '60', '58 6f ef …'],
            ['c1 = p1 ⊕ b1', '<b>2c</b>', '<b>52</b>', '<b>3b</b>', '<b>d8</b>', '<b>0f</b>', '58 6f ef … (same as b1, because x ⊕ 0 = x)'],
          ])}
          <div class="math">c1 = 2c 52 3b d8 0f 58 6f ef 29 64 4f 9e 1c 9c fb bb</div>`],
        ['The server recovers it', `
          <p>The server knows the secret and sees RA in the packet. It computes the same b1. Then:</p>
          <div class="math">c1 ⊕ b1 = 68 65 6c 6c 6f 00 … = "hello" + padding</div>
          <p>It strips the zeros and checks <code>hello</code> against the directory.</p>`],
      ],
      answer: `
        <p><b>User-Password = 2c 52 3b d8 0f 58 6f ef 29 64 4f 9e 1c 9c fb bb</b>. The server XORs it with the same MD5 mask and gets <code>hello</code>.</p>
        <p>Look at bytes 6–16. They are just the mask, because the password bytes there were zero. So the whole safety rests on the shared secret and MD5. Anyone who records the traffic and later learns (or cracks) the secret can rebuild the mask and decode every captured password. That is why real deployments use EAP-TLS or RadSec instead.</p>`,
    },
  });
})();
