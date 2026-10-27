/* "Step by step" for every topic: the whole method as a numbered list of who does what,
   split into phases (setup once / every login …). Short, simple sentences for quick revision.
   Also registers the "All steps" reference page that shows every topic's list on one page. */
(function () {
  'use strict';
  const HS = window.HS, esc = HS.esc;
  const S = (id, d) => { const t = HS.byId[id]; if (t) t.walk = d; };

  /* ================= Start here ================= */
  S('concepts', {
    phases: [
      ['Setup', 'done once per user', [
        ['Admin', 'Creates the user account and stores a credential (a password hash, a public key, …).'],
        ['Admin', 'Gives the user roles or permissions, e.g. "editor".'],
      ]],
      ['Every request', '', [
        ['Client', 'Sends the request together with a proof: a cookie, a token, a password or a signature.'],
        ['Server', '<b>Authentication:</b> checks the proof. Missing or wrong → <code>401</code>.'],
        ['Server', 'Builds the <b>principal</b>: user ID, roles, department.'],
        ['Server', '<b>Authorization:</b> asks "may this user do this action on this object?" and checks the rules.'],
        ['Server', 'No rule says yes → <code>403</code> (default deny).'],
        ['Server', 'Yes → does the work and returns <code>200</code>. Repeats the authorization check for every object it touches.'],
      ]],
    ],
  });

  S('passwords', {
    phases: [
      ['Sign-up', 'done once', [
        ['User', 'Types a new password. It travels inside HTTPS.'],
        ['Server', 'Checks the length and rejects passwords found in breach lists.'],
        ['Server', 'Makes a random <b>salt</b> (16 bytes).'],
        ['Server', 'Runs a slow hash (Argon2id or bcrypt) on password + salt.'],
        ['Server', 'Stores only the result string (algorithm, cost, salt, hash). Forgets the password.'],
      ]],
      ['Every login', '', [
        ['User', 'Types username and password. They travel inside HTTPS.'],
        ['Server', 'Loads that user\'s hash string. (No such user? It still runs a dummy hash, so the timing gives nothing away.)'],
        ['Server', 'Reads the algorithm, cost and salt <b>from the stored string</b>.'],
        ['Server', 'Hashes the typed password with the same salt and cost.'],
        ['Server', 'Compares the two hashes in constant time.'],
        ['Server', 'Match → starts a session (or asks for MFA). No match → "wrong username or password", counts the failure, rate-limits.'],
        ['Server', 'Optional: if the stored cost is old, re-hashes now with the new cost (it has the plain password for this one moment).'],
      ]],
    ],
    fix: 'The server never "decrypts" a password. A hash is one-way. It can only be recomputed and compared.',
  });

  /* ================= Core web ================= */
  S('basic-auth', {
    phases: [
      ['Setup', 'done once', [
        ['Admin', 'Creates the user and stores a password hash (e.g. in <code>.htpasswd</code>). Turns on HTTPS.'],
      ]],
      ['Every request', '', [
        ['Browser', 'Asks for <code>/admin</code> with no credentials.'],
        ['Server', 'Replies <code>401</code> with <code>WWW-Authenticate: Basic realm="Admin"</code>.'],
        ['Browser', 'Shows its built-in login box. The user types username and password.'],
        ['Browser', 'Joins them as <code>user:password</code>, Base64-encodes it, and sends the request again with <code>Authorization: Basic …</code>.'],
        ['Server', 'Base64-decodes, splits at the first colon, and checks the password hash.'],
        ['Server', 'Correct → <code>200</code> with the page. Wrong → <code>401</code> again.'],
        ['Browser', 'Remembers the credentials and adds the same header to <b>every</b> later request. There is no session and no real logout.'],
      ]],
    ],
    fix: 'Base64 is not encryption. Anyone who sees the header can decode the password, so Basic is only safe inside HTTPS. (Digest sends an MD5 hash with a server nonce instead, but is outdated.)',
  });

  S('sessions', {
    phases: [
      ['Login', '', [
        ['Browser', 'Sends username + password in a POST over HTTPS.'],
        ['Server', 'Checks the password.'],
        ['Server', 'Makes a <b>new</b> random session ID (128+ bits) and throws away any old one. This blocks session fixation.'],
        ['Server', 'Saves <code>{userId, role, expiry, csrfToken}</code> in the session store (Redis / DB) under that ID.'],
        ['Server', 'Sends <code>Set-Cookie: sid=…; HttpOnly; Secure; SameSite=Lax</code>.'],
        ['Browser', 'Stores the cookie.'],
      ]],
      ['Every request', '', [
        ['Browser', 'Adds <code>Cookie: sid=…</code> by itself.'],
        ['Server', 'Looks up the ID in the store. Missing or expired → treated as logged out.'],
        ['Server', 'Found → loads the user. For POST/PUT/DELETE it also checks the CSRF token. Pushes the expiry forward.'],
      ]],
      ['Logout', '', [
        ['Server', 'Deletes the session record and tells the browser to delete the cookie. The session is dead at once.'],
      ]],
    ],
  });

  S('api-keys', {
    phases: [
      ['Setup', 'done once per key', [
        ['Developer', 'Clicks "Create key" in the dashboard and picks scopes.'],
        ['Server', 'Makes a random key with a prefix, e.g. <code>sk_live_…</code>, and shows it <b>once</b>.'],
        ['Server', 'Stores only the SHA-256 hash of the key, plus the owner, scopes and a short prefix for display.'],
        ['Developer', 'Saves the key in a secret manager or environment variable — never in source code.'],
      ]],
      ['Every API call', '', [
        ['App', 'Sends the key in a header (<code>Authorization: Bearer …</code> or <code>X-API-Key</code>) over HTTPS.'],
        ['Gateway', 'Hashes the received key and looks the hash up.'],
        ['Gateway', 'Not found or revoked → <code>401</code>.'],
        ['Gateway', 'Scope does not cover this endpoint → <code>403</code>. Over the rate limit → <code>429</code>.'],
        ['Gateway', 'All good → forwards the request with the account ID and logs the usage.'],
      ]],
      ['Rotation', '', [
        ['Developer', 'Creates a new key, deploys it, then deletes the old one.'],
      ]],
    ],
  });

  S('jwt', {
    phases: [
      ['Setup', 'done once', [
        ['Auth server', 'Creates a signing key: a shared secret (HS256) or a key pair (RS256 / ES256).'],
        ['APIs', 'Get the verification key: the same secret, or the public key from the JWKS URL.'],
      ]],
      ['Login', '', [
        ['User', 'Logs in at the auth server (password, MFA, …).'],
        ['Auth server', 'Builds a header (<code>alg</code>, <code>kid</code>) and a payload (<code>sub</code>, roles, <code>iss</code>, <code>aud</code>, <code>exp</code>).'],
        ['Auth server', 'Base64url-encodes both, signs <code>header.payload</code>, and adds the signature as the third part.'],
        ['Auth server', 'Sends the token to the client (often with a refresh token).'],
      ]],
      ['Every API call', '', [
        ['Client', 'Sends <code>Authorization: Bearer &lt;token&gt;</code>.'],
        ['API', 'Splits the token into 3 parts and picks the key by <code>kid</code>. It uses the algorithm <b>it expects</b>, not whatever the header says.'],
        ['API', 'Verifies the signature. Bad → <code>401</code>.'],
        ['API', 'Checks <code>exp</code>, <code>nbf</code>, <code>iss</code>, <code>aud</code>. Bad → <code>401</code>.'],
        ['API', 'Reads the claims and does authorization. No database lookup was needed.'],
      ]],
      ['When it expires', '', [
        ['Client', 'Sends the refresh token to the auth server and gets a new access token.'],
      ]],
    ],
    fix: 'A JWT is signed, not encrypted. Anyone can read the payload. The signature only stops changes.',
  });

  S('oauth', {
    phases: [
      ['Setup', 'done once per app', [
        ['Developer', 'Registers the app at the provider. Gets a <code>client_id</code> (and a <code>client_secret</code> for server apps). Sets the redirect URI and allowed scopes.'],
      ]],
      ['Every authorization (Authorization Code + PKCE)', '', [
        ['User', 'Clicks "Connect my Google Photos" in the app.'],
        ['App', 'Makes a random <code>state</code> and a random <code>code_verifier</code>. Computes <code>code_challenge = SHA-256(verifier)</code>.'],
        ['App', 'Redirects the browser to the provider\'s <code>/authorize</code> with <code>client_id</code>, <code>redirect_uri</code>, <code>scope</code>, <code>state</code> and <code>code_challenge</code>.'],
        ['User', 'Logs in <b>on the provider\'s page</b>. The app never sees the password.'],
        ['Provider', 'Shows the consent screen. The user approves the scopes.'],
        ['Provider', 'Redirects the browser back to <code>redirect_uri</code> with a one-time <code>code</code> and the same <code>state</code>.'],
        ['App', 'Checks that <code>state</code> matches the one it saved.'],
        ['App backend', 'POSTs to <code>/token</code>: the code, the <code>code_verifier</code>, the redirect URI and its client credentials.'],
        ['Provider', 'Checks the code (unused, unexpired, same client, same redirect URI) and that <code>SHA-256(verifier) = challenge</code>.'],
        ['Provider', 'Returns an access token (and a refresh token) with the granted scopes.'],
        ['App', 'Calls the API with <code>Bearer &lt;access token&gt;</code>. The API checks the token and its scopes.'],
      ]],
    ],
    fix: 'OAuth is for <b>authorization</b> (letting an app use an API). It does not tell the app who the user is — that is what OpenID Connect adds.',
  });

  S('oidc', {
    phases: [
      ['Setup', 'done once', [
        ['Developer', 'Registers the app (client_id, redirect URI).'],
        ['App', 'Reads the provider\'s <code>/.well-known/openid-configuration</code> and downloads the JWKS (public keys).'],
      ]],
      ['Every login', '', [
        ['User', 'Clicks "Sign in with Google".'],
        ['App', 'Makes <code>state</code>, <code>nonce</code> and a PKCE verifier. Redirects with <code>scope=openid email</code>.'],
        ['User', 'Logs in at Google.'],
        ['Google', 'Redirects back with a code.'],
        ['App', 'Checks <code>state</code> and exchanges the code at <code>/token</code>.'],
        ['Google', 'Returns an <b>ID token</b> (a signed JWT about the user) and an access token.'],
        ['App', 'Verifies the ID token signature with the JWKS key matching its <code>kid</code>.'],
        ['App', 'Checks <code>iss</code>, <code>aud</code> = its own client_id, <code>exp</code> and <code>nonce</code>.'],
        ['App', 'Finds or creates the user by <code>iss + sub</code> (not by email).'],
        ['App', 'Creates its <b>own</b> session cookie. The ID token is not sent to APIs.'],
      ]],
    ],
  });

  /* ================= Transport ================= */
  S('tls', {
    phases: [
      ['Setup', 'done once (renewed every few months)', [
        ['Server', 'Makes a key pair. The private key never leaves the server.'],
        ['Server', 'Sends a certificate request (CSR) to a CA, e.g. Let\'s Encrypt.'],
        ['CA', 'Checks the server really controls the domain (ACME challenge), then signs a certificate.'],
        ['Server', 'Installs the certificate and its chain.'],
        ['Browser / OS', 'Already ships with the trusted root CA certificates.'],
      ]],
      ['Every connection (TLS 1.3)', '', [
        ['Client', '<b>ClientHello:</b> supported ciphers, a random value, the site name (SNI) and a key share (a fresh X25519 public value).'],
        ['Server', '<b>ServerHello:</b> the chosen cipher and its own fresh key share.'],
        ['Both', 'Combine the key shares (ECDHE) into the same shared secret. Derive handshake keys. <b>Everything after this is encrypted.</b>'],
        ['Server', 'Sends its certificate chain.'],
        ['Server', '<b>CertificateVerify:</b> signs a hash of the handshake so far with its private key.'],
        ['Server', '<b>Finished:</b> an HMAC over the whole handshake.'],
        ['Client', 'Checks the chain up to a trusted root, the dates, and that the hostname is in the SAN.'],
        ['Client', 'Verifies the CertificateVerify signature with the certificate\'s public key, and checks Finished.'],
        ['Client', 'Sends its own Finished.'],
        ['Both', 'Derive application keys and exchange HTTP data encrypted with AES-GCM or ChaCha20-Poly1305.'],
      ]],
    ],
    fix: 'Old explanations say "the client encrypts a secret with the server\'s public key". That was RSA key exchange in TLS 1.2 and earlier. TLS 1.3 removed it: both sides use Diffie–Hellman, and the certificate key is only used to <b>sign</b>.',
  });

  S('mtls', {
    phases: [
      ['Setup', 'done once (renewed often)', [
        ['Organization', 'Runs an internal CA.'],
        ['Each service', 'Makes a key pair and a CSR. The CA issues a certificate with the service identity in the SAN (e.g. <code>spiffe://corp/payments</code>).'],
        ['Each service', 'Installs its own key + certificate and the CA root. A service mesh does this and rotates certificates automatically.'],
      ]],
      ['Every connection', '', [
        ['Client', 'ClientHello (as in normal TLS).'],
        ['Server', 'ServerHello, its certificate, and a <b>CertificateRequest</b> ("show me yours, issued by this CA").'],
        ['Server', 'CertificateVerify + Finished.'],
        ['Client', 'Verifies the server certificate (as in normal TLS).'],
        ['Client', 'Sends <b>its own</b> certificate.'],
        ['Client', '<b>CertificateVerify:</b> signs the handshake hash with its private key. Then Finished.'],
        ['Server', 'Checks the client certificate: chain to the internal CA, dates, Extended Key Usage = clientAuth.'],
        ['Server', 'Verifies the client\'s signature with the public key in that certificate.'],
        ['Server', 'Reads the identity from the SAN and applies authorization rules.'],
        ['Both', 'Exchange encrypted data.'],
      ]],
    ],
  });

  S('ssh', {
    phases: [
      ['Setup', 'done once', [
        ['Server', 'At install time, makes its own <b>host key pair</b> (<code>/etc/ssh/ssh_host_ed25519_key</code>).'],
        ['Client', 'Runs <code>ssh-keygen</code>. Gets a user key pair. The private key is encrypted with your passphrase and saved in <code>~/.ssh/id_ed25519</code>.'],
        ['Client', 'Copies the <b>public</b> key to the server (<code>ssh-copy-id</code>).'],
        ['Server', 'Stores it as one line in <code>~/.ssh/authorized_keys</code> of that user. The file must not be writable by others.'],
      ]],
      ['Every login — part A: secure channel (the server proves itself)', '', [
        ['Both', 'TCP connect to port 22. Swap version strings (<code>SSH-2.0-OpenSSH_9.x</code>).'],
        ['Both', 'Swap lists of supported algorithms and pick the first match on each list.'],
        ['Both', '<b>Key exchange:</b> each sends a fresh X25519 public value. Both compute the same shared secret.'],
        ['Both', 'Hash everything exchanged so far → the <b>exchange hash H</b>. The first H becomes the <b>session ID</b>.'],
        ['Server', 'Signs H with its <b>host private key</b> and sends the host public key + signature.'],
        ['Client', 'Looks up the host key in <code>~/.ssh/known_hosts</code>. First visit → shows the fingerprint and asks you. Different key → big warning, stops. Then verifies the signature.'],
        ['Both', 'Derive encryption keys from the shared secret + H. <b>Everything after this is encrypted.</b>'],
      ]],
      ['Every login — part B: user authentication (you prove yourself)', '', [
        ['Client', '"I am user <code>sakitha</code>. Can I use this key?" Sends the <b>whole public key</b>, no signature yet.'],
        ['Server', 'Looks for that key in <code>sakitha</code>\'s <code>authorized_keys</code>. Not there → "try another method". There → <code>PK_OK</code>.'],
        ['Client', 'Signs <code>session ID + username + "ssh-connection" + "publickey" + algorithm + public key</code> with the <b>private key</b> (usually via <code>ssh-agent</code>; asks for the passphrase if the key is locked).'],
        ['Client', 'Sends the signature.'],
        ['Server', 'Verifies the signature with the stored public key. Also applies any options on that line (<code>from=</code>, <code>command=</code>, …).'],
        ['Server', 'Valid → <code>USERAUTH_SUCCESS</code>. The client opens a channel and you get a shell.'],
      ]],
    ],
    fix: `<ul>
      <li><b>Missing phase:</b> before you prove anything, the server proves <b>itself</b> with its host key, and the channel becomes encrypted (part A).</li>
      <li><b>The client sends the full public key</b>, not just an ID. The server searches <code>authorized_keys</code> for that exact key.</li>
      <li><b>No separate random challenge in SSH-2.</b> The "challenge" is the <b>session ID</b> from the key exchange. Both sides already know it, so the server just replies "OK, prove it". (The "server encrypts a random number with your public key" story is from SSH-1, which is obsolete.)</li>
      <li>The query step (12–13) is optional. A client may send the signature straight away.</li>
    </ul>`,
  });

  /* ================= Enterprise ================= */
  S('sso', {
    phases: [
      ['Setup', 'done once per app', [
        ['Admin', 'Registers each app with the IdP and swaps metadata: the IdP\'s login URL and signing certificate ⇄ the app\'s ID and return URL.'],
        ['Admin', 'User accounts live in one place: the IdP\'s directory.'],
      ]],
      ['First app of the day', '', [
        ['User', 'Opens App A. App A has no session for them.'],
        ['App A', 'Redirects the browser to the IdP with a login request.'],
        ['IdP', 'Has no session either → asks for password + MFA.'],
        ['IdP', 'Creates its <b>own</b> session cookie (on the IdP domain).'],
        ['IdP', 'Sends a signed assertion / ID token back to App A through the browser.'],
        ['App A', 'Verifies the signature and creates its own session.'],
      ]],
      ['Second app', '', [
        ['User', 'Opens App B. No session → redirect to the IdP.'],
        ['Browser', 'Sends the IdP cookie with that redirect.'],
        ['IdP', 'Sees a valid session → <b>no password asked</b>. Issues a signed assertion for App B.'],
        ['App B', 'Verifies it and creates its own session.'],
      ]],
    ],
    fix: 'Logging out of one app does not end the IdP session. You need Single Logout, or short app sessions.',
  });

  S('saml', {
    phases: [
      ['Setup', 'done once', [
        ['Admins', 'SP and IdP swap metadata XML: IdP login URL + signing certificate ⇄ SP Entity ID + ACS (return) URL.'],
      ]],
      ['Every login (SP-initiated)', '', [
        ['User', 'Opens the app (SP). No session.'],
        ['SP', 'Builds an <b>AuthnRequest</b> with an ID (e.g. <code>_req77</code>), saves that ID, and redirects the browser to the IdP (compressed + Base64 in the URL).'],
        ['IdP', 'Logs the user in, or uses its existing session.'],
        ['IdP', 'Builds an <b>Assertion</b>: NameID, attributes, Audience, time limits, InResponseTo=<code>_req77</code>.'],
        ['IdP', 'Signs it with an XML signature (its private key).'],
        ['IdP', 'Returns an HTML form. The browser auto-POSTs <code>SAMLResponse</code> to the SP\'s ACS URL.'],
        ['SP', 'Base64-decodes it and verifies the signature with the IdP certificate from metadata.'],
        ['SP', 'Checks Issuer, Audience, Recipient, time window, InResponseTo, and that it was not used before.'],
        ['SP', 'Reads the user and attributes from the <b>signed</b> element and creates its own session.'],
      ]],
    ],
  });

  S('kerberos', {
    phases: [
      ['Setup', 'done once', [
        ['Admin', 'Creates the user in Active Directory. The KDC stores a key derived from the password.'],
        ['Admin', 'Registers each service (an SPN). The KDC and the service share the service key (keytab).'],
        ['KDC', 'Has its own secret <code>krbtgt</code> key that nobody else knows.'],
      ]],
      ['Logon (once a day) — AS exchange', '', [
        ['PC', 'You type your password. The PC turns it into your user key. The password is not sent.'],
        ['PC', '<b>AS-REQ:</b> sends your name + the current time, encrypted with your user key (pre-authentication).'],
        ['KDC', 'Decrypts it with its copy of your key. Time within 5 minutes → you are proven.'],
        ['KDC', '<b>AS-REP:</b> sends a <b>TGT</b> (locked with the krbtgt key) and a session key SK1 (locked with your key).'],
        ['PC', 'Opens SK1. Keeps the TGT + SK1 (≈10 hours). No longer needs your password for tickets.'],
      ]],
      ['Opening a service — TGS and AP exchanges', '', [
        ['PC', '<b>TGS-REQ:</b> sends the TGT + an authenticator (name + time, locked with SK1) + the service name.'],
        ['KDC', 'Opens the TGT with the krbtgt key, finds SK1, opens and checks the authenticator.'],
        ['KDC', '<b>TGS-REP:</b> sends a <b>service ticket</b> (locked with the service key; holds SK2 + your groups) and SK2 (locked with SK1).'],
        ['PC', '<b>AP-REQ:</b> sends the service ticket + a new authenticator locked with SK2 to the file server.'],
        ['Service', 'Opens the ticket with its own key, gets SK2, opens the authenticator, checks the time (±5 min) and replay cache.'],
        ['Service', 'Optional: proves itself back (AP-REP). Grants access based on the groups in the ticket.'],
      ]],
    ],
    fix: 'The service never contacts the KDC during login. It trusts the ticket because only it and the KDC know the service key.',
  });

  S('ldap', {
    phases: [
      ['Setup', 'done once', [
        ['Admin', 'Builds the directory tree and adds users (DN, attributes, password hash) and groups.'],
        ['Admin', 'Gives the app a read-only <b>service account</b>. Turns on LDAPS (port 636) or StartTLS.'],
      ]],
      ['Every login (search-then-bind)', '', [
        ['User', 'Types username + password into the app.'],
        ['App', 'Opens a TLS connection to the directory.'],
        ['App', '<b>Binds</b> as its service account.'],
        ['App', '<b>Searches</b> <code>(&amp;(objectClass=person)(uid=&lt;escaped username&gt;))</code> and gets the user\'s DN. Zero or several results → fail.'],
        ['App', 'Rejects an empty password (an empty bind can "succeed" anonymously).'],
        ['App', '<b>Binds again</b> as the user\'s DN with the typed password.'],
        ['Directory', 'Checks the password hash → success, or <code>invalidCredentials</code>.'],
        ['App', 'Reads the user\'s groups (<code>memberOf</code>) and maps them to roles.'],
        ['App', 'Creates its own session.'],
      ]],
    ],
  });

  S('radius', {
    phases: [
      ['Setup', 'done once', [
        ['Admin', 'Adds each access point (NAS) to the RADIUS server with its IP and a <b>shared secret</b>. The same secret goes into the access point.'],
        ['Admin', 'Connects RADIUS to the directory and writes policies (e.g. group Engineering → VLAN 20).'],
      ]],
      ['Every Wi-Fi connection (802.1X)', '', [
        ['Laptop', 'Joins the enterprise SSID. The access point blocks all traffic except authentication (EAP).'],
        ['Access point', 'Asks for an identity. The laptop answers.'],
        ['Access point', 'Wraps the EAP message in a RADIUS <b>Access-Request</b> and sends it to the server on UDP 1812 (with Message-Authenticator).'],
        ['Server ⇄ Laptop', 'Run the EAP method through the access point, in several <b>Access-Challenge</b> rounds. PEAP: build a TLS tunnel (the laptop checks the server certificate) and check the password inside. EAP-TLS: the laptop uses a certificate.'],
        ['Server', 'Checks the credentials with the directory.'],
        ['Server', 'Sends <b>Access-Accept</b> (with VLAN, session time, and Wi-Fi key material) or <b>Access-Reject</b>. The reply is authenticated with the shared secret.'],
        ['Access point', 'Checks the reply, opens the port, applies the VLAN. Laptop and AP derive the Wi-Fi encryption keys (4-way handshake).'],
        ['Access point', 'Sends Accounting-Start / Stop to port 1813 for logs.'],
      ]],
    ],
    fix: 'RADIUS has three parties, not two: the user never talks to the RADIUS server directly. The access point (NAS) is the middleman.',
  });

  /* ================= Modern & MFA ================= */
  S('mfa', {
    phases: [
      ['Enrollment', 'done once per factor', [
        ['User', 'Logs in with the password and chooses a second factor.'],
        ['Server', 'Sets it up: a TOTP secret (QR code), a passkey registration, or a phone number.'],
        ['User', 'Proves it works once (e.g. types the first code).'],
        ['Server', 'Saves the factor and gives one-time <b>recovery codes</b> (stored hashed).'],
      ]],
      ['Every login', '', [
        ['User', 'Enters username + password. The server checks them.'],
        ['Server', 'Creates a short <b>pending</b> session ("password OK, MFA needed"). It gives no real access.'],
        ['Server', 'Asks for the second factor.'],
        ['User', 'Gives it: a code, a push approval with number matching, or a security-key touch.'],
        ['Server', 'Checks it, counts failures, locks after a few wrong tries.'],
        ['Server', 'Pass → upgrades to a full session with a <b>new</b> session ID.'],
        ['Server', 'Optional: sets a "remember this device" cookie for some days.'],
      ]],
    ],
  });

  S('totp', {
    phases: [
      ['Setup', 'done once', [
        ['Server', 'Makes a random 20-byte secret and stores it <b>encrypted</b>.'],
        ['Server', 'Shows a QR code: <code>otpauth://totp/…?secret=BASE32…</code>.'],
        ['Phone app', 'Scans it and stores the secret.'],
        ['User', 'Types the first code to confirm both sides match.'],
      ]],
      ['Every login', '', [
        ['Phone app', 'Computes the time step <code>T = floor(unix_time ÷ 30)</code>.'],
        ['Phone app', 'Computes <code>HMAC-SHA1(secret, T)</code>, cuts 4 bytes out (dynamic truncation), takes <code>mod 10⁶</code> → 6 digits.'],
        ['User', 'Types the code. No network was needed on the phone.'],
        ['Server', 'Computes the codes for T−1, T and T+1 with its copy of the secret.'],
        ['Server', 'Match and that step not used before → accept and remember the step. Otherwise count a failure.'],
      ]],
    ],
  });

  S('webauthn', {
    phases: [
      ['Registration', 'done once per device / passkey', [
        ['User', 'While logged in, clicks "Add a passkey".'],
        ['Server', 'Sends a random challenge, its RP ID (<code>bank.com</code>) and a user handle.'],
        ['Browser', 'Checks the RP ID fits the real site address, then asks the authenticator.'],
        ['Authenticator', 'Asks for fingerprint / face / PIN. Makes a <b>new key pair just for this site</b>. The private key stays inside.'],
        ['Authenticator', 'Returns a credential ID and the public key.'],
        ['Server', 'Checks the challenge and origin. Stores credential ID + public key + counter.'],
      ]],
      ['Every login', '', [
        ['Server', 'Sends a fresh random challenge.'],
        ['Browser', 'Checks the RP ID against the <b>real</b> address bar. Wrong site → refuses.'],
        ['Authenticator', 'Finds the key for this RP. User touches / scans a finger.'],
        ['Authenticator', 'Signs <code>authenticatorData + SHA-256(clientDataJSON)</code>. clientDataJSON holds the challenge and the real origin.'],
        ['Browser', 'Sends credential ID, authenticatorData, clientDataJSON and the signature.'],
        ['Server', 'Checks challenge, origin, rpIdHash and flags, verifies the signature with the stored public key, checks the counter.'],
        ['Server', 'All good → creates a session.'],
      ]],
    ],
  });

  S('magic-links', {
    phases: [
      ['Every login', '', [
        ['User', 'Types an email address.'],
        ['Server', 'Always shows "If that email has an account, we sent a link" (so attackers cannot test emails).'],
        ['Server', 'If the account exists: makes a random 256-bit token and stores its <b>hash</b> + expiry (≈10 min) + "unused".'],
        ['Server', 'Emails a link containing the raw token.'],
        ['User', 'Clicks the link, then the "Sign in" button (stops email scanners from using the link).'],
        ['Server', 'Hashes the token, finds the row, checks it is unexpired and unused.'],
        ['Server', 'Marks it used in the same database step.'],
        ['Server', 'Creates a normal session cookie and redirects into the app.'],
      ]],
    ],
  });

  S('hmac-sig', {
    phases: [
      ['Setup', 'done once', [
        ['Both sides', 'Share a random secret key and keep it in a secret manager.'],
        ['Both sides', 'Agree on the exact string to sign (e.g. <code>timestamp + "." + body</code>) and a time window.'],
      ]],
      ['Every message', '', [
        ['Sender', 'Builds the canonical string from the request.'],
        ['Sender', 'Computes <code>HMAC-SHA256(secret, string)</code>.'],
        ['Sender', 'Sends the request with the timestamp and the signature in headers.'],
        ['Receiver', 'Checks the timestamp is inside the window (and the nonce is new).'],
        ['Receiver', 'Rebuilds the same string from the <b>raw</b> bytes it received.'],
        ['Receiver', 'Computes the HMAC with its own copy of the secret.'],
        ['Receiver', 'Compares in constant time. Match → trust and process. No match → <code>401</code>.'],
      ]],
    ],
    fix: 'The secret is never sent. Only the signature travels, and it only fits this exact message.',
  });

  /* ================= Authorization ================= */
  S('authz-models', {
    phases: [
      ['Setup', 'done once (updated over time)', [
        ['Team', 'Lists the actions (read, edit, delete …) and picks a model.'],
        ['Admin', 'RBAC: assigns roles to users. ABAC: writes rules over attributes. ReBAC: stores relationships (user → group → folder → doc).'],
        ['System', 'Loads that data into the decision point (PDP).'],
      ]],
      ['Every request', '', [
        ['Server', 'Authenticates the user first.'],
        ['PEP (middleware)', 'Catches the request and builds the question: <b>subject, action, resource</b> (+ context like time).'],
        ['PDP', 'Decides. RBAC: role → permission lookup. ABAC: evaluate the rule. ReBAC: search the graph for a path.'],
        ['PDP', 'No rule allows → <b>deny</b> (default deny).'],
        ['PEP', 'Enforces: <code>403</code>, or lets the request continue. Logs the decision.'],
      ]],
    ],
  });

  S('oauth-scopes', {
    phases: [
      ['Setup', 'done once', [
        ['API owner', 'Defines the scopes and which endpoint needs which scope.'],
        ['Admin', 'Sets which scopes each client app may ever ask for.'],
      ]],
      ['Every grant', '', [
        ['App', 'Asks for scopes in the <code>/authorize</code> request.'],
        ['Auth server', 'Drops scopes this client is not allowed to have.'],
        ['User', 'Sees the rest on the consent screen and approves some or all.'],
        ['Auth server', 'Issues a token with the <b>granted</b> scopes. The app reads which ones it really got.'],
      ]],
      ['Every API call', '', [
        ['API', 'Validates the token.'],
        ['API', 'Looks up the scope this endpoint needs. Not in the token → <code>403 insufficient_scope</code>.'],
        ['API', 'Scope is there → still checks the <b>user\'s own</b> permission on this object, then proceeds.'],
      ]],
    ],
  });

  S('opa', {
    phases: [
      ['Setup', 'done once (updated through CI)', [
        ['Team', 'Writes the policy in Rego with <code>default allow := false</code>, plus unit tests. CI runs <code>opa test</code>.'],
        ['CI', 'Builds a bundle. OPA (usually a sidecar next to each service) downloads the policy and data.'],
      ]],
      ['Every request', '', [
        ['Service', 'Receives the request and authenticates the user.'],
        ['Service', 'Builds the <b>input</b> JSON: user, method, path, resource.'],
        ['Service', 'POSTs it to the local OPA: <code>/v1/data/app/authz/allow</code>.'],
        ['OPA', 'Evaluates the Rego rules against the input + its data.'],
        ['OPA', 'Returns <code>{"result": true}</code> or <code>false</code>, and writes a decision log.'],
        ['Service', 'Enforces it: <code>403</code> or continue.'],
      ]],
    ],
    fix: 'OPA only <b>decides</b>. The service must still enforce the answer.',
  });

  /* ---------- shared renderer (used by the topic page and the All-steps page) ---------- */
  HS.renderWalk = (w, compact) => {
    let n = 0;
    return `<div class="walk${compact ? ' compact' : ''}">${w.phases.map(([name, sub, steps]) => `
      <div class="walk-phase"><h4>${name}${sub ? `<small>${sub}</small>` : ''}</h4>
        <ol class="walk-steps" start="${n + 1}">${steps.map(([who, what]) => { n++; return `<li><span class="num">${n}</span><span class="who">${who}</span><span class="what">${what}</span></li>`; }).join('')}</ol>
      </div>`).join('')}
      ${w.fix ? `<div class="callout warn walk-fix"><b>Often explained wrong</b>${/^\s*</.test(w.fix) ? w.fix : `<p>${w.fix}</p>`}</div>` : ''}</div>`;
  };

  /* ---------- reference page: every step-by-step on one page ---------- */
  HS.pages.steps = {
    group: 'ref', short: 'All step-by-steps', title: 'All step-by-steps',
    render(main) {
      const groups = (HS.GROUPS || []).filter((g) => g.id !== 'ref');
      const list = HS.topics.filter((t) => t.walk);
      main.innerHTML = `<div class="page">
        <header class="t-head">
          <div class="eyebrow"><b>Reference</b><span>${list.length} methods</span><span>quick revision</span></div>
          <h1>All step-by-steps</h1>
          <p class="lede">Every method as a numbered list of who does what — setup first, then what happens on each login or request. Read top to bottom for a quick revision, or jump to one method.</p>
          <nav class="toc" aria-label="Methods">${list.map((t) => `<button type="button" data-j="${t.id}">${esc(t.short || t.title)}</button>`).join('')}</nav>
        </header>
        ${groups.map((g) => {
          const ts = list.filter((t) => t.group === g.id); if (!ts.length) return '';
          return `<h2 class="steps-group">${esc(g.name)}</h2>` + ts.map((t) => `<section class="blk steps-card" id="w-${t.id}">
            <h3><a href="#${t.id}">${esc(t.short || t.title)}</a><a class="steps-open" href="#${t.id}">Open topic →</a></h3>
            ${HS.renderWalk(t.walk, true)}</section>`).join('');
        }).join('')}
        ${HS.pager ? HS.pager('steps') : ''}
      </div>`;
      main.querySelectorAll('.toc button').forEach((b) => b.addEventListener('click', () => {
        const el = document.getElementById('w-' + b.dataset.j);
        if (el) el.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
      }));
    },
  };
})();
