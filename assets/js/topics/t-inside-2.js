/* "How it works inside" + "Solved example" for: OAuth 2.0, OpenID Connect, TLS, mTLS, SSH.
   Short, simple sentences. Every number below was computed with real code. Toy RSA/DH
   numbers are small on purpose so you can follow them; real keys are far bigger. */
(function () {
  'use strict';
  const HS = window.HS, C = window.C, T = HS.tbl;
  const IN = (id, d) => { const t = HS.byId[id]; if (!t) return; t.inside = d.inside; t.example = d.example; };

  /* ================= OAuth 2.0 ================= */
  IN('oauth', {
    inside: [
      ['Who holds what', `
        ${T(['Item', 'Who holds it', 'What it looks like', 'Secret?'], [
          ['client_id', 'Public. In the app and in URLs.', '<code>app-123</code>', 'No'],
          ['client_secret', 'Only the app\'s backend server', 'long random string', 'Yes. Mobile and browser apps cannot keep one.'],
          ['state', 'User\'s browser session (app side)', '<code>xyz-8f3k…</code>', 'Random, one per login'],
          ['code_verifier (PKCE)', 'The app, in memory, for one login', '43–128 random chars', 'Yes, until it is used'],
          ['Authorization code', 'Passes through the browser once', '<code>SplxlOBeZQQYbYS6WxSbIA</code>', 'Short-lived (≈1 min), single use'],
          ['Access token', 'App → sent to the API', 'opaque string or a JWT', 'Yes. Lives minutes to an hour.'],
          ['Refresh token', 'App backend (or secure storage)', 'opaque string', 'Yes. Lives days or months.'],
        ])}
        <p>Notice what is missing: your password. The app never sees it. You type it only on the provider's page.</p>`],
      ['The redirect, line by line', `
        <p>The app sends your browser to the provider with this URL:</p>
        ${C('http', `
          GET https://accounts.example.com/authorize
              ?response_type=code
              &client_id=app-123
              &redirect_uri=https://app.example/cb
              &scope=photos.read
              &state=xyz-8f3k
              &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
              &code_challenge_method=S256
        `)}
        <p>After you agree, the provider sends the browser back:</p>
        ${C('http', `
          302 Found
          Location: https://app.example/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz-8f3k
        `)}`],
      ['Why the state parameter exists', `
        <ol>
          <li>Before the redirect, the app makes a random <code>state</code>. It saves it in your session.</li>
          <li>The provider sends the same <code>state</code> back.</li>
          <li>The app compares. Different or missing → stop.</li>
        </ol>
        <p>This stops an attacker from pushing <b>their</b> code into <b>your</b> browser. Without it, you could end up linked to the attacker's account. This is login CSRF.</p>`],
      ['PKCE: the math inside', `
        <p>PKCE ("pixie") ties the code to the app that started the login.</p>
        <div class="math">code_verifier  = 32 random bytes → base64url  (43 chars)
code_challenge = base64url( SHA-256( code_verifier ) )</div>
        <ul>
          <li>The <b>challenge</b> goes out at the start, in the URL. Anyone may see it.</li>
          <li>The <b>verifier</b> stays in the app. It is sent only in the final back-channel call.</li>
          <li>SHA-256 is one-way. Nobody can get the verifier from the challenge.</li>
        </ul>`],
      ['The code-for-token exchange', `
        ${C('http', `
          POST /token HTTP/1.1
          Host: accounts.example.com
          Content-Type: application/x-www-form-urlencoded

          grant_type=authorization_code
          &code=SplxlOBeZQQYbYS6WxSbIA
          &redirect_uri=https://app.example/cb
          &client_id=app-123
          &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
        `, 'Server-to-server call. It does not go through the browser.')}
        <p>The provider now checks four things:</p>
        <ol>
          <li>The code exists, is not expired, and was never used.</li>
          <li>The code was issued to this <code>client_id</code>.</li>
          <li><code>redirect_uri</code> matches the one used at the start.</li>
          <li><code>SHA-256(code_verifier)</code> equals the saved <code>code_challenge</code>.</li>
        </ol>
        ${C('json', `
          { "access_token": "eyJhbGciOi…", "token_type": "Bearer", "expires_in": 3600,
            "refresh_token": "8xLOxBtZp8", "scope": "photos.read" }
        `, 'The reply')}`],
      ['Refreshing without asking you again', `
        <p>When the access token expires, the app sends the refresh token to <code>/token</code> with <code>grant_type=refresh_token</code>. It gets a new access token.</p>
        <p>Good providers <b>rotate</b> the refresh token each time. The old one stops working. If a stolen old one is used, the provider sees reuse and can cancel the whole family of tokens.</p>`],
    ],
    example: {
      title: 'Follow PKCE with the official RFC 7636 numbers',
      problem: `
        <p>A mobile app starts a login. Its random verifier is:</p>
        <div class="math">code_verifier = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk</div>
        <ol>
          <li>What <code>code_challenge</code> does it send?</li>
          <li>A malicious app on the same phone steals the returned <code>code</code>. It does not know the verifier, so it guesses one. Does it get a token?</li>
        </ol>`,
      steps: [
        ['Hash the verifier with SHA-256', `
          <div class="math">SHA-256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
= 13d31e961a1ad8ec2f16b10c4c982e0876a878ad6df144566ee1894acb70f9c3  (hex, 32 bytes)</div>`],
        ['Encode the 32 bytes with base64url', `
          <div class="math">base64url(…) = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM</div>
          <p>This is the <code>code_challenge</code>. It goes in the first URL. The provider saves it next to the code it will issue.</p>`],
        ['The real app redeems the code', `
          <p>It sends the code plus the real verifier. The provider hashes the verifier and gets <code>E9Melhoa…-cM</code>. It matches the saved challenge. Tokens are issued.</p>`],
        ['The thief tries to redeem the code', `
          <p>The thief sends the stolen code with a made-up verifier, for example <code>attacker-guess-verifier-0000000000000000000</code>.</p>
          <div class="math">base64url(SHA-256(guess)) = OuuP98GmcZuuLANel1yvLoPt1qkslb38plFTAxgpoYM
saved challenge           = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM   → no match</div>
          <p>The provider replies <code>400 invalid_grant</code>. Because codes are single use, it may also cancel the code.</p>`],
      ],
      answer: `
        <p><b>code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM</b> (the same value printed in RFC 7636, Appendix B).</p>
        <p>The thief gets <b>no token</b>. Holding the code is not enough. You must also hold the verifier, and the verifier never left the real app.</p>
        <p>Try it: open the PKCE playground below and paste the verifier. It shows the same challenge.</p>`,
    },
  });

  /* ================= OpenID Connect ================= */
  IN('oidc', {
    inside: [
      ['What is inside an ID token', `
        <p>The ID token is a JWT. It is signed by the provider (the OP). The app (the RP) reads it to learn who logged in.</p>
        ${C('json', `
          {
            "iss": "https://accounts.google.com",
            "sub": "110169484474386276334",
            "aud": "1234.apps.googleusercontent.com",
            "iat": 1798758600,
            "exp": 1798762200,
            "nonce": "n-0S6_WzA2Mj",
            "email": "sakitha@example.com",
            "email_verified": true,
            "at_hash": "acoNTFEet9fGfB-taNiivA"
          }
        `, 'Decoded ID token payload')}
        ${T(['Claim', 'Simple meaning'], [
          ['iss', 'Who made this token.'],
          ['sub', 'The user\'s permanent ID at that provider. It never changes.'],
          ['aud', 'Which app this token is for. It must be <b>your</b> client_id.'],
          ['iat / exp', 'Made at / expires at (Unix seconds).'],
          ['nonce', 'Your random value, sent back. It proves the token belongs to <b>this</b> login.'],
          ['at_hash', 'A short hash of the access token. It ties the two tokens together.'],
        ])}
        <p>Use <code>iss + sub</code> as the user key in your database. Do not use email. Emails can change and can be reused.</p>`],
      ['How the app finds the provider\'s keys', `
        <ol>
          <li>The app reads <code>https://accounts.google.com/.well-known/openid-configuration</code>. This JSON lists every endpoint.</li>
          <li>One field is <code>jwks_uri</code>. The app downloads that key set and caches it.</li>
        </ol>
        ${C('json', `
          { "keys": [ { "kty": "RSA", "kid": "a1b2c3", "use": "sig", "alg": "RS256",
                        "n": "0vx7agoebGcQSuu…(342 chars)", "e": "AQAB" } ] }
        `, 'One JWK (JSON Web Key). n = the RSA modulus, e = the exponent.')}
        <p><code>"e": "AQAB"</code> is Base64 for the bytes 01 00 01. That is 65,537 — the usual RSA public exponent.</p>`],
      ['How the signature is checked', `
        <ol>
          <li>Read <code>kid</code> from the token header.</li>
          <li>Find the key with the same <code>kid</code> in the JWKS. Not found? Re-download the JWKS once (keys rotate).</li>
          <li>Compute <code>SHA-256(header + "." + payload)</code>.</li>
          <li>Run RSA verify with <code>n</code> and <code>e</code>. It must match the signature.</li>
        </ol>
        <p>Only the provider holds the private key. So only the provider could have made a valid signature.</p>`],
      ['How nonce and at_hash work', `
        <p><b>nonce:</b> the app makes a random value. It saves it in your session. It sends it in the login URL. The provider copies it into the ID token. The app checks they match. An old or stolen ID token has a different nonce. So it cannot be replayed into your login.</p>
        <p><b>at_hash:</b></p>
        <div class="math">at_hash = base64url( left half of SHA-256( access_token ) )</div>
        <p>For RS256 that is the first 16 of the 32 bytes. If an attacker swaps the access token, at_hash no longer matches.</p>`],
    ],
    example: {
      title: 'Validate two ID tokens like a real app',
      problem: `
        <p>Your app has these settings:</p>
        <ul>
          <li>Expected issuer: <code>https://accounts.google.com</code></li>
          <li>Your client_id: <code>1234.apps.googleusercontent.com</code></li>
          <li>Nonce saved in this user's session: <code>n-0S6_WzA2Mj</code></li>
          <li>Time now: <code>1798761900</code></li>
        </ul>
        <p>Two ID tokens arrive. Both have a valid RS256 signature from Google's JWKS. Which one do you accept?</p>
        ${T(['Claim', 'Token 1', 'Token 2'], [
          ['iss', 'https://accounts.google.com', 'https://accounts.google.com'],
          ['aud', '1234.apps.googleusercontent.com', '<b>9999.apps.googleusercontent.com</b>'],
          ['exp', '1798762200', '1798762200'],
          ['nonce', 'n-0S6_WzA2Mj', 'n-0S6_WzA2Mj'],
          ['access token sent with it', '<code>ya29.a0AfB_byC-example-access-token</code>', '—'],
          ['at_hash', 'acoNTFEet9fGfB-taNiivA', '—'],
        ])}`,
      steps: [
        ['Signature (both)', `<p>Both pass. But a valid signature only proves "Google made this". It does not prove "Google made this <b>for me</b>, <b>now</b>". Keep going.</p>`],
        ['Issuer', `<p>Both say <code>https://accounts.google.com</code>. Both pass.</p>`],
        ['Audience', `
          <p>Token 1: <code>aud</code> = our client_id. Pass.</p>
          <p>Token 2: <code>aud</code> = <code>9999…</code>. That token was made for another app. <b>Fail.</b> Someone took a token from a different app and replayed it here. This is the <b>token substitution</b> attack.</p>`],
        ['Expiry (token 1)', `
          <div class="math">exp − now = 1798762200 − 1798761900 = 300 seconds</div>
          <p>Still valid for 5 more minutes. Pass.</p>`],
        ['Nonce (token 1)', `<p>Token nonce = session nonce = <code>n-0S6_WzA2Mj</code>. Pass.</p>`],
        ['at_hash (token 1)', `
          <div class="math">SHA-256("ya29.a0AfB_byC-example-access-token")
= 69ca0d4c511eb7d7c67c1fad68d8a2bc 36f2ca2bfdd0df4105a47eb8efbbbd9d
left 16 bytes → base64url → acoNTFEet9fGfB-taNiivA</div>
          <p>This equals the <code>at_hash</code> claim. Pass.</p>`],
      ],
      answer: `
        <p><b>Accept token 1. Reject token 2</b> (wrong audience).</p>
        <p>Then log the user in as <code>iss + sub</code>. Remember the order: signature, then iss, aud, exp, nonce. Skipping <code>aud</code> is one of the most common real OIDC bugs.</p>`,
    },
  });

  /* ================= TLS / HTTPS ================= */
  IN('tls', {
    inside: [
      ['What a certificate looks like', `
        <p>A certificate is a signed ID card for a public key. On disk it is a PEM file:</p>
        ${C('text', `
          -----BEGIN CERTIFICATE-----
          MIIFazCCBFOgAwIBAgISA3x…(about 1,500 Base64 characters)…
          -----END CERTIFICATE-----
        `)}
        <p>Decoded with <code>openssl x509 -noout -text -in cert.pem</code> (shortened):</p>
        ${C('text', `
          Subject:  CN = shop.example.com
          Issuer:   C = US, O = Let's Encrypt, CN = R11
          Validity: Not Before: Oct  1 00:00:00 2026 GMT
                    Not After : Dec 30 23:59:59 2026 GMT
          Subject Public Key Info:  id-ecPublicKey, 256 bit (P-256)
          X509v3 Subject Alternative Name:  DNS:shop.example.com, DNS:www.shop.example.com
          X509v3 Extended Key Usage:        TLS Web Server Authentication
          Signature Algorithm: sha256WithRSAEncryption
          Signature Value:  5e:a1:09:…  (made with the CA's private key)
        `)}`],
      ['What lives where', `
        ${T(['Item', 'Lives on', 'Secret?'], [
          ['Server private key', 'Server only (<code>/etc/ssl/private/</code>, or an HSM)', '<b>Yes</b>. Never leaves.'],
          ['Server certificate + chain', 'Server. Sent to every client in the handshake.', 'No'],
          ['Root CA certificates', 'Client trust store (OS or browser). About 150 roots.', 'No, but must not be tampered with'],
          ['Ephemeral ECDHE keys', 'RAM on both sides, for one handshake', 'Yes. Deleted right after.'],
          ['Session (traffic) keys', 'RAM on both sides', 'Yes. Deleted when the connection ends.'],
        ])}
        <p>Because the ephemeral keys are deleted, a key stolen next year cannot decrypt today's traffic. This is <b>forward secrecy</b>.</p>`],
      ['Step 1 inside: agreeing on a secret (Diffie–Hellman)', `
        <p>Both sides must end with the same secret. But everything they send can be seen. Diffie–Hellman solves this.</p>
        <div class="math">Public:  prime p, base g
Client:  picks secret a → sends A = gᵃ mod p
Server:  picks secret b → sends B = gᵇ mod p
Client:  s = Bᵃ mod p
Server:  s = Aᵇ mod p          (both equal g^(a·b) mod p)</div>
        <p>An eavesdropper sees p, g, A and B. To get s, they need a or b. Finding a from A is the <b>discrete logarithm</b> problem. It is very hard for big numbers.</p>
        <p>TLS 1.3 normally uses <b>X25519</b>. The idea is the same, but numbers are replaced by points on a curve. A key is only 32 bytes.</p>`],
      ['Step 2 inside: proving the server is real', `
        <p>Diffie–Hellman alone does not say <b>who</b> you share a secret with. So the server proves its identity:</p>
        <ol>
          <li>The server sends its certificate chain.</li>
          <li>The server signs a hash of the whole handshake so far. This is the <b>CertificateVerify</b> message. It uses the private key that matches the certificate.</li>
          <li>The client checks the signature with the public key from the certificate.</li>
          <li>The client checks the certificate: the CA's signature, the dates, and that the SAN contains the name in the address bar.</li>
          <li>The client walks up the chain until it reaches a root in its trust store.</li>
        </ol>
        <p>A man in the middle can copy the certificate. But he cannot make the CertificateVerify signature without the private key.</p>`],
      ['Step 3 inside: turning one secret into many keys', `
        <p>TLS 1.3 feeds the DH secret and the handshake hash into <b>HKDF</b>. HKDF is a key-derivation function built on HMAC.</p>
        <div class="math">shared secret ─HKDF─▶ handshake keys  (encrypt the certificate messages)
             └─HKDF─▶ application keys (encrypt your HTTP data)</div>
        <p>Each direction gets its own key. The <b>Finished</b> message is an HMAC over the whole handshake. If an attacker changed even one byte earlier, Finished fails and the connection stops.</p>`],
      ['Step 4 inside: encrypting the data', `
        <p>Your HTTP request is now cut into records. Each record is encrypted with <b>AES-GCM</b> or <b>ChaCha20-Poly1305</b>. These are <b>AEAD</b> ciphers: they encrypt and add a 16-byte tag.</p>
        <ul>
          <li>The tag detects any change to the ciphertext.</li>
          <li>Each record uses a new nonce (the IV mixed with a record counter). So the same request never encrypts the same way twice.</li>
        </ul>`],
    ],
    example: {
      title: 'Do a Diffie–Hellman exchange with small numbers',
      problem: `
        <p>Client and server agree, in public, on <code>p = 23</code> and <code>g = 5</code>.</p>
        <p>The client secretly picks <code>a = 6</code>. The server secretly picks <code>b = 15</code>.</p>
        <ol>
          <li>What does each side send?</li>
          <li>What shared secret do they get?</li>
          <li>An eavesdropper saw everything sent. Can they find the secret?</li>
        </ol>`,
      steps: [
        ['Client computes its public value A', `
          <div class="math">A = 5⁶ mod 23 = 15,625 mod 23</div>
          <p>23 × 679 = 15,617. Then 15,625 − 15,617 = 8.</p>
          <div class="math">A = 8</div>`],
        ['Server computes its public value B', `
          <div class="math">B = 5¹⁵ mod 23 = 30,517,578,125 mod 23 = 19</div>
          <p>Tip: big powers are easier in small steps. Reduce after every multiply. In Python: <code>pow(5, 15, 23)</code> → 19.</p>`],
        ['Both compute the secret', `
          <div class="math">Client: s = B ᵃ mod p = 19⁶ mod 23 = 2
Server: s = A ᵇ mod p = 8¹⁵ mod 23 = 2</div>
          <p>Same answer. Neither side ever sent 2.</p>`],
        ['Think like the eavesdropper', `
          <p>The eavesdropper knows p = 23, g = 5, A = 8, B = 19. They need a, where 5ᵃ mod 23 = 8.</p>
          <p>With tiny numbers they can just try every a:</p>
          ${T(['a', '1', '2', '3', '4', '5', '<b>6</b>', '7', '…'], [
            ['5ᵃ mod 23', '5', '2', '10', '4', '20', '<b>8</b>', '17', '…'],
          ])}
          <p>Found a = 6. Then 19⁶ mod 23 = 2. Broken.</p>`],
        ['Scale up to real TLS', `
          <p>X25519 works with numbers near 2²⁵⁵. The best known attack needs about 2¹²⁶ ≈ 8.5 × 10³⁷ steps. At a billion billion (10¹⁸) steps per second, that is about 2.7 trillion years. Listing all values is impossible.</p>`],
      ],
      answer: `
        <p>Client sends <b>A = 8</b>. Server sends <b>B = 19</b>. Shared secret <b>s = 2</b>.</p>
        <p>With p = 23 an eavesdropper breaks it in seconds. With real sizes they cannot. The math is the same — only the size changes.</p>
        <p>The Diffie–Hellman playground below starts with exactly these numbers. Change a or b and watch the secret change.</p>`,
    },
  });

  /* ================= Mutual TLS ================= */
  IN('mtls', {
    inside: [
      ['What changes from normal TLS', `
        <p>In normal TLS only the server shows a certificate. In mTLS the server asks for one back. Three extra messages appear:</p>
        <ol>
          <li><b>CertificateRequest</b> (server → client): "Show me yours. It must come from one of these CAs."</li>
          <li><b>Certificate</b> (client → server): the client's certificate chain.</li>
          <li><b>CertificateVerify</b> (client → server): the client signs the handshake hash with its private key.</li>
        </ol>
        <p>Message 3 is the real proof. Anyone can copy a certificate. Only the owner can sign with the matching private key.</p>`],
      ['What lives where', `
        ${T(['Item', 'Service A (client)', 'Service B (server)'], [
          ['Own private key', '<code>a.key</code> — secret', '<code>b.key</code> — secret'],
          ['Own certificate', '<code>a.crt</code> (SAN: payments-api)', '<code>b.crt</code> (SAN: ledger-api)'],
          ['Trusted CA', '<code>internal-ca.crt</code>', '<code>internal-ca.crt</code>'],
          ['CA private key', '— (never on services)', '— (only on the CA, ideally in an HSM)'],
        ])}
        <p>Both sides trust the same internal CA. They do not need to know each other in advance. The CA vouches for both.</p>`],
      ['How a client certificate is born', `
        <ol>
          <li>The service makes a key pair. The private key never leaves the service.</li>
          <li>It builds a <b>CSR</b> (certificate signing request): its public key + its name, signed by itself.</li>
          <li>The CA checks the request is allowed. Then it signs a certificate with the CA private key.</li>
          <li>The service gets back the certificate. Often it is valid for only hours. A service mesh (Istio, Linkerd) renews it automatically.</li>
        </ol>
        ${C('bash', `
          openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \\
            -keyout a.key -out a.csr -subj "/CN=payments-api"
          openssl x509 -req -in a.csr -CA internal-ca.crt -CAkey internal-ca.key \\
            -days 1 -out a.crt -extfile <(printf "extendedKeyUsage=clientAuth\\nsubjectAltName=URI:spiffe://corp.internal/payments-api")
        `, 'Doing it by hand (a mesh does this for you)')}`],
      ['How the server checks the client certificate', `
        <ol>
          <li><b>Signature:</b> verify the CA's signature on the certificate with the CA public key.</li>
          <li><b>Dates:</b> now must be between Not Before and Not After.</li>
          <li><b>Purpose:</b> Extended Key Usage must include <code>clientAuth</code>.</li>
          <li><b>Revocation (optional):</b> not on a CRL / OCSP says good. Short-lived certs often skip this.</li>
          <li><b>Possession:</b> the CertificateVerify signature is valid with the cert's public key.</li>
          <li><b>Identity:</b> read the SAN, e.g. <code>spiffe://corp.internal/payments-api</code>. Now authorization can use it.</li>
        </ol>`],
    ],
    example: {
      title: 'Check a client certificate step by step (toy RSA)',
      problem: `
        <p>The internal CA has a toy RSA key: <code>n = 2773</code>, public exponent <code>e = 17</code>. (Its private exponent is <code>d = 157</code>. Only the CA knows it.)</p>
        <p>Service A connects to Service B at <b>2026-10-27 10:00 UTC</b> and shows this certificate:</p>
        ${T(['Field', 'Value'], [
          ['SAN', 'spiffe://corp.internal/payments-api'],
          ['Not Before / Not After', '2026-10-27 06:00 / 2026-10-28 06:00'],
          ['Extended Key Usage', 'clientAuth'],
          ['Hash of the certificate body (toy number)', 'h = 1234'],
          ['CA signature', 's = 726'],
        ])}
        <p>Should Service B accept it? Who is calling?</p>`,
      steps: [
        ['See how the CA made the signature', `
          <div class="math">s = hᵈ mod n = 1234¹⁵⁷ mod 2773 = 726</div>
          <p>This needs d. Only the CA can do it.</p>`],
        ['Verify the signature with the public key', `
          <p>Service B computes <code>sᵉ mod n</code>. If it gives back h, the signature is good.</p>
          <p>Use square-and-multiply. 17 = 16 + 1, so square four times, then multiply once more by 726:</p>
          ${T(['Step', 'Value mod 2773'], [
            ['726¹', '726'],
            ['726² = 726 × 726', '206'],
            ['726⁴ = 206 × 206', '841'],
            ['726⁸ = 841 × 841', '166'],
            ['726¹⁶ = 166 × 166', '2599'],
            ['726¹⁷ = 2599 × 726', '<b>1234</b>'],
          ])}
          <p>1234 = h. The CA really signed this certificate. Nobody changed it.</p>`],
        ['Check the dates', `<p>10:00 on Oct 27 is after 06:00 Oct 27 and before 06:00 Oct 28. Pass. (This cert lives only 24 hours. That is normal in a mesh.)</p>`],
        ['Check the purpose', `<p>EKU contains <code>clientAuth</code>. Pass. A server-only cert would fail here.</p>`],
        ['Check possession', `<p>Service A also sent CertificateVerify, signed with its own private key. B verifies it with the public key inside the cert (the same kind of math as above). Pass.</p>`],
      ],
      answer: `
        <p><b>Accept.</b> The caller is <code>spiffe://corp.internal/payments-api</code>. Service B can now apply rules like "payments-api may call POST /ledger".</p>
        <p>Toy numbers only show the idea. Real RSA uses n with 2048–4096 bits, adds padding and signs a SHA-256 hash. Many meshes use ECDSA P-256 instead, which is faster.</p>`,
    },
  });

  /* ================= SSH ================= */
  IN('ssh', {
    inside: [
      ['What the keys look like', `
        <p>Run <code>ssh-keygen -t ed25519</code> and you get two files.</p>
        <p><b>The public key</b> (<code>~/.ssh/id_ed25519.pub</code>). One line, three parts: type, Base64 key, comment.</p>
        ${C('text', `
          ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJQfFM6GsIZx3PTnNFfEHvLRmLyHHztxmj2W0tx4pM/r sakitha@laptop
        `, 'A real public key, made for this page')}
        <p><b>The private key</b> (<code>~/.ssh/id_ed25519</code>). A Base64 block between two marker lines:</p>
        ${C('text', `
          -----BEGIN OPENSSH PRIVATE KEY-----
          b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD…
          …(about 7 lines)…
          -----END OPENSSH PRIVATE KEY-----
        `, 'Shape only. Never paste a real private key anywhere.')}
        <p>The first Base64 characters decode to <code>openssh-key-v1</code>, then <code>aes256-ctr</code> and <code>bcrypt</code>. That means: this key is <b>encrypted</b> with your passphrase. bcrypt turns the passphrase into an AES key. Without a passphrase it would say <code>none</code> instead.</p>`],
      ['Taking the public key line apart', `
        <p>Decode the Base64 part and look at the bytes. It is a list of length-prefixed fields:</p>
        ${C('text', `
          00 00 00 0b                       → length 11
          73 73 68 2d 65 64 32 35 35 31 39  → "ssh-ed25519"
          00 00 00 20                       → length 32
          94 1f 14 ce 86 b0 86 71 dc f4 e7 34 57 c4 1e f2
          d1 98 bc 87 1f 3b 71 9a 3d 96 d2 dc 78 a4 cf eb   → the 32-byte public key A
        `)}
        <p>That is why every Ed25519 public key starts with <code>AAAAC3NzaC1lZDI1NTE5</code>. Those characters are just the encoded header.</p>
        <p>The <b>fingerprint</b> you see in prompts is a hash of these bytes:</p>
        <div class="math">fingerprint = "SHA256:" + base64( SHA-256( key bytes ) )  (no "=")
            = SHA256:FoaFFoJphXpcEIzotuVtHJb7pXF/OD1Z0qEiHbL5ZfQ</div>
        <p>Check yours with <code>ssh-keygen -lf ~/.ssh/id_ed25519.pub</code>.</p>`],
      ['How the machine makes the keys', `
        <p><b>Ed25519 (the default today):</b></p>
        <ol>
          <li><code>ssh-keygen</code> asks the OS for 32 random bytes. This is the <b>seed</b>. It is the real secret.</li>
          <li>It hashes the seed with SHA-512. It takes the first 32 bytes and fixes a few bits ("clamping"). This number is called <b>a</b>.</li>
          <li>It multiplies a fixed starting point <b>B</b> on the curve by a: <code>A = a · B</code>. "Multiply" here means "add the point to itself a times", using fast shortcuts.</li>
          <li><b>A</b> is the public key (32 bytes). The seed is the private key.</li>
        </ol>
        <p>Going forward (a → A) takes microseconds. Going back (A → a) is the <b>elliptic-curve discrete log</b> problem. With today's computers it would take longer than the age of the universe.</p>
        <p><b>RSA (older, still common):</b></p>
        <ol>
          <li>Pick two random primes p and q (about 1,536 bits each for a 3072-bit key).</li>
          <li><code>n = p × q</code>. Public exponent <code>e = 65537</code>.</li>
          <li>Private exponent <code>d</code> = the number where <code>e × d mod (p−1)(q−1) = 1</code>.</li>
          <li>Public key = (n, e). Private key = d (plus p, q).</li>
        </ol>
        <p>Finding d from n needs p and q. Splitting a huge n into p × q is the <b>factoring</b> problem. It is very hard.</p>`],
      ['What goes where', `
        ${T(['File', 'On which machine', 'Contains', 'Secret?', 'Permissions'], [
          ['<code>~/.ssh/id_ed25519</code>', 'Your laptop', 'Your private key (encrypted by passphrase)', '<b>Yes</b>', '<code>600</code>'],
          ['<code>~/.ssh/id_ed25519.pub</code>', 'Your laptop', 'Your public key', 'No', '<code>644</code>'],
          ['<code>~/.ssh/authorized_keys</code>', 'Server, in your account', 'Public keys allowed to log in as you (one per line)', 'No, but must not be writable by others', '<code>600</code>'],
          ['<code>~/.ssh/known_hosts</code>', 'Your laptop', 'Public host keys of servers you trust', 'No', '<code>644</code>'],
          ['<code>/etc/ssh/ssh_host_ed25519_key</code>', 'Server', 'The server\'s own private key', '<b>Yes</b>', '<code>600</code>, root only'],
          ['<code>/etc/ssh/ssh_host_ed25519_key.pub</code>', 'Server', 'The server\'s public host key', 'No', '<code>644</code>'],
        ])}
        <p>Remember the direction. <b>Your</b> public key goes to the <b>server</b> (authorized_keys). The <b>server's</b> public key comes to <b>you</b> (known_hosts). Private keys never move.</p>
        <p>If <code>~/.ssh</code> or <code>authorized_keys</code> can be written by other users, <code>sshd</code> ignores the file (StrictModes). This is a common "why does my key not work?" cause.</p>
        ${C('text', `
          # authorized_keys line with limits (options go before the key)
          from="10.0.0.0/8",no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJQf… sakitha@laptop

          # known_hosts line (hashed hostname so a thief cannot read your server list)
          |1|aGVsbG9zYWx0MTIzNDU2Nzg=|9F3x…= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI…
        `)}`],
      ['How the login is verified', `
        <ol>
          <li><b>Key exchange.</b> Laptop and server run X25519 (Diffie–Hellman on a curve). They get a shared secret.</li>
          <li><b>Session ID.</b> Both hash the whole exchange: <code>H = SHA-256(versions, algorithm lists, host key, both DH values, shared secret)</code>. The first H is the <b>session ID</b>. It is unique to this connection.</li>
          <li><b>Server proves itself.</b> The server signs H with its host private key. Your laptop checks it with the host key in <code>known_hosts</code>.</li>
          <li><b>You prove yourself.</b> Your laptop builds this message and signs it with your private key:
            <div class="math">session ID ‖ 50 ‖ "sakitha" ‖ "ssh-connection" ‖ "publickey" ‖ TRUE ‖ "ssh-ed25519" ‖ your public key</div></li>
          <li><b>Server checks.</b> Is that public key in <code>authorized_keys</code>? Does the signature verify with it? Both yes → you get a shell.</li>
        </ol>
        <p>The session ID is inside what you sign. So a recorded signature is useless on any other connection.</p>`],
      ['The Ed25519 check, in simple math', `
        <p>To sign message M with secret a and public A:</p>
        <div class="math">r = hash( secret part of seed ‖ M )      a fresh number per message
R = r · B                                  a curve point
k = hash( R ‖ A ‖ M )
S = r + k · a   (mod L)
signature = (R, S)                         64 bytes</div>
        <p>The server only knows A, M, R and S. It checks one equation:</p>
        <div class="math">S · B  ==  R + k · A</div>
        <p>Why does it hold? Put in S = r + k·a:</p>
        <div class="math">S·B = (r + k·a)·B = r·B + k·(a·B) = R + k·A   ✓</div>
        <p>You can make S only if you know a. The server checks S without ever learning a.</p>`],
      ['What the agent does', `
        <p><code>ssh-agent</code> is a small background program. You unlock the key once (<code>ssh-add</code>). The agent keeps it in memory.</p>
        <p>When <code>ssh</code> needs a signature, it sends the data to the agent through a local socket (<code>SSH_AUTH_SOCK</code>). The agent signs and returns only the signature. The key never goes to <code>ssh</code> or to the network.</p>`],
    ],
    example: {
      title: 'Make a toy RSA SSH key, sign a session, verify it',
      problem: `
        <p>Use tiny primes so you can follow every step: <code>p = 61</code>, <code>q = 53</code>, <code>e = 17</code>.</p>
        <ol>
          <li>Make the key pair.</li>
          <li>The session ID (made tiny) is <code>m = 65</code>. Sign it.</li>
          <li>Show how the server verifies.</li>
          <li>An attacker changes the signature by 1. What happens?</li>
        </ol>`,
      steps: [
        ['Build the public key (n, e)', `
          <div class="math">n = p × q = 61 × 53 = 3233
public key = (n = 3233, e = 17)</div>
          <p>This goes into the server's <code>authorized_keys</code>.</p>`],
        ['Build the private key d', `
          <div class="math">φ(n) = (p − 1)(q − 1) = 60 × 52 = 3120</div>
          <p>We need d where <code>17 × d mod 3120 = 1</code>. The extended Euclid algorithm gives <b>d = 2753</b>.</p>
          <div class="math">check: 17 × 2753 = 46,801 = 15 × 3120 + 1   ✓</div>
          <p>d stays in <code>~/.ssh/id_rsa</code> on your laptop. p and q are thrown away or kept secret.</p>`],
        ['Sign the session ID on the laptop', `
          <div class="math">signature s = mᵈ mod n = 65²⁷⁵³ mod 3233 = 588</div>
          <p>Do this with a computer: <code>pow(65, 2753, 3233)</code> in Python → 588. Only the holder of d can do this step.</p>
          <p>The laptop sends <b>588</b>. It does not send d.</p>`],
        ['Verify on the server', `
          <p>The server knows the session ID too (m = 65). It uses the public key from <code>authorized_keys</code>:</p>
          ${T(['Step', 'Value mod 3233'], [
            ['588¹', '588'],
            ['588²', '3046'],
            ['588⁴', '2639'],
            ['588⁸', '439'],
            ['588¹⁶', '1974'],
            ['588¹⁷ = 1974 × 588', '<b>65</b>'],
          ])}
          <div class="math">sᵉ mod n = 588¹⁷ mod 3233 = 65 = m   ✓  → login allowed</div>`],
        ['Try a forged signature', `
          <div class="math">589¹⁷ mod 3233 = 2838 ≠ 65   ✗  → login refused</div>
          <p>Changing the signature even a little gives a random-looking result. The attacker would need d to find the one correct value.</p>`],
      ],
      answer: `
        <p><b>Public key (3233, 17)</b> goes to the server. <b>Private key d = 2753</b> stays on the laptop. <b>Signature = 588</b>. The server computes 588¹⁷ mod 3233 = 65, which matches the session ID, so it lets you in.</p>
        <p>Why is this safe for real keys? To find d, an attacker must split n into p × q. For 3233 that is easy (61 × 53). For a 3072-bit n nobody can do it. Real SSH RSA also signs a SHA-256/512 hash with padding, not the raw session ID.</p>
        <p>Ed25519 keys use the curve equation from "How it works inside" instead of this, but the idea is the same: sign with the secret, check with the public part.</p>`,
    },
  });
})();
