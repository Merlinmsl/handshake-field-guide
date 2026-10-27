/* Augments every topic with an Architecture breakdown and a TL;DR "explain it" card.
   Kept separate so the core topic files stay readable. Runs after all topics are registered. */
(function () {
  'use strict';
  const HS = window.HS;
  const A = (id, parts, note) => { const t = HS.byId[id]; if (t && !t.arch) t.arch = { parts, note }; };
  const TL = (id, lines) => { const t = HS.byId[id]; if (t && !t.tldr) t.tldr = lines; };

  /* ---- Architecture: the moving parts of each method ---- */
  A('concepts', [
    ['user', 'Principal / subject', 'The identity making the request — a person or a service. Everything downstream is a decision <em>about</em> this subject.'],
    ['lock', 'Authentication', 'Verifies the claimed identity against a credential. Produces a proven identity, nothing more.'],
    ['policy', 'Authorization (PDP)', 'Given the proven identity, decides whether a specific action on a specific object is allowed.'],
    ['db', 'Protected resource', 'The data or capability being guarded. Each access is a fresh authorization decision, not a one-time gate.'],
  ], 'Authentication happens once and produces an identity; authorization happens on <em>every</em> object access. Collapsing the two — "they logged in, so let them" — is the root of most access-control bugs.');

  A('passwords', [
    ['browser', 'Client', 'Collects the password over TLS and sends it once. Should never log or cache it.'],
    ['server', 'Auth server', 'Runs the slow hash, does a constant-time compare, enforces rate limits and lockout.'],
    ['db', 'Credential store', 'Holds only {salt, slow-hash} per user — never plaintext, never a fast hash.', 'hashes only'],
    ['lock', 'Secret manager (optional)', 'Holds the site-wide pepper outside the database, so a DB-only breach can\'t verify guesses.'],
  ], 'The design assumption is that the credential store <em>will</em> be stolen. Salting + a slow memory-hard hash make that breach survivable; rate limiting handles live guessing.');

  A('basic-auth', [
    ['browser', 'Client', 'Caches credentials per realm and re-attaches the <code>Authorization</code> header on every request.'],
    ['server', 'Server', 'Challenges with <code>401 + WWW-Authenticate</code>, then decodes and verifies on each request.'],
    ['lock', 'TLS channel', 'Mandatory for Basic — the Base64 credentials are trivially reversible otherwise.'],
  ], 'There is no session and no server-side state: the credential travels on every request. That is what makes it simple for scripts and awkward (no logout) for humans.');

  A('sessions', [
    ['browser', 'Browser', 'Stores the opaque session ID in a cookie and auto-attaches it to same-site requests.'],
    ['server', 'App server', 'Looks the ID up on every request, regenerates it on login, issues CSRF tokens.'],
    ['db', 'Session store', 'Redis or a DB holding the real state (user, roles, expiry) keyed by the ID.', 'Redis / DB'],
  ], 'The cookie is just a claim-ticket; the authority is server-side, which is why sessions revoke instantly but need a shared store to scale. Cookies being auto-attached is exactly why CSRF defence is required.');

  A('api-keys', [
    ['server', 'Caller', 'Loads the key from a secret manager (never source) and sends it in a header over TLS.'],
    ['net', 'Gateway', 'Hashes and looks up the key, resolves the owning account, enforces scopes and rate limits.'],
    ['db', 'Key store', 'Holds hashed keys with their scopes and owner — plaintext shown only once at creation.', 'hashed'],
  ], 'A key is a bearer credential with usually no expiry, so the architecture leans on scoping, hashed storage, rotation and leak detection to bound the damage of an inevitable leak.');

  A('jwt', [
    ['idp', 'Issuer / auth service', 'Signs tokens with its private key (RS256) or a shared secret (HS256). The only party that can mint them.'],
    ['browser', 'Client', 'Holds the token and presents it as a <code>Bearer</code> on each request.'],
    ['server', 'Verifier (any service)', 'Validates the signature, <code>exp</code>, <code>iss</code> and <code>aud</code> locally — no lookup.', 'stateless'],
    ['key', 'JWKS endpoint', 'Publishes the issuer\'s public keys by <code>kid</code>, so verifiers can rotate keys seamlessly.'],
  ], 'Local verification with no central lookup is the whole value proposition — and the reason revocation is hard. Short-lived access tokens plus refresh tokens are the standard workaround.');

  A('oauth', [
    ['user', 'Resource owner', 'The user who consents to scoped access and authenticates only at the provider.'],
    ['browser', 'Client app', 'Runs the Authorization Code + PKCE flow; never sees the user\'s password.'],
    ['idp', 'Authorization server', 'Authenticates the user, shows consent, issues scoped access + refresh tokens.'],
    ['cloud', 'Resource server', 'Holds the data and enforces the token\'s scopes on each call.'],
  ], 'Separating who issues tokens (authorization server) from who holds the data (resource server) is what lets a user grant limited access to an app without ever sharing a password.');

  A('oidc', [
    ['browser', 'Relying Party (RP)', 'The app; requests <code>scope=openid</code> and validates the id_token to learn who logged in.'],
    ['idp', 'OpenID Provider (OP)', 'Authenticates the user and issues the signed id_token plus an access token.'],
    ['key', 'Discovery + JWKS', 'The <code>/.well-known</code> document and key set that let the RP find endpoints and verify tokens.'],
  ], 'OIDC is a thin layer over OAuth: one extra scope and one extra token (the id_token). The RP consumes the id_token for identity and must never forward it to APIs — those take the access token.');

  A('tls', [
    ['browser', 'Client', 'Offers versions/ciphers and a DH key share; validates the server certificate.'],
    ['server', 'Server', 'Proves it holds the certificate\'s private key; both sides derive the session keys.'],
    ['idp', 'Certificate Authority', 'Issues and signs the certificate that binds the server\'s key to its domain name.'],
    ['net', 'CT logs / OCSP', 'Public transparency logs and revocation checks that police mis-issued certificates.'],
  ], 'The handshake does authentication (certificate) and key agreement (ephemeral DH) together. Everything else in this guide rides inside the confidential, authenticated channel it establishes.');

  A('mtls', [
    ['server', 'Client service', 'Presents its own certificate and proves possession of the private key.'],
    ['server', 'Server service', 'Requests and verifies the client certificate in addition to presenting its own.'],
    ['idp', 'Internal CA', 'Issues short-lived identity certs to every workload (often via SPIFFE/SPIRE).'],
    ['net', 'Service mesh', 'Sidecars that establish mTLS and rotate certs transparently to app code.', 'Istio / Linkerd'],
  ], 'Both ends authenticate with certificates, so the certificate <em>is</em> the identity. The hard part is the certificate lifecycle at scale, which a mesh + an internal CA automate.');

  A('ssh', [
    ['terminal', 'Client', 'Holds the private key (ideally in an agent), verifies the host key against <code>known_hosts</code>.'],
    ['server', 'Server (sshd)', 'Stores the user\'s public key in <code>authorized_keys</code>, challenges the client to sign.'],
    ['idp', 'SSH CA (at scale)', 'Signs short-lived user and host certificates, removing per-host key files and TOFU prompts.'],
  ], 'Two authentications happen every session: the host proves itself (known_hosts) and the user proves themselves (key signature). An SSH CA is the PKI-style answer to managing both across a fleet.');

  A('sso', [
    ['user', 'User + IdP session', 'One browser session at the IdP is what makes the second, third app log in seamlessly.'],
    ['idp', 'Identity Provider', 'The single place that authenticates (with MFA) and issues assertions.'],
    ['cloud', 'Service Providers', 'Each app trusts the IdP, consumes its assertion, and creates its own local session.'],
  ], 'There are really two session layers — the IdP session and each app\'s local session. That split is why SSO is seamless but Single Logout is unreliable, and why the IdP is the crown-jewel target.');

  A('saml', [
    ['browser', 'Browser', 'Relays signed XML documents between SP and IdP via HTTP-Redirect/POST bindings.'],
    ['cloud', 'Service Provider', 'Builds the AuthnRequest and verifies the returned assertion\'s signature.'],
    ['idp', 'Identity Provider', 'Authenticates the user and signs the XML assertion with XML-DSig.'],
    ['key', 'Signing certificate', 'The IdP cert the SP uses to verify assertions — its expiry breaks every login at once.'],
  ], 'The IdP and SP never talk directly; the browser carries self-contained, signed assertions between them. XML-DSig\'s flexibility is the source of the signature-wrapping attack class.');

  A('kerberos', [
    ['terminal', 'Client', 'Proves identity once, then caches the TGT and per-service tickets.'],
    ['idp', 'KDC (AS + TGS)', 'The trusted third party: the AS authenticates, the TGS issues service tickets.', 'AS + TGS'],
    ['server', 'Service', 'Decrypts the service ticket with its own key and trusts the KDC\'s vouching — no KDC round-trip.'],
  ], 'Each ticket is encrypted for its intended recipient, so a ticket is useless to anyone else and services verify offline. The KDC\'s own key (krbtgt) is the single catastrophic point of failure.');

  A('ldap', [
    ['user', 'User', 'Supplies a username and password to an app over TLS.'],
    ['server', 'Application', 'Resolves the DN, binds as the user to authenticate, reads groups to authorize.'],
    ['dir', 'Directory', 'The hierarchical source of truth for users, groups and devices (AD/OpenLDAP).', 'AD / OpenLDAP'],
  ], 'Authentication is literally a <em>bind</em> (a login) to a directory entry; authorization is a <em>search</em> of that entry\'s group memberships. Most enterprise auth ultimately resolves to this directory.');

  A('radius', [
    ['user', 'Supplicant', 'The device seeking network access; speaks 802.1X/EAP to the NAS.'],
    ['net', 'NAS', 'The Wi-Fi AP, switch or VPN gateway — relays credentials and enforces the verdict. Decides nothing itself.', 'AP / switch'],
    ['server', 'RADIUS server', 'Authenticates, authorizes a network profile (VLAN), and records accounting.'],
    ['dir', 'Identity store', 'The directory (AD/LDAP) RADIUS checks credentials and groups against.'],
  ], 'Policy is centralised in the RADIUS server; the access point is a dumb relay. That separation is what lets one server govern network access for an entire campus or ISP, with accounting as the third "A".');

  A('mfa', [
    ['user', 'User', 'Presents a first factor (knowledge) and a second from a different category.'],
    ['server', 'Auth server', 'Verifies the password, then challenges and verifies the second factor; applies step-up/risk logic.'],
    ['phone', 'Second-factor device', 'An authenticator app, hardware key or phone proving possession (or a biometric proving inherence).'],
  ], 'The security comes from the factors being different <em>categories</em>, so one compromise isn\'t enough. The factor you choose matters enormously — SMS is relayable, a passkey is phishing-resistant.');

  A('totp', [
    ['phone', 'Authenticator', 'Computes <code>HMAC(secret, time/30)</code> → 6 digits, entirely offline.'],
    ['server', 'Verifier', 'Recomputes the same value, allows an adjacent window for drift, rate-limits attempts.'],
    ['key', 'Shared secret', 'Exchanged once at enrolment (QR) and stored on both sides — encrypt it at rest.'],
  ], 'No message is exchanged to make a code: both sides derive it from one shared secret and the clock. That offline elegance is also its limit — the code is phishable and the seed lives on both sides.');

  A('webauthn', [
    ['key', 'Authenticator', 'Holds the non-exportable private key in secure hardware; signs after a local gesture.'],
    ['browser', 'Browser (client)', 'Enforces the RP ID / origin check and supplies the real origin to be signed — the user can\'t override it.'],
    ['server', 'Relying Party', 'Stores only the public key; verifies the signature, origin and challenge.', 'public key only'],
  ], 'The browser binding the signature to the real origin is the entire anti-phishing mechanism. A server breach leaks only public keys, which are useless to an attacker.');

  A('magic-links', [
    ['user', 'User', 'Requests a link with only an email address; clicks it to log in.'],
    ['server', 'App server', 'Mints a single-use, short-lived, hashed token; verifies and consumes it on click.'],
    ['mail', 'Email provider', 'The real credential store — whoever controls the inbox can log in.', 'the dependency'],
  ], 'Authentication is delegated to the email provider: the inbox is the credential. The token must be single-use, short-lived and hashed, but the floor on security is the user\'s email account.');

  A('hmac-sig', [
    ['server', 'Client', 'Builds a canonical string + timestamp and signs it with the shared secret — sends the signature, not the secret.'],
    ['server', 'Server', 'Rebuilds the same canonical string, recomputes the HMAC, compares in constant time, checks freshness.'],
    ['key', 'Shared secret', 'Held by both sides and never transmitted; rotated with dual-secret overlap.'],
  ], 'The secret authenticates each request without ever crossing the wire, and the signature covers the contents so tampering is detected. A timestamp/nonce is what adds replay protection on top.');

  A('authz-models', [
    ['user', 'Subject', 'The authenticated identity whose request is being judged.'],
    ['server', 'PEP', 'Policy Enforcement Point — the app/gateway that gathers input and enforces the verdict.', 'enforces'],
    ['policy', 'PDP', 'Policy Decision Point — evaluates the chosen model (ACL/RBAC/ABAC/ReBAC) and returns allow/deny.', 'decides'],
    ['db', 'Policy + relationship data', 'Roles, attributes or the relationship graph the decision reads from.'],
  ], 'Separating the decision (PDP) from enforcement (PEP) keeps policy consistent and auditable. Real systems compose models — RBAC for coarse roles, ABAC for conditions, ReBAC for sharing.');

  A('oauth-scopes', [
    ['browser', 'Client app', 'Requests the minimum scopes a feature needs; receives them inside the access token.'],
    ['idp', 'Authorization server', 'Shows consent per scope and encodes the granted scopes in the token.'],
    ['cloud', 'Resource server', 'Checks the token\'s scope <em>and</em> the user\'s object-level permission on each call.'],
  ], 'Scopes are coarse, app-level permissions layered on top of normal object authorization — never a replacement for it. Checking scope alone, without ownership, is a classic data-leak bug.');

  A('opa', [
    ['server', 'Service (PEP)', 'Sends the decision input and enforces the answer; contains no rules itself. Fails closed if OPA is down.', 'enforces'],
    ['policy', 'OPA (PDP)', 'Evaluates the Rego policy against the input and returns a JSON decision.', 'decides'],
    ['db', 'Policy + data', 'Version-controlled Rego policies plus roles/relationships, distributed to every instance.'],
  ], 'Policy-as-code: rules live in one declarative, testable place and services query for decisions. Deploy OPA as a sidecar for latency, default-deny in policy, and fail-closed at the enforcement point.');

  /* ---- Real-world use: where you actually meet each method ---- */
  const U = (id, rows) => { const t = HS.byId[id]; if (t && !t.uses) t.uses = rows; };
  U('passwords', [
    ['Almost every login form', 'Still the default first factor for consumer and enterprise accounts.'],
    ['Linux /etc/shadow', 'Stores salted hashes (yescrypt/SHA-512-crypt) for local user accounts.'],
    ['Django, Rails, Laravel', 'Ship with salted slow hashing (PBKDF2, bcrypt, Argon2) built in.'],
    ['Have I Been Pwned', 'Used at sign-up to reject passwords already seen in breaches.'],
  ]);
  U('basic-auth', [
    ['Internal dashboards', 'Prometheus, Grafana sidecars and admin panels behind a reverse proxy.'],
    ['Package registries & CI', 'npm, PyPI and Docker registries accept tokens sent via Basic auth from scripts.'],
    ['Webhooks & IoT devices', 'Simple devices and legacy integrations that can\'t do OAuth.'],
    ['curl -u', 'The quickest way to authenticate a one-off scripted call.'],
  ]);
  U('sessions', [
    ['Traditional web apps', 'Django, Rails, Laravel and Express default to server-side sessions.'],
    ['Online banking', 'Short-lived, instantly revocable sessions with CSRF protection.'],
    ['E-commerce carts', 'The original use case for cookies, still everywhere.'],
    ['Admin consoles', 'Where instant logout and revocation matter more than scale.'],
  ]);
  U('api-keys', [
    ['Stripe, Twilio, SendGrid', 'Prefixed secret keys (e.g. <code>sk_live_</code>) for server-to-server calls.'],
    ['Google Maps / OpenAI-style APIs', 'Keys for metering, quotas and billing per project.'],
    ['Internal microservices', 'Simple shared credentials between services you own.'],
    ['GitHub personal access tokens', 'Scoped, expiring keys for scripts and CI.'],
  ]);
  U('jwt', [
    ['OAuth / OIDC tokens', 'Access tokens and id_tokens from Auth0, Okta, Entra ID and Google are JWTs.'],
    ['Microservice auth', 'API gateways verify JWTs at the edge and pass claims downstream.'],
    ['Single-page & mobile apps', 'Bearer tokens sent to stateless APIs.'],
    ['Cloud workload identity', 'Kubernetes service-account tokens and CI OIDC tokens (e.g. GitHub Actions) are JWTs.'],
  ]);
  U('oauth', [
    ['"Allow this app to…" screens', 'Granting a third-party app access to your Google Drive, GitHub repos or Spotify.'],
    ['Social & developer platforms', 'GitHub Apps, Slack apps and Microsoft Graph integrations.'],
    ['Machine-to-machine', 'Client Credentials grants between backend services.'],
    ['TVs and CLIs', 'Device Code flow: "go to this URL and enter the code" on Netflix, the GitHub CLI, etc.'],
  ]);
  U('oidc', [
    ['"Sign in with Google / Microsoft / Apple"', 'Every social login button.'],
    ['Enterprise SSO for new apps', 'Okta, Entra ID and Auth0 integrations increasingly default to OIDC.'],
    ['Kubernetes', 'API servers can authenticate users via an OIDC identity provider.'],
    ['CI/CD to cloud', 'GitHub Actions and GitLab exchange OIDC tokens for short-lived cloud credentials.'],
  ]);
  U('tls', [
    ['Every https:// site', 'The padlock — now the overwhelming majority of web traffic.'],
    ['Email', 'SMTP (STARTTLS), IMAPS and POP3S protect mail in transit.'],
    ['Databases & APIs', 'Postgres, MySQL and gRPC connections over TLS.'],
    ['VPNs & DNS', 'OpenVPN, DNS-over-HTTPS and DNS-over-TLS.'],
  ]);
  U('mtls', [
    ['Service meshes', 'Istio and Linkerd encrypt and authenticate every pod-to-pod call.'],
    ['Open Banking APIs', 'UK/EU Open Banking and FAPI profiles require client certificates.'],
    ['IoT fleets', 'AWS IoT Core and Azure IoT authenticate devices with X.509 certs.'],
    ['Zero-trust access', 'Cloudflare Access and BeyondCorp-style proxies verify device certificates.'],
  ]);
  U('ssh', [
    ['Server administration', 'Logging into Linux servers and cloud VMs.'],
    ['Git over SSH', '<code>git@github.com:…</code> pushes authenticate with SSH keys.'],
    ['File transfer & tunnels', '<code>scp</code>, <code>sftp</code> and port forwarding.'],
    ['Bastion hosts', 'Jump boxes and SSH certificate authorities in large fleets.'],
  ]);
  U('saml', [
    ['Enterprise SaaS SSO', 'Logging into Salesforce, Workday, AWS console or Slack via Okta/ADFS.'],
    ['Government & education', 'Shibboleth and national identity federations.'],
    ['Microsoft ADFS', 'The classic on-premises SAML IdP for Active Directory shops.'],
    ['Legacy enterprise apps', 'Older apps that only speak SAML.'],
  ]);
  U('kerberos', [
    ['Windows domain logon', 'Every login to a domain-joined PC.'],
    ['File shares & Exchange', 'Seamless SMB share and Outlook access in Active Directory.'],
    ['Hadoop & big data', 'Kerberos secures Hadoop, Kafka and HDFS clusters.'],
    ['Linux in AD', 'SSSD and <code>kinit</code> join Linux machines to Kerberos realms.'],
  ]);
  U('radius', [
    ['Enterprise Wi-Fi (WPA2/3-Enterprise)', 'Per-user Wi-Fi logins via 802.1X.'],
    ['eduroam', 'Global academic roaming Wi-Fi built on a RADIUS hierarchy.'],
    ['VPN gateways', 'Cisco, Palo Alto and Fortinet VPNs authenticate against RADIUS.'],
    ['ISPs', 'Broadband and mobile subscriber authentication and accounting/billing.'],
  ]);
  U('totp', [
    ['Authenticator apps', 'Google Authenticator, Microsoft Authenticator, Authy, 1Password.'],
    ['Developer platforms', 'GitHub, AWS, Google and most SaaS offer TOTP 2FA.'],
    ['Password managers', 'Many can store TOTP seeds alongside the password.'],
    ['Hardware OTP tokens', 'Key-fob tokens in banking and enterprise VPNs.'],
  ]);
  U('webauthn', [
    ['Consumer passkeys', 'Google, Apple, Microsoft, GitHub, PayPal and Amazon accounts.'],
    ['Hardware security keys', 'YubiKey and Titan keys for high-value and admin accounts.'],
    ['Enterprise phishing-resistant MFA', 'Required for privileged access in many organisations and governments.'],
    ['Platform authenticators', 'Windows Hello, Touch ID and Face ID unlock passkeys.'],
  ]);
  U('magic-links', [
    ['Slack & Notion', '"Email me a sign-in link" passwordless login.'],
    ['Newsletter & community platforms', 'Low-friction logins for infrequent users.'],
    ['Email OTP codes', 'Many apps send a 6-digit code instead of a link.'],
    ['Account verification', 'The same token pattern verifies email ownership at sign-up.'],
  ]);
  U('hmac-sig', [
    ['AWS API calls', 'Every SDK and CLI request is signed with Signature Version 4.'],
    ['Stripe & GitHub webhooks', 'Payloads carry an HMAC signature header you must verify.'],
    ['Slack request signing', 'Slack signs requests to your app with a timestamp + HMAC.'],
    ['Signed URLs', 'S3 pre-signed URLs and CDN signed links.'],
  ]);
  U('authz-models', [
    ['Unix file permissions & S3 ACLs', 'Classic access control lists.'],
    ['Enterprise apps & Kubernetes RBAC', 'Roles mapped to permissions.'],
    ['AWS IAM conditions', 'Attribute-based rules on tags, IPs and time.'],
    ['Google Drive sharing', 'Relationship-based access (Zanzibar), also OpenFGA and SpiceDB.'],
  ]);
  U('oauth-scopes', [
    ['Google API consent', 'Scopes like <code>drive.readonly</code> and <code>gmail.send</code>.'],
    ['GitHub tokens', '<code>repo</code>, <code>read:org</code>, <code>workflow</code> scopes on tokens and apps.'],
    ['Microsoft Graph', 'Delegated permissions like <code>Mail.Read</code> and <code>User.Read</code>.'],
    ['Slack apps', 'Bot and user scopes such as <code>chat:write</code>.'],
  ]);
  U('opa', [
    ['Kubernetes admission control', 'OPA Gatekeeper enforces cluster policies.'],
    ['API authorization', 'Envoy and API gateways call OPA for allow/deny decisions.'],
    ['Infrastructure as code', 'Conftest checks Terraform and Kubernetes manifests in CI.'],
    ['Alternatives', 'AWS Cedar / Verified Permissions and OpenFGA solve similar problems.'],
  ]);

  /* ---- playgrounds for pages that had none, or gain from a second one ---- */
  const addTool = (id, tool) => {
    const t = HS.byId[id]; if (!t) return;
    const cur = [].concat(t.tool || []);
    if (!cur.includes(tool)) t.tool = cur.concat(tool);
  };
  addTool('concepts', 'authz');
  addTool('ssh', 'pubkey');
  addTool('mtls', 'pubkey');
  addTool('webauthn', 'pubkey');
  addTool('sso', 'samloidc');
  addTool('magic-links', 'replay');

  /* ---- TL;DR: the 30-second answer an interviewer wants ---- */
  TL('concepts', [
    'Authentication proves <b>who you are</b>; authorization decides <b>what you may do</b>. AuthN always comes first.',
    '<code>401</code> = not authenticated (log in); <code>403</code> = authenticated but not allowed.',
    'Authentication happens once; authorization must be checked on <b>every object access</b> — skipping that is the IDOR/BOLA bug.',
  ]);
  TL('passwords', [
    'Never store plaintext or a fast hash. Store a <b>unique salt + slow memory-hard hash</b> (Argon2id/scrypt/bcrypt).',
    'Salt defeats rainbow tables and makes equal passwords differ; slowness makes offline guessing uneconomic.',
    'Modern NIST: favour length, drop forced composition and routine rotation, screen against breach lists, add MFA.',
  ]);
  TL('basic-auth', [
    'Sends <code>base64(user:password)</code> in the <code>Authorization</code> header — encoding, not encryption, so TLS is mandatory.',
    'Driven by the <code>401 + WWW-Authenticate</code> challenge; stateless, so the credential rides on every request.',
    'Prefer Basic-over-TLS to Digest (which forces weak server-side storage). Fine for scripts, awkward for humans (no logout).',
  ]);
  TL('sessions', [
    'The cookie holds only an <b>opaque session ID</b>; the real state lives server-side, keyed by that ID.',
    'Instantly revocable, but needs a shared store (Redis) to scale across servers.',
    'Cookies auto-attach by destination → CSRF risk → defend with <code>SameSite</code> + CSRF tokens; regenerate the ID on login.',
  ]);
  TL('api-keys', [
    'A <b>bearer credential</b> for machine-to-machine: possession = access, usually with no expiry.',
    'Send in a header over TLS (never a URL); store hashed; scope to least privilege; rotate.',
    'Because leaks last until noticed, lean on scoping, secret managers and leak detection. HMAC signing is the stronger cousin.',
  ]);
  TL('jwt', [
    'A <b>signed, self-contained</b> token: <code>header.payload.signature</code>, Base64URL — readable, not encrypted.',
    'Any service verifies it <b>locally</b> with the issuer\'s key — no lookup — which is why it scales but is hard to revoke.',
    'Validate signature + <code>exp</code> + <code>iss</code> + <code>aud</code>, and <b>pin the algorithm</b> to stop alg:none / key-confusion.',
  ]);
  TL('oauth', [
    'OAuth is <b>delegated authorization</b>, not login: an app gets a scoped token to act on your behalf without your password.',
    'Default flow is <b>Authorization Code + PKCE</b>: one-time code via redirect, exchanged (with the PKCE verifier) for tokens.',
    '<code>state</code> stops CSRF on the redirect; PKCE stops a stolen code being redeemed; access tokens are short + refresh tokens renew.',
  ]);
  TL('oidc', [
    'OIDC = OAuth + <code>scope=openid</code> + an <b>id_token</b> (a signed JWT) that tells the app who logged in.',
    'id_token is for the <b>app</b> (identity); access_token is for <b>APIs</b> — never mix them up.',
    'The RP validates the id_token\'s signature (via JWKS), <code>iss</code>, <code>aud</code>, <code>exp</code> and <code>nonce</code>.',
  ]);
  TL('tls', [
    'Provides <b>confidentiality, integrity and server authentication</b> (via a CA-signed certificate).',
    'The handshake agrees keys with <b>ephemeral Diffie–Hellman</b> (TLS 1.3) — the secret never crosses the wire — giving forward secrecy.',
    'Trust = the cert chains to a root in your trust store and the hostname matches; HSTS removes the click-through bypass.',
  ]);
  TL('mtls', [
    'Mutual TLS: <b>both</b> client and server authenticate with certificates — the cert is the identity, no shared secret.',
    'Ideal for <b>zero-trust</b>: network access alone is useless without a valid client certificate.',
    'The hard part is the certificate lifecycle at scale — solved by a service mesh + SPIFFE/SPIRE short-lived identities.',
  ]);
  TL('ssh', [
    'Key-pair auth: you prove possession by <b>signing a challenge</b>; the private key never leaves your machine.',
    'The first-connection fingerprint prompt is <b>host authentication</b> (known_hosts) — the TOFU weak point.',
    'At scale, an <b>SSH certificate authority</b> signs short-lived user and host keys, removing authorized_keys sprawl and TOFU.',
  ]);
  TL('sso', [
    'SSO is a <b>pattern</b> (built on SAML/OIDC/Kerberos): authenticate once at an <b>IdP</b>, access many apps (SPs).',
    'Upside: one strong MFA-protected login + instant deprovisioning. Downside: the IdP is a single point of failure and a prime phishing target.',
    'Two session layers (IdP + per-app) make Single Logout unreliable; authorization is still each app\'s job.',
  ]);
  TL('saml', [
    'XML-based enterprise SSO: the IdP sends the SP a <b>signed assertion</b> (XML-DSig) via the browser.',
    'SP-initiated flow: app → AuthnRequest → IdP login → signed SAMLResponse POSTed to the SP\'s ACS.',
    'Watch for <b>XML Signature Wrapping</b> (verify the signed element is the one you read) and expiring IdP certs. Never hand-roll it.',
  ]);
  TL('kerberos', [
    'Ticket-based SSO with a trusted <b>KDC</b>: authenticate once for a <b>TGT</b>, trade it for per-service tickets.',
    'Each ticket is encrypted for its target service, so the password never travels and services verify offline.',
    'Needs synced clocks (timestamps stop replay). Key attacks: Kerberoasting, pass-the-ticket, and the catastrophic golden ticket (stolen krbtgt).',
  ]);
  TL('ldap', [
    'The <b>directory</b> (AD/LDAP) is the central source of truth for users and groups.',
    'Authentication = a <b>bind</b> (logging in as the user\'s DN); authorization = <b>searching</b> group memberships.',
    'Always use LDAPS/StartTLS, disable anonymous bind, and escape inputs to prevent LDAP injection.',
  ]);
  TL('radius', [
    'The <b>AAA</b> server for network access: Authentication, Authorization and <b>Accounting</b>.',
    'The access point (NAS) is a <b>relay</b> — it forwards credentials to RADIUS and enforces the verdict; policy is central.',
    'Enterprise Wi-Fi uses 802.1X/EAP; <b>EAP-TLS</b> (certificates) is the gold standard. RADSEC encrypts the legacy UDP protocol.',
  ]);
  TL('mfa', [
    'Requires proof from <b>two different factor categories</b> (know / have / are) — two passwords don\'t count.',
    'Not all MFA is equal: SMS (SIM-swap, relay) → TOTP (phishable) → push w/ number-matching → <b>passkeys (phishing-resistant)</b>.',
    'Code-based factors can be relayed by a real-time proxy; only origin-bound passkeys stop that. Recovery is the usual weak point.',
  ]);
  TL('totp', [
    'A 6-digit code = <b>HMAC(shared secret, current 30s window)</b>, computed identically and offline on both sides.',
    'TOTP (time counter) vs HOTP (event counter); the time version needs no event sync, just roughly aligned clocks.',
    'Phishable (the code isn\'t bound to a site) and seed-based (encrypt seeds at rest). A strong SMS replacement, below passkeys.',
  ]);
  TL('webauthn', [
    'Public-key login (passkeys): the <b>private key stays in hardware</b>; the server stores only the public key.',
    '<b>Phishing-resistant by construction</b> — the browser binds the signature to the real origin, which a fake site can\'t match.',
    'A single tap is still MFA (device you have + biometric/PIN you are/know). Synced passkeys solved the lost-device problem.',
  ]);
  TL('magic-links', [
    'Passwordless login by clicking a <b>one-time emailed token</b> — proving control of the inbox.',
    'The token must be random, hashed, single-use and short-lived; optionally bound to the requesting session.',
    'Security floor = the user\'s email account, so it\'s a poor fit for high-assurance systems. Watch URL pre-fetching by mail scanners.',
  ]);
  TL('hmac-sig', [
    'Prove you hold a shared secret by <b>signing each request</b> (HMAC) and sending the signature — the secret never travels.',
    'The signature covers the request contents, so tampering is detected; a <b>timestamp/nonce</b> adds replay protection.',
    'Provides integrity + authenticity, not confidentiality (still need TLS). Symmetric, so no non-repudiation. Verify raw bytes, constant-time.',
  ]);
  TL('authz-models', [
    '<b>ACL</b> (per-object lists) → <b>RBAC</b> (roles) → <b>ABAC</b> (attribute rules) → <b>ReBAC</b> (relationship graph).',
    'RBAC is simple but hits <b>role explosion</b> when access needs conditions; ABAC/ReBAC express those directly.',
    'Separate the decision (PDP) from enforcement (PEP), default-deny, and check <b>every object</b>. Real systems compose models.',
  ]);
  TL('oauth-scopes', [
    'A scope = what an <b>app</b> may do on the user\'s behalf; consented by the user, carried in the access token.',
    'Scope is <b>app-level, not object-level</b>: the API must still check the specific object belongs to the token\'s user.',
    'Scopes (OAuth), roles (your app) and claims (OIDC identity) are three distinct layers — don\'t conflate them.',
  ]);
  TL('opa', [
    'Policy-as-code: authorization rules live in one declarative place (Rego) and services <b>query</b> OPA for decisions.',
    'Cleanly splits <b>PDP</b> (OPA decides) from <b>PEP</b> (your service enforces) — consistent, versioned, unit-testable.',
    'Default-deny in policy and <b>fail-closed</b> at the enforcement point; deploy as a sidecar for latency. Also guards Kubernetes.',
  ]);
})();
