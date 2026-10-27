/* Handshake Field Guide — interactive playgrounds.
   Every demo is a learning aid: it shows what a verifier checks and why it
   accepts or rejects input. Crypto uses the browser's WebCrypto where possible. */
(function () {
  'use strict';
  const HS = window.HS, esc = HS.esc;
  const T = HS.tools;

  /* ---------- small helpers ---------- */
  const enc = new TextEncoder();
  const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const b64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b64urlStr = (s) => b64url(enc.encode(s));
  function b64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    try { return decodeURIComponent(escape(atob(str))); } catch (e) { return atob(str); }
  }
  const hex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  async function hmac(keyBytes, msgBytes, hash = 'SHA-256') {
    const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, msgBytes));
  }
  async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
  const el = (html) => { const d = document.createElement('div'); d.innerHTML = html.trim(); return d.firstElementChild; };
  function shell(host, title, tag, bodyHTML) {
    host.innerHTML = `<div class="pg"><div class="pg-h"><h3>${title}</h3><span>${tag}</span></div><div class="pg-b">${bodyHTML}</div></div>`;
    return host.querySelector('.pg-b');
  }
  const checksHTML = (rows) => `<ul class="checks">${rows.map(([s, t]) => `<li class="${s}">${t}</li>`).join('')}</ul>`;

  /* ================================================================
     1. JWT decoder & verifier
  ================================================================ */
  const SAMPLE_SECRET = 'super-secret-signing-key';
  T.jwt = async function (host) {
    const now = Math.floor(Date.now() / 1000);
    const b = shell(host, 'JWT decoder & verifier', 'HS256', `
      <p>A JWT is three Base64URL chunks joined by dots: <code>header.payload.signature</code>. The first two are only <em>encoded</em>, not encrypted — anyone can read them. The signature is what proves the token has not been tampered with. Edit any field and watch the signature check flip.</p>
      <div class="g2">
        <div>
          <label class="fld"><span>Shared secret (HS256)</span><input id="jwt-sec" type="text" value="${SAMPLE_SECRET}"></label>
          <div class="fld"><span>Header</span><textarea id="jwt-h" spellcheck="false">{
  "alg": "HS256",
  "typ": "JWT"
}</textarea></div>
          <div class="fld"><span>Payload (claims)</span><textarea id="jwt-p" spellcheck="false">{
  "sub": "user_8842",
  "name": "Sakitha",
  "role": "editor",
  "iat": ${now},
  "exp": ${now + 900}
}</textarea></div>
          <div class="btn-row"><button class="btn" id="jwt-sign">Sign &amp; build token</button><button class="btn ghost" id="jwt-expire">Make it expired</button></div>
          <p class="muted" style="font-size:13.5px;margin:0">This verifier is configured like a real one: it only accepts <code>HS256</code>, checks the signature, and checks <code>exp</code>.</p>
        </div>
        <div>
          <div class="fld"><span>Encoded token</span><textarea id="jwt-tok" spellcheck="false" style="min-height:120px"></textarea></div>
          <div class="btn-row"><button class="btn ghost" id="jwt-verify">Decode &amp; verify</button><button class="btn ghost" id="jwt-tamper">Tamper: make me an admin</button></div>
          <div id="jwt-col" class="out" style="min-height:40px"></div>
          <div id="jwt-res"></div>
        </div>
      </div>`);
    const $ = (id) => b.querySelector(id);
    const colour = (tok) => {
      const parts = tok.split('.');
      return parts.map((p, i) => `<span class="${['tok-h', 'tok-p', 'tok-s'][i] || ''}">${esc(p)}</span>`).join('<span class="muted">.</span>');
    };
    async function build() {
      let h, p;
      try { h = JSON.stringify(JSON.parse($('#jwt-h').value)); p = JSON.stringify(JSON.parse($('#jwt-p').value)); }
      catch (e) { $('#jwt-res').innerHTML = `<p class="callout bad">The header or payload is not valid JSON, so it cannot be encoded.</p>`; return; }
      const signingInput = b64urlStr(h) + '.' + b64urlStr(p);
      const sig = b64url(await hmac(enc.encode($('#jwt-sec').value), enc.encode(signingInput)));
      const tok = signingInput + '.' + sig;
      $('#jwt-tok').value = tok;
      $('#jwt-col').innerHTML = colour(tok);
      verify();
    }
    async function verify() {
      const tok = $('#jwt-tok').value.trim();
      $('#jwt-col').innerHTML = colour(tok);
      const parts = tok.split('.');
      if (parts.length !== 3) { $('#jwt-res').innerHTML = `<p class="callout bad">A JWT needs exactly three dot-separated parts.</p>`; return; }
      const rows = [];
      let header = {}, payload = {};
      try { header = JSON.parse(b64urlDecode(parts[0])); rows.push(['pass', `Header decodes: <code>${esc(JSON.stringify(header))}</code>`]); }
      catch (e) { rows.push(['fail', 'Header is not valid Base64URL JSON']); }
      try { payload = JSON.parse(b64urlDecode(parts[1])); rows.push(['pass', `Payload decodes: <b>${esc(payload.name || payload.sub || '—')}</b>, role <b>${esc(payload.role || '—')}</b>`]); }
      catch (e) { rows.push(['fail', 'Payload is not valid Base64URL JSON']); }
      const expectSig = b64url(await hmac(enc.encode($('#jwt-sec').value), enc.encode(parts[0] + '.' + parts[1])));
      const sigOk = expectSig === parts[2];
      rows.push([sigOk ? 'pass' : 'fail', sigOk ? 'Signature matches — token was issued with this secret and not altered' : 'Signature does <b>not</b> match. Either the secret is wrong or header/payload were changed after signing']);
      // algorithm pinning: never trust the alg the token claims
      const algOk = header.alg === 'HS256';
      if (!algOk) rows.push(['fail', header.alg && String(header.alg).toLowerCase() === 'none'
        ? '<b>alg: none</b> means "no signature". A pinned verifier rejects it outright.'
        : `Header claims <code>alg: ${esc(header.alg || '(missing)')}</code>, but this verifier only accepts <code>HS256</code>. Rejected without looking further.`]);
      else rows.push(['pass', 'Algorithm is HS256, the only one this verifier allows']);
      // expiry is part of the verdict, not a footnote
      const nowS = Math.floor(Date.now() / 1000);
      let expOk = true;
      if (typeof payload.exp !== 'number') { expOk = false; rows.push(['fail', 'No numeric <code>exp</code> claim. This verifier requires an expiry.']); }
      else {
        expOk = payload.exp > nowS;
        const mins = Math.round(Math.abs(payload.exp - nowS) / 60);
        rows.push([expOk ? 'pass' : 'fail', `exp = ${payload.exp} (${expOk ? `expires in ${mins} min` : `expired ${mins} min ago`})`]);
      }
      const ok = sigOk && algOk && expOk;
      $('#jwt-res').innerHTML = `<div class="verdict ${ok ? 'good' : 'bad'}">${ok ? 'Token would be ACCEPTED' : 'Token would be REJECTED'}</div>${checksHTML(rows)}`;
    }
    $('#jwt-sign').addEventListener('click', build);
    $('#jwt-verify').addEventListener('click', verify);
    $('#jwt-tamper').addEventListener('click', () => {
      // flip role to admin in the payload text but DON'T re-sign — show the signature catches it
      try {
        const p = JSON.parse($('#jwt-p').value); p.role = 'admin'; $('#jwt-p').value = JSON.stringify(p, null, 2);
      } catch (e) {}
      const parts = $('#jwt-tok').value.split('.');
      try { if (parts.length === 3) { parts[1] = b64urlStr(JSON.stringify(JSON.parse($('#jwt-p').value))); $('#jwt-tok').value = parts.join('.'); } } catch (e) {}
      verify();
    });
    $('#jwt-expire').addEventListener('click', () => {
      try {
        const p = JSON.parse($('#jwt-p').value); const t = Math.floor(Date.now() / 1000);
        p.iat = t - 3600; p.exp = t - 600; $('#jwt-p').value = JSON.stringify(p, null, 2);
      } catch (e) {}
      build(); // properly signed, but expired: the signature passes and exp fails
    });
    await build();
  };

  /* ================================================================
     2. HMAC avalanche — one byte changes everything
  ================================================================ */
  T.hmac = async function (host) {
    const b = shell(host, 'HMAC signature explorer', 'SHA-256', `
      <p>HMAC turns a message plus a secret key into a fixed-length tag. Change a single character of the message or the key and roughly half the output bits flip — the <em>avalanche effect</em>. That is why a tag cannot be nudged toward a forgery.</p>
      <div class="g2">
        <div><label class="fld"><span>Secret key</span><input id="hm-key" type="text" value="billing-service-v2"></label>
        <label class="fld"><span>Message</span><input id="hm-msg" type="text" value="POST /refunds amount=20.00"></label>
        <div class="out" id="hm-out"></div></div>
        <div><label class="fld"><span>Message, altered (try changing 20 to 200)</span><input id="hm-msg2" type="text" value="POST /refunds amount=200.00"></label>
        <div class="out" id="hm-out2"></div>
        <p class="mono" id="hm-diff" style="color:var(--pk-int);font-weight:600"></p></div>
      </div>`);
    const $ = (s) => b.querySelector(s);
    async function run() {
      const key = enc.encode($('#hm-key').value);
      const a = hex(await hmac(key, enc.encode($('#hm-msg').value)));
      const c = hex(await hmac(key, enc.encode($('#hm-msg2').value)));
      $('#hm-out').innerHTML = a.replace(/(.{8})/g, '$1 ');
      // highlight differing nibbles
      let diffNibbles = 0, out2 = '';
      for (let i = 0; i < c.length; i++) { const d = c[i] !== a[i]; if (d) diffNibbles++; out2 += `<span style="${d ? 'color:var(--pk-atk);font-weight:700' : ''}">${c[i]}</span>`; }
      $('#hm-out2').innerHTML = out2.replace(/(<span[^>]*>.<\/span>){8}/g, '$& ');
      // bit-level difference
      let bits = 0; for (let i = 0; i < a.length; i++) { bits += (parseInt(a[i], 16) ^ parseInt(c[i], 16)).toString(2).replace(/0/g, '').length; }
      $('#hm-diff').textContent = `${bits} of 256 output bits differ (${Math.round(bits / 256 * 100)}%) from a tiny message change.`;
    }
    b.querySelectorAll('input').forEach((i) => i.addEventListener('input', run));
    await run();
  };

  /* ================================================================
     3. TOTP (authenticator code) generator
  ================================================================ */
  const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function base32decode(s) {
    s = s.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
    let bits = '', out = [];
    for (const c of s) { const v = BASE32.indexOf(c); if (v < 0) continue; bits += v.toString(2).padStart(5, '0'); }
    for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
    return new Uint8Array(out);
  }
  async function totp(secretB32, step = 30, digits = 6, t = Date.now()) {
    const counter = Math.floor(t / 1000 / step);
    const buf = new ArrayBuffer(8); const dv = new DataView(buf);
    dv.setUint32(4, counter >>> 0); dv.setUint32(0, Math.floor(counter / 2 ** 32));
    const mac = await hmac(base32decode(secretB32), new Uint8Array(buf), 'SHA-1');
    const offset = mac[mac.length - 1] & 0x0f;
    const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
    return (bin % 10 ** digits).toString().padStart(digits, '0');
  }
  T.totp = async function (host) {
    const b = shell(host, 'TOTP generator (like Google Authenticator)', 'RFC 6238', `
      <p>Your authenticator app and the server share one secret. Both compute <code>HMAC-SHA1(secret, current 30-second window)</code> and take 6 digits from it. No network, no messages — the code is derived from shared time, which is why it works on a plane.</p>
      <label class="fld" style="max-width:360px"><span>Shared secret (Base32)</span><input id="tp-sec" type="text" value="JBSWY3DPEHPK3PXP"></label>
      <div style="display:flex;gap:26px;align-items:center;flex-wrap:wrap;margin:8px 0">
        <div style="font:800 46px var(--f-mono);letter-spacing:.12em;color:var(--accent)" id="tp-code">------</div>
        <div style="flex:1;min-width:180px"><div style="height:8px;border-radius:4px;background:var(--surface-3);overflow:hidden"><i id="tp-bar" style="display:block;height:100%;background:var(--accent)"></i></div>
        <p class="mono" id="tp-left" style="color:var(--ink-3);margin:6px 0 0;font-size:12px"></p></div>
      </div>
      <p class="muted" id="tp-prev" style="font:13px var(--f-mono)"></p>
      <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
        <label class="fld" style="width:200px;margin:0"><span>Act as the server: verify a code</span><input id="tp-try" type="text" inputmode="numeric" maxlength="6" placeholder="6 digits"></label>
        <button class="btn ghost" id="tp-check">Verify</button>
      </div>
      <div id="tp-res"></div>`);
    const $ = (s) => b.querySelector(s);
    let timer;
    $('#tp-check').addEventListener('click', async () => {
      const sec = $('#tp-sec').value.trim() || 'JBSWY3DPEHPK3PXP', code = $('#tp-try').value.trim(), now = Date.now();
      try {
        const cur = await totp(sec, 30, 6, now), prev = await totp(sec, 30, 6, now - 30000);
        const ok = code === cur || code === prev;
        $('#tp-res').innerHTML = checksHTML([[ok ? 'pass' : 'fail', ok
          ? `Accepted: matches the ${code === cur ? 'current' : 'previous'} 30-second window. A real server would now mark this code as used so it can't be replayed.`
          : 'Rejected: matches neither the current nor the previous window. Real servers also lock out after a few wrong tries, because 6 digits is only a million possibilities.']]);
      } catch (e) { $('#tp-res').innerHTML = checksHTML([['fail', 'That secret is not valid Base32 (letters A–Z and digits 2–7).']]); }
    });
    async function tick() {
      if (!host.isConnected) { clearInterval(timer); return; } // page changed: stop ticking
      const sec = $('#tp-sec').value.trim() || 'JBSWY3DPEHPK3PXP';
      try {
        const now = Date.now();
        $('#tp-code').textContent = await totp(sec, 30, 6, now);
        const prev = await totp(sec, 30, 6, now - 30000);
        const left = 30 - Math.floor((now / 1000) % 30);
        $('#tp-bar').style.width = (left / 30 * 100) + '%';
        $('#tp-bar').style.background = left <= 5 ? 'var(--warn)' : 'var(--accent)';
        $('#tp-left').textContent = `${left}s until this code rolls over`;
        $('#tp-prev').textContent = `Server also accepts the previous window (${prev}) to allow for clock drift.`;
      } catch (e) { $('#tp-code').textContent = 'bad key'; }
    }
    $('#tp-sec').addEventListener('input', tick);
    timer = setInterval(tick, 1000);
    tick();
  };
  HS._totp = totp; // exposed for self-tests against the RFC 6238 vectors

  /* ================================================================
     4. OAuth PKCE builder
  ================================================================ */
  T.pkce = async function (host) {
    const b = shell(host, 'PKCE challenge builder', 'OAuth 2.0 / RFC 7636', `
      <p>A mobile or single-page app cannot keep a client secret. PKCE fixes this: the app invents a random <code>code_verifier</code>, sends only its SHA-256 hash (the <code>code_challenge</code>) when starting login, then proves ownership by revealing the verifier when exchanging the code. A stolen authorization code is useless without the verifier.</p>
      <div class="btn-row"><button class="btn" id="pk-gen">Generate a fresh verifier</button></div>
      <label class="fld"><span>code_verifier (random, kept in the app)</span><input id="pk-ver" type="text"></label>
      <div class="out" id="pk-out"></div>
      <p class="muted">The authorization request carries the challenge + <code>S256</code>. The token request carries the raw verifier. The server re-hashes the verifier and checks it equals the challenge it stored.</p>`);
    const $ = (s) => b.querySelector(s);
    async function derive() {
      const v = $('#pk-ver').value;
      const chal = b64url(await sha256(enc.encode(v)));
      $('#pk-out').innerHTML = `code_challenge_method = <b>S256</b>\ncode_challenge = SHA256(verifier) =\n<span class="tok-s">${esc(chal)}</span>`;
    }
    $('#pk-gen').addEventListener('click', () => {
      const rnd = crypto.getRandomValues(new Uint8Array(32));
      $('#pk-ver').value = b64url(rnd); derive();
    });
    $('#pk-ver').addEventListener('input', derive);
    $('#pk-gen').click();
  };

  /* ================================================================
     5. Diffie–Hellman shared-secret (toy numbers)
  ================================================================ */
  T.dh = function (host) {
    const b = shell(host, 'Diffie–Hellman key exchange', 'toy numbers', `
      <p>Two parties agree on a shared secret over a public channel without ever sending it. They publicly agree on a prime <code>p</code> and base <code>g</code>, each picks a private number, and they exchange <code>g^private mod p</code>. Each raises the other's public value to their own private power and lands on the same secret. An eavesdropper sees <code>p, g</code> and both public values but cannot feasibly recover the secret (for real sizes). Small numbers here so you can follow the arithmetic.</p>
      <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:flex-end">
        <label class="fld" style="width:120px"><span>prime p</span><input id="dh-p" type="number" value="23"></label>
        <label class="fld" style="width:120px"><span>base g</span><input id="dh-g" type="number" value="5"></label>
        <label class="fld" style="width:140px"><span>Alice private a</span><input id="dh-a" type="number" value="6"></label>
        <label class="fld" style="width:140px"><span>Bob private b</span><input id="dh-b" type="number" value="15"></label>
      </div>
      <div class="out" id="dh-out"></div>`);
    const $ = (s) => b.querySelector(s);
    const pmod = (base, e, m) => { let r = 1n; base %= m; while (e > 0n) { if (e & 1n) r = (r * base) % m; e >>= 1n; base = (base * base) % m; } return r; };
    function run() {
      try {
        const p = BigInt($('#dh-p').value), g = BigInt($('#dh-g').value), a = BigInt($('#dh-a').value), bb = BigInt($('#dh-b').value);
        if (p < 2n) throw 0;
        const A = pmod(g, a, p), B = pmod(g, bb, p);
        const s1 = pmod(B, a, p), s2 = pmod(A, bb, p);
        $('#dh-out').innerHTML = `Public: A = g^a mod p = <span class="tok-p">${A}</span>  ·  B = g^b mod p = <span class="tok-p">${B}</span>\nAlice computes B^a mod p = <span class="tok-s">${s1}</span>\nBob   computes A^b mod p = <span class="tok-s">${s2}</span>\n<b>${s1 === s2 ? 'Both reached the same shared secret: ' + s1 : 'mismatch'}</b>  (an eavesdropper only saw p, g, A, B)`;
      } catch (e) { $('#dh-out').textContent = 'Enter positive integers (p ≥ 2).'; }
    }
    b.querySelectorAll('input').forEach((i) => i.addEventListener('input', run));
    run();
  };

  /* ================================================================
     6. API key vs session — what travels on each request
  ================================================================ */
  T.apikey = function (host) {
    const b = shell(host, 'What rides on each request?', 'headers', `
      <p>Flip between schemes and watch what the client must attach to every single call, and what the server does with it.</p>
      <div class="filters"><label class="fld" style="margin:0"><span>Scheme</span><select id="ak-mode">
        <option value="key">API key (header)</option>
        <option value="basic">HTTP Basic</option>
        <option value="bearer">Bearer / JWT</option>
        <option value="session">Session cookie</option>
      </select></label></div>
      <div class="out" id="ak-req"></div>
      <div id="ak-note"></div>`);
    const $ = (s) => b.querySelector(s);
    const modes = {
      key: { req: `GET /v1/charges HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer sk_live_8fK2...9aD1`, note: ['info', 'The key <b>is</b> the identity and the password at once. Leaks are catastrophic and keys rarely expire — scope them and rotate them.'] },
      basic: { req: `GET /reports HTTP/1.1\nHost: intranet.local\nAuthorization: Basic c2FraXRoYTpodW50ZXIy`, note: ['fail', 'That Base64 string decodes straight back to <code>sakitha:hunter2</code>. Basic is only safe inside TLS, and the credentials travel on every request.'] },
      bearer: { req: `GET /v1/me HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJhbGci...<jwt>`, note: ['pass', 'The server verifies the signature locally — no database lookup. Short expiry limits the damage of a leak.'] },
      session: { req: `GET /account HTTP/1.1\nHost: shop.example.com\nCookie: sid=s%3Aa7Fh2...; \nX-CSRF-Token: 9f2c...`, note: ['info', 'The cookie is an opaque pointer; the real state lives server-side and can be revoked instantly. Browsers attach it automatically, which is exactly why CSRF protection is needed.'] },
    };
    function run() { const m = modes[$('#ak-mode').value]; $('#ak-req').textContent = m.req; $('#ak-note').innerHTML = checksHTML([m.note]); }
    $('#ak-mode').addEventListener('change', run); run();
  };

  /* ================================================================
     7. RBAC vs ABAC vs ReBAC decision sandbox
  ================================================================ */
  T.authz = function (host) {
    const b = shell(host, 'Will this request be allowed?', 'RBAC · ABAC · ReBAC', `
      <p>Same request, three models. Change the context and see which models say yes. Notice how each needs different information to decide.</p>
      <div style="display:flex;gap:14px;flex-wrap:wrap">
        <label class="fld" style="width:150px"><span>User role</span><select id="az-role"><option>viewer</option><option selected>editor</option><option>admin</option></select></label>
        <label class="fld" style="width:150px"><span>Action</span><select id="az-act"><option>read</option><option selected>update</option><option>delete</option></select></label>
        <label class="fld" style="width:170px"><span>Is user the owner?</span><select id="az-own"><option>no</option><option selected>yes</option></select></label>
        <label class="fld" style="width:150px"><span>Time</span><select id="az-time"><option selected>business hours</option><option>after hours</option></select></label>
        <label class="fld" style="width:190px"><span>Shared with user?</span><select id="az-share"><option>no</option><option selected>yes (as editor)</option></select></label>
      </div>
      <div id="az-out"></div>`);
    const $ = (s) => b.querySelector(s);
    function run() {
      const role = $('#az-role').value, act = $('#az-act').value, own = $('#az-own').value === 'yes', hours = $('#az-time').value, share = $('#az-share').value.startsWith('yes');
      // RBAC: role -> permissions
      const rolePerms = { viewer: ['read'], editor: ['read', 'update'], admin: ['read', 'update', 'delete'] };
      const rbac = rolePerms[role].includes(act);
      // ABAC: policy = allow if owner OR admin, and deletes only in business hours
      const abac = (own || role === 'admin') && !(act === 'delete' && hours !== 'business hours');
      // ReBAC: relationship on the object; editor-share allows read/update, delete needs owner
      const rebac = (share && (act === 'read' || act === 'update')) || (own && true) || (role === 'admin');
      const row = (name, ok, rule, why) => [ok ? 'pass' : 'fail', `<b>${name}: ${ok ? 'ALLOW' : 'DENY'}</b> · rule <code>${rule}</code><br><span class="muted">${why}</span>`];
      $('#az-out').innerHTML = checksHTML([
        row('RBAC', rbac, 'viewer→read · editor→read,update · admin→all',
          `Role <code>${role}</code> ${rbac ? 'includes' : 'does not include'} <code>${act}</code>. It can't see ownership, time or sharing.`),
        row('ABAC', abac, '(owner OR admin) AND NOT (delete outside business hours)',
          `Attributes: owner=${own}, admin=${role === 'admin'}, time=${hours}.`),
        row('ReBAC', rebac, 'owner OR admin OR (shared-as-editor AND action≠delete)',
          `Relationships on this document: owner=${own}, shared-with-you=${share}.`),
      ]);
    }
    b.querySelectorAll('select').forEach((s) => s.addEventListener('change', run)); run();
  };

  /* ================================================================
     8. WebAuthn / passkey origin binding
  ================================================================ */
  T.webauthn = function (host) {
    const b = shell(host, 'Why a passkey cannot be phished', 'WebAuthn / FIDO2', `
      <p>Every passkey is scoped to one site, its <b>RP ID</b> (a domain such as <code>bank.com</code>). The <em>browser</em> checks the page's real address against that RP ID before your authenticator is even asked, then puts the real origin into the data that gets signed. The user can't be talked into overriding either check. Try a look-alike address, or a genuine subdomain.</p>
      <div style="display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end">
        <label class="fld" style="flex:1;min-width:200px"><span>Passkey registered for (RP ID)</span><input id="wa-rp" type="text" value="bank.com"></label>
        <label class="fld" style="flex:1;min-width:220px"><span>Address the browser is actually on</span><input id="wa-now" type="text" value="https://bank-secure.com"></label>
      </div>
      <div class="btn-row" style="margin-top:0">
        <button class="btn ghost" data-ex="https://bank-secure.com">Look-alike</button>
        <button class="btn ghost" data-ex="https://login.bank.com">Real subdomain</button>
        <button class="btn ghost" data-ex="https://bank.com.evil.net">Tricky prefix</button>
        <button class="btn ghost" data-ex="http://bank.com">Plain http</button>
      </div>
      <div id="wa-out"></div>`);
    const $ = (s) => b.querySelector(s);
    function run() {
      const rp = $('#wa-rp').value.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
      let url = null;
      try { url = new URL($('#wa-now').value.trim()); } catch (e) { url = null; }
      if (!url || !rp) { $('#wa-out').innerHTML = checksHTML([['info', 'Enter an RP ID and a full address such as https://bank.com']]); return; }
      const hostName = url.hostname.toLowerCase();
      const secure = url.protocol === 'https:' || hostName === 'localhost';
      // RP ID must equal the host or be a parent domain of it (a registrable-suffix check, simplified)
      const scoped = hostName === rp || hostName.endsWith('.' + rp);
      const rows = [];
      rows.push([secure ? 'pass' : 'fail', secure ? `Secure context (${esc(url.protocol)})` : 'Not a secure context. WebAuthn only runs over https (or localhost).']);
      rows.push([scoped ? 'pass' : 'fail', scoped
        ? `Browser gate: <code>${esc(hostName)}</code> is <code>${esc(rp)}</code> or one of its subdomains, so a <code>${esc(rp)}</code> passkey may be used here.`
        : `Browser gate: <code>${esc(hostName)}</code> is not <code>${esc(rp)}</code> or a subdomain of it. The browser refuses to ask for a <code>${esc(rp)}</code> passkey, so your authenticator never sees the request. Nothing is signed, so there is nothing to relay.`]);
      if (secure && scoped) rows.push(['pass', `The signed data records origin <code>${esc(url.origin)}</code> and the hash of RP ID <code>${esc(rp)}</code>. The server checks both against its own values.`]);
      else rows.push(['info', 'Even if a forged response reached the real server, it would carry the wrong origin and RP ID hash and be rejected. That is the second layer.']);
      const ok = secure && scoped;
      $('#wa-out').innerHTML = `<div class="verdict ${ok ? 'good' : 'bad'}">${ok ? 'Passkey can be used here' : 'Passkey is not offered: phishing attempt fails'}</div>${checksHTML(rows)}`;
    }
    b.querySelectorAll('input').forEach((i) => i.addEventListener('input', run));
    b.querySelectorAll('[data-ex]').forEach((btn) => btn.addEventListener('click', () => { $('#wa-now').value = btn.dataset.ex; run(); }));
    run();
  };

  /* ================================================================
     9. Certificate chain walker (TLS)
  ================================================================ */
  T.certchain = function (host) {
    const b = shell(host, 'How your browser trusts a certificate', 'TLS / X.509', `
      <p>A server certificate is trusted only if it chains up to a root your device already trusts. Each link is signed by the one above it. Break any signature and the chain fails. Click a link to toggle a tampered signature.</p>
      <div id="cc-chain" style="display:grid;gap:8px;margin:10px 0"></div>
      <div id="cc-out"></div>`);
    const $ = (s) => b.querySelector(s);
    const chain = [
      { n: 'Root CA — "Example Trust Root X1"', s: 'In your OS/browser trust store', ok: true, root: true },
      { n: 'Intermediate CA — "Example TLS CA G2"', s: 'Signed by the root', ok: true },
      { n: 'Leaf — CN=shop.example.com', s: 'Signed by the intermediate · matches the address bar', ok: true },
    ];
    function run() {
      $('#cc-chain').innerHTML = chain.map((c, i) => `<button class="station" data-i="${i}" style="text-align:left;cursor:${c.root ? 'default' : 'pointer'}">
        <b>${c.root ? HS.icon('lock') : HS.icon('idp')} ${esc(c.n)} <span class="st ${c.ok ? 'd' : ''}" style="margin-left:auto;background:${c.ok ? 'var(--ok)' : 'var(--bad)'};border-color:${c.ok ? 'var(--ok)' : 'var(--bad)'}"></span></b>
        <span>${esc(c.s)}${c.ok ? '' : ' · signature INVALID'}</span></button>`).join('');
      $('#cc-chain').querySelectorAll('button').forEach((btn) => btn.addEventListener('click', () => { const i = +btn.dataset.i; if (chain[i].root) return; chain[i].ok = !chain[i].ok; run(); }));
      const firstBad = chain.findIndex((c) => !c.ok);
      const ok = firstBad === -1;
      $('#cc-out').innerHTML = `<div class="verdict ${ok ? 'good' : 'bad'}">${ok ? 'Chain valid — padlock shown' : 'Chain broken — browser shows a security warning'}</div>` +
        checksHTML(ok ? [['pass', 'Every signature verifies up to a trusted root, and the leaf matches the hostname.']] : [['fail', `The <b>${esc(chain[firstBad].n.split('—')[0].trim())}</b> link does not verify, so everything below it is untrusted. The browser stops here.`]]);
    }
    run();
  };

  /* ================================================================
     10. Replay / nonce demo (generic challenge-response)
  ================================================================ */
  T.replay = function (host) {
    const b = shell(host, 'Why a nonce stops replay', 'challenge–response', `
      <p>If a captured message is accepted twice, an attacker can resend it. A server-issued one-time number (a <em>nonce</em>) that is remembered and never reused breaks that. Send a signed request, then try to replay the same bytes.</p>
      <div class="btn-row"><button class="btn" id="rp-new">Server issues a fresh nonce</button><button class="btn ghost" id="rp-send">Client sends request</button><button class="btn danger" id="rp-replay">Attacker replays captured request</button></div>
      <div class="out" id="rp-out">Click "Server issues a fresh nonce" to begin.</div>`);
    const $ = (s) => b.querySelector(s);
    let nonce = null; const used = new Set(); let captured = null;
    const log = [];
    const show = () => $('#rp-out').innerHTML = log.slice(-7).join('\n');
    $('#rp-new').addEventListener('click', () => { nonce = b64url(crypto.getRandomValues(new Uint8Array(6))); log.push(`SERVER → client: here is nonce ${nonce}`); show(); });
    $('#rp-send').addEventListener('click', () => {
      if (!nonce) { log.push('…client has no nonce yet'); return show(); }
      captured = { body: 'transfer 500', nonce };
      if (used.has(nonce)) { log.push(`SERVER: nonce ${nonce} already used → REJECT`); }
      else { used.add(nonce); log.push(`CLIENT → server: {transfer 500, nonce ${nonce}} → ACCEPTED, nonce retired`); nonce = null; }
      show();
    });
    $('#rp-replay').addEventListener('click', () => {
      if (!captured) { log.push('…nothing captured to replay yet'); return show(); }
      if (used.has(captured.nonce)) log.push(`ATTACKER → server: replays {transfer 500, nonce ${captured.nonce}} → REJECTED (nonce already spent)`);
      else { used.add(captured.nonce); log.push(`ATTACKER replay ACCEPTED — nonce was never retired!`); }
      show();
    });
  };

  /* ================================================================
     11. Kerberos ticket inspector (conceptual)
  ================================================================ */
  T.kerberos = function (host) {
    const b = shell(host, 'Kerberos ticket flow', 'tickets & keys', `
      <p>Kerberos avoids sending your password around. You prove yourself once to get a Ticket-Granting Ticket (TGT), then trade it for per-service tickets. Each ticket is encrypted with a key only the right party holds, so a service ticket is useless to anyone but that service. Step through it.</p>
      <div class="btn-row"><button class="btn ghost" id="kb-prev">◀</button><span class="mono" id="kb-pos" style="align-self:center"></span><button class="btn ghost" id="kb-next">▶</button></div>
      <div class="out" id="kb-out" style="min-height:90px"></div>`);
    const $ = (s) => b.querySelector(s);
    const steps = [
      ['AS-REQ', 'You → Authentication Server: "I am sakitha." Timestamp encrypted with a key derived from your password proves you know it — the password itself never travels.'],
      ['AS-REP', 'AS → you: a TGT (encrypted with the KDC\'s own secret, opaque to you) + a session key (encrypted for you). You cannot read the TGT; you just hold it.'],
      ['TGS-REQ', 'You → Ticket-Granting Server: "Here is my TGT, I want to talk to the file server." You authenticate with the session key.'],
      ['TGS-REP', 'TGS → you: a service ticket encrypted with the <b>file server\'s</b> key, plus a new session key for talking to it.'],
      ['AP-REQ', 'You → File server: present the service ticket. Only the file server can decrypt it, and it finds your identity and session key inside, vouched for by the KDC.'],
      ['Access', 'File server trusts the KDC\'s vouching and grants access. At no point did your password or a reusable secret reach the file server.'],
    ];
    let i = 0;
    function run() { $('#kb-pos').textContent = `Step ${i + 1} / ${steps.length}`; $('#kb-out').innerHTML = `<b class="tok-p">${steps[i][0]}</b>\n${steps[i][1]}`; $('#kb-prev').disabled = i === 0; $('#kb-next').disabled = i === steps.length - 1; }
    $('#kb-prev').addEventListener('click', () => { if (i > 0) i--; run(); });
    $('#kb-next').addEventListener('click', () => { if (i < steps.length - 1) i++; run(); });
    run();
  };

  /* ================================================================
     12. Password storage — plaintext vs hash vs salted slow hash
  ================================================================ */
  T.pwstore = async function (host) {
    const b = shell(host, 'How a breach plays out by storage choice', 'hashing & salting', `
      <p>Two users pick the same password. See what a stolen database reveals under each storage choice. (Uses SHA-256 to illustrate; real systems use a deliberately <em>slow</em> algorithm such as bcrypt, scrypt or Argon2.)</p>
      <div style="display:flex;gap:14px;flex-wrap:wrap">
        <label class="fld" style="width:200px"><span>User A password</span><input id="pw-a" type="text" value="hunter2"></label>
        <label class="fld" style="width:200px"><span>User B password</span><input id="pw-b" type="text" value="hunter2"></label>
      </div>
      <div class="filters"><label class="fld" style="margin:0"><span>Stored as</span><select id="pw-mode">
        <option value="plain">Plaintext</option><option value="hash">Unsalted hash</option><option value="salt" selected>Salted hash</option></select></label></div>
      <div class="out" id="pw-out"></div><div id="pw-note"></div>`);
    const $ = (s) => b.querySelector(s);
    async function run() {
      const a = $('#pw-a').value, bb = $('#pw-b').value, mode = $('#pw-mode').value;
      let rowA, rowB, note;
      if (mode === 'plain') { rowA = a; rowB = bb; note = ['fail', 'A database thief reads every password instantly, and people reuse them across sites.']; }
      else if (mode === 'hash') { rowA = hex(await sha256(enc.encode(a))); rowB = hex(await sha256(enc.encode(bb))); note = [rowA === rowB ? 'fail' : 'info', 'Same password → identical hash. Thieves spot reused passwords and crack common ones with precomputed rainbow tables.']; }
      else { const sa = 'a7f3', sb = '91c0'; rowA = sa + ':' + hex(await sha256(enc.encode(sa + a))); rowB = sb + ':' + hex(await sha256(enc.encode(sb + bb))); note = ['pass', 'A unique random salt per user makes identical passwords store differently and defeats precomputed tables. A slow algorithm then makes each guess expensive.']; }
      $('#pw-out').innerHTML = `User A → ${esc(rowA).replace(/(.{48})/, '$1\n        ')}\nUser B → ${esc(rowB).replace(/(.{48})/, '$1\n        ')}`;
      $('#pw-note').innerHTML = checksHTML([note]);
    }
    b.querySelectorAll('input,select').forEach((i) => i.addEventListener('input', run));
    await run();
  };

  /* ================================================================
     13. SAML vs OIDC token shape comparison
  ================================================================ */
  T.samloidc = function (host) {
    const b = shell(host, 'SAML assertion vs OIDC ID token', 'federation formats', `
      <p>Both let an identity provider vouch for you to an app. They carry the same idea in very different envelopes — XML signed with XML-DSig versus a compact signed JSON token. Flip between them.</p>
      <div class="filters"><label class="chk"><input type="radio" name="so" value="saml" checked> SAML 2.0</label><label class="chk"><input type="radio" name="so" value="oidc"> OIDC</label></div>
      <div class="out" id="so-out" style="max-height:320px;overflow:auto"></div><div id="so-note"></div>`);
    const $ = (s) => b.querySelector(s);
    const saml = `<saml:Assertion IssueInstant="2026-10-26T09:15:00Z">
  <saml:Issuer>https://idp.company.com</saml:Issuer>
  <ds:Signature>…XML-DSig over the assertion…</ds:Signature>
  <saml:Subject>
    <saml:NameID>sakitha@company.com</saml:NameID>
  </saml:Subject>
  <saml:Conditions NotOnOrAfter="2026-10-26T09:20:00Z"/>
  <saml:AttributeStatement>
    <saml:Attribute Name="role"><saml:AttributeValue>editor</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`;
    const oidc = `// ID token (a JWT) — payload after decoding
{
  "iss": "https://idp.company.com",
  "sub": "8842-sakitha",
  "aud": "internal-wiki",
  "exp": 1730003600,
  "iat": 1730000000,
  "email": "sakitha@company.com",
  "role": "editor"
}
// signed with the IdP's key, verified via its JWKS endpoint`;
    function run() {
      const v = b.querySelector('input[name=so]:checked').value;
      $('#so-out').textContent = v === 'saml' ? saml : oidc;
      $('#so-note').innerHTML = checksHTML([v === 'saml'
        ? ['info', 'SAML: verbose XML, redirect/POST through the browser, dominant in enterprise SSO and legacy apps.']
        : ['info', 'OIDC: compact JWT on top of OAuth 2.0, JSON everywhere, the default for new web, mobile and API logins.']]);
    }
    b.querySelectorAll('input').forEach((i) => i.addEventListener('change', run)); run();
  };

  /* ================================================================
     14. Public-key challenge–response (SSH keys, mTLS, passkeys)
  ================================================================ */
  T.pubkey = async function (host) {
    const b = shell(host, 'Prove you hold a private key without sending it', 'ECDSA P-256 · WebCrypto', `
      <p>This is the core move behind SSH keys, TLS client certificates and passkeys. The server keeps only your <b>public</b> key. To log in, you sign a fresh, connection-specific value with your <b>private</b> key, and the server checks the signature. The private key below was generated in your browser as non-extractable, so not even this page can read it.</p>
      <div class="g2">
        <div>
          <div class="fld"><span>Server has stored your public key (fingerprint)</span><div class="out" id="pkk-fp">generating…</div></div>
          <div class="fld"><span>Fresh value to sign (e.g. SSH session ID)</span><div class="out" id="pkk-ch"></div></div>
          <div class="btn-row"><button class="btn" id="pkk-sign">Sign with my private key</button><button class="btn ghost" id="pkk-new">New connection</button></div>
        </div>
        <div>
          <div class="fld"><span>Signature sent to the server</span><div class="out" id="pkk-sig">(not signed yet)</div></div>
          <div class="btn-row"><button class="btn ghost" id="pkk-alter">Alter the signed value</button><button class="btn ghost" id="pkk-other">Sign with someone else's key</button></div>
          <div id="pkk-res"></div>
        </div>
      </div>`);
    const $ = (s) => b.querySelector(s);
    if (!crypto.subtle) { $('#pkk-fp').textContent = 'WebCrypto unavailable in this browser.'; return; }
    const alg = { name: 'ECDSA', namedCurve: 'P-256' }, sigAlg = { name: 'ECDSA', hash: 'SHA-256' };
    const mine = await crypto.subtle.generateKey(alg, false, ['sign', 'verify']);
    const other = await crypto.subtle.generateKey(alg, false, ['sign', 'verify']);
    const spki = await crypto.subtle.exportKey('spki', mine.publicKey);
    $('#pkk-fp').textContent = 'SHA256:' + b64(await sha256(new Uint8Array(spki))).replace(/=+$/, '');
    let challenge, signed = null, signedOver = null;
    const fresh = () => { challenge = crypto.getRandomValues(new Uint8Array(24)); signed = null; $('#pkk-ch').textContent = hex(challenge); $('#pkk-sig').textContent = '(not signed yet)'; $('#pkk-res').innerHTML = ''; };
    async function check(sig, overBytes, note) {
      const ok = await crypto.subtle.verify(sigAlg, mine.publicKey, sig, challenge);
      $('#pkk-sig').textContent = b64(sig).slice(0, 64) + '…';
      $('#pkk-res').innerHTML = `<div class="verdict ${ok ? 'good' : 'bad'}">${ok ? 'Server: signature valid. Logged in.' : 'Server: signature invalid. Rejected.'}</div>` + checksHTML([[ok ? 'pass' : 'fail', note]]);
    }
    $('#pkk-sign').addEventListener('click', async () => {
      signed = await crypto.subtle.sign(sigAlg, mine.privateKey, challenge); signedOver = challenge;
      check(signed, challenge, 'Verified with the stored public key. Only a signature travelled; the private key never left the browser.');
    });
    $('#pkk-alter').addEventListener('click', async () => {
      const sig = signed || await crypto.subtle.sign(sigAlg, mine.privateKey, challenge);
      const saved = challenge; challenge = new Uint8Array(saved); challenge[0] ^= 1;
      $('#pkk-ch').textContent = hex(challenge);
      await check(sig, saved, 'The value changed by one bit after signing, so the signature no longer matches. A signature captured from an old connection fails the same way, because every connection uses a new value.');
    });
    $('#pkk-other').addEventListener('click', async () => {
      const sig = await crypto.subtle.sign(sigAlg, other.privateKey, challenge);
      check(sig, challenge, 'Signed by a key the server has never seen. Holding the right private key is the whole credential.');
    });
    $('#pkk-new').addEventListener('click', fresh);
    fresh();
  };

  HS.tools._missing = (host, id) => { host.innerHTML = `<p class="callout warn">Playground “${esc(id)}” is still loading.</p>`; };
})();
