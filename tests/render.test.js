/* Render test: loads the whole site in jsdom, mounts every topic flow, playground and page,
   checks cross-links, quiz keys, and verifies the TOTP generator against RFC 6238 vectors.
   Run with:  npm test */
const fs = require('fs'), path = require('path');
const { JSDOM } = require('jsdom');

const ROOT = path.join(__dirname, '..', 'assets', 'js');
const files = ['engine.js', 'tools.js',
  'topics/t-core1.js', 'topics/t-core2.js', 'topics/t-core3.js', 'topics/t-enterprise.js',
  'topics/t-modern.js', 'topics/t-authz.js', 'topics/t-extra.js',
  'topics/t-inside-1.js', 'topics/t-inside-2.js', 'topics/t-inside-3.js', 'topics/t-inside-4.js', 'topics/t-steps.js', 'reference.js'];

const html = `<!doctype html><html><head></head><body>
<header class="top"><button class="menu-btn" id="menuBtn"></button><input id="q"><span id="progTxt"></span><i id="progBar"></i></header>
<nav class="side" id="side"></nav><div class="scrim" id="scrim"></div><main id="main"></main></body></html>`;

const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true, url: 'https://x.test/' });
const { window } = dom;

// minimal WebCrypto + helpers jsdom lacks
const { webcrypto } = require('crypto');
Object.defineProperty(window, 'crypto', { value: webcrypto, configurable: true, writable: true });
window.TextEncoder = TextEncoder; window.TextDecoder = TextDecoder;
window.matchMedia = () => ({ matches: false, addEventListener() {}, addListener() {} });
window.requestAnimationFrame = (cb) => setTimeout(() => cb(performance.now()), 0);
window.cancelAnimationFrame = (id) => clearTimeout(id);
window.performance = { now: () => Date.now() };
window.hljs = { highlightElement() {} };
global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
global.atob = (s) => Buffer.from(s, 'base64').toString('binary');
window.btoa = global.btoa; window.atob = global.atob;
let storeObj = {};
window.localStorage = { getItem: (k) => storeObj[k] || null, setItem: (k, v) => (storeObj[k] = '' + v), removeItem: (k) => delete storeObj[k] };

const errors = [];
window.addEventListener('error', (e) => errors.push('window error: ' + e.message));
const origErr = console.error; console.error = (...a) => errors.push('console.error: ' + a.map(String).join(' '));

// execute each script in the window context
const vm = require('vm');
const ctx = dom.getInternalVMContext();
for (const f of files) {
  try { vm.runInContext(fs.readFileSync(path.join(ROOT, f), 'utf8'), ctx, { filename: f }); }
  catch (e) { errors.push(`PARSE/RUN ${f}: ${e.message}`); }
}

const HS = window.HS;
if (!HS) { console.log('FATAL: HS not defined'); process.exit(1); }
// stubs the inline index.html script normally provides
HS.GROUPS = [
  { id: 'start', name: 'Start here' }, { id: 'core', name: 'Core web & transport' },
  { id: 'ent', name: 'Enterprise & SSO' }, { id: 'modern', name: 'Modern & MFA' },
  { id: 'authz', name: 'Authorization' }, { id: 'ref', name: 'Reference' },
];
HS.stCls = () => '';
HS.progress = { get: () => ({}), visit() {}, quiz() {} };
HS.refreshNav = () => {};
HS.pager = () => '';

(async () => {
  // mount every topic
  const main = window.document.getElementById('main');
  const players = [];
  const mounted = [];
  // replicate renderTopic by invoking router pieces: easiest is to call HS.route via hash
  function go(id) {
    window.location.hash = '#' + id;
    window.dispatchEvent(new window.Event('hashchange'));
  }
  // need router: reference.js sets up router in index.html inline script, which we didn't load.
  // Instead directly test data integrity + tool mount + quiz.
  const seen = new Set();
  // Validate topic flow data
  for (const t of HS.topics) {
    if (seen.has(t.id)) errors.push('DUP topic id ' + t.id); seen.add(t.id);
    if (!t.title || !t.tagline) errors.push('topic ' + t.id + ' missing title/tagline');
    for (const key of ['related']) if (t[key]) t[key].forEach((r) => { if (!HS.byId[r] && !HS.pages[r]) errors.push(`topic ${t.id}: related '${r}' not found`); });
    if (t.flow) {
      const ids = new Set(t.flow.nodes.map((n) => n.id));
      ['normal', 'attack'].forEach((sc) => {
        if (!t.flow[sc]) return;
        t.flow[sc].steps.forEach((s, i) => {
          if (!ids.has(s.f)) errors.push(`${t.id}/${sc} step ${i}: node '${s.f}' missing`);
          if (s.t && !ids.has(s.t)) errors.push(`${t.id}/${sc} step ${i}: node '${s.t}' missing`);
          if (!s.l) errors.push(`${t.id}/${sc} step ${i}: no label`);
        });
      });
      // instantiate a player
      try { const host = window.document.createElement('div'); main.appendChild(host); const p = new HS.FlowPlayer(host, t.flow); p.setScenario(0); if (t.flow.attack) p.setScenario(1); p.destroy(); host.remove(); }
      catch (e) { errors.push(`${t.id}: FlowPlayer threw: ${e.message}`); }
    }
    // tools
    if (t.tool) [].concat(t.tool).forEach((id) => { if (!HS.tools[id]) errors.push(`${t.id}: tool '${id}' not registered`); });
    mounted.push(t.id);
  }
  // Exercise every registered tool
  for (const [id, fn] of Object.entries(HS.tools)) {
    if (id.startsWith('_')) continue;
    try { const host = window.document.createElement('div'); main.appendChild(host); await fn(host); host.remove(); }
    catch (e) { errors.push(`tool ${id} threw: ${e.message}`); }
  }
  // reference pages render
  for (const [id, pg] of Object.entries(HS.pages)) {
    if (typeof pg.render === 'function') {
      try { const host = window.document.createElement('div'); main.appendChild(host); pg.render(host, players); host.remove(); }
      catch (e) { errors.push(`page ${id}.render threw: ${e.message}`); }
    }
  }

  // crypto self-tests: TOTP against RFC 6238 appendix B vectors (SHA-1, 8 digits, seed "12345678901234567890")
  if (HS._totp) {
    const seedB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890" in Base32
    const vectors = [[59, '94287082'], [1111111109, '07081804'], [1234567890, '89005924'], [2000000000, '69279037']];
    for (const [t, exp] of vectors) {
      const got = await HS._totp(seedB32, 30, 8, t * 1000);
      if (got !== exp) errors.push(`TOTP vector t=${t}: got ${got}, expected ${exp}`);
    }
  } else errors.push('HS._totp not exposed for vector test');
  // quiz answer keys must point at a real option
  HS.topics.forEach((t) => (t.quiz || []).forEach((q, i) => { if (!(q.a >= 0 && q.a < q.o.length)) errors.push(`${t.id}: quiz ${i + 1} answer index out of range`); }));
  // arch + tldr coverage
  HS.topics.forEach((t) => { if (!t.arch) errors.push(`${t.id}: no architecture`); if (!t.tldr) errors.push(`${t.id}: no tldr`); });
  // "Step by step" coverage and shape
  HS.topics.forEach((t) => {
    const w = t.walk;
    if (!w || !Array.isArray(w.phases) || !w.phases.length) { errors.push(`${t.id}: no step-by-step`); return; }
    const n = w.phases.reduce((a, ph) => a + (Array.isArray(ph[2]) ? ph[2].length : 0), 0);
    if (n < 4) errors.push(`${t.id}: step-by-step has only ${n} steps`);
    w.phases.forEach((ph, i) => (ph[2] || []).forEach((s, j) => { if (!s[0] || !s[1]) errors.push(`${t.id}: step ${i + 1}.${j + 1} needs an actor and a description`); }));
  });
  if (!HS.pages.steps) errors.push('All step-by-steps page not registered');
  // "How it works inside" + "Solved example" coverage and shape
  HS.topics.forEach((t) => {
    if (!Array.isArray(t.inside) || t.inside.length < 3) errors.push(`${t.id}: needs an "inside" section with at least 3 parts`);
    else t.inside.forEach((p, i) => { if (!p[0] || !p[1]) errors.push(`${t.id}: inside part ${i + 1} missing heading or body`); });
    const ex = t.example;
    if (!ex) errors.push(`${t.id}: no solved example`);
    else if (!ex.title || !ex.problem || !ex.answer || !Array.isArray(ex.steps) || ex.steps.length < 2) errors.push(`${t.id}: solved example incomplete`);
  });
  // the HTML of the new sections must parse without leaking unclosed tags
  HS.topics.forEach((t) => {
    const parts = (t.inside || []).map((p) => p[1]).concat(t.example ? [t.example.problem, t.example.answer, ...t.example.steps.map((s) => s[1])] : []);
    parts.forEach((htmlPart, i) => {
      const box = window.document.createElement('div'); box.innerHTML = htmlPart;
      const open = (htmlPart.match(/<(div|table|ol|ul|section|figure|pre)\b/g) || []).length;
      const close = (htmlPart.match(/<\/(div|table|ol|ul|section|figure|pre)>/g) || []).length;
      if (open !== close) errors.push(`${t.id}: unbalanced block tags in new section part ${i + 1} (${open} open, ${close} close)`);
    });
  });
  // re-derive the numbers used in the solved examples so a typo can't slip in
  await (async () => {
    const nc = require('crypto');
    const sha = (s, enc = 'hex') => nc.createHash('sha256').update(s).digest(enc);
    const mac = (k, s, alg = 'sha256', enc = 'hex') => nc.createHmac(alg, k).update(s).digest(enc);
    const pm = (b, e, m) => { b = BigInt(b); e = BigInt(e); m = BigInt(m); let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return Number(r); };
    const md5 = (b) => nc.createHash('md5').update(b).digest();
    const radMask = md5(Buffer.concat([Buffer.from('testing123'), Buffer.from('0f403f9473978057bd83d5cb98f4227a', 'hex')]));
    const pw = Buffer.alloc(16); Buffer.from('hello').copy(pw);
    const jwtIn = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url') + '.' + Buffer.from('{"sub":"42","name":"Sakitha","role":"student","exp":1798761600}').toString('base64url');
    const at = nc.createHash('sha256').update('ya29.a0AfB_byC-example-access-token').digest().subarray(0, 16).toString('base64url');
    const ssha = (() => { const salt = Buffer.from('a1b2c3d4', 'hex'); const d = nc.createHash('sha1').update(Buffer.concat([Buffer.from('secret'), salt])).digest(); return '{SSHA}' + Buffer.concat([d, salt]).toString('base64'); })();
    const facts = [
      ['basic-auth', Buffer.from('Aladdin:open sesame').toString('base64')],
      ['basic-auth', nc.createHash('md5').update(`${nc.createHash('md5').update('Mufasa:testrealm@host.com:Circle Of Life').digest('hex')}:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:${nc.createHash('md5').update('GET:/dir/index.html').digest('hex')}`).digest('hex')],
      ['api-keys', sha('hfg_live_7Qm2Xc9TfV4kLp8ZrW3nYb6HsJ1dGa5E')],
      ['api-keys', sha('hfg_live_7Qm2Xc9TfV4kLp8ZrW3nYb6HsJ1dGa5F')],
      ['jwt', mac('my-secret', jwtIn, 'sha256', 'base64url')],
      ['oauth', sha('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'base64url')],
      ['oidc', at],
      ['tls', `A = ${pm(5, 6, 23)}`], ['tls', `B = ${pm(5, 15, 23)}`], ['tls', `s = ${pm(19, 6, 23)}`],
      ['mtls', `${pm(1234, 157, 2773)}`], ['mtls', `${pm(726, 17, 2773)}`],
      ['ssh', `${pm(65, 2753, 3233)}`], ['ssh', `588¹⁷ mod 3233 = ${pm(588, 17, 3233)}`], ['ssh', `589¹⁷ mod 3233 = ${pm(589, 17, 3233)}`],
      ['ldap', ssha],
      ['radius', [...Buffer.from(pw.map((x, i) => x ^ radMask[i]))].map((x) => x.toString(16).padStart(2, '0')).join(' ')],
      ['webauthn', sha('bank.com')], ['webauthn', sha('bank-secure.com')],
      ['magic-links', sha('Xk3p9LwQ2vT8nR5yB1cF7hJ0mD4sG6aZqE2uW9oP8iY')],
      ['hmac-sig', mac('whsec_demo123', '1700000000.{"order":1042,"amount":500}')],
      ['hmac-sig', mac('whsec_demo123', '1700000000.{"order":1042,"amount":5000}')],
    ];
    const text = (t) => [JSON.stringify(t.inside || []), JSON.stringify(t.example || {})].join(' ');
    facts.forEach(([id, v]) => { if (!text(HS.byId[id]).includes(v)) errors.push(`${id}: solved-example value "${v}" not found (recomputed)`); });
    if (HS._totp) { const six = await HS._totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 30, 6, 59000); if (!text(HS.byId.totp).includes(six)) errors.push('totp: 6-digit example code ' + six + ' not found'); }
  })();

  console.error = origErr;
  console.log('Files loaded :', files.join(', '));
  console.log('Topics       :', HS.topics.length, '->', HS.topics.map((t) => t.id).join(', '));
  console.log('Pages        :', Object.keys(HS.pages).join(', ') || '(none)');
  console.log('Tools        :', Object.keys(HS.tools).filter((k) => !k.startsWith('_')).join(', '));
  console.log('Flows w/ attack:', HS.topics.filter((t) => t.flow && t.flow.attack).length, '/', HS.topics.filter((t) => t.flow).length);
  console.log('Quizzes      :', HS.topics.filter((t) => t.quiz).length);
  console.log('Step-by-step :', HS.topics.filter((t) => t.walk).length);
  console.log('Inside/solved:', HS.topics.filter((t) => t.inside).length, '/', HS.topics.filter((t) => t.example).length);
  if (errors.length) { console.log('\n❌ ' + errors.length + ' ISSUES:'); errors.forEach((e) => console.log('  - ' + e)); process.exit(1); }
  else console.log('\n✅ No errors. All flows, tools, quizzes and pages mount clean.');
})();
