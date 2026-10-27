(function () {
  'use strict';
  const HS = window.HS, esc = HS.esc;
  const GROUPS = [
    { id: 'start', name: 'Start here', blurb: 'Vocabulary and building blocks' },
    { id: 'core', name: 'Core web & transport', blurb: 'What every backend uses' },
    { id: 'ent', name: 'Enterprise & SSO', blurb: 'Federation and corporate networks' },
    { id: 'modern', name: 'Modern & MFA', blurb: 'Phishing resistance and signing' },
    { id: 'authz', name: 'Authorization', blurb: 'Deciding what someone may do' },
    { id: 'ref', name: 'Reference', blurb: 'Compare, practise, look up' },
  ];
  HS.GROUPS = GROUPS;

  /* ---------- progress (per-viewer, optional) ---------- */
  const KEY = 'handshake-progress-v1';
  let prog = {};
  try { prog = JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch (e) { prog = {}; }
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(prog)); } catch (e) {} };
  HS.progress = {
    get: (id) => prog[id] || {},
    visit(id) { prog[id] = { ...(prog[id] || {}), v: 1 }; save(); },
    quiz(id, score, total) { const best = Math.max((prog[id] || {}).best || 0, score); prog[id] = { ...(prog[id] || {}), v: 1, best, total, done: best / total >= 0.7 ? 1 : (prog[id] || {}).done || 0 }; save(); },
  };
  const stCls = (id) => { const p = prog[id] || {}; return p.done ? 'd' : p.v ? 'v' : ''; };
  HS.stCls = stCls;

  /* ---------- ordered route list ---------- */
  const pageOrder = () => {
    const list = [];
    GROUPS.forEach((g) => {
      if (g.id === 'start' && HS.pages.home) list.push({ id: 'home', group: 'start', short: 'Overview', page: HS.pages.home });
      HS.topics.filter((t) => t.group === g.id).forEach((t) => list.push({ id: t.id, group: g.id, short: t.short || t.title, topic: t }));
      Object.entries(HS.pages).forEach(([id, p]) => { if (p.group === g.id && id !== 'home') list.push({ id, group: g.id, short: p.short, page: p }); });
    });
    return list;
  };
  HS.pageOrder = pageOrder;

  /* ---------- full-text search index (built once, lazily) ---------- */
  const strip = (h) => String(h || '').replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ').replace(/\s+/g, ' ');
  let INDEX = null;
  function buildIndex() {
    INDEX = {};
    HS.topics.forEach((t) => {
      const parts = [t.title, t.short, t.tagline, t.kind, t.analogy, t.basics, t.deep, t.howto,
        (t.spec || []).flat().join(' '), (t.tldr || []).join(' '), (t.uses || []).flat().join(' '),
        (t.pros || []).join(' '), (t.cons || []).join(' '), (t.hidden || []).flat().join(' '),
        (t.attacks || []).flat().join(' '), (t.interview || []).map((q) => q[0] + ' ' + q[1]).join(' '),
        (t.history || []).flat().join(' ')];
      INDEX[t.id] = { head: (t.title + ' ' + t.short).toLowerCase(), body: strip(parts.join(' ')) };
    });
  }
  function snippet(body, f) {
    const i = body.toLowerCase().indexOf(f);
    if (i < 0) return '';
    const a = Math.max(0, i - 28), b = Math.min(body.length, i + f.length + 40);
    return (a ? '…' : '') + esc(body.slice(a, i)) + '<mark>' + esc(body.slice(i, i + f.length)) + '</mark>' + esc(body.slice(i + f.length, b)) + (b < body.length ? '…' : '');
  }

  /* ---------- sidebar ---------- */
  const side = document.getElementById('side');
  function renderSide(filter = '') {
    const f = filter.trim().toLowerCase();
    if (f && !INDEX) buildIndex();
    const list = pageOrder();
    let html = '';
    GROUPS.forEach((g) => {
      const items = list.filter((x) => x.group === g.id).map((x) => {
        if (!f) return { x };
        if ((x.short + ' ' + (x.page ? x.page.title || '' : '')).toLowerCase().includes(f)) return { x, title: true };
        const ix = x.topic && INDEX[x.id];
        if (ix && ix.head.includes(f)) return { x, title: true };
        if (ix && ix.body.toLowerCase().includes(f)) return { x, hit: snippet(ix.body, f) };
        return null;
      }).filter(Boolean);
      if (!items.length) return;
      html += `<h6>${esc(g.name)}</h6>`;
      items.forEach(({ x, hit }) => {
        html += `<a href="#${x.id}" data-id="${x.id}"><span class="st ${x.topic ? stCls(x.id) : ''}" ${x.topic ? '' : 'style="visibility:hidden"'}></span>${esc(x.short)}${x.topic && x.topic.port ? `<span class="tg">${esc(x.topic.port)}</span>` : ''}</a>`;
        if (hit) html += `<span class="hit">${hit}</span>`;
      });
    });
    if (!html) html = `<p class="muted" style="padding:10px">No topic matches “${esc(filter)}”. Try the glossary.</p>`;
    html += `<div class="legend"><span><i class="st" style="width:9px;height:9px;border-radius:50%;border:1.5px solid var(--line-2)"></i>Not opened</span><span><i style="width:9px;height:9px;border-radius:50%;border:1.5px solid var(--accent)"></i>Opened</span><span><i style="width:9px;height:9px;border-radius:50%;background:var(--ok)"></i>Quiz passed (70%+)</span></div>`;
    side.innerHTML = html;
    markActive();
  }
  function markActive() { side.querySelectorAll('a').forEach((a) => a.classList.toggle('on', a.dataset.id === current)); }
  function updProgress() {
    const total = HS.topics.length, done = HS.topics.filter((t) => (prog[t.id] || {}).done).length;
    document.getElementById('progTxt').textContent = `${done} / ${total} passed`;
    document.getElementById('progBar').style.width = (total ? (done / total) * 100 : 0) + '%';
  }
  HS.refreshNav = () => { renderSide(document.getElementById('q').value); updProgress(); };

  /* ---------- topic page renderer ---------- */
  const SECTIONS = [
    ['analogy', 'In 30 seconds'], ['flow', 'Watch it happen'], ['basics', 'Basics'], ['deep', 'Deep dive'], ['arch', 'Architecture'],
    ['uses', 'Real-world use'], ['howto', 'How to use it'], ['proscons', 'Pros & cons'], ['history', 'History'], ['hidden', 'Hidden details'],
    ['attacks', 'Attacks & defenses'], ['tool', 'Playground'], ['interview', 'Interview prep'], ['quiz', 'Quiz'],
  ];
  const LEVEL = { basics: 'Level 1', deep: 'Level 2', arch: 'Level 2', hidden: 'Level 3', attacks: 'Level 3' };

  function renderTopic(t, main) {
    const has = (k) => k === 'proscons' ? t.pros || t.cons : k === 'tool' ? t.tool && t.tool.length : t[k];
    const g = GROUPS.find((x) => x.id === t.group);
    let h = `<article class="page topic">
      <header class="t-head">
        <div class="eyebrow"><b>${esc(g ? g.name : '')}</b><span>${esc(t.level || '')}</span>${t.kind ? `<span>${esc(t.kind)}</span>` : ''}</div>
        <h1>${t.title}</h1>
        <p class="lede">${t.tagline}</p>
        ${t.spec ? `<dl class="spec">${t.spec.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join('')}</dl>` : ''}
        <nav class="toc" aria-label="On this page">${SECTIONS.filter(([k]) => has(k)).map(([k, n]) => `<button type="button" data-s="${k}">${n}</button>`).join('')}</nav>
      </header>`;
    if (t.analogy) h += `<div class="analogy" id="s-analogy">${HS.icon(t.icon || 'key')}<div>${t.analogy}</div></div>`;
    if (t.tldr) h += `<div class="tldr"><h3>${HS.icon('terminal')}If an interviewer asks "explain ${esc(t.short || t.title)}"</h3><ol>${t.tldr.map((x) => `<li>${x}</li>`).join('')}</ol></div>`;
    if (t.flow) h += `<section class="blk" id="s-flow"><h2>Watch it happen</h2>
      <div class="fp-host"></div>
      <div class="fp-legend"><span><i style="background:var(--pk-req)"></i>Request</span><span><i style="background:var(--pk-res)"></i>Response</span><span><i style="background:var(--pk-int)"></i>Internal work / encrypted channel</span><span><i style="background:var(--pk-atk)"></i>Attacker</span><span>Keys: <kbd>Space</kbd> play, <kbd>←</kbd> <kbd>→</kbd> step</span></div></section>`;
    const block = (k, title, body) => `<section class="blk" id="s-${k}"><h2>${title}${LEVEL[k] ? `<span class="lv">${LEVEL[k]}</span>` : ''}</h2>${body}</section>`;
    if (t.basics) h += block('basics', 'Basics', `<div class="prose">${t.basics}</div>`);
    if (t.deep) h += block('deep', 'Deep dive', `<div class="prose">${t.deep}</div>`);
    if (t.arch) {
      const a = t.arch;
      const body = typeof a === 'string' ? a
        : `<div class="arch">${a.parts.map(([ic, name, role, tag]) => `<div><b>${HS.icon(ic)}${name}${tag ? `<small>${esc(tag)}</small>` : ''}</b><p>${role}</p></div>`).join('')}</div>${a.note ? `<p class="arch-note">${a.note}</p>` : ''}`;
      h += block('arch', 'Architecture', body);
    }
    if (t.uses) h += block('uses', 'Where you meet it in real life', `<ul class="uses">${t.uses.map(([a, b]) => `<li><b>${a}</b><span>${b}</span></li>`).join('')}</ul>`);
    if (t.howto) h += block('howto', 'How to use it', t.howto);
    if (t.pros || t.cons) h += block('proscons', 'Pros & cons', `<div class="cols"><div class="pc pro"><h4>Strengths</h4><ul>${(t.pros || []).map((x) => `<li>${x}</li>`).join('')}</ul></div><div class="pc con"><h4>Weaknesses</h4><ul>${(t.cons || []).map((x) => `<li>${x}</li>`).join('')}</ul></div></div>`);
    if (t.history) h += block('history', 'History', `<ol class="timeline">${t.history.map(([y, x]) => `<li><time>${y}</time><div>${x}</div></li>`).join('')}</ol>`);
    if (t.hidden) h += block('hidden', 'Hidden details & gotchas', `<div class="hidden-list">${t.hidden.map(([a, b]) => `<div><b>${a}</b><p>${b}</p></div>`).join('')}</div>`);
    if (t.attacks) h += block('attacks', 'Attacks & defenses', `<div class="tbl-wrap"><table class="t"><thead><tr><th>Attack</th><th>How it works</th><th>Defense</th></tr></thead><tbody>${t.attacks.map(([a, b, c]) => `<tr><td>${a}</td><td>${b}</td><td>${c}</td></tr>`).join('')}</tbody></table></div>`);
    if (t.tool && t.tool.length) h += block('tool', 'Playground', [].concat(t.tool).map((id, i) => `<div class="tool-host" data-tool="${id}"></div>`).join(''));
    if (t.interview) h += block('interview', 'Interview prep', `<p class="muted">Try answering out loud before opening each one. Levels are a rough guide to how often the question comes up for junior, mid and senior roles.</p><div class="qa">${t.interview.map(([q, a, l]) => `<details><summary><span>${q}</span><span class="lvl ${l || 'mid'}">${l || 'mid'}</span></summary><div class="ans">${a}</div></details>`).join('')}</div>`);
    if (t.quiz) h += block('quiz', 'Check yourself', `<div class="quiz-host"></div>`);
    if (t.related) h += `<section class="blk"><h2>Related topics</h2><div class="related">${t.related.filter((r) => HS.byId[r] || HS.pages[r]).map((r) => `<a href="#${r}">${esc((HS.byId[r] || HS.pages[r]).short || (HS.byId[r] || HS.pages[r]).title)}</a>`).join('')}</div></section>`;
    h += pager(t.id) + `</article>`;
    main.innerHTML = h;

    if (t.flow) players.push(new HS.FlowPlayer(main.querySelector('.fp-host'), t.flow));
    main.querySelectorAll('.tool-host').forEach((el) => {
      const fn = HS.tools[el.dataset.tool];
      if (fn) { try { fn(el); } catch (e) { el.innerHTML = `<p class="callout bad">This playground could not start: ${esc(e.message)}</p>`; console.error(e); } }
    });
    if (t.quiz) renderQuiz(main.querySelector('.quiz-host'), t);
    main.querySelectorAll('.toc button').forEach((b) => b.addEventListener('click', () => {
      const el = document.getElementById('s-' + b.dataset.s);
      if (el) el.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    }));
    HS.progress.visit(t.id);
  }

  function pager(id) {
    const list = pageOrder(), i = list.findIndex((x) => x.id === id);
    const pv = list[i - 1], nx = list[i + 1];
    return `<nav class="pager">${pv ? `<a href="#${pv.id}"><span>Previous</span><b>${esc(pv.short)}</b></a>` : ''}${nx ? `<a class="nx" href="#${nx.id}"><span>Next</span><b>${esc(nx.short)}</b></a>` : ''}</nav>`;
  }
  HS.pager = pager;

  /* shuffle options per render so the right answer isn't always in the same slot */
  function shuffled(q) {
    const idx = q.o.map((_, i) => i);
    for (let i = idx.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [idx[i], idx[j]] = [idx[j], idx[i]]; }
    return { ...q, o: idx.map((i) => q.o[i]), a: idx.indexOf(q.a) };
  }
  function renderQuiz(host, t) {
    const qs = t.quiz.map(shuffled);
    let answered = 0, right = 0;
    host.innerHTML = `<div class="quiz">${qs.map((q, i) => `<div class="qz" data-i="${i}"><p class="q">${i + 1}. ${q.q}</p>${q.o.map((o, j) => `<label><input type="radio" name="qz-${t.id}-${i}" id="qz-${t.id}-${i}-${j}" value="${j}"><span>${o}</span></label>`).join('')}<div class="exp" hidden></div></div>`).join('')}
      <div class="quiz-bar"><span class="score mono">Answer all ${qs.length} questions. 70% marks this topic as passed.</span><button type="button" class="btn ghost retry">Reset quiz</button></div></div>`;
    const score = host.querySelector('.score');
    host.querySelectorAll('.qz').forEach((box) => {
      const q = qs[+box.dataset.i];
      box.querySelectorAll('input').forEach((inp) => inp.addEventListener('change', () => {
        if (box.classList.contains('done')) return;
        box.classList.add('done');
        const pick = +inp.value;
        box.querySelectorAll('label').forEach((lb, j) => {
          lb.querySelector('input').disabled = true;
          if (j === q.a) lb.classList.add('right'); else if (j === pick) lb.classList.add('wrong');
        });
        const ex = box.querySelector('.exp'); ex.hidden = false;
        ex.innerHTML = `<b>${pick === q.a ? 'Correct.' : 'Not quite.'}</b> ${q.e || ''}`;
        answered++; if (pick === q.a) right++;
        if (answered === qs.length) {
          HS.progress.quiz(t.id, right, qs.length);
          score.innerHTML = `Score: <b>${right} / ${qs.length}</b> ${right / qs.length >= 0.7 ? '· topic passed' : '· review the explanations and retry'}`;
          HS.refreshNav();
        } else score.textContent = `${answered} of ${qs.length} answered`;
      }));
    });
    host.querySelector('.retry').addEventListener('click', () => renderQuiz(host, t));
  }
  HS.renderQuiz = renderQuiz;

  /* ---------- router ---------- */
  const main = document.getElementById('main');
  let current = null, players = [];
  function route() {
    const id = (location.hash || '#home').slice(1) || 'home';
    players.forEach((p) => p.destroy()); players = [];
    current = HS.byId[id] || HS.pages[id] ? id : 'home';
    document.body.classList.remove('nav-open');
    if (HS.byId[current]) renderTopic(HS.byId[current], main);
    else if (HS.pages[current]) { main.innerHTML = ''; HS.pages[current].render(main, players); }
    else main.innerHTML = `<div class="page"><h1>Not found</h1></div>`;
    if (window.hljs) main.querySelectorAll('pre.code code').forEach((c) => {
      const lang = (c.className.match(/language-(\w+)/) || [])[1];
      if (!lang || !hljs.getLanguage(lang)) return; // e.g. text, rego, nginx aren't in the common bundle
      try { hljs.highlightElement(c); } catch (e) {}
    });
    window.scrollTo(0, 0);
    HS.refreshNav();
  }
  HS.route = route;
  window.addEventListener('hashchange', route);
  document.getElementById('menuBtn').addEventListener('click', () => document.body.classList.toggle('nav-open'));
  document.getElementById('scrim').addEventListener('click', () => document.body.classList.remove('nav-open'));
  const q = document.getElementById('q');
  q.addEventListener('input', () => renderSide(q.value));
  q.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { const a = side.querySelector('a[data-id]'); if (a) { location.hash = a.dataset.id; q.value = ''; renderSide(); } }
  });
  route();
})();
