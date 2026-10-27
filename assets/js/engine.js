/* Handshake Field Guide — registry, helpers and the packet-flow player */
(function () {
  'use strict';

  const HS = (window.HS = {
    topics: [], byId: {}, tools: {}, pages: {},
    add(t) { this.topics.push(t); this.byId[t.id] = t; },
  });

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  HS.esc = esc;

  function dedent(src) {
    const lines = src.replace(/^\n+/, '').replace(/\s+$/, '').split('\n');
    let min = Infinity;
    lines.forEach((l) => { if (l.trim()) min = Math.min(min, l.match(/^ */)[0].length); });
    return lines.map((l) => l.slice(min === Infinity ? 0 : min)).join('\n');
  }
  HS.dedent = dedent;
  /* code block helper used inside topic content */
  window.C = (lang, src, caption) =>
    `<figure class="codefig">${caption ? `<figcaption>${caption}</figcaption>` : ''}<pre class="code"><code class="language-${lang}">${esc(dedent(src))}</code></pre></figure>`;

  /* ---------- icons ---------- */
  const ICONS = {
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/>',
    browser: '<rect x="3" y="4" width="18" height="13" rx="1.5"/><path d="M3 8h18M1 21h22"/>',
    server: '<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/>',
    db: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    idp: '<path d="M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5z"/><path d="M9 12l2 2 4-4"/>',
    attacker: '<path d="M12 2a7 7 0 0 0-7 7v4l-2 8h18l-2-8V9a7 7 0 0 0-7-7z"/><path d="M9 11.5h1.5M13.5 11.5H15"/>',
    key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L21 2M17 6l3 3M14 9l2 2"/>',
    phone: '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="1.5"/><path d="M3 7l9 6 9-6"/>',
    cloud: '<path d="M7 18a5 5 0 1 1 .9-9.9A6 6 0 0 1 19 10a4 4 0 0 1 0 8z"/>',
    policy: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9 7 7M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="1.5"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    net: '<rect x="2" y="13" width="20" height="7" rx="1.5"/><path d="M6 16.5h.01M10 16.5h.01M8 13V9M16 13V9M5 6a10 10 0 0 1 14 0"/>',
    dir: '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-5h14v5"/>',
    terminal: '<rect x="2" y="4" width="20" height="16" rx="1.5"/><path d="M6 9l3 3-3 3M11 15h6"/>',
    ticket: '<path d="M3 7h18v3a2 2 0 0 0 0 4v3H3v-3a2 2 0 0 0 0-4z"/><path d="M14 7v10" stroke-dasharray="2 2"/>',
  };
  HS.icon = (name, cls = '') =>
    `<svg class="ico ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.server}</svg>`;

  const UI = {
    play: '<path d="M7 4l13 8-13 8z" fill="currentColor" stroke="none"/>',
    pause: '<rect x="6" y="4" width="4" height="16" fill="currentColor" stroke="none"/><rect x="14" y="4" width="4" height="16" fill="currentColor" stroke="none"/>',
    prev: '<path d="M19 5l-9 7 9 7zM6 5v14"/>',
    next: '<path d="M5 5l9 7-9 7zM18 5v14"/>',
    restart: '<path d="M4 12a8 8 0 1 0 2.3-5.7M4 4v5h5"/>',
  };
  const ui = (n) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${UI[n]}</svg>`;

  const reduceMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const KIND_NAME = { req: 'Request', res: 'Response', int: 'Internal step', atk: 'Attacker' };

  /* measure an SVG <text>; falls back to a per-character estimate when layout isn't available */
  function textW(el, str, perChar) {
    el.textContent = str;
    let w = 0;
    try { w = el.getComputedTextLength(); } catch (e) { w = 0; }
    return w > 0 ? w : str.length * perChar;
  }
  /* set text, truncating with an ellipsis so it fits maxW; returns the final width */
  function fitText(el, str, maxW, perChar) {
    let w = textW(el, str, perChar);
    if (w <= maxW) return w;
    let lo = 1, hi = str.length;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (textW(el, str.slice(0, mid) + '…', perChar) <= maxW) lo = mid; else hi = mid - 1;
    }
    return textW(el, str.slice(0, lo).trimEnd() + '…', perChar);
  }

  /* ---------- the player ---------- */
  class FlowPlayer {
    constructor(host, flow) {
      this.host = host;
      this.flow = flow;
      this.scenarios = [];
      if (flow.normal) this.scenarios.push({ key: 'normal', name: flow.normal.name || 'Normal flow', ...flow.normal });
      if (flow.attack) this.scenarios.push({ key: 'attack', name: flow.attack.name || 'Attack mode', ...flow.attack });
      (flow.extra || []).forEach((s, i) => this.scenarios.push({ key: 'x' + i, ...s }));
      this.speed = 1;
      this.playing = false;
      this.raf = 0;
      this.timer = 0;
      this.build();
      this.setScenario(0);
    }

    build() {
      const tabs = this.scenarios
        .map((s, i) => `<button type="button" class="fp-tab ${s.key === 'attack' ? 'is-attack' : ''}" data-i="${i}" role="tab">${esc(s.name)}</button>`)
        .join('');
      this.host.classList.add('fp');
      this.host.innerHTML = `
        <div class="fp-top">
          <div class="fp-tabs" role="tablist">${tabs}</div>
          <p class="fp-sum"></p>
        </div>
        <div class="fp-stage">
          <div class="fp-pane fp-topo-pane">
            <div class="fp-pane-label">Network view</div>
            <svg class="fp-topo" viewBox="0 0 640 300" role="img"></svg>
          </div>
          <div class="fp-pane fp-seq-pane">
            <div class="fp-pane-label">Sequence diagram <span>click a row to jump</span></div>
            <div class="fp-seq-scroll"><div class="fp-seq-inner"><div class="fp-seq-head"></div><svg class="fp-seq"></svg></div></div>
          </div>
        </div>
        <div class="fp-controls">
          <button type="button" class="fp-btn" data-a="restart" title="Restart">${ui('restart')}<span class="sr">Restart</span></button>
          <button type="button" class="fp-btn" data-a="prev" title="Previous step (Left arrow)">${ui('prev')}<span class="sr">Previous</span></button>
          <button type="button" class="fp-btn fp-play" data-a="play" title="Play / pause (Space)">${ui('play')}<span class="fp-play-l">Play</span></button>
          <button type="button" class="fp-btn" data-a="next" title="Next step (Right arrow)">${ui('next')}<span class="sr">Next</span></button>
          <input class="fp-scrub" type="range" min="0" max="1" value="0" step="1" aria-label="Step">
          <span class="fp-count"></span>
          <label class="fp-speed">Speed
            <select>
              <option value="0.5">0.5×</option><option value="1" selected>1×</option><option value="1.5">1.5×</option><option value="2">2×</option>
            </select>
          </label>
        </div>
        <div class="fp-narr">
          <div class="fp-story" aria-live="polite">
            <div class="fp-step-meta"></div>
            <h4 class="fp-step-title"></h4>
            <div class="fp-step-text"></div>
          </div>
          <div class="fp-inspect"></div>
        </div>`;
      const q = (s) => this.host.querySelector(s);
      this.el = {
        sum: q('.fp-sum'), topo: q('.fp-topo'), seq: q('.fp-seq'), seqHead: q('.fp-seq-head'), seqScroll: q('.fp-seq-scroll'),
        play: q('.fp-play'), scrub: q('.fp-scrub'), count: q('.fp-count'), speed: q('.fp-speed select'),
        meta: q('.fp-step-meta'), title: q('.fp-step-title'), text: q('.fp-step-text'), inspect: q('.fp-inspect'),
      };
      this.host.tabIndex = 0;
      this.host.querySelectorAll('.fp-tab').forEach((b) => b.addEventListener('click', () => this.setScenario(+b.dataset.i)));
      this.host.querySelectorAll('.fp-btn').forEach((b) => b.addEventListener('click', () => this[b.dataset.a]()));
      this.el.scrub.addEventListener('input', () => { this.pause(); this.goTo(+this.el.scrub.value); });
      this.el.speed.addEventListener('change', () => (this.speed = +this.el.speed.value));
      this.host.addEventListener('keydown', (e) => {
        if (e.target.closest('select,input,textarea')) return;
        // let a focused button handle Space itself, otherwise it fires twice
        if (e.key === ' ' && e.target.closest('button,a')) return;
        if (e.key === ' ') { e.preventDefault(); this.play(); }
        else if (e.key === 'ArrowRight') { e.preventDefault(); this.next(); }
        else if (e.key === 'ArrowLeft') { e.preventDefault(); this.prev(); }
      });
    }

    setScenario(idx) {
      this.pause();
      this.sc = this.scenarios[idx];
      this.host.querySelectorAll('.fp-tab').forEach((b, i) => { b.classList.toggle('on', i === idx); b.setAttribute('aria-selected', i === idx); });
      this.host.classList.toggle('attack', this.sc.key === 'attack');
      this.steps = this.sc.steps.map((s) => ({ ...s, t: s.t || s.f, k: s.k || (s.t && s.t !== s.f ? 'req' : 'int') }));
      const used = new Set();
      this.steps.forEach((s) => { used.add(s.f); used.add(s.t); });
      this.nodes = this.flow.nodes.filter((n) => used.has(n.id));
      this.nodeById = {};
      this.nodes.forEach((n) => (this.nodeById[n.id] = n));
      this.order = (this.sc.order || this.flow.order || this.nodes.map((n) => n.id)).filter((id) => used.has(id));
      this.nodes.forEach((n) => { if (!this.order.includes(n.id)) this.order.push(n.id); });
      this.el.sum.innerHTML = this.sc.summary || '';
      this.el.scrub.max = this.steps.length - 1;
      this.buildTopo();
      this.buildSeq();
      this.goTo(0);
      this.watchSize();
    }

    /* rebuild the sequence diagram at real pixel size whenever its pane width changes */
    watchSize() {
      if (this.ro || typeof ResizeObserver === 'undefined') return;
      let last = this.el.seqScroll.clientWidth;
      this.ro = new ResizeObserver(() => {
        const w = this.el.seqScroll.clientWidth;
        if (Math.abs(w - last) < 6) return;
        last = w;
        clearTimeout(this.roT);
        this.roT = setTimeout(() => { this.buildSeq(); this.renderStatic(); this.renderMotion(); }, 120);
      });
      this.ro.observe(this.el.seqScroll);
    }

    /* geometry: straight link unless another node sits on the segment */
    linkGeom(a, b) {
      const ax = a.x, ay = a.y, bx = b.x, by = b.y;
      const dx = bx - ax, dy = by - ay, L = Math.hypot(dx, dy) || 1;
      let bend = 0;
      for (const n of this.nodes) {
        if (n === a || n === b) continue;
        const t = ((n.x - ax) * dx + (n.y - ay) * dy) / (L * L);
        if (t <= 0.05 || t >= 0.95) continue;
        const px = ax + t * dx, py = ay + t * dy;
        if (Math.hypot(n.x - px, n.y - py) < 48) bend = 78;
      }
      const nx = -dy / L, ny = dx / L;
      const flip = ny > 0 ? -1 : 1; // bend upward when possible
      const cx = (ax + bx) / 2 + nx * bend * flip, cy = (ay + by) / 2 + ny * bend * flip;
      const pt = (t) => ({
        x: (1 - t) * (1 - t) * ax + 2 * (1 - t) * t * cx + t * t * bx,
        y: (1 - t) * (1 - t) * ay + 2 * (1 - t) * t * cy + t * t * by,
      });
      const trim = Math.min(0.38, 66 / L);
      return { d: bend ? `M${ax},${ay} Q${cx},${cy} ${bx},${by}` : `M${ax},${ay} L${bx},${by}`, pt, t0: trim, t1: 1 - trim };
    }

    buildTopo() {
      const svg = this.el.topo;
      const pairs = new Map();
      this.steps.forEach((s) => {
        if (s.f === s.t) return;
        const key = [s.f, s.t].sort().join('|');
        if (!pairs.has(key)) pairs.set(key, this.linkGeom(this.nodeById[s.f], this.nodeById[s.t]));
      });
      this.links = pairs;
      let html = `<g class="links">`;
      pairs.forEach((g, key) => (html += `<path class="link" data-k="${key}" d="${g.d}"/>`));
      html += `</g><g class="nodes">`;
      this.nodes.forEach((n) => {
        html += `<g class="node ${n.icon === 'attacker' ? 'n-atk' : ''}" data-id="${n.id}" transform="translate(${n.x - 62},${n.y - 30})">
          <rect class="n-ring" x="-6" y="-6" width="136" height="72" rx="15"/>
          <rect class="n-box" width="124" height="60" rx="11"/>
          <g transform="translate(10,18)"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" class="n-ico">${ICONS[n.icon] || ICONS.server}</svg></g>
          <text class="n-label" x="42" y="27">${esc(n.label)}</text>
          <text class="n-sub" x="42" y="43">${esc(n.sub || '')}</text>
        </g>`;
      });
      html += `</g><g class="bubble" opacity="0"><rect rx="8" height="26"/><text y="17"></text></g>
        <g class="packet" opacity="0"><rect rx="7" height="22"/><path class="pk-lock" d="M9,10.5h8v7h-8z M10.5,10.5v-2a2.5,2.5 0 0 1 5,0v2"/><text y="15"></text></g>
        <g class="burst" opacity="0"><circle r="16"/><path d="M-7,-7 L7,7 M7,-7 L-7,7"/></g>
        <g class="outcome" opacity="0"><rect x="8" y="5" rx="8" height="26"/><text x="20" y="22.5"></text></g>`;
      svg.innerHTML = html;
      svg.setAttribute('aria-label', 'Network diagram: ' + this.nodes.map((n) => n.label).join(', '));
      this.sizeNodes();
    }

    /* widen each node box to fit its text, keep it inside the canvas, squeeze text only as a last resort */
    sizeNodes() {
      const MAXW = 172, PAD = 54;
      this.el.topo.querySelectorAll('.node').forEach((g) => {
        const n = this.nodeById[g.dataset.id];
        const lab = g.querySelector('.n-label'), sub = g.querySelector('.n-sub');
        const lw = textW(lab, n.label, 7.8), sw = textW(sub, n.sub || '', 6.1);
        const w = Math.max(124, Math.min(MAXW, Math.ceil(Math.max(lw, sw) + PAD)));
        [[lab, lw], [sub, sw]].forEach(([el, tw]) => {
          if (tw + PAD > MAXW) { el.setAttribute('textLength', MAXW - PAD); el.setAttribute('lengthAdjust', 'spacingAndGlyphs'); }
        });
        g.querySelector('.n-box').setAttribute('width', w);
        g.querySelector('.n-ring').setAttribute('width', w + 12);
        const left = Math.max(4, Math.min(636 - w, n.x - w / 2));
        g.setAttribute('transform', `translate(${left},${n.y - 30})`);
      });
    }

    buildSeq() {
      const n = this.order.length, G = 26, rowH = 46, top = 14;
      // lay out in real pixels so labels render at a readable size; scroll only when columns get cramped
      const avail = this.el.seqScroll.clientWidth || 600;
      const W = Math.max(avail, G + n * 112);
      const colX = (id) => G + (this.order.indexOf(id) + 0.5) * ((W - G) / n);
      this.el.seq.parentElement.style.width = W + 'px';
      this.el.seqHead.style.gridTemplateColumns = `repeat(${n}, 1fr)`;
      this.el.seqHead.style.paddingLeft = G + 'px';
      this.el.seqHead.innerHTML = this.order
        .map((id) => { const nd = this.nodeById[id]; return `<div class="sh ${nd.icon === 'attacker' ? 'sh-atk' : ''}">${HS.icon(nd.icon)}<span>${esc(nd.label)}</span></div>`; })
        .join('');
      const H = top + this.steps.length * rowH + 10;
      this.seqGeom = { W, H, rowH, top };
      let s = `<defs>${['req', 'res', 'int', 'atk'].map((k) => `<marker id="m-${k}-${this.uid()}" class="mk-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z"/></marker>`).join('')}</defs>`;
      this.markerIds = {};
      s.replace(/id="(m-(\w+)-\w+)"/g, (_, id, k) => (this.markerIds[k] = id));
      this.order.forEach((id) => { const x = colX(id); s += `<line class="lifeline" x1="${x}" y1="0" x2="${x}" y2="${H}"/>`; });
      this.steps.forEach((st, i) => {
        const y = top + i * rowH + 28;
        const xf = colX(st.f), xt = colX(st.t);
        s += `<g class="row" data-i="${i}"><rect class="row-bg" x="0" y="${y - 28}" width="${W}" height="${rowH}"/>
          <text class="row-n" x="13" y="${y + 4}">${i + 1}</text>`;
        if (st.f === st.t) {
          const left = xf > W * 0.68;
          const dx = left ? -30 : 30;
          // label sits centred above a small loop, so it never runs over the arrow
          s += `<path class="arr k-${st.k}" d="M${xf},${y - 5} h${dx} v14 h${-dx + (left ? -4 : 4)}" marker-end="url(#${this.markerIds[st.k]})"/>
            <text class="arr-l ${st.enc ? 'enc' : ''}" x="${xf}" y="${y - 12}" text-anchor="middle">${esc(st.l)}</text>`;
        } else {
          const end = st.blocked ? xf + (xt - xf) * 0.62 : xt + (xt > xf ? -2 : 2);
          if (st.enc) s += `<line class="enc-halo" x1="${xf}" y1="${y}" x2="${end}" y2="${y}"/>`;
          s += `<line class="arr k-${st.k} ${st.k === 'res' ? 'dash' : ''}" x1="${xf}" y1="${y}" x2="${end}" y2="${y}" ${st.blocked ? '' : `marker-end="url(#${this.markerIds[st.k]})"`}/>`;
          if (st.blocked) s += `<path class="xmark" d="M${end - 6},${y - 6} l12,12 M${end + 6},${y - 6} l-12,12"/>`;
          const lx = (xf + xt) / 2;
          s += `<text class="arr-l ${st.enc ? 'enc' : ''}" x="${lx}" y="${y - 7}" text-anchor="middle">${esc(st.l)}</text>`;
        }
        s += `</g>`;
      });
      s += `<circle class="seq-dot" r="5" opacity="0"/>`;
      this.el.seq.setAttribute('viewBox', `0 0 ${W} ${H}`);
      this.el.seq.setAttribute('width', W);
      this.el.seq.setAttribute('height', H);
      this.el.seq.innerHTML = s;
      this.colX = colX;
      // keep every arrow label inside the canvas (long labels between adjacent columns used to clip)
      this.el.seq.querySelectorAll('.arr-l').forEach((t) => {
        const w = textW(t, t.textContent, 6.9);
        const anchor = t.getAttribute('text-anchor');
        const x = +t.getAttribute('x');
        if (anchor === 'middle') t.setAttribute('x', Math.max(G + w / 2, Math.min(W - 4 - w / 2, x)));
        else if (anchor === 'end' && x - w < G) { t.setAttribute('text-anchor', 'start'); t.setAttribute('x', G + 2); }
        else if (anchor === 'start' && x + w > W - 4) { t.setAttribute('text-anchor', 'end'); t.setAttribute('x', W - 4); }
      });
      this.el.seq.querySelectorAll('.row').forEach((r) => r.addEventListener('click', () => { this.pause(); this.goTo(+r.dataset.i); }));
    }

    uid() { return (this._u = this._u || Math.random().toString(36).slice(2, 7)); }

    /* ---------- state rendering ---------- */
    renderStatic() {
      const st = this.steps[this.i];
      const n = this.steps.length;
      this.el.scrub.value = this.i;
      this.el.count.textContent = `Step ${this.i + 1} / ${n}`;
      // seq rows
      this.el.seq.querySelectorAll('.row').forEach((r, j) => {
        r.classList.toggle('past', j < this.i);
        r.classList.toggle('cur', j === this.i);
        r.classList.toggle('future', j > this.i);
      });
      // keep current row visible
      const sc = this.el.seqScroll, svgEl = this.el.seq;
      const scale = svgEl.clientHeight / this.seqGeom.H || 0;
      if (scale) {
        const head = this.el.seqHead.offsetHeight;
        const yTop = (this.seqGeom.top + this.i * this.seqGeom.rowH) * scale + head;
        const yBot = yTop + this.seqGeom.rowH * scale;
        if (yTop - head < sc.scrollTop) sc.scrollTop = yTop - head - 8;
        else if (yBot > sc.scrollTop + sc.clientHeight) sc.scrollTop = yBot - sc.clientHeight + 8;
      }
      // nodes + links
      this.el.topo.querySelectorAll('.node').forEach((g) => {
        const id = g.dataset.id;
        g.classList.toggle('from', id === st.f);
        g.classList.toggle('to', id === st.t && st.f !== st.t);
        g.classList.toggle('busy', id === st.f && st.f === st.t);
      });
      const key = [st.f, st.t].sort().join('|');
      this.el.topo.querySelectorAll('.link').forEach((l) => {
        l.setAttribute('class', 'link' + (l.dataset.k === key && st.f !== st.t ? ' on k-' + st.k : ''));
      });
      // outcome banner
      const oc = this.el.topo.querySelector('.outcome');
      if ((st.ok || st.fail) && this.p >= 1) {
        const txt = st.ok || st.fail;
        const w = fitText(oc.querySelector('text'), txt, 600, 7.3);
        oc.querySelector('rect').setAttribute('width', w + 24);
        oc.setAttribute('class', 'outcome ' + (st.ok ? 'good' : 'bad'));
        oc.setAttribute('opacity', 1);
      } else oc.setAttribute('opacity', 0);
      // narration
      const fromN = this.nodeById[st.f], toN = this.nodeById[st.t];
      const route = st.f === st.t ? `${esc(fromN.label)} · internal` : `${esc(fromN.label)} → ${esc(toN.label)}`;
      this.el.meta.innerHTML = `<span class="chip k-${st.k}">${KIND_NAME[st.k]}</span><span class="route">${route}</span>${st.port ? `<span class="route mono">${esc(st.port)}</span>` : ''}`;
      this.el.title.textContent = st.title || st.l;
      this.el.text.innerHTML = st.d || '';
      this.renderInspect(st);
    }

    renderInspect(st) {
      const box = this.el.inspect;
      if (!st.data) { box.hidden = true; box.innerHTML = ''; return; }
      box.hidden = false;
      const wire = st.f === st.t ? ''
        : st.k === 'int' ? `<div class="wire local">${HS.icon('policy')} A check, not a network message. The link shows which parties it involves.</div>`
        : st.enc ? `<div class="wire enc">${HS.icon('lock')} Encrypted on the wire. An eavesdropper sees only ciphertext.</div>`
        : st.k === 'atk' ? `<div class="wire atk">${HS.icon('attacker')} Attacker-controlled step</div>`
        : `<div class="wire plain">Readable by anyone on the path unless the channel is protected</div>`;
      const rows = Object.entries(st.data)
        .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`)
        .join('');
      box.innerHTML = `<div class="ins-h">${st.f === st.t ? 'State inside ' + esc(this.nodeById[st.f].label) : 'Packet inspector'}<span>${esc(st.l)}</span></div>${wire}<div class="ins-scroll"><table>${rows}</table></div>`;
    }

    renderMotion() {
      const st = this.steps[this.i];
      const svg = this.el.topo;
      const pk = svg.querySelector('.packet'), bub = svg.querySelector('.bubble'), burst = svg.querySelector('.burst');
      const dot = this.el.seq.querySelector('.seq-dot');
      const p = this.p;
      burst.setAttribute('opacity', 0);
      if (st.f === st.t) {
        pk.setAttribute('opacity', 0);
        const n = this.nodeById[st.f];
        const tx = bub.querySelector('text');
        if (this._bubKey !== this.sc.key + this.i) {
          this._bubKey = this.sc.key + this.i;
          this._bubW = fitText(tx, st.l, 296, 6.6) + 22;
        }
        const w = this._bubW;
        let bx = n.x - w / 2;
        bx = Math.max(4, Math.min(636 - w, bx));
        const by = n.y < 110 ? n.y + 40 : n.y - 70;
        bub.setAttribute('transform', `translate(${bx},${by + (1 - p) * 8})`);
        bub.querySelector('rect').setAttribute('width', w);
        tx.setAttribute('x', w / 2); tx.setAttribute('text-anchor', 'middle');
        bub.setAttribute('class', 'bubble k-' + st.k);
        bub.setAttribute('opacity', Math.min(1, p * 1.6));
        const x = this.colX(st.f), y = this.seqGeom.top + this.i * this.seqGeom.rowH + 28;
        dot.setAttribute('cx', x + (x > this.seqGeom.W * 0.68 ? -30 : 30) * Math.sin(p * Math.PI));
        dot.setAttribute('cy', y - 5 + 14 * p);
        dot.setAttribute('class', 'seq-dot k-' + st.k);
        dot.setAttribute('opacity', p < 1 ? 1 : 0);
        return;
      }
      bub.setAttribute('opacity', 0);
      const a = this.nodeById[st.f], b = this.nodeById[st.t];
      const g = this.links.get([st.f, st.t].sort().join('|'));
      const forward = [st.f, st.t].sort()[0] === st.f;
      let reach = st.blocked ? 0.62 : 1;
      let tt = Math.min(p, reach);
      const tg = g.t0 + (g.t1 - g.t0) * tt;
      // the geometry is stored a->b sorted; reverse when travelling the other way
      const lp = g.pt(forward ? tg : 1 - tg);
      const tx = pk.querySelector('text');
      const lock = st.enc ? 14 : 0;
      if (this._pkKey !== this.sc.key + this.i) {
        this._pkKey = this.sc.key + this.i;
        this._pkW = fitText(tx, st.l, 236 - lock, 6.6) + 18 + lock;
      }
      const w = this._pkW;
      pk.setAttribute('transform', `translate(${lp.x - w / 2},${lp.y - 11})`);
      pk.querySelector('rect').setAttribute('width', w);
      tx.setAttribute('x', w / 2 + lock / 2); tx.setAttribute('text-anchor', 'middle');
      pk.setAttribute('class', 'packet k-' + st.k + (st.enc ? ' enc' : ''));
      const fade = st.blocked && p > reach ? Math.max(0, 1 - (p - reach) / (1 - reach)) : 1;
      pk.setAttribute('opacity', fade);
      if (st.blocked && p >= reach) {
        burst.setAttribute('transform', `translate(${lp.x},${lp.y - 26})`);
        burst.setAttribute('opacity', 1);
      }
      // seq dot
      const xf = this.colX(st.f), xt = this.colX(st.t), y = this.seqGeom.top + this.i * this.seqGeom.rowH + 28;
      dot.setAttribute('cx', xf + (xt - xf) * tt);
      dot.setAttribute('cy', y);
      dot.setAttribute('class', 'seq-dot k-' + st.k);
      dot.setAttribute('opacity', p < 1 ? 1 : 0);
      // keep packet resting on link midpoint after arrival so the frame reads at rest
      if (p >= 1 && !st.blocked) {
        const mid = g.pt(forward ? g.t0 + (g.t1 - g.t0) * 0.5 : 1 - (g.t0 + (g.t1 - g.t0) * 0.5));
        pk.setAttribute('transform', `translate(${mid.x - w / 2},${mid.y - 11})`);
      }
    }

    /* ---------- transport ---------- */
    cancel() { cancelAnimationFrame(this.raf); clearTimeout(this.timer); }
    goTo(i) {
      this.cancel();
      this.i = Math.max(0, Math.min(this.steps.length - 1, i));
      this.p = 1;
      this.shown = false; // this step was jumped to, not watched
      this.renderStatic();
      this.renderMotion();
    }
    animate(i) {
      this.cancel();
      this.i = i; this.p = 0; this.shown = true;
      this.renderStatic();
      this.renderMotion();
      const st = this.steps[i];
      const dur = reduceMotion() ? 0 : (st.f === st.t ? 900 : st.blocked ? 1700 : 1350) / this.speed;
      const t0 = performance.now();
      const tick = (now) => {
        const raw = dur ? Math.min(1, (now - t0) / dur) : 1;
        this.p = raw < 0.5 ? 2 * raw * raw : 1 - Math.pow(-2 * raw + 2, 2) / 2;
        this.renderMotion();
        if (raw < 1) this.raf = requestAnimationFrame(tick);
        else {
          this.p = 1;
          this.renderStatic();
          this.renderMotion();
          if (this.playing) {
            const txt = (st.d || '').replace(/<[^>]+>/g, '');
            const dwell = Math.min(9000, 1700 + txt.length * 20) / this.speed;
            this.timer = setTimeout(() => this.advance(), dwell);
          }
        }
      };
      this.raf = requestAnimationFrame(tick);
    }
    advance() {
      if (!this.playing) return;
      if (this.i >= this.steps.length - 1) { this.pause(); return; }
      this.animate(this.i + 1);
    }
    play() {
      if (this.playing) { this.pause(); return; }
      this.playing = true;
      this.updPlay();
      if (!this.shown) this.animate(this.i);               // play the step you're looking at first
      else if (this.i >= this.steps.length - 1) this.animate(0); // finished: start over
      else this.advance();
    }
    pause() { this.playing = false; this.cancel(); if (this.p < 1) { this.p = 1; this.renderStatic(); this.renderMotion(); } this.updPlay(); }
    updPlay() {
      this.el.play.innerHTML = this.playing ? `${ui('pause')}<span class="fp-play-l">Pause</span>` : `${ui('play')}<span class="fp-play-l">Play</span>`;
    }
    next() { if (this.i < this.steps.length - 1) { const wasPlaying = this.playing; this.cancel(); this.animate(this.i + 1); this.playing = wasPlaying; } }
    prev() { this.pause(); this.goTo(this.i - 1); }
    restart() { this.pause(); this.goTo(0); }
    destroy() { this.cancel(); clearTimeout(this.roT); if (this.ro) this.ro.disconnect(); }
  }
  HS.FlowPlayer = FlowPlayer;
})();
