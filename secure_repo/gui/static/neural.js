/* Secure Repo - neural network style map of insecure points (canvas, no dependencies).
 *
 * Layers:   source files  ->  weaknesses  ->  OWASP Top 10 categories  ->  severity
 * Every edge carries the number of findings flowing through it; animated pulses travel
 * along the connections like signals in a neural network. Clicking a node highlights its
 * full activation path and asks the host page to explain it.
 */
(function () {
  'use strict';
  const SR = window.SR;
  const LAYER_TITLES = ['SOURCE FILES', 'WEAKNESSES', 'OWASP TOP 10', 'SEVERITY'];
  const CAT_COLOR = '#9d7bff';
  const MAX_FILES = 42;
  const MAX_WEAK = 56;

  function hexToRgb(hex) {
    const v = parseInt(hex.slice(1), 16);
    return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
  }
  function rgba(hex, a) {
    const c = hexToRgb(hex);
    return 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + a + ')';
  }
  function easeOutBack(t) {
    const c1 = 1.70158, c3 = c1 + 1;
    return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2);
  }
  function bezier(p0, p1, p2, p3, t) {
    const u = 1 - t;
    return u * u * u * p0 + 3 * u * u * t * p1 + 3 * u * t * t * p2 + t * t * t * p3;
  }

  class NeuralMap {
    constructor(canvas, options) {
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.opts = options || {};
      this.nodes = [];
      this.edges = [];
      this.layout = 'neural';
      this.view = { x: 0, y: 0, k: 1 };
      this.hover = null;
      this.selected = null;
      this.active = null; // {nodes:Set, edges:Set}
      this.query = '';
      this.severities = new Set(SR.SEV);
      this.pulses = true;
      this.particles = [];
      this.intro = performance.now();
      this.running = false;
      this.alpha = 0;
      this.dpr = Math.max(1, window.devicePixelRatio || 1);
      const styles = getComputedStyle(document.documentElement);
      this.fontMono = styles.getPropertyValue('--mono') || 'monospace';
      this.fontUI = styles.getPropertyValue('--font') || 'sans-serif';
      this.w = 800;
      this.h = 600;
      this._bind();
    }

    /* ---------------------------------------------------------------- data */
    setData(report) {
      this.report = report;
      this.rebuild();
    }

    rebuild() {
      const findings = (this.report.findings || []).filter((f) => this.severities.has(f.severity) &&
        f.status !== 'false_positive' && f.status !== 'filtered');
      const weight = { critical: 15, high: 7, medium: 3, low: 1, info: 0.3 };
      const fileScore = new Map();
      const weakScore = new Map();
      const fileKey = (f) => (!f.file || f.file === '.' ? '(repository)' : f.file);
      const weakKey = (f) => (f.rule_id === 'SR-DEP-001' && f.extra && f.extra.package
        ? 'dep:' + f.extra.package + '@' + (f.extra.version || '') : f.rule_id);
      findings.forEach((f) => {
        fileScore.set(fileKey(f), (fileScore.get(fileKey(f)) || 0) + weight[f.severity]);
        weakScore.set(weakKey(f), (weakScore.get(weakKey(f)) || 0) + weight[f.severity]);
      });
      const topFiles = new Set([...fileScore.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_FILES).map((e) => e[0]));
      const topWeak = new Set([...weakScore.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_WEAK).map((e) => e[0]));
      const otherFiles = fileScore.size - topFiles.size;
      const otherWeak = weakScore.size - topWeak.size;

      const nodes = new Map();
      const edges = new Map();
      const node = (id, props) => {
        let n = nodes.get(id);
        if (!n) {
          n = Object.assign({ id: id, count: 0, sev: {}, findings: [], x: 0, y: 0, vx: 0, vy: 0, r: 8 }, props);
          nodes.set(id, n);
        }
        return n;
      };
      const edge = (a, b) => {
        const id = a.id + '>' + b.id;
        let e = edges.get(id);
        if (!e) { e = { id: id, a: a, b: b, w: 0 }; edges.set(id, e); }
        e.w += 1;
      };
      const owasp = this.report.owasp || {};
      findings.forEach((f) => {
        const fk = fileKey(f);
        const wk = weakKey(f);
        const fileNode = topFiles.has(fk)
          ? node('f:' + fk, { layer: 0, type: 'file', label: SR.basename(fk), full: fk })
          : node('f:__other', { layer: 0, type: 'file', label: '+' + otherFiles + ' more files', full: 'Other files', other: true });
        const isDep = wk.indexOf('dep:') === 0;
        const weakNode = topWeak.has(wk)
          ? node('w:' + wk, { layer: 1, type: 'weak', label: isDep ? wk.slice(4) : f.title, full: isDep ? f.title : f.title,
            rule: f.rule_id, dep: isDep })
          : node('w:__other', { layer: 1, type: 'weak', label: '+' + otherWeak + ' more weaknesses', full: 'Other weaknesses', other: true });
        const code = f.owasp || 'OTHER';
        const catNode = node('c:' + code, { layer: 2, type: 'cat', code: code,
          label: (code === 'OTHER' ? '' : code + ' ') + ((owasp[code] && owasp[code].name) || code), full: (owasp[code] && owasp[code].name) || code });
        const sevNode = node('s:' + f.severity, { layer: 3, type: 'sev', severity: f.severity, label: f.severity.toUpperCase(), full: f.severity });
        [fileNode, weakNode, catNode, sevNode].forEach((n) => {
          n.count += 1;
          n.sev[f.severity] = (n.sev[f.severity] || 0) + 1;
          n.findings.push(f);
        });
        edge(fileNode, weakNode);
        edge(weakNode, catNode);
        edge(catNode, sevNode);
      });
      nodes.forEach((n) => {
        n.worst = SR.worst(Object.keys(n.sev));
        n.color = n.type === 'cat' ? CAT_COLOR : SR.SEV_COLOR[n.type === 'sev' ? n.severity : n.worst];
        const base = n.type === 'sev' ? 13 : n.type === 'cat' ? 9 : 6;
        n.r = Math.min(n.type === 'sev' ? 30 : 22, base + Math.sqrt(n.count) * (n.type === 'sev' ? 2.2 : 1.9));
        n.out = []; n.inn = [];
      });
      edges.forEach((e) => { e.a.out.push(e); e.b.inn.push(e); });
      this.nodes = Array.from(nodes.values());
      this.edges = Array.from(edges.values());
      this.maxW = Math.max(1, ...this.edges.map((e) => e.w));
      this.particles = [];
      this.selected = null;
      this.active = null;
      this._layoutNeural();
      if (this.layout === 'organic') this._startForce(true);
      this.fit(false);
      this.intro = performance.now();
      this._applyQuery();
      if (this.opts.onEmpty) this.opts.onEmpty(this.nodes.length === 0);
    }

    /* ---------------------------------------------------------------- layout */
    _layoutNeural() {
      const layers = [[], [], [], []];
      this.nodes.forEach((n) => layers[n.layer].push(n));
      layers[3].sort((a, b) => SR.SEV_RANK[a.severity] - SR.SEV_RANK[b.severity]);
      const catOrder = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10', 'OTHER'];
      layers[2].sort((a, b) => catOrder.indexOf(a.code) - catOrder.indexOf(b.code));
      const catIndex = new Map(layers[2].map((n, i) => [n, i]));
      layers[1].sort((a, b) => {
        const ca = catIndex.get(a.out[0] && a.out[0].b) || 0;
        const cb = catIndex.get(b.out[0] && b.out[0].b) || 0;
        return ca - cb || SR.SEV_RANK[a.worst] - SR.SEV_RANK[b.worst] || b.count - a.count || (a.other ? 1 : 0) - (b.other ? 1 : 0);
      });
      const weakIndex = new Map(layers[1].map((n, i) => [n, i]));
      layers[0].forEach((n) => {
        let sum = 0, total = 0;
        n.out.forEach((e) => { sum += weakIndex.get(e.b) * e.w; total += e.w; });
        n.bary = total ? sum / total : 0;
      });
      layers[0].sort((a, b) => (a.other ? 1 : 0) - (b.other ? 1 : 0) || a.bary - b.bary);

      const minGap = [26, 26, 48, 90];
      const tallest = Math.max(...layers.map((layer, li) => minGap[li] * Math.max(layer.length - 1, 0))) + 140;
      const H = Math.max(this.h, tallest);
      // Keep the world aspect ratio equal to the viewport so column spacing survives "fit".
      const W = Math.max(this.w, 900, H * (this.w / Math.max(this.h, 1)));
      const padX = Math.max(180, W * 0.17);
      const colW = (W - padX * 2) / 3;
      layers.forEach((layer, li) => {
        const gap = Math.max(minGap[li], (H - 100) / Math.max(layer.length, 1));
        const total = gap * (layer.length - 1);
        layer.forEach((n, i) => {
          n.gap = gap;
          n.tx = padX + colW * li;
          n.ty = H / 2 - total / 2 + gap * i;
          if (this.layout === 'neural' || !n.placed) { n.x = n.tx; n.y = n.ty; n.placed = true; }
        });
      });
      this.layers = layers;
    }

    setLayout(mode) {
      this.layout = mode;
      if (mode === 'neural') {
        this._layoutNeural();
        this.alpha = 0;
      } else {
        this._startForce(true);
      }
      this.fit(true);
    }

    _startForce(reset) {
      if (reset) {
        this.nodes.forEach((n) => {
          n.x = n.tx + (Math.random() - 0.5) * 60;
          n.y = n.ty + (Math.random() - 0.5) * 60;
          n.vx = 0; n.vy = 0;
        });
      }
      this.alpha = 1;
    }

    _tickForce() {
      if (this.layout !== 'organic' || this.alpha < 0.01) return;
      const nodes = this.nodes;
      const cx = this.w / 2, cy = this.h / 2;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 1) { dx = Math.random(); dy = Math.random(); d2 = 1; }
          const minD = a.r + b.r + 26;
          const force = (1800 / d2) + (d2 < minD * minD ? 0.4 : 0);
          const d = Math.sqrt(d2);
          const fx = (dx / d) * force, fy = (dy / d) * force;
          a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
        }
      }
      this.edges.forEach((e) => {
        const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const target = 70 + (e.a.r + e.b.r);
        const k = 0.012 * (d - target);
        const fx = (dx / d) * k, fy = (dy / d) * k;
        e.a.vx += fx; e.a.vy += fy; e.b.vx -= fx; e.b.vy -= fy;
      });
      nodes.forEach((n) => {
        n.vx += (cx - n.x) * 0.002 + ((n.layer - 1.5) * 90 + cx - n.x) * 0.0015;
        n.vy += (cy - n.y) * 0.002;
        if (n === this.dragNode) { n.vx = 0; n.vy = 0; return; }
        n.vx *= 0.82; n.vy *= 0.82;
        n.x += n.vx * this.alpha; n.y += n.vy * this.alpha;
      });
      this.alpha *= 0.992;
    }

    /* ---------------------------------------------------------------- view */
    resize() {
      const rect = this.canvas.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      this.w = rect.width; this.h = rect.height;
      this.canvas.width = Math.round(rect.width * this.dpr);
      this.canvas.height = Math.round(rect.height * this.dpr);
      if (this.nodes.length) {
        this._layoutNeural();
        this.fit(false);
      }
    }

    fit(animate) {
      if (!this.nodes.length) return;
      // Labels keep a constant on-screen size, so their world size depends on the zoom:
      // estimate the zoom, then refine it once with label margins at that zoom.
      let k = 1, minX, minY, maxX, maxY;
      for (let pass = 0; pass < 3; pass++) {
        minX = Infinity; minY = Infinity; maxX = -Infinity; maxY = -Infinity;
        this.nodes.forEach((n) => {
          const labelLeft = n.layer === 0 && this.layout === 'neural' ? 175 / k : 0;
          const labelRight = n.layer === 0 && this.layout === 'neural' ? 0 : 185 / k;
          minX = Math.min(minX, n.x - n.r - labelLeft); maxX = Math.max(maxX, n.x + n.r + labelRight);
          minY = Math.min(minY, n.y - n.r - 34 / k); maxY = Math.max(maxY, n.y + n.r + 14 / k);
        });
        k = Math.min(1.4, Math.max(0.2, Math.min(this.w / (maxX - minX + 30), this.h / (maxY - minY + 30))));
      }
      const target = { k: k, x: this.w / 2 - ((minX + maxX) / 2) * k, y: this.h / 2 - ((minY + maxY) / 2) * k };
      if (!animate) { this.view = target; return; }
      const from = Object.assign({}, this.view);
      const start = performance.now();
      const step = (now) => {
        const p = Math.min(1, (now - start) / 500);
        const e = 1 - Math.pow(1 - p, 3);
        this.view = { k: from.k + (target.k - from.k) * e, x: from.x + (target.x - from.x) * e, y: from.y + (target.y - from.y) * e };
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }

    setSeverities(set) { this.severities = set; this.rebuild(); }
    setQuery(q) { this.query = (q || '').trim().toLowerCase(); this._applyQuery(); }
    setPulses(on) { this.pulses = on; if (!on) this.particles = []; }

    _applyQuery() {
      if (!this.query) { this.active = this.selected ? this._path(this.selected) : null; return; }
      const nodes = new Set(), edges = new Set();
      this.nodes.forEach((n) => {
        const text = (n.label + ' ' + (n.full || '') + ' ' + (n.rule || '') + ' ' +
          n.findings.slice(0, 50).map((f) => f.cwe + ' ' + f.rule_id).join(' ')).toLowerCase();
        if (text.indexOf(this.query) >= 0) {
          const p = this._path(n);
          p.nodes.forEach((x) => nodes.add(x));
          p.edges.forEach((x) => edges.add(x));
        }
      });
      this.active = { nodes: nodes, edges: edges };
    }

    _path(start) {
      const nodes = new Set([start]), edges = new Set();
      const walk = (n, dir) => {
        (dir === 'out' ? n.out : n.inn).forEach((e) => {
          if (edges.has(e)) return;
          edges.add(e);
          const next = dir === 'out' ? e.b : e.a;
          nodes.add(next);
          walk(next, dir);
        });
      };
      walk(start, 'out');
      walk(start, 'in');
      return { nodes: nodes, edges: edges };
    }

    select(node) {
      this.selected = node;
      this.active = node ? this._path(node) : null;
      if (!node && this.query) this._applyQuery();
    }

    /* ---------------------------------------------------------------- loop */
    start() {
      if (this.running) return;
      this.running = true;
      const loop = () => {
        if (!this.running) return;
        this._tickForce();
        this._draw(performance.now());
        requestAnimationFrame(loop);
      };
      requestAnimationFrame(loop);
    }
    stop() { this.running = false; }

    _edgePoint(e, t) {
      const ax = e.a.x, ay = e.a.y, bx = e.b.x, by = e.b.y;
      if (this.layout === 'neural') {
        const dx = (bx - ax) * 0.5;
        return [bezier(ax, ax + dx, bx - dx, bx, t), bezier(ay, ay, by, by, t)];
      }
      return [ax + (bx - ax) * t, ay + (by - ay) * t];
    }

    _draw(now) {
      const ctx = this.ctx;
      const dpr = this.dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, this.w, this.h);
      if (!this.nodes.length) return;
      const v = this.view;
      ctx.setTransform(dpr * v.k, 0, 0, dpr * v.k, dpr * v.x, dpr * v.y);
      const t = (now - this.intro) / 1000;
      const appear = (n) => Math.max(0, Math.min(1, (now - this.intro - n.layer * 260) / 520));
      const active = this.active;

      // layer titles
      if (this.layout === 'neural' && this.layers) {
        ctx.font = '700 ' + (11 / v.k) + 'px ' + this.fontMono;
        ctx.textAlign = 'center';
        this.layers.forEach((layer, li) => {
          if (!layer.length) return;
          const top = Math.min(...layer.map((n) => n.y - n.r));
          ctx.fillStyle = 'rgba(159,176,201,' + (0.7 * Math.min(1, t * 2)) + ')';
          ctx.fillText(LAYER_TITLES[li] + '  ·  ' + layer.length, layer[0].x, top - 22 / v.k);
          ctx.strokeStyle = 'rgba(0,229,255,0.08)';
          ctx.setLineDash([3, 6]);
          ctx.beginPath();
          ctx.lineWidth = 1 / v.k;
          ctx.moveTo(layer[0].x, top - 12 / v.k);
          ctx.lineTo(layer[0].x, Math.max(...layer.map((n) => n.y + n.r)) + 16);
          ctx.stroke();
          ctx.setLineDash([]);
        });
      }

      // edges
      this.edges.forEach((e) => {
        const a = Math.min(appear(e.a), appear(e.b));
        if (a <= 0) return;
        const on = !active || active.edges.has(e);
        const strength = 0.1 + 0.5 * (e.w / this.maxW);
        const alpha = (on ? (active ? 0.85 : strength) : 0.035) * a;
        const grad = ctx.createLinearGradient(e.a.x, e.a.y, e.b.x, e.b.y);
        grad.addColorStop(0, rgba(e.a.color, alpha));
        grad.addColorStop(1, rgba(e.b.color, alpha));
        ctx.strokeStyle = grad;
        ctx.lineWidth = ((on && active ? 1.4 : 0.8) + 3.2 * (e.w / this.maxW)) / Math.max(0.35, Math.min(1, v.k));
        ctx.beginPath();
        ctx.moveTo(e.a.x, e.a.y);
        if (this.layout === 'neural') {
          const dx = (e.b.x - e.a.x) * 0.5;
          ctx.bezierCurveTo(e.a.x + dx, e.a.y, e.b.x - dx, e.b.y, e.b.x, e.b.y);
        } else {
          ctx.lineTo(e.b.x, e.b.y);
        }
        ctx.stroke();
      });

      // pulses (signals travelling through the network)
      if (this.pulses && t > 1.2) {
        const pool = active ? this.edges.filter((e) => active.edges.has(e)) : this.edges;
        const spawn = active ? 3 : 1.4;
        for (let i = 0; i < spawn && this.particles.length < 320 && pool.length; i++) {
          const e = pool[Math.floor(Math.random() * pool.length)];
          if (Math.random() < 0.25 + 0.75 * (e.w / this.maxW)) {
            this.particles.push({ e: e, t: 0, s: 0.006 + Math.random() * 0.01 });
          }
        }
        this.particles = this.particles.filter((p) => {
          p.t += p.s;
          if (p.t >= 1) return false;
          if (active && !active.edges.has(p.e)) return false;
          const pt = this._edgePoint(p.e, p.t);
          const color = p.t < 0.5 ? p.e.a.color : p.e.b.color;
          ctx.fillStyle = rgba(color, 0.18);
          ctx.beginPath(); ctx.arc(pt[0], pt[1], 5 / Math.min(1, v.k), 0, Math.PI * 2); ctx.fill();
          ctx.fillStyle = rgba('#ffffff', 0.9);
          ctx.beginPath(); ctx.arc(pt[0], pt[1], 1.7 / Math.min(1, v.k), 0, Math.PI * 2); ctx.fill();
          return true;
        });
      }

      // decide which labels fit: greedy per layer so labels never overlap on screen
      const labels = new Set();
      const wants = (n) => n === this.hover || n === this.selected ||
        (this.layout === 'neural' ? (n.gap || 0) * v.k >= 13 : v.k > 0.6) || (active && active.nodes.has(n));
      if (this.layout === 'neural' && this.layers) {
        this.layers.forEach((layer) => {
          let lastY = -Infinity;
          layer.forEach((n) => {
            if (!wants(n)) return;
            const sy = n.y * v.k;
            if (n === this.hover || n === this.selected || sy - lastY >= 13) { labels.add(n); lastY = sy; }
          });
        });
      } else {
        this.nodes.forEach((n) => { if (wants(n)) labels.add(n); });
      }

      // nodes
      const mono = this.fontMono;
      const ui = this.fontUI;
      this.nodes.forEach((n) => {
        const p = appear(n);
        if (p <= 0) return;
        const on = !active || active.nodes.has(n);
        const scale = easeOutBack(p);
        const breathe = n.type === 'sev' ? 1 + 0.05 * Math.sin(t * 2.2 + n.layer) : 1;
        const r = Math.max(n.r, 4.5 / v.k) * scale * breathe;
        const dim = on ? 1 : 0.18;
        const glow = ctx.createRadialGradient(n.x, n.y, r * 0.2, n.x, n.y, r * 2.6);
        glow.addColorStop(0, rgba(n.color, 0.45 * dim));
        glow.addColorStop(1, rgba(n.color, 0));
        ctx.fillStyle = glow;
        ctx.beginPath(); ctx.arc(n.x, n.y, r * 2.6, 0, Math.PI * 2); ctx.fill();
        const core = ctx.createRadialGradient(n.x - r * 0.3, n.y - r * 0.3, r * 0.1, n.x, n.y, r);
        core.addColorStop(0, rgba('#ffffff', 0.85 * dim));
        core.addColorStop(0.35, rgba(n.color, 0.95 * dim));
        core.addColorStop(1, rgba(n.color, 0.55 * dim));
        ctx.fillStyle = core;
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2); ctx.fill();
        ctx.lineWidth = 1.2;
        ctx.strokeStyle = rgba('#ffffff', 0.35 * dim);
        ctx.stroke();
        if (n === this.selected || n === this.hover) {
          ctx.save();
          ctx.strokeStyle = rgba(n === this.selected ? '#00ff9c' : '#00e5ff', 0.95);
          ctx.lineWidth = 2 / v.k;
          ctx.setLineDash([4 / v.k, 4 / v.k]);
          ctx.lineDashOffset = -t * 20 / v.k;
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 6 / v.k, 0, Math.PI * 2); ctx.stroke();
          ctx.restore();
        }
        if (n.type === 'sev' || n.type === 'cat') {
          ctx.fillStyle = rgba('#05070d', 0.9 * dim);
          ctx.font = '800 ' + Math.max(9 / v.k, Math.min(13, r * 0.7)) + 'px ' + mono;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(String(n.count), n.x, n.y + 0.5);
        }
        // labels
        const showLabel = labels.has(n);
        if (showLabel && p > 0.6) {
          const fs = 12 / v.k;
          ctx.font = (n.type === 'sev' ? '800 ' + fs + 'px ' + mono : '500 ' + fs + 'px ' + ui);
          ctx.textBaseline = 'middle';
          ctx.fillStyle = on ? (n === this.hover || n === this.selected ? '#ffffff' : 'rgba(219,231,247,0.86)') : 'rgba(219,231,247,0.18)';
          const text = SR.trunc(n.label, n.layer === 0 ? 30 : 34);
          if (n.layer === 0 && this.layout === 'neural') {
            ctx.textAlign = 'right';
            ctx.fillText(text, n.x - r - 8 / v.k, n.y);
          } else {
            ctx.textAlign = 'left';
            ctx.fillText(text, n.x + r + 8 / v.k, n.y);
          }
        }
      });
    }

    /* ---------------------------------------------------------------- interaction */
    _toWorld(clientX, clientY) {
      const rect = this.canvas.getBoundingClientRect();
      return [(clientX - rect.left - this.view.x) / this.view.k, (clientY - rect.top - this.view.y) / this.view.k];
    }
    _hit(clientX, clientY) {
      const p = this._toWorld(clientX, clientY);
      let best = null, bestD = Infinity;
      this.nodes.forEach((n) => {
        const d = Math.hypot(n.x - p[0], n.y - p[1]);
        if (d < Math.max(n.r, 4.5 / this.view.k) + 6 / this.view.k && d < bestD) { best = n; bestD = d; }
      });
      return best;
    }

    _bind() {
      const c = this.canvas;
      let down = null;
      c.addEventListener('pointerdown', (ev) => {
        c.setPointerCapture(ev.pointerId);
        const hit = this._hit(ev.clientX, ev.clientY);
        down = { x: ev.clientX, y: ev.clientY, vx: this.view.x, vy: this.view.y, node: hit, moved: false };
        if (hit && this.layout === 'organic') this.dragNode = hit;
        c.classList.add('grabbing');
      });
      c.addEventListener('pointermove', (ev) => {
        if (down) {
          const dx = ev.clientX - down.x, dy = ev.clientY - down.y;
          if (Math.abs(dx) + Math.abs(dy) > 3) down.moved = true;
          if (this.dragNode) {
            const p = this._toWorld(ev.clientX, ev.clientY);
            this.dragNode.x = p[0]; this.dragNode.y = p[1];
            this.alpha = Math.max(this.alpha, 0.3);
          } else if (down.moved) {
            this.view.x = down.vx + dx; this.view.y = down.vy + dy;
          }
          return;
        }
        const hit = this._hit(ev.clientX, ev.clientY);
        if (hit !== this.hover) {
          this.hover = hit;
          c.style.cursor = hit ? 'pointer' : 'grab';
        }
        if (this.opts.onHover) this.opts.onHover(hit, ev.clientX, ev.clientY);
      });
      const end = (ev) => {
        if (!down) return;
        c.classList.remove('grabbing');
        if (!down.moved) {
          const hit = down.node;
          this.select(hit);
          if (this.opts.onSelect) this.opts.onSelect(hit);
        }
        this.dragNode = null;
        down = null;
        try { c.releasePointerCapture(ev.pointerId); } catch (e) { /* ignore */ }
      };
      c.addEventListener('pointerup', end);
      c.addEventListener('pointercancel', end);
      c.addEventListener('pointerleave', () => { if (!down && this.opts.onHover) this.opts.onHover(null); this.hover = null; });
      c.addEventListener('wheel', (ev) => {
        ev.preventDefault();
        const rect = c.getBoundingClientRect();
        const mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
        const factor = Math.exp(-ev.deltaY * 0.0015);
        const k = Math.min(4, Math.max(0.15, this.view.k * factor));
        this.view.x = mx - ((mx - this.view.x) / this.view.k) * k;
        this.view.y = my - ((my - this.view.y) / this.view.k) * k;
        this.view.k = k;
      }, { passive: false });
      c.addEventListener('dblclick', () => this.fit(true));
      if (window.ResizeObserver) {
        new ResizeObserver(SR.debounce(() => this.resize(), 80)).observe(c.parentElement);
      }
    }
  }

  SR.NeuralMap = NeuralMap;
})();
