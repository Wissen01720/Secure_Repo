/* Secure Repo - repository structure rendered as nested boxes (squarified treemap). */
(function () {
  'use strict';
  const SR = window.SR;
  const MAX_CHILDREN = 260;

  function squarify(items, x, y, w, h) {
    const total = items.reduce((s, i) => s + i.value, 0);
    if (!total || w <= 0 || h <= 0) return [];
    const scale = (w * h) / total;
    const list = items.map((i) => ({ item: i.item, value: i.value, area: i.value * scale }));
    const out = [];
    const rect = { x: x, y: y, w: w, h: h };
    let row = [];
    const worst = (r, len) => {
      if (!r.length || len <= 0) return Infinity;
      let sum = 0, max = -Infinity, min = Infinity;
      r.forEach((c) => { sum += c.area; max = Math.max(max, c.area); min = Math.min(min, c.area); });
      return Math.max((len * len * max) / (sum * sum), (sum * sum) / (len * len * min));
    };
    const place = (r) => {
      const sum = r.reduce((s, c) => s + c.area, 0);
      if (rect.w >= rect.h) {
        const cw = sum / rect.h;
        let cy = rect.y;
        r.forEach((c) => { const ch = c.area / cw; out.push({ item: c.item, x: rect.x, y: cy, w: cw, h: ch }); cy += ch; });
        rect.x += cw; rect.w -= cw;
      } else {
        const rh = sum / rect.w;
        let cx = rect.x;
        r.forEach((c) => { const cw = c.area / rh; out.push({ item: c.item, x: cx, y: rect.y, w: cw, h: rh }); cx += cw; });
        rect.y += rh; rect.h -= rh;
      }
    };
    let i = 0;
    while (i < list.length) {
      const len = Math.min(rect.w, rect.h);
      const next = row.concat([list[i]]);
      if (!row.length || worst(next, len) <= worst(row, len)) { row = next; i++; }
      else { place(row); row = []; }
    }
    if (row.length) place(row);
    return out;
  }

  class BoxMap {
    constructor(el, options) {
      this.el = el;
      this.opts = Object.assign({ metric: 'size', maxDepth: 3, live: false }, options || {});
      this.tree = null;
      this.current = null;
      this.index = new Map();
      this.parent = new Map();
      this.els = new Map();
      this.scanned = new Set();
      this.risk = new Map();
      if (window.ResizeObserver) {
        new ResizeObserver(SR.debounce(() => { if (this.tree && this.el.offsetWidth) this.render(); }, 90)).observe(el);
      }
    }

    setTree(tree) {
      this.tree = tree;
      this.index.clear();
      this.parent.clear();
      const walk = (node, parent) => {
        this.index.set(node.path, node);
        if (parent) this.parent.set(node.path, parent);
        (node.children || []).forEach((c) => walk(c, node));
      };
      walk(tree, null);
      this.current = tree;
      this.render();
    }

    setMetric(metric) { this.opts.metric = metric; this.render(); }

    setRoot(path) {
      const node = this.index.get(path);
      if (node && node.type === 'dir') { this.current = node; this.render(); }
    }

    crumbs() {
      const chain = [];
      let node = this.current;
      while (node) { chain.unshift(node); node = this.parent.get(node.path); }
      return chain;
    }

    _value(node) {
      const v = this.opts.metric === 'lines' ? node.lines : node.size;
      return Math.max(Number(v) || 0, node.type === 'dir' ? 1 : 1);
    }

    render() {
      if (!this.tree) return;
      const w = this.el.clientWidth, h = this.el.clientHeight;
      if (!w || !h) return;
      this.el.textContent = '';
      this.els.clear();
      this._renderChildren(this.current, this.el, 0, 0, w, h, 0);
      if (this.opts.onPath) this.opts.onPath(this.crumbs());
      this.scanned.forEach((p) => this._mark(p, false));
      this.risk.forEach((sev, p) => this._risk(p, sev));
    }

    _renderChildren(node, container, x, y, w, h, depth) {
      let children = (node.children || []).slice();
      if (!children.length) return;
      children.sort((a, b) => this._value(b) - this._value(a));
      let rest = [];
      if (children.length > MAX_CHILDREN) { rest = children.slice(MAX_CHILDREN); children = children.slice(0, MAX_CHILDREN); }
      const items = children.map((c) => ({ item: c, value: this._value(c) }));
      if (rest.length) items.push({ item: { more: rest.length, name: '+' + rest.length + ' more' }, value: rest.reduce((s, c) => s + this._value(c), 0) });
      squarify(items, x, y, w, h).forEach((r) => {
        const pad = depth === 0 ? 1.5 : 1;
        const bw = r.w - pad * 2, bh = r.h - pad * 2;
        if (bw < 2 || bh < 2) return;
        const child = r.item;
        const box = document.createElement('div');
        box.style.left = (r.x + pad) + 'px';
        box.style.top = (r.y + pad) + 'px';
        box.style.width = bw + 'px';
        box.style.height = bh + 'px';
        if (child.more) {
          box.className = 'bm-box bm-more';
          box.textContent = bw > 50 ? child.name : '';
          container.appendChild(box);
          return;
        }
        const isDir = child.type === 'dir';
        box.className = 'bm-box ' + (isDir ? 'bm-dir' : 'bm-file') + (child.risk ? ' risk-' + child.risk : '');
        box.dataset.path = child.path;
        if (isDir) {
          const label = document.createElement('div');
          label.className = 'bm-label';
          label.textContent = bh > 16 ? child.name + '/' : '';
          label.addEventListener('click', (ev) => { ev.stopPropagation(); this.setRoot(child.path); });
          box.appendChild(label);
          if (depth < this.opts.maxDepth && bw > 24 && bh > 30) {
            this._renderChildren(child, box, 2, 18, bw - 4, bh - 20, depth + 1);
          }
          box.addEventListener('click', (ev) => { ev.stopPropagation(); this.setRoot(child.path); });
        } else {
          if (bw > 44 && bh > 16) {
            const label = document.createElement('div');
            label.className = 'bm-label';
            label.textContent = child.name;
            box.appendChild(label);
          }
          box.addEventListener('click', (ev) => { ev.stopPropagation(); if (this.opts.onSelect) this.opts.onSelect(child); });
        }
        if (child.findings && bw > 34 && bh > 30) {
          const count = document.createElement('div');
          count.className = 'bm-count';
          count.style.color = SR.SEV_COLOR[child.risk] || '#fff';
          count.textContent = '▲' + child.findings;
          box.appendChild(count);
        }
        box.addEventListener('mousemove', (ev) => { ev.stopPropagation(); if (this.opts.onHover) this.opts.onHover(child, ev.clientX, ev.clientY); });
        box.addEventListener('mouseleave', () => { if (this.opts.onHover) this.opts.onHover(null); });
        this.els.set(child.path, box);
        container.appendChild(box);
      });
    }

    _nearest(path) {
      let p = path;
      while (p) {
        const el = this.els.get(p);
        if (el) return el;
        const cut = p.lastIndexOf('/');
        if (cut < 0) break;
        p = p.slice(0, cut);
      }
      return null;
    }

    _mark(path, flash) {
      const el = this._nearest(path);
      if (!el) return;
      if (el.dataset.path === path) el.classList.add('scanned');
      if (flash) {
        el.classList.remove('flash');
        void el.offsetWidth; // restart the CSS animation
        el.classList.add('flash');
      }
    }

    markScanned(paths) {
      paths.forEach((p) => this.scanned.add(p));
      const tail = paths.slice(-24);
      paths.forEach((p) => this._mark(p, tail.indexOf(p) >= 0));
    }

    _risk(path, severity) {
      const el = this._nearest(path);
      if (!el) return;
      const current = SR.SEV.find((s) => el.classList.contains('risk-' + s));
      if (!current || SR.SEV_RANK[severity] < SR.SEV_RANK[current]) {
        SR.SEV.forEach((s) => el.classList.remove('risk-' + s));
        el.classList.add('risk-' + severity);
      }
    }

    markFinding(path, severity) {
      if (!path || path === '.') return;
      const prev = this.risk.get(path);
      if (!prev || SR.SEV_RANK[severity] < SR.SEV_RANK[prev]) this.risk.set(path, severity);
      this._risk(path, severity);
    }
  }

  SR.BoxMap = BoxMap;
})();
