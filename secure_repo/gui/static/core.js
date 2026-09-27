/* Secure Repo - shared helpers (no dependencies). All dynamic text is escaped. */
(function () {
  'use strict';
  const SR = (window.SR = window.SR || {});

  SR.SEV = ['critical', 'high', 'medium', 'low', 'info'];
  SR.SEV_COLOR = { critical: '#ff2e63', high: '#ff8a00', medium: '#ffd23f', low: '#4dabf7', info: '#8892b0' };
  SR.SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  SR.GRADE_COLOR = { A: '#00ff9c', B: '#7ee787', C: '#ffd23f', D: '#ff8a00', F: '#ff2e63' };

  SR.esc = function (value) {
    return String(value === undefined || value === null ? '' : value).replace(/[&<>"'`]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c];
    });
  };

  /* Sets markup that was assembled exclusively from SR.esc()-escaped values. */
  SR.setHTML = function (el, markup) {
    el.innerHTML = markup; // nosec - every dynamic value is passed through SR.esc() by the callers
    return el;
  };

  SR.$ = (sel, root) => (root || document).querySelector(sel);
  SR.$$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  SR.el = function (tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const key of Object.keys(attrs)) {
        const value = attrs[key];
        if (value === undefined || value === null || value === false) continue;
        if (key === 'class') node.className = value;
        else if (key === 'text') node.textContent = value;
        else if (key === 'style' && typeof value === 'object') Object.assign(node.style, value);
        else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
        else if (key === 'dataset') Object.assign(node.dataset, value);
        else node.setAttribute(key, value === true ? '' : value);
      }
    }
    (children || []).forEach((child) => {
      if (child === null || child === undefined || child === false) return;
      node.appendChild(typeof child === 'string' || typeof child === 'number' ? document.createTextNode(String(child)) : child);
    });
    return node;
  };

  SR.num = (n) => (Number(n) || 0).toLocaleString('en-US');
  SR.bytes = function (b) {
    b = Number(b) || 0;
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(1) : b.toFixed(0)) + ' ' + units[i];
  };
  SR.clock = function (seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    return String(Math.floor(seconds / 60)).padStart(2, '0') + ':' + String(seconds % 60).padStart(2, '0');
  };
  SR.where = (f) => (!f.file || f.file === '.' ? '(repository)' : f.file + (f.line ? ':' + f.line : ''));
  SR.basename = (p) => String(p || '').split(/[\\/]/).pop() || p;
  SR.trunc = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + '…' : String(s));
  SR.worst = function (list) {
    let best = null;
    list.forEach((s) => { if (s && (best === null || SR.SEV_RANK[s] < SR.SEV_RANK[best])) best = s; });
    return best;
  };
  SR.sevTag = (sev) => '<span class="sev-tag" style="--c:' + SR.SEV_COLOR[sev] + '">' + SR.esc(sev) + '</span>';

  /* ---------------------------------------------------------------- session token */
  (function initToken() {
    let token = '';
    const match = /(?:^|[#&])token=([A-Za-z0-9_\-]+)/.exec(window.location.hash || '');
    try {
      if (match) {
        token = match[1];
        // The local GUI session token is kept per-tab so a reload keeps working; the page has a strict
        // CSP (no inline or third-party scripts) and the token dies with the local server process.
        sessionStorage.setItem('sr-token', token); // nosec - reviewed design decision (see comment above)
        history.replaceState(null, '', window.location.pathname);
      } else {
        token = sessionStorage.getItem('sr-token') || '';
      }
    } catch (e) {
      token = match ? match[1] : '';
    }
    SR.token = token;
  })();

  SR.api = async function (path, options) {
    options = options || {};
    const init = { method: options.method || 'GET', headers: { 'X-SR-Token': SR.token }, cache: 'no-store' };
    if (options.body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(options.body);
    }
    const response = await fetch(path, init);
    let data = null;
    try { data = await response.json(); } catch (e) { data = null; }
    if (!response.ok) {
      const message = (data && data.error) || ('Request failed (' + response.status + ')');
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return data;
  };
  SR.withToken = (url) => url + (url.indexOf('?') >= 0 ? '&' : '?') + 'token=' + encodeURIComponent(SR.token);

  /* ---------------------------------------------------------------- UI helpers */
  SR.toast = function (message, kind) {
    const wrap = document.getElementById('toasts');
    if (!wrap) return;
    const node = SR.el('div', { class: 'toast ' + (kind || ''), text: message });
    wrap.appendChild(node);
    setTimeout(() => { node.style.transition = 'opacity .4s'; node.style.opacity = '0'; }, 4200);
    setTimeout(() => node.remove(), 4700);
  };

  SR.download = function (filename, content, mime) {
    const blob = content instanceof Blob ? content : new Blob([content], { type: mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = SR.el('a', { href: url, download: filename });
    document.body.appendChild(link);
    link.click();
    setTimeout(() => { URL.revokeObjectURL(url); link.remove(); }, 1000);
  };

  SR.countUp = function (el, to, duration) {
    const start = performance.now();
    const from = 0;
    duration = duration || 1200;
    function step(now) {
      const p = Math.max(0, Math.min(1, (now - start) / duration));
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * eased);
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
    setTimeout(() => { el.textContent = to; }, duration + 120); // guarantee the final value
  };

  SR.debounce = function (fn, wait) {
    let t = null;
    return function () {
      const args = arguments;
      clearTimeout(t);
      t = setTimeout(() => fn.apply(null, args), wait);
    };
  };
})();
