/* Secure Repo GUI - start-up. */
(function () {
  'use strict';
  const SR = window.SR;
  const A = SR.app;
  const $ = SR.$, el = SR.el;
  const { S } = A;

  async function init() {
    A.boot();
    A.bindStatic();
    if (S.reportMode) {
      document.body.classList.add('report-mode');
      A.setStatus('ok', 'offline report');
      setTimeout(() => A.showResults(window.__SR_REPORT__, null, null), 700);
      return;
    }
    try {
      const [ctx] = await Promise.all([SR.api('/api/context'), new Promise((r) => setTimeout(r, 1100))]);
      S.ctx = ctx;
      A.setStatus('ok', 'engine online · ' + ctx.platform);
      $('#brand-ver').textContent = 'v' + ctx.version;
      $('#stat-rules').textContent = ctx.rules;
      $('#stat-fw').textContent = ctx.frameworks.length;
      A.initSetup(ctx);
      A.checkUpdates();
      if (ctx.preload) {
        const data = await SR.api('/api/scans/' + ctx.preload + '/report');
        A.showResults(data.report, data.scan_id, data.report_dir);
      } else {
        A.show('setup');
        A.heroAnimation();
      }
    } catch (err) {
      A.setStatus('off', 'no session');
      const term = $('#boot-term');
      term.appendChild(el('div', { class: 'line', style: { color: '#ff2e63' },
        text: '[ FAIL ] ' + (err.status === 401 ? 'Invalid or missing session token. Open the exact URL printed by "secure-repo gui".' : err.message) }));
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();
