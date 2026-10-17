/* Secure Repo GUI - hero animation, update banner and static bindings. */
(function () {
  'use strict';
  const SR = window.SR;
  const A = SR.app;
  const $ = SR.$, $$ = SR.$$, esc = SR.esc, el = SR.el;
  const { S } = A;

  /* ================================================================== hero animation */
  function heroAnimation() {
    const canvas = $('#hero-canvas');
    if (!canvas || canvas.dataset.on) return;
    canvas.dataset.on = '1';
    const ctx = canvas.getContext('2d');
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    let nodes = [], links = [], pulses = [], w = 0, h = 0;
    const colors = ['#00ff9c', '#00e5ff', '#9d7bff', '#ff2e97', '#ffd23f'];
    function build() {
      const rect = canvas.getBoundingClientRect();
      w = rect.width; h = rect.height;
      canvas.width = w * dpr; canvas.height = h * dpr;
      nodes = []; links = [];
      const layers = [5, 7, 6, 4];
      layers.forEach((count, li) => {
        for (let i = 0; i < count; i++) {
          nodes.push({ x: (w / (layers.length + 1)) * (li + 1), y: (h / (count + 1)) * (i + 1), l: li, c: colors[(li + i) % colors.length], p: Math.random() * 6 });
        }
      });
      nodes.forEach((a) => nodes.forEach((b) => { if (b.l === a.l + 1 && Math.random() < 0.55) links.push([a, b]); }));
    }
    function frame(now) {
      if (!$('#view-setup').classList.contains('active')) { requestAnimationFrame(frame); return; }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      links.forEach((l) => {
        ctx.strokeStyle = 'rgba(0,229,255,0.12)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        const dx = (l[1].x - l[0].x) / 2;
        ctx.moveTo(l[0].x, l[0].y);
        ctx.bezierCurveTo(l[0].x + dx, l[0].y, l[1].x - dx, l[1].y, l[1].x, l[1].y);
        ctx.stroke();
      });
      if (Math.random() < 0.3 && links.length) pulses.push({ l: links[Math.floor(Math.random() * links.length)], t: 0 });
      pulses = pulses.filter((p) => {
        p.t += 0.012;
        if (p.t >= 1) return false;
        const a = p.l[0], b = p.l[1], t = p.t, u = 1 - t, dx = (b.x - a.x) / 2;
        const x = u * u * u * a.x + 3 * u * u * t * (a.x + dx) + 3 * u * t * t * (b.x - dx) + t * t * t * b.x;
        const y = u * u * u * a.y + 3 * u * u * t * a.y + 3 * u * t * t * b.y + t * t * t * b.y;
        ctx.fillStyle = a.c;
        ctx.globalAlpha = 0.9;
        ctx.beginPath(); ctx.arc(x, y, 2.2, 0, Math.PI * 2); ctx.fill();
        ctx.globalAlpha = 1;
        return true;
      });
      nodes.forEach((n) => {
        const r = 5 + Math.sin(now / 600 + n.p) * 1.4;
        const g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 4);
        g.addColorStop(0, n.c + '88'); g.addColorStop(1, n.c + '00');
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(n.x, n.y, r * 4, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = n.c;
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2); ctx.fill();
      });
      requestAnimationFrame(frame);
    }
    build();
    window.addEventListener('resize', SR.debounce(build, 150));
    requestAnimationFrame(frame);
  }

  function showUpdateDetails() {
    const info = S.update || {};
    A.openDrawer('// update', (body) => {
      let html = '<span class="tag">' + esc(info.mode === 'git' ? 'git clone install' : 'pip install') + '</span><h2>' +
        esc(info.available ? 'Secure Repo ' + (info.latest_version || '') + ' is available' : 'Secure Repo is up to date') + '</h2>' +
        '<dl class="kv"><dt>Installed</dt><dd>' + esc(info.current_version) + (info.current_commit ? ' (' + esc(info.current_commit.slice(0, 7)) + ')' : '') + '</dd>' +
        '<dt>Latest</dt><dd>' + esc(info.latest_version || '-') + (info.latest_commit ? ' (' + esc(info.latest_commit.slice(0, 7)) + ')' : '') + '</dd>' +
        '<dt>Source</dt><dd>' + esc(info.source || '') + '</dd></dl>';
      const changes = S.updateChanges || [];
      if (changes.length) html += '<h5 class="fix">What\'s new</h5><ul class="ub-changes">' + changes.map((c) => '<li><code>' + esc(c.split(' ')[0]) + '</code> ' + esc(c.split(' ').slice(1).join(' ')) + '</li>').join('') + '</ul>';
      if (info.notes) html += '<h5 class="where">Release notes</h5><div class="snippet">' + esc(info.notes) + '</div>';
      SR.setHTML(body, html);
      if (info.available && !S.updateInstalled) {
        body.appendChild(el('button', { class: 'btn launch', type: 'button', style: { marginTop: '18px' }, text: 'INSTALL UPDATE', onclick: installUpdate }));
      }
    });
  }

  /* ================================================================== static bindings */
  function bindStatic() {
    $$('.tab').forEach((t) => t.addEventListener('click', () => A.openTab(t.dataset.tab)));
    $('#drawer-close').addEventListener('click', A.closeDrawer);
    $('#ub-details').addEventListener('click', showUpdateDetails);
    $('#ub-install').addEventListener('click', installUpdate);
    $('#ub-close').addEventListener('click', () => { $('#update-banner').hidden = true; });
    $('#backdrop').addEventListener('click', A.closeDrawer);
    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') A.closeDrawer(); });
    $('#btn-new').addEventListener('click', () => {
      if (S.es) S.es.close();
      A.show('setup');
      heroAnimation();
      A.setStatus('ok', 'ready');
    });
    $('#btn-cancel').addEventListener('click', async () => {
      if (!S.scanId) return;
      try { await SR.api('/api/scans/' + S.scanId + '/cancel', { method: 'POST', body: {} }); A.log('warn', 'Abort requested...'); }
      catch (err) { SR.toast(err.message, 'error'); }
    });
    $('#file-load').addEventListener('change', (ev) => {
      const file = ev.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const data = JSON.parse(reader.result);
          if (!data || data.schema !== 'secure-repo/report@1') throw new Error('This is not a Secure Repo report.json file.');
          A.showResults(data, null, null);
          SR.toast('Report loaded: ' + data.meta.name, 'ok');
        } catch (err) {
          SR.toast(err.message, 'error');
        }
        ev.target.value = '';
      };
      reader.readAsText(file);
    });
    $('#f-cat').addEventListener('change', (ev) => { S.fState.cat = ev.target.value; S.fState.limit = 150; A.renderFindings(); });
    $('#f-q').addEventListener('input', SR.debounce((ev) => { S.fState.q = ev.target.value; S.fState.limit = 150; A.renderFindings(); }, 150));
    $('#f-tests-chip').addEventListener('click', (ev) => {
      ev.preventDefault();
      S.fState.hideTests = !S.fState.hideTests;
      $('#f-tests-chip').classList.toggle('on', S.fState.hideTests);
      A.renderFindings();
    });
    $('#f-more').addEventListener('click', () => { S.fState.limit += 300; A.renderFindings(); });
    [['#f-flow-chip', 'flow'], ['#f-supp-chip', 'suppressed']].forEach((pair) => {
      $(pair[0]).addEventListener('click', (ev) => {
        ev.preventDefault();
        S.fState[pair[1]] = !S.fState[pair[1]];
        $(pair[0]).classList.toggle('on', S.fState[pair[1]]);
        A.renderFindings();
      });
    });
    $('#d-q').addEventListener('input', SR.debounce((ev) => { S.dState.q = ev.target.value; S.dState.limit = 200; A.renderDeps(); }, 150));
    $('#d-eco').addEventListener('change', (ev) => { S.dState.eco = ev.target.value; A.renderDeps(); });
    [['#d-vuln-chip', 'vuln'], ['#d-direct-chip', 'direct']].forEach((pair) => {
      $(pair[0]).addEventListener('click', (ev) => {
        ev.preventDefault();
        S.dState[pair[1]] = !S.dState[pair[1]];
        $(pair[0]).classList.toggle('on', S.dState[pair[1]]);
        A.renderDeps();
      });
    });
    $('#d-more').addEventListener('click', () => { S.dState.limit += 400; A.renderDeps(); });
  }

  /* ================================================================== updates */
  async function checkUpdates() {
    let info;
    try { info = await SR.api('/api/update'); } catch (err) { return; }
    if (!info || info.disabled) return;
    S.update = info;
    const banner = $('#update-banner');
    if (info.post_update) {
      banner.hidden = false;
      banner.classList.add('done');
      $('#ub-badge').textContent = 'UPDATED';
      $('#ub-title').textContent = 'Secure Repo was updated to ' + (info.post_update.to || info.current_version);
      $('#ub-sub').textContent = (info.post_update.changes || []).length + ' change(s) included';
      $('#ub-install').hidden = true;
      S.updateChanges = info.post_update.changes || [];
    }
    if (!info.available) return;
    banner.hidden = false;
    banner.classList.remove('done');
    $('#ub-badge').textContent = 'UPDATE';
    $('#ub-title').textContent = 'Secure Repo ' + (info.latest_version || info.latest_commit.slice(0, 7)) + ' is available';
    $('#ub-sub').textContent = 'you have ' + info.current_version + ' · ' + (info.commits_behind ? info.commits_behind + ' new change(s)' : 'new release') + ' · install it without re-cloning';
    $('#ub-install').hidden = false;
    S.updateChanges = info.changes || [];
  }

  async function installUpdate() {
    if (!window.confirm('Install the new version of Secure Repo now? Running scans must be finished.')) return;
    const button = $('#ub-install');
    button.disabled = true;
    button.textContent = 'Installing...';
    try {
      const result = await SR.api('/api/update/install', { method: 'POST', body: {} });
      S.updateInstalled = true;
      A.closeDrawer();
      const banner = $('#update-banner');
      banner.classList.add('done');
      $('#ub-badge').textContent = result.deferred ? 'PENDING' : 'INSTALLED';
      $('#ub-title').textContent = result.message;
      $('#ub-sub').textContent = result.deferred ? '' : 'Restart Secure Repo (Ctrl+C in the terminal, then run it again) to use the new version.';
      button.hidden = true;
      SR.toast(result.message, 'ok');
    } catch (err) {
      button.disabled = false;
      button.textContent = 'Install update';
      SR.toast(err.message, 'error');
    }
  }

  A.heroAnimation = heroAnimation; A.showUpdateDetails = showUpdateDetails; A.bindStatic = bindStatic; A.checkUpdates = checkUpdates; A.installUpdate = installUpdate;
})();
