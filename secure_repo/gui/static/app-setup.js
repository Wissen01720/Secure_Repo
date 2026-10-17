/* Secure Repo GUI - target selection, branch discovery and authentication. */
(function () {
  'use strict';
  const SR = window.SR;
  const A = SR.app;
  const $ = SR.$, $$ = SR.$$, esc = SR.esc, el = SR.el;
  const { S } = A;

  /* ================================================================== views */
  function show(view) {
    $$('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + view));
    window.scrollTo({ top: 0, behavior: 'smooth' });
    if (view !== 'results' && S.neural) S.neural.stop();
  }

  function setStatus(kind, text) {
    const pill = $('#conn-status');
    pill.className = 'pill ' + kind;
    $('#conn-text').textContent = text;
  }

  /* ================================================================== boot */
  function boot() {
    const term = $('#boot-term');
    const logo = [
      ' ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗',
      ' ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝',
      ' ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ',
      ' ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ',
      ' ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗',
      ' ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝  //REPO',
    ].join('\n');
    term.appendChild(el('div', { class: 'boot-logo', text: logo }));
    const lines = [
      ['ok', '[  OK  ]', ' Loading neural visualization engine'],
      ['ok', '[  OK  ]', ' Mounting structure box mapper'],
      ['ok', '[  OK  ]', ' Loading detection signatures'],
      ['ok', '[  OK  ]', ' Establishing secure local channel (127.0.0.1)'],
      ['dim', '[ INFO ]', ' Read-only mode: target code is never executed'],
    ];
    lines.forEach((l, i) => {
      const line = el('div', { class: 'line', style: { animationDelay: (i * 0.12) + 's' } }, [
        el('span', { class: l[0], text: l[1] }), el('span', { text: l[2] })]);
      term.appendChild(line);
    });
    term.appendChild(el('div', { class: 'line cursor', style: { animationDelay: (lines.length * 0.12) + 's' } }, [
      el('span', { class: 'ok', text: 'root@secure-repo:~# ' })]));
  }

  /* ================================================================== setup */
  function initSetup(ctx) {
    const current = $('.target-card[data-kind="current"]');
    $('#current-sub').textContent = ctx.repo_root ? ctx.repo_root + ' @ ' + (ctx.current_branch || 'detached') : ctx.cwd + ' (not a Git repository)';
    $('#in-path').value = ctx.cwd;
    $('#opt-online').checked = !ctx.defaults.offline;
    if (ctx.defaults.min_confidence) $('#opt-confidence').value = ctx.defaults.min_confidence;
    if (ctx.defaults.learning === false) $('#opt-learning').checked = false;
    if (ctx.defaults.semantic === false) $('#opt-engine').value = 'patterns';
    const chips = $('#fw-chips');
    ctx.frameworks.forEach((fw) => {
      S.frameworks.add(fw.id);
      const chip = el('span', { class: 'chip on', text: fw.name, title: fw.description + ' (' + fw.controls + ' controls)' });
      chip.addEventListener('click', () => {
        chip.classList.toggle('on');
        if (chip.classList.contains('on')) S.frameworks.add(fw.id); else S.frameworks.delete(fw.id);
      });
      chips.appendChild(chip);
    });
    $$('.target-card').forEach((card) => card.addEventListener('click', () => pickTarget(card.dataset.kind)));
    ['#in-url', '#in-path'].forEach((sel) => $(sel).addEventListener('input', () => { S.discovered = false; updateSetup(); }));
    $('#in-url').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') discover(); });
    $('#in-token').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') discover(); });
    $('#in-path').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') discover(); });
    $('#btn-discover').addEventListener('click', discover);
    $('#branch-filter').addEventListener('input', renderBranches);
    $('#opt-compliance').addEventListener('change', () => { $('#fw-box').hidden = !$('#opt-compliance').checked; });
    $('#opt-authorized').addEventListener('change', updateSetup);
    $('#btn-launch').addEventListener('click', launch);
    pickTarget(ctx.repo_root ? 'current' : 'local');
    if (!ctx.git_available) SR.toast('git was not found on PATH - branch discovery and remote scans are unavailable.', 'warn');
    current.title = ctx.repo_root || ctx.cwd;
  }

  function pickTarget(kind) {
    S.target.kind = kind;
    S.discovered = false;
    if (kind !== 'remote') $('#auth-box').hidden = true;
    S.branches = [];
    S.branch = null;
    $$('.target-card').forEach((c) => c.classList.toggle('active', c.dataset.kind === kind));
    $('#input-remote').hidden = kind !== 'remote';
    $('#input-local').hidden = kind !== 'local';
    if (kind === 'remote') setTimeout(() => $('#in-url').focus(), 50);
    renderBranches();
    updateSetup();
  }

  function targetLocation() {
    if (S.target.kind === 'remote') return $('#in-url').value.trim();
    if (S.target.kind === 'local') return $('#in-path').value.trim();
    return (S.ctx && (S.ctx.repo_root || S.ctx.cwd)) || '';
  }

  function updateSetup() {
    const loc = targetLocation();
    $('#btn-discover').disabled = !S.target.kind || !loc;
    $('#step-branch').classList.toggle('locked', !S.discovered);
    $('#step-options').classList.toggle('locked', !S.discovered);
    const ready = S.discovered && (!S.isGit || S.branch !== null) && $('#opt-authorized').checked;
    $('#btn-launch').disabled = !ready;
  }

  function authBody() {
    if (S.target.kind !== 'remote') return {};
    const token = $('#in-token').value.trim();
    return token ? { token: token, username: $('#in-username').value.trim() } : {};
  }

  function showAuth(info) {
    const box = $('#auth-box');
    box.hidden = false;
    if (!info.https) {
      $('#auth-help').textContent = 'This is an SSH URL: load an SSH key with access to the repository, or use the https:// URL with an access token.';
      SR.toast('Authentication required (SSH key)', 'warn');
      return;
    }
    $('#auth-help').textContent = (info.rejected ? 'The token was rejected (wrong token, missing scope or SSO not authorized). ' : '') + info.error;
    $('#in-username').placeholder = 'Username (optional, default: ' + (info.username_hint || 'git') + ')';
    $('#in-token').focus();
    SR.toast(info.rejected ? 'Access token rejected' : 'Private repository: enter an access token and discover again', 'warn');
  }

  function renderBranches() {
    const list = $('#branch-list');
    const filter = $('#branch-filter');
    list.textContent = '';
    filter.hidden = !(S.discovered && S.isGit && S.branches.length > 6);
    if (!S.discovered) {
      SR.setHTML(list, '<div class="empty">Select a target and discover its branches.</div>');
      return;
    }
    if (!S.isGit) {
      SR.setHTML(list, '<div class="empty">No Git repository detected.<br>The folder <b>' + esc(S.target.location) + '</b> will be scanned as-is.</div>');
      return;
    }
    const q = filter.value.trim().toLowerCase();
    S.branches.filter((b) => !q || b.name.toLowerCase().indexOf(q) >= 0).forEach((b, i) => {
      const badges = [];
      if (b.current) badges.push('<span class="badge current">current</span>');
      if (b.default) badges.push('<span class="badge default">default</span>');
      if (b.remote) badges.push('<span class="badge remote">remote</span>');
      const row = el('div', { class: 'branch' + (S.branch === b.name ? ' active' : ''), style: { animationDelay: Math.min(i, 12) * 0.03 + 's' } });
      SR.setHTML(row, '<span class="radio"></span><div><div class="name">' + esc(b.name) + '</div><div class="meta">' +
        esc(b.commit || '') + (b.date ? ' · ' + esc(b.date) : '') + '</div></div><div>' + badges.join(' ') + '</div>');
      row.addEventListener('click', () => { S.branch = b.name; renderBranches(); updateSetup(); });
      list.appendChild(row);
    });
  }

  async function discover() {
    const location = targetLocation();
    if (!location) return;
    const btn = $('#btn-discover');
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = 'Enumerating branches...';
    const list = $('#branch-list');
    SR.setHTML(list, '<div class="empty">' + esc(S.target.kind === 'remote' ? 'Running git ls-remote against ' + location + ' ...' : 'Reading local refs...') + '</div>');
    try {
      const data = await SR.api('/api/branches', { method: 'POST', body: Object.assign({ kind: S.target.kind, location: location }, authBody()) });
      $('#auth-box').hidden = !$('#in-token').value;
      S.target.location = data.target;
      S.branches = data.branches;
      S.isGit = data.git;
      S.discovered = true;
      const preferred = S.branches.find((b) => b.current) || S.branches.find((b) => b.default) || S.branches[0];
      S.branch = preferred ? preferred.name : null;
      if (!S.isGit) SR.toast('Not a Git repository - the folder will be scanned as-is.', 'warn');
      else SR.toast(S.branches.length + ' branch(es) discovered', 'ok');
    } catch (err) {
      S.discovered = false;
      if (err.data && err.data.auth_required) {
        showAuth(err.data);
      } else {
        SR.toast(err.message, 'error');
      }
    }
    btn.textContent = original;
    btn.disabled = false;
    renderBranches();
    updateSetup();
  }

  async function launch() {
    const btn = $('#btn-launch');
    btn.disabled = true;
    const branchObj = S.branches.find((b) => b.name === S.branch);
    const branch = S.isGit && !(branchObj && branchObj.current) ? S.branch : null;
    const body = {
      kind: S.target.kind, location: S.target.location, branch: branch, authorized: $('#opt-authorized').checked,
      token: authBody().token, username: authBody().username,
      options: {
        offline: !$('#opt-online').checked, compliance: $('#opt-compliance').checked,
        frameworks: Array.from(S.frameworks), include_tests: $('#opt-tests').checked,
        max_file_size_kb: parseInt($('#opt-size').value, 10), auditor: $('#opt-auditor').value.trim(),
        min_confidence: $('#opt-confidence').value, learning: $('#opt-learning').checked,
        trust_repo_config: $('#opt-trust').checked ? true : null,
        semantic: $('#opt-engine').value === 'layered',
      },
    };
    try {
      const data = await SR.api('/api/scan', { method: 'POST', body: body });
      A.startScan(data.scan_id, S.target.location, branch || S.branch || 'working tree');
    } catch (err) {
      SR.toast(err.message, 'error');
    }
    btn.disabled = false;
  }

  A.show = show; A.setStatus = setStatus; A.boot = boot; A.initSetup = initSetup; A.pickTarget = pickTarget; A.targetLocation = targetLocation; A.updateSetup = updateSetup; A.authBody = authBody; A.showAuth = showAuth; A.renderBranches = renderBranches; A.discover = discover; A.launch = launch;
})();
