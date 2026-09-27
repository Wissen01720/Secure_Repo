/* Secure Repo - GUI application controller. */
(function () {
  'use strict';
  const SR = window.SR;
  const $ = SR.$, $$ = SR.$$, esc = SR.esc, el = SR.el;

  const STAGE_WEIGHT = { acquire: 6, enumerate: 4, analyze: 48, dependencies: 6, intel: 20, hygiene: 3, compliance: 3, scoring: 2, report: 8 };
  const DEFAULT_STAGES = [
    { id: 'acquire', title: 'Acquiring source' }, { id: 'enumerate', title: 'Mapping repository structure' },
    { id: 'analyze', title: 'Static code, secret & config analysis' }, { id: 'dependencies', title: 'Discovering libraries & dependencies' },
    { id: 'intel', title: 'Vulnerability intelligence lookup' }, { id: 'hygiene', title: 'Repository security hygiene' },
    { id: 'compliance', title: 'Compliance audit' }, { id: 'scoring', title: 'Risk scoring' }, { id: 'report', title: 'Generating reports' },
  ];

  const S = {
    ctx: null,
    reportMode: !!window.__SR_REPORT__,
    target: { kind: null, location: '' },
    branches: [],
    branch: null,
    isGit: true,
    discovered: false,
    frameworks: new Set(),
    scanId: null,
    es: null,
    stages: {},
    progress: {},
    counts: {},
    findingsLive: 0,
    scanStart: 0,
    timer: null,
    report: null,
    reportDir: null,
    neural: null,
    boxLive: null,
    boxRes: null,
    fState: { sev: new Set(SR.SEV), cat: '', q: '', hideTests: false, limit: 150 },
    dState: { q: '', eco: '', vuln: false, direct: false, limit: 200 },
  };

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

  async function init() {
    boot();
    bindStatic();
    if (S.reportMode) {
      document.body.classList.add('report-mode');
      setStatus('ok', 'offline report');
      setTimeout(() => showResults(window.__SR_REPORT__, null, null), 700);
      return;
    }
    try {
      const [ctx] = await Promise.all([SR.api('/api/context'), new Promise((r) => setTimeout(r, 1100))]);
      S.ctx = ctx;
      setStatus('ok', 'engine online · ' + ctx.platform);
      $('#brand-ver').textContent = 'v' + ctx.version;
      $('#stat-rules').textContent = ctx.rules;
      $('#stat-fw').textContent = ctx.frameworks.length;
      initSetup(ctx);
      if (ctx.preload) {
        const data = await SR.api('/api/scans/' + ctx.preload + '/report');
        showResults(data.report, data.scan_id, data.report_dir);
      } else {
        show('setup');
        heroAnimation();
      }
    } catch (err) {
      setStatus('off', 'no session');
      const term = $('#boot-term');
      term.appendChild(el('div', { class: 'line', style: { color: '#ff2e63' },
        text: '[ FAIL ] ' + (err.status === 401 ? 'Invalid or missing session token. Open the exact URL printed by "secure-repo gui".' : err.message) }));
    }
  }

  /* ================================================================== setup */
  function initSetup(ctx) {
    const current = $('.target-card[data-kind="current"]');
    $('#current-sub').textContent = ctx.repo_root ? ctx.repo_root + ' @ ' + (ctx.current_branch || 'detached') : ctx.cwd + ' (not a Git repository)';
    $('#in-path').value = ctx.cwd;
    $('#opt-online').checked = !ctx.defaults.offline;
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
      const data = await SR.api('/api/branches', { method: 'POST', body: { kind: S.target.kind, location: location } });
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
      SR.toast(err.message, 'error');
    }
    btn.textContent = original;
    btn.disabled = false;
    renderBranches();
    updateSetup();
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

  async function launch() {
    const btn = $('#btn-launch');
    btn.disabled = true;
    const branchObj = S.branches.find((b) => b.name === S.branch);
    const branch = S.isGit && !(branchObj && branchObj.current) ? S.branch : null;
    const body = {
      kind: S.target.kind, location: S.target.location, branch: branch, authorized: $('#opt-authorized').checked,
      options: {
        offline: !$('#opt-online').checked, compliance: $('#opt-compliance').checked,
        frameworks: Array.from(S.frameworks), include_tests: $('#opt-tests').checked,
        max_file_size_kb: parseInt($('#opt-size').value, 10), auditor: $('#opt-auditor').value.trim(),
      },
    };
    try {
      const data = await SR.api('/api/scan', { method: 'POST', body: body });
      startScan(data.scan_id, S.target.location, branch || S.branch || 'working tree');
    } catch (err) {
      SR.toast(err.message, 'error');
    }
    btn.disabled = false;
  }

  /* ================================================================== scan */
  function startScan(scanId, location, branch) {
    S.scanId = scanId;
    S.stages = {};
    S.progress = {};
    S.counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    S.findingsLive = 0;
    S.scanStart = Date.now();
    $('#scan-title').textContent = 'Auditing ' + SR.basename(location.replace(/[\\/]+$/, '').replace(/\.git$/, ''));
    $('#scan-sub').textContent = location + '  @  ' + branch;
    $('#scan-failed').hidden = true;
    $('#log').textContent = '';
    $('#m-files').textContent = '0';
    $('#m-findings').textContent = '0';
    $('#scan-progress').style.width = '0%';
    const stageList = $('#stage-list');
    stageList.textContent = '';
    ((S.ctx && S.ctx.stages) || DEFAULT_STAGES).forEach((st) => {
      S.stages[st.id] = { status: 'pending', title: st.title, start: 0 };
      stageList.appendChild(el('li', { class: 'stage pending', id: 'st-' + st.id }, [
        el('span', { class: 'st-ico', text: '' }),
        el('span', {}, [el('span', { class: 'st-title', text: st.title }), el('span', { class: 'st-detail', text: 'queued' })]),
        el('span', { class: 'st-time', text: '' }),
      ]));
    });
    const counters = $('#live-counters');
    counters.textContent = '';
    SR.SEV.forEach((s) => counters.appendChild(el('div', { class: 'sev-counter', id: 'cnt-' + s }, [
      el('b', { text: '0', style: { color: SR.SEV_COLOR[s] } }), el('span', { text: s })])));
    $('#btn-cancel').disabled = false;
    show('scan');
    setStatus('busy', 'scan in progress');
    if (!S.boxLive) {
      S.boxLive = new SR.BoxMap($('#live-boxmap'), { live: true, maxDepth: 3, onHover: tooltipForNode });
    } else {
      $('#live-boxmap').textContent = '';
      S.boxLive.tree = null;
      S.boxLive.scanned = new Set();
      S.boxLive.risk = new Map();
    }
    clearInterval(S.timer);
    S.timer = setInterval(() => { $('#m-elapsed').textContent = SR.clock((Date.now() - S.scanStart) / 1000); }, 500);
    log('info', 'Engagement ' + scanId + ' started against ' + location);
    connectEvents(scanId);
  }

  function connectEvents(scanId) {
    if (S.es) S.es.close();
    const es = new EventSource(SR.withToken('/api/scans/' + scanId + '/events'));
    S.es = es;
    es.onmessage = (msg) => {
      let ev;
      try { ev = JSON.parse(msg.data); } catch (e) { return; }
      handleEvent(ev);
    };
    es.addEventListener('end', () => es.close());
    es.onerror = () => { /* EventSource reconnects automatically using Last-Event-ID */ };
  }

  function log(level, message, extraClass) {
    const box = $('#log');
    const time = new Date().toLocaleTimeString('en-GB');
    const prefix = { info: '[*]', ok: '[+]', warn: '[!]', error: '[x]' }[level] || '[*]';
    const line = el('div', { class: 'l ' + level + (extraClass ? ' ' + extraClass : '') }, [
      el('span', { class: 't', text: time }), el('span', { class: 'p', text: prefix + ' ' }), document.createTextNode(message)]);
    box.appendChild(line);
    while (box.childNodes.length > 500) box.removeChild(box.firstChild);
    box.scrollTop = box.scrollHeight;
  }

  function overallProgress() {
    let total = 0, done = 0;
    Object.keys(STAGE_WEIGHT).forEach((id) => {
      const w = STAGE_WEIGHT[id];
      total += w;
      const st = S.stages[id];
      if (!st) return;
      if (st.status === 'done' || st.status === 'skip') done += w;
      else if (st.status === 'start') {
        const p = S.progress[id];
        done += w * (p && p.total ? Math.min(1, p.current / p.total) : 0.1);
      }
    });
    return Math.round((done / total) * 100);
  }

  function handleEvent(ev) {
    switch (ev.type) {
      case 'stage': {
        const st = S.stages[ev.id];
        if (!st) break;
        st.status = ev.status;
        const li = $('#st-' + ev.id);
        li.className = 'stage ' + ({ start: 'running', done: 'done', skip: 'skip', error: 'error' }[ev.status] || '');
        li.querySelector('.st-ico').textContent = { done: '✓', skip: '–', error: '✕' }[ev.status] || '';
        li.querySelector('.st-detail').textContent = ev.detail || (ev.status === 'start' ? 'running...' : ev.status);
        if (ev.status === 'start') { st.start = ev.ts; log('info', '>>> ' + ev.title); }
        else if (st.start) {
          li.querySelector('.st-time').textContent = (ev.ts - st.start).toFixed(1) + 's';
          log(ev.status === 'done' ? 'ok' : 'warn', ev.title + (ev.detail ? ' — ' + ev.detail : ''));
        }
        break;
      }
      case 'log':
        log(ev.level, ev.message);
        break;
      case 'progress': {
        S.progress[ev.stage] = ev;
        const li = $('#st-' + ev.stage);
        if (li && ev.total) li.querySelector('.st-detail').textContent = Math.round((100 * ev.current) / ev.total) + '% · ' + (ev.label || '');
        break;
      }
      case 'structure':
        S.boxLive.setTree(ev.tree);
        log('ok', 'Repository map received: ' + ev.files + ' files');
        break;
      case 'files':
        S.boxLive.markScanned(ev.paths);
        $('#m-files').textContent = SR.num(ev.done) + ' / ' + SR.num(ev.total);
        if (ev.paths.length) $('#live-current').textContent = '>> ' + ev.paths[ev.paths.length - 1];
        break;
      case 'finding': {
        S.counts[ev.severity] = (S.counts[ev.severity] || 0) + 1;
        S.findingsLive += 1;
        const c = $('#cnt-' + ev.severity);
        if (c) {
          c.querySelector('b').textContent = S.counts[ev.severity];
          c.classList.remove('bump'); void c.offsetWidth; c.classList.add('bump');
        }
        $('#m-findings').textContent = SR.num(S.findingsLive);
        S.boxLive.markFinding(ev.file, ev.severity);
        if (ev.severity === 'critical' || ev.severity === 'high' || ev.severity === 'medium') {
          log('warn', ev.severity.toUpperCase() + '  ' + ev.title + '  →  ' + SR.where(ev), 'f-' + ev.severity);
        }
        break;
      }
      case 'complete':
        onComplete(ev);
        break;
      case 'failed':
        onFailed(ev.message);
        break;
      default:
        break;
    }
    const pct = overallProgress();
    $('#scan-progress').style.width = pct + '%';
    $('#m-pct').textContent = pct + '%';
  }

  async function onComplete(ev) {
    clearInterval(S.timer);
    $('#scan-progress').style.width = '100%';
    $('#m-pct').textContent = '100%';
    $('#btn-cancel').disabled = true;
    log('ok', 'MISSION COMPLETE — reports stored in ' + (ev.report_dir || '-'));
    setStatus('ok', 'scan complete');
    if (S.es) S.es.close();
    try {
      const data = await SR.api('/api/scans/' + ev.scan_id + '/report');
      setTimeout(() => showResults(data.report, data.scan_id, data.report_dir), 900);
    } catch (err) {
      SR.toast(err.message, 'error');
    }
  }

  function onFailed(message) {
    clearInterval(S.timer);
    if (S.es) S.es.close();
    setStatus('off', 'scan stopped');
    log('error', message);
    const box = $('#scan-failed');
    box.hidden = false;
    box.textContent = '';
    box.appendChild(el('b', { text: 'Scan stopped: ' }));
    box.appendChild(document.createTextNode(message));
    box.appendChild(el('div', { style: { marginTop: '10px' } }, [el('button', { class: 'btn small', type: 'button', text: 'Back to setup', onclick: () => show('setup') })]));
    $('#btn-cancel').disabled = true;
  }

  /* ================================================================== results */
  function showResults(report, scanId, reportDir) {
    S.report = report;
    S.scanId = scanId;
    S.reportDir = reportDir;
    S.fState = { sev: new Set(SR.SEV), cat: '', q: '', hideTests: false, limit: 150 };
    show('results');
    const sum = report.summary, meta = report.meta;
    $('#res-name').textContent = meta.name;
    const chips = $('#res-chips');
    chips.textContent = '';
    [['branch', meta.branch || 'n/a'], ['commit', (meta.commit || 'n/a').slice(0, 12)], ['mode', meta.mode],
      ['files', SR.num(sum.files_total)], ['lines', SR.num(sum.lines)], ['duration', meta.duration_seconds + 's'],
      ['date', (meta.started_at || '').replace('T', ' ').replace('+00:00', ' UTC')]].forEach((c) => {
      chips.appendChild(el('span', { class: 'meta-chip' }, [c[0] + ' ', el('b', { text: c[1] })]));
    });
    // score ring
    const color = SR.GRADE_COLOR[sum.grade] || '#fff';
    const arc = $('#score-arc');
    arc.style.stroke = color;
    arc.style.color = color;
    const circumference = 2 * Math.PI * 52;
    arc.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => requestAnimationFrame(() => { arc.style.strokeDashoffset = circumference * (1 - sum.score / 100); }));
    SR.countUp($('#score-num'), sum.score, 1500);
    $('#score-num').style.color = color;
    const grade = $('#score-grade');
    grade.textContent = sum.grade;
    grade.style.background = color;
    // severity cards
    const cards = $('#sev-cards');
    cards.textContent = '';
    SR.SEV.forEach((s) => {
      const b = el('b', { text: '0' });
      const card = el('div', { class: 'sev-card', style: { '--c': SR.SEV_COLOR[s] }, title: 'Show ' + s + ' findings' }, [b, el('span', { text: s })]);
      card.style.setProperty('--c', SR.SEV_COLOR[s]);
      card.addEventListener('click', () => { S.fState.sev = new Set([s]); openTab('findings'); renderFindings(); });
      cards.appendChild(card);
      SR.countUp(b, sum.by_severity[s] || 0, 1000);
    });
    renderActions();
    $('#n-findings').textContent = report.findings.length;
    $('#n-deps').textContent = report.dependencies.length;
    renderOverview();
    renderFindingsFilters();
    renderFindings();
    renderDepsFilters();
    renderDeps();
    renderCompliance();
    renderExport();
    $('#footer').textContent = 'Secure Repo ' + report.tool.version + ' · ' + report.tool.rules + ' rules · by ' + report.tool.author +
      ' · read-only analysis · secrets redacted';
    const wanted = /(?:^|[#&])tab=(\w+)/.exec(window.location.hash || '');
    openTab(wanted && $('#tab-' + wanted[1]) ? wanted[1] : 'overview');
  }

  function renderActions() {
    const box = $('#res-actions');
    box.textContent = '';
    if (S.scanId && !S.reportMode) {
      [['html', 'Download HTML report'], ['zip', 'Download full evidence (.zip)'], ['json', 'Download JSON']].forEach((d, i) => {
        box.appendChild(el('a', { class: 'btn' + (i === 0 ? ' primary' : ''), href: SR.withToken('/api/scans/' + S.scanId + '/download/' + d[0]), text: d[1] }));
      });
    } else {
      box.appendChild(el('button', { class: 'btn primary', type: 'button', text: 'Download JSON', onclick: downloadJSON }));
      box.appendChild(el('button', { class: 'btn', type: 'button', text: 'Print / Save as PDF', onclick: () => window.print() }));
    }
  }

  function downloadJSON() {
    SR.download((S.report.meta.name || 'report') + '_secure-repo.json', JSON.stringify(S.report, null, 2), 'application/json');
  }

  function openTab(name) {
    $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $$('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + name));
    if (name === 'neural') initNeural(); else if (S.neural) S.neural.stop();
    if (name === 'structure') initStructure();
  }

  function hbar(label, value, max, color, onclick) {
    const fill = el('div', { class: 'fil', style: { '--c': color } });
    fill.style.setProperty('--c', color);
    const row = el('div', { class: 'hbar' + (onclick ? ' click' : ''), style: { cursor: onclick ? 'pointer' : 'default' } }, [
      el('span', { class: 'lbl', text: label, title: label }), el('div', { class: 'trk' }, [fill]), el('span', { class: 'num', text: SR.num(value) })]);
    if (onclick) row.addEventListener('click', onclick);
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = (max ? (100 * value) / max : 0) + '%'; }));
    return row;
  }

  function renderOverview() {
    const r = S.report, sum = r.summary;
    const panel = $('#tab-overview');
    panel.textContent = '';
    const total = Math.max(1, sum.findings);
    // severity distribution
    const stacked = el('div', { class: 'stacked' });
    SR.SEV.forEach((s) => {
      const part = el('div', { style: { width: '0%', background: SR.SEV_COLOR[s] }, title: s + ': ' + sum.by_severity[s] });
      stacked.appendChild(part);
      requestAnimationFrame(() => requestAnimationFrame(() => { part.style.width = (100 * sum.by_severity[s]) / total + '%'; }));
    });
    const sevCard = el('div', { class: 'card' }, [el('h3', { text: 'Risk distribution' }), stacked]);
    const peak = Math.max(1, ...SR.SEV.map((s) => sum.by_severity[s]));
    SR.SEV.forEach((s) => sevCard.appendChild(hbar(s.toUpperCase(), sum.by_severity[s], peak, SR.SEV_COLOR[s], () => {
      S.fState.sev = new Set([s]); openTab('findings'); renderFindings();
    })));
    // OWASP
    const owCard = el('div', { class: 'card' }, [el('h3', { text: 'OWASP Top 10 (2021)' })]);
    const owMax = Math.max(1, ...Object.values(sum.by_owasp));
    Object.keys(r.owasp).forEach((code) => {
      if (!sum.by_owasp[code]) return;
      owCard.appendChild(hbar((code === 'OTHER' ? '' : code + ' ') + r.owasp[code].name, sum.by_owasp[code], owMax, '#9d7bff'));
    });
    if (!Object.keys(sum.by_owasp).length) owCard.appendChild(el('p', { class: 'muted', text: 'No findings mapped.' }));
    // top files
    const filesCard = el('div', { class: 'card' }, [el('h3', { text: 'Most exposed files' })]);
    sum.top_files.slice(0, 10).forEach((f) => {
      const row = el('div', { class: 'list-row' });
      SR.setHTML(row, SR.sevTag(f.risk) + '<span class="t mono">' + esc(f.file === '.' ? '(repository)' : f.file) + '</span><span class="s">' + esc(f.count) + ' findings</span>');
      row.addEventListener('click', () => openFileDrawer(f.file === '.' ? '.' : f.file));
      filesCard.appendChild(row);
    });
    if (!sum.top_files.length) filesCard.appendChild(el('p', { class: 'muted', text: 'Nothing to show - no findings.' }));
    // top weaknesses
    const byRule = new Map();
    r.findings.forEach((f) => {
      const e = byRule.get(f.rule_id) || { rule: f.rule_id, title: (r.rules[f.rule_id] || {}).title || f.title, count: 0, sev: [] };
      e.count++; e.sev.push(f.severity); byRule.set(f.rule_id, e);
    });
    const weakCard = el('div', { class: 'card' }, [el('h3', { text: 'Top weaknesses' })]);
    Array.from(byRule.values()).sort((a, b) => SR.SEV_RANK[SR.worst(a.sev)] - SR.SEV_RANK[SR.worst(b.sev)] || b.count - a.count)
      .slice(0, 10).forEach((w) => {
        const row = el('div', { class: 'list-row' });
        SR.setHTML(row, SR.sevTag(SR.worst(w.sev)) + '<span class="t">' + esc(w.title) + '</span><span class="s">×' + esc(w.count) + '</span>');
        row.addEventListener('click', () => openRuleDrawer(w.rule));
        weakCard.appendChild(row);
      });
    // languages
    const langCard = el('div', { class: 'card' }, [el('h3', { text: 'Languages (lines of code)' })]);
    const langs = Object.entries(r.languages || {}).slice(0, 9);
    const lmax = Math.max(1, ...langs.map((l) => l[1].lines));
    langs.forEach((l) => langCard.appendChild(hbar(l[0] + ' · ' + l[1].files + ' files', l[1].lines, lmax, '#00e5ff')));
    // hygiene + libraries
    const hyg = r.hygiene || {};
    const labels = { security_policy: 'Security policy (SECURITY.md)', gitignore_secrets: '.gitignore excludes secrets', dependency_updates: 'Automated dependency updates',
      license: 'License file', ci: 'Continuous integration', codeowners: 'Code owners', lockfiles: 'Dependencies locked', inventory: 'Library inventory (SBOM)' };
    const hygCard = el('div', { class: 'card' }, [el('h3', { text: 'Security hygiene' })]);
    Object.keys(labels).forEach((k) => {
      if (!(k in hyg)) return;
      hygCard.appendChild(el('div', { class: 'check ' + (hyg[k] ? 'yes' : 'no') }, [el('i', { text: hyg[k] ? '✓' : '✕' }), el('span', { text: labels[k] })]));
    });
    const ds = r.dependency_summary;
    hygCard.appendChild(el('div', { class: 'muted', style: { marginTop: '12px', fontSize: '12px' },
      text: ds.total + ' libraries · ' + ds.vulnerable + ' vulnerable · ' + ds.vulnerabilities + ' advisories · intel ' + (ds.online ? 'online' : 'offline') }));
    const notes = (r.meta.notes || []).map((n) => el('div', { class: 'muted', style: { fontSize: '12px' }, text: '• ' + n }));
    panel.appendChild(el('div', { class: 'grid-3' }, [sevCard, owCard, hygCard]));
    panel.appendChild(el('div', { class: 'grid-3', style: { marginTop: '18px' } }, [filesCard, weakCard, langCard]));
    if (notes.length) panel.appendChild(el('div', { class: 'card', style: { marginTop: '18px' } }, [el('h3', { text: 'Notes' })].concat(notes)));
  }

  /* ---------------------------------------------------------------- neural */
  function initNeural() {
    const canvas = $('#neural-canvas');
    if (!S.neural) {
      S.neural = new SR.NeuralMap(canvas, {
        onSelect: (node) => { if (node) openNodeDrawer(node); },
        onHover: tooltipForGraph,
        onEmpty: (empty) => { $('#neural-empty').hidden = !empty; },
      });
      $$('#nm-layout button').forEach((b) => b.addEventListener('click', () => {
        $$('#nm-layout button').forEach((x) => x.classList.toggle('on', x === b));
        S.neural.setLayout(b.dataset.layout);
      }));
      const sevBox = $('#nm-sev');
      SR.SEV.forEach((s) => {
        const chip = el('span', { class: 'chip sev on', dataset: { sev: s }, text: s });
        chip.addEventListener('click', () => {
          chip.classList.toggle('on');
          const set = new Set($$('#nm-sev .chip.on').map((c) => c.dataset.sev));
          S.neural.setSeverities(set);
        });
        sevBox.appendChild(chip);
      });
      $('#nm-search').addEventListener('input', SR.debounce((ev) => S.neural.setQuery(ev.target.value), 150));
      $('#nm-fit').addEventListener('click', () => S.neural.fit(true));
      $('#nm-pulse').addEventListener('click', (ev) => {
        S.neural.setPulses(!S.neural.pulses);
        ev.target.textContent = 'Pulses: ' + (S.neural.pulses ? 'on' : 'off');
      });
      const legend = $('#nm-legend');
      SR.SEV.forEach((s) => legend.appendChild(el('span', {}, [el('i', { style: { background: SR.SEV_COLOR[s] } }), s])));
      legend.appendChild(el('span', {}, [el('i', { style: { background: '#9d7bff' } }), 'OWASP category']));
    }
    if (S.neural.report !== S.report) {
      S.neural.resize();
      S.neural.setData(S.report);
    } else {
      S.neural.resize();
    }
    S.neural.start();
  }

  /* ---------------------------------------------------------------- structure */
  function initStructure() {
    if (!S.boxRes) {
      S.boxRes = new SR.BoxMap($('#res-boxmap'), {
        maxDepth: 3, onHover: tooltipForNode, onSelect: (node) => openFileDrawer(node.path),
        onPath: (chain) => {
          const crumbs = $('#crumbs');
          crumbs.textContent = '';
          chain.forEach((n, i) => {
            if (i) crumbs.appendChild(el('span', { text: '/' }));
            crumbs.appendChild(el('button', { type: 'button', text: n.name || 'root', onclick: () => S.boxRes.setRoot(n.path) }));
          });
        },
      });
      $$('#bm-metric button').forEach((b) => b.addEventListener('click', () => {
        $$('#bm-metric button').forEach((x) => x.classList.toggle('on', x === b));
        S.boxRes.setMetric(b.dataset.metric);
      }));
      const legend = $('#bm-legend');
      SR.SEV.forEach((s) => legend.appendChild(el('span', {}, [el('i', { style: { background: SR.SEV_COLOR[s] } }), s])));
      legend.appendChild(el('span', {}, [el('i', { style: { background: 'rgba(98,113,140,.5)' } }), 'clean']));
    }
    if (S.boxRes.tree !== S.report.structure) {
      requestAnimationFrame(() => S.boxRes.setTree(S.report.structure));
    } else {
      requestAnimationFrame(() => S.boxRes.render());
    }
  }

  /* ---------------------------------------------------------------- findings */
  function renderFindingsFilters() {
    const sevBox = $('#f-sev');
    sevBox.textContent = '';
    SR.SEV.forEach((s) => {
      const chip = el('span', { class: 'chip sev' + (S.fState.sev.has(s) ? ' on' : ''), dataset: { sev: s }, text: s + ' ' + (S.report.summary.by_severity[s] || 0) });
      chip.addEventListener('click', () => {
        if (S.fState.sev.has(s)) S.fState.sev.delete(s); else S.fState.sev.add(s);
        S.fState.limit = 150;
        renderFindings();
      });
      sevBox.appendChild(chip);
    });
    const cat = $('#f-cat');
    cat.length = 1;
    Object.keys(S.report.summary.by_category).forEach((c) => cat.appendChild(el('option', { value: c, text: c + ' (' + S.report.summary.by_category[c] + ')' })));
  }

  function renderFindings() {
    $$('#f-sev .chip').forEach((c) => c.classList.toggle('on', S.fState.sev.has(c.dataset.sev)));
    const f = S.fState;
    const q = f.q.toLowerCase();
    const items = S.report.findings.filter((x) => f.sev.has(x.severity) && (!f.cat || x.category === f.cat) && (!f.hideTests || !x.in_test) &&
      (!q || (x.title + ' ' + x.file + ' ' + x.rule_id + ' ' + x.cwe + ' ' + x.snippet + ' ' + x.id).toLowerCase().indexOf(q) >= 0));
    const list = $('#findings-list');
    list.textContent = '';
    if (!items.length) {
      list.appendChild(el('div', { class: 'empty', text: 'No findings match the current filters.' }));
    }
    items.slice(0, f.limit).forEach((x) => {
      const row = el('div', { class: 'finding' });
      row.style.setProperty('--c', SR.SEV_COLOR[x.severity]);
      SR.setHTML(row, '<div>' + SR.sevTag(x.severity) + '</div><div style="min-width:0"><div class="ft">' + esc(x.title) +
        (x.in_test ? '<span class="tag">test</span>' : '') + '<span class="tag">' + esc(x.category) + '</span></div><div class="fl">' + esc(SR.where(x)) +
        '</div>' + (x.snippet ? '<div class="fs">' + esc(x.snippet) + '</div>' : '') + '</div><div class="fid">' + esc(x.id) + '<br>' + esc(x.cwe || '') + '</div>');
      row.addEventListener('click', () => openFindingDrawer(x));
      list.appendChild(row);
    });
    const more = $('#f-more');
    more.hidden = items.length <= f.limit;
    more.textContent = 'Show more (' + (items.length - f.limit) + ' remaining)';
  }

  /* ---------------------------------------------------------------- dependencies */
  function renderDepsFilters() {
    const ds = S.report.dependency_summary;
    const cards = $('#eco-cards');
    cards.textContent = '';
    [['libraries', ds.total, '#00e5ff'], ['direct', ds.direct, '#9d7bff'], ['transitive', ds.transitive, '#8892b0'],
      ['vulnerable', ds.vulnerable, ds.vulnerable ? '#ff2e63' : '#00ff9c'], ['advisories', ds.vulnerabilities, ds.vulnerabilities ? '#ff8a00' : '#00ff9c']]
      .concat(Object.entries(ds.ecosystems).map((e) => [e[0], e[1], '#dbe7f7'])).forEach((c) => {
        cards.appendChild(el('div', { class: 'eco' }, [el('b', { text: SR.num(c[1]), style: { color: c[2] } }), el('span', { text: c[0] })]));
      });
    const eco = $('#d-eco');
    eco.length = 1;
    Object.keys(ds.ecosystems).forEach((e) => eco.appendChild(el('option', { value: e, text: e })));
  }

  function renderDeps() {
    const d = S.dState;
    const q = d.q.toLowerCase();
    const rows = S.report.dependencies.filter((x) => (!d.eco || x.ecosystem === d.eco) && (!d.vuln || x.vulnerabilities.length || x.issues.length) &&
      (!d.direct || x.direct) && (!q || x.name.toLowerCase().indexOf(q) >= 0));
    const table = $('#deps-table');
    table.textContent = '';
    if (!S.report.dependencies.length) {
      SR.setHTML(table, '<tbody><tr><td class="muted">No dependency manifests were found in this repository.</td></tr></tbody>');
      return;
    }
    SR.setHTML(table, '<thead><tr><th>Library</th><th>Version</th><th>Ecosystem</th><th>Type</th><th>Risk</th><th>Advisories / issues</th><th>License</th><th>Latest</th><th>Manifest</th></tr></thead>');
    const body = el('tbody');
    rows.slice(0, d.limit).forEach((x) => {
      const tr = el('tr', { class: 'click' });
      const risk = x.max_severity ? SR.sevTag(x.max_severity) : (x.issues.length ? '<span class="st warning">REVIEW</span>' : '<span class="st pass">OK</span>');
      const adv = x.vulnerabilities.slice(0, 3).map((v) => esc(v.id)).join(', ') + (x.vulnerabilities.length > 3 ? ' +' + (x.vulnerabilities.length - 3) : '') +
        (x.issues.length ? (x.vulnerabilities.length ? ' · ' : '') + esc(x.issues[0]) : '');
      SR.setHTML(tr, '<td class="mono">' + esc(x.name) + '</td><td class="mono">' + esc(x.version || x.spec || '*') + '</td><td>' + esc(x.ecosystem) +
        '</td><td>' + (x.direct ? 'direct' : '<span class="muted">transitive</span>') + '</td><td>' + risk + '</td><td class="mono" style="max-width:320px">' + (adv || '<span class="muted">-</span>') +
        '</td><td class="mono">' + esc((x.licenses || []).join(', ') || '-') + '</td><td class="mono">' + esc(x.latest || '-') + '</td><td class="mono muted">' + esc(x.manifest) + '</td>');
      tr.addEventListener('click', () => openDepDrawer(x));
      body.appendChild(tr);
    });
    table.appendChild(body);
    const more = $('#d-more');
    more.hidden = rows.length <= d.limit;
    more.textContent = 'Show more (' + (rows.length - d.limit) + ' remaining)';
  }

  /* ---------------------------------------------------------------- compliance */
  function ring(score, size) {
    const r = size / 2 - 6, c = 2 * Math.PI * r;
    const color = score >= 80 ? '#00ff9c' : score >= 50 ? '#ffd23f' : '#ff2e63';
    return '<svg viewBox="0 0 ' + size + ' ' + size + '"><circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="6"/>' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + color + '" stroke-width="6" stroke-linecap="round" stroke-dasharray="' + c.toFixed(1) +
      '" stroke-dashoffset="' + (c * (1 - score / 100)).toFixed(1) + '"/></svg><b style="color:' + color + '">' + esc(score) + '%</b>';
  }

  function renderCompliance() {
    const panel = $('#tab-compliance');
    panel.textContent = '';
    const comp = S.report.compliance;
    if (!comp || !comp.enabled) {
      SR.setHTML(panel, '<div class="card"><div class="empty"><b>Compliance audit was not enabled for this scan.</b><br>' +
        'Enable "Compliance audit" in the engagement options (GUI) or run <code>secure-repo scan . --compliance</code> to map the evidence to OWASP, PCI DSS, ISO 27001, SOC 2, GDPR, HIPAA and NIST SSDF.</div></div>');
      return;
    }
    const grid = el('div', { class: 'fw-grid' });
    comp.frameworks.forEach((fw) => {
      const card = el('div', { class: 'card fw' });
      const s = fw.summary;
      let html = '<div class="fw-top"><div class="mini-ring">' + ring(fw.score, 64) + '</div><div><h4>' + esc(fw.name) + '</h4><div class="ver">' + esc(fw.version) +
        '</div><div class="fw-counts"><span class="st pass">PASS ' + s.pass + '</span><span class="st warning">WARN ' + s.warning + '</span><span class="st fail">FAIL ' + s.fail +
        '</span><span class="st manual">MANUAL ' + s.manual + '</span></div></div></div><p class="muted" style="font-size:12px;margin:12px 0 0">' + esc(fw.description) + '</p><div class="controls">';
      fw.controls.forEach((c) => {
        html += '<div class="control"><div><span class="st ' + esc(c.status) + '">' + esc(c.status.toUpperCase()) + '</span></div><div class="cid">' + esc(c.id) + '</div><div><b>' + esc(c.title) +
          '</b><div class="muted" style="font-size:12px">' + esc(c.description) + '</div><ul>' + c.evidence.map((e) => '<li>' + esc(e) + '</li>').join('') + '</ul></div></div>';
      });
      html += '</div>';
      SR.setHTML(card, html);
      card.addEventListener('click', (ev) => {
        if (ev.target.closest('.controls')) return;
        card.classList.toggle('open');
      });
      grid.appendChild(card);
    });
    panel.appendChild(grid);
    panel.appendChild(el('div', { class: 'disclaimer', text: comp.disclaimer }));
  }

  /* ---------------------------------------------------------------- export */
  function renderExport() {
    const panel = $('#tab-export');
    panel.textContent = '';
    const items = [
      ['html', 'HTML', 'Interactive report', 'Self-contained page with the neural map, structure boxes and explanations. Works offline.'],
      ['zip', 'ZIP', 'Full evidence package', 'The complete organized report folder with integrity manifest (SHA-256).'],
      ['json', 'JSON', 'Machine-readable results', 'Every finding, library, advisory and compliance control.'],
      ['sarif', 'SARIF', 'SARIF 2.1.0', 'Import into GitHub code scanning, Azure DevOps or your IDE.'],
      ['md', 'MD', 'Executive summary', 'Markdown summary for tickets, wikis and pull requests.'],
      ['sbom', 'SBOM', 'CycloneDX 1.5 SBOM', 'Software bill of materials with vulnerabilities.'],
      ['csv', 'CSV', 'Findings spreadsheet', 'All findings as CSV.'],
      ['deps', 'CSV', 'Library inventory', 'Every library (direct & transitive) as CSV.'],
    ];
    const grid = el('div', { class: 'export-grid' });
    const live = S.scanId && !S.reportMode;
    items.forEach((it) => {
      const card = el('div', { class: 'card export' }, [el('div', { class: 'ico', text: it[1] }), el('h4', { text: it[2] }), el('p', { text: it[3] })]);
      if (live) card.appendChild(el('a', { class: 'btn primary', href: SR.withToken('/api/scans/' + S.scanId + '/download/' + it[0]), text: 'Download' }));
      else if (it[0] === 'json') card.appendChild(el('button', { class: 'btn primary', type: 'button', text: 'Download', onclick: downloadJSON }));
      else card.appendChild(el('span', { class: 'muted', style: { fontSize: '12px' }, text: 'Available in the report folder generated by the scan.' }));
      grid.appendChild(card);
    });
    panel.appendChild(grid);
    if (S.reportDir) {
      const pathCard = el('div', { class: 'card', style: { marginTop: '18px' } }, [el('h3', { text: 'Report folder (evidence locker)' }),
        el('div', { class: 'path-box', style: { margin: '12px 0' }, text: S.reportDir })]);
      if (live) {
        pathCard.appendChild(el('button', { class: 'btn', type: 'button', text: 'Open folder', onclick: async () => {
          try { await SR.api('/api/scans/' + S.scanId + '/open-folder', { method: 'POST', body: {} }); SR.toast('Folder opened', 'ok'); }
          catch (err) { SR.toast(err.message, 'error'); }
        } }));
      }
      panel.appendChild(pathCard);
    }
    panel.appendChild(el('div', { class: 'card', style: { marginTop: '18px' } }, [el('h3', { text: 'Print' }),
      el('p', { class: 'muted', text: 'Use your browser to print the results or save them as PDF.' }),
      el('button', { class: 'btn', type: 'button', text: 'Print / Save as PDF', onclick: () => window.print() })]));
  }

  /* ================================================================== drawer */
  function openDrawer(kicker, build) {
    const body = $('#drawer-body');
    body.textContent = '';
    $('#drawer-kicker').textContent = kicker;
    build(body);
    body.scrollTop = 0;
    $('#drawer').classList.add('open');
    $('#drawer').setAttribute('aria-hidden', 'false');
    $('#backdrop').classList.add('show');
  }
  function closeDrawer() {
    $('#drawer').classList.remove('open');
    $('#drawer').setAttribute('aria-hidden', 'true');
    $('#backdrop').classList.remove('show');
    if (S.neural) S.neural.select(null);
  }

  function refsHTML(rule) {
    return (rule.references || []).map((u) => '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' + esc(u) + '</a>').join('');
  }

  function vulnTable(vulns) {
    if (!vulns || !vulns.length) return '';
    return '<h5 class="why">Known vulnerabilities</h5><div class="table-wrap"><table class="data"><thead><tr><th>Advisory</th><th>Severity</th><th>Fixed in</th></tr></thead><tbody>' +
      vulns.map((v) => '<tr><td class="mono"><a href="' + esc(v.url) + '" target="_blank" rel="noopener noreferrer">' + esc(v.id) + '</a>' +
        (v.aliases && v.aliases.length ? '<div class="muted">' + esc(v.aliases.slice(0, 2).join(', ')) + '</div>' : '') + '<div style="font-family:var(--font);font-size:12px;color:var(--text-2)">' +
        esc(v.summary) + '</div></td><td>' + SR.sevTag(v.severity) + (v.cvss ? '<div class="mono muted">CVSS ' + esc(v.cvss) + '</div>' : '') + '</td><td class="mono">' +
        esc((v.fixed || []).join(', ') || '-') + '</td></tr>').join('') + '</tbody></table></div>';
  }

  function openFindingDrawer(f) {
    const rule = S.report.rules[f.rule_id] || {};
    const owasp = S.report.owasp[f.owasp] || {};
    openDrawer('// finding ' + f.id, (body) => {
      let html = SR.sevTag(f.severity) + ' <span class="tag">' + esc(f.category) + '</span>' + (f.in_test ? '<span class="tag">test code</span>' : '') +
        '<h2>' + esc(f.title) + '</h2><dl class="kv"><dt>Location</dt><dd>' + esc(SR.where(f)) + '</dd><dt>Rule</dt><dd>' + esc(f.rule_id) + ' · confidence ' + esc(f.confidence) +
        '</dd><dt>CWE</dt><dd>' + esc(f.cwe || '-') + '</dd><dt>OWASP</dt><dd>' + esc((f.owasp || '-') + ' ' + (owasp.name || '')) + '</dd></dl>';
      if (f.snippet) html += '<div class="snippet">' + esc(f.snippet) + '</div>';
      if (f.detail) html += '<h5 class="where">Detail</h5><p>' + esc(f.detail) + '</p>';
      if (rule.description) html += '<h5 class="why">Why is this insecure?</h5><p>' + esc(rule.description) + '</p>';
      if (rule.recommendation) html += '<h5 class="fix">How to fix it</h5><p>' + esc(rule.recommendation) + '</p>';
      html += vulnTable(f.extra && f.extra.vulnerabilities);
      if (rule.references && rule.references.length) html += '<h5 class="refs">References</h5><div class="refs">' + refsHTML(rule) + '</div>';
      SR.setHTML(body, html);
      const others = S.report.findings.filter((x) => x.rule_id === f.rule_id && x.id !== f.id);
      if (others.length) {
        body.appendChild(el('h5', { class: 'where', text: 'Other occurrences (' + others.length + ')' }));
        others.slice(0, 40).forEach((o) => body.appendChild(occRow(o)));
      }
    });
  }

  function occRow(f) {
    const row = el('div', { class: 'occ' });
    SR.setHTML(row, '<span>' + esc(SR.where(f)) + '<div class="muted" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(f.snippet || f.title) + '</div></span>' + SR.sevTag(f.severity));
    row.addEventListener('click', () => openFindingDrawer(f));
    return row;
  }

  function openRuleDrawer(ruleId, subset) {
    const rule = S.report.rules[ruleId] || {};
    const items = subset || S.report.findings.filter((f) => f.rule_id === ruleId);
    openDrawer('// weakness ' + ruleId, (body) => {
      const sev = SR.worst(items.map((f) => f.severity)) || rule.severity || 'info';
      let html = SR.sevTag(sev) + ' <span class="tag">' + esc(rule.category || '') + '</span><h2>' + esc(rule.title || ruleId) + '</h2><dl class="kv"><dt>Occurrences</dt><dd>' +
        items.length + '</dd><dt>CWE</dt><dd>' + esc(rule.cwe || '-') + '</dd><dt>OWASP</dt><dd>' + esc(rule.owasp || '-') + '</dd></dl>';
      if (rule.description) html += '<h5 class="why">Why is this insecure?</h5><p>' + esc(rule.description) + '</p>';
      if (rule.recommendation) html += '<h5 class="fix">How to fix it</h5><p>' + esc(rule.recommendation) + '</p>';
      if (items.length && items[0].extra && items[0].extra.vulnerabilities) html += vulnTable(items[0].extra.vulnerabilities);
      if (rule.references && rule.references.length) html += '<h5 class="refs">References</h5><div class="refs">' + refsHTML(rule) + '</div>';
      html += '<h5 class="where">Where it happens</h5>';
      SR.setHTML(body, html);
      items.slice(0, 80).forEach((f) => body.appendChild(occRow(f)));
    });
  }

  function openFileDrawer(path) {
    const key = !path || path === '.' ? '.' : path;
    const items = S.report.findings.filter((f) => (key === '.' ? (!f.file || f.file === '.') : f.file === key)).sort((a, b) => a.line - b.line);
    openDrawer('// file', (body) => {
      let html = '<h2 class="mono" style="font-size:16px;word-break:break-all">' + esc(key === '.' ? '(repository level)' : key) + '</h2>';
      html += '<p>' + (items.length ? esc(items.length + ' security finding(s) in this location. Select one to read why it is insecure and how to fix it.') : 'No findings in this file.') + '</p>';
      SR.setHTML(body, html);
      items.forEach((f) => {
        const row = el('div', { class: 'occ' });
        SR.setHTML(row, '<span>' + esc((f.line ? 'L' + f.line + ' · ' : '') + f.title) + '<div class="muted" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(f.snippet || f.detail) + '</div></span>' + SR.sevTag(f.severity));
        row.addEventListener('click', () => openFindingDrawer(f));
        body.appendChild(row);
      });
    });
  }

  function openNodeDrawer(node) {
    if (node.type === 'file') {
      if (node.other) return openListDrawer('Other files', node.findings);
      return openFileDrawer(node.full === '(repository)' ? '.' : node.full);
    }
    if (node.type === 'weak') {
      if (node.other) return openListDrawer('Other weaknesses', node.findings);
      if (node.dep) return openFindingDrawer(node.findings[0]);
      return openRuleDrawer(node.rule, node.findings);
    }
    if (node.type === 'cat') {
      const info = S.report.owasp[node.code] || {};
      return openDrawer('// OWASP category', (body) => {
        SR.setHTML(body, '<span class="tag">' + esc(node.code) + '</span><h2>' + esc(info.name || node.code) + '</h2><p>' + esc(info.description || '') +
          '</p><h5 class="where">Weaknesses in this category (' + node.count + ' findings)</h5>');
        groupByRule(node.findings).forEach((g) => body.appendChild(ruleRow(g)));
      });
    }
    if (node.type === 'sev') {
      const desc = { critical: 'Directly exploitable weakness or exposed credential. Remediate immediately.', high: 'Serious weakness that is likely exploitable. Remediate before the next release.',
        medium: 'Weakness that requires specific conditions to be exploited. Plan remediation.', low: 'Defense-in-depth issue or hardening opportunity.', info: 'Informational observation that supports security governance.' };
      return openDrawer('// severity', (body) => {
        SR.setHTML(body, SR.sevTag(node.severity) + '<h2>' + esc(node.count) + ' ' + esc(node.severity) + ' finding(s)</h2><p>' + esc(desc[node.severity]) + '</p><h5 class="where">Weaknesses</h5>');
        groupByRule(node.findings).forEach((g) => body.appendChild(ruleRow(g)));
      });
    }
    return null;
  }

  function groupByRule(findings) {
    const map = new Map();
    findings.forEach((f) => {
      const g = map.get(f.rule_id) || { rule: f.rule_id, title: (S.report.rules[f.rule_id] || {}).title || f.title, items: [] };
      g.items.push(f);
      map.set(f.rule_id, g);
    });
    return Array.from(map.values()).sort((a, b) => b.items.length - a.items.length);
  }

  function ruleRow(g) {
    const row = el('div', { class: 'occ' });
    SR.setHTML(row, '<span>' + esc(g.title) + '<div class="muted">' + esc(g.rule) + ' · ' + g.items.length + ' occurrence(s)</div></span>' + SR.sevTag(SR.worst(g.items.map((f) => f.severity))));
    row.addEventListener('click', () => openRuleDrawer(g.rule, g.items));
    return row;
  }

  function openListDrawer(title, findings) {
    openDrawer('// group', (body) => {
      SR.setHTML(body, '<h2>' + esc(title) + '</h2><p>' + esc(findings.length) + ' findings</p>');
      findings.slice(0, 120).forEach((f) => body.appendChild(occRow(f)));
    });
  }

  function openDepDrawer(d) {
    openDrawer('// library', (body) => {
      let html = (d.max_severity ? SR.sevTag(d.max_severity) : '<span class="st pass">NO KNOWN VULNERABILITIES</span>') +
        '<h2 class="mono">' + esc(d.name) + '</h2><dl class="kv"><dt>Version</dt><dd>' + esc(d.version || '(unresolved) ' + d.spec) + '</dd><dt>Ecosystem</dt><dd>' + esc(d.ecosystem) +
        '</dd><dt>Type</dt><dd>' + (d.direct ? 'direct' : 'transitive') + ' · ' + esc(d.scope) + '</dd><dt>Source</dt><dd>' + esc(d.source) + (d.locked ? ' · locked' : ' · not locked') +
        '</dd><dt>License</dt><dd>' + esc((d.licenses || []).join(', ') || 'unknown') + '</dd><dt>Latest</dt><dd>' + esc(d.latest || 'unknown') + '</dd><dt>Manifests</dt><dd>' + esc((d.manifests || [d.manifest]).join(', ')) + '</dd></dl>';
      if (d.issues && d.issues.length) html += '<h5 class="why">Issues</h5><ul>' + d.issues.map((i) => '<li>' + esc(i) + '</li>').join('') + '</ul>';
      html += vulnTable(d.vulnerabilities);
      if (!d.version) html += '<h5 class="fix">Note</h5><p>The exact version could not be resolved (no lockfile / range specifier), so it could not be checked against vulnerability databases. Commit a lockfile to enable precise checks.</p>';
      SR.setHTML(body, html);
    });
  }

  /* ================================================================== tooltip */
  function showTip(x, y, html) {
    const tip = $('#tooltip');
    if (!html) { tip.classList.remove('show'); return; }
    SR.setHTML(tip, html);
    const w = tip.offsetWidth || 260, h = tip.offsetHeight || 60;
    tip.style.left = Math.min(window.innerWidth - w - 12, x + 14) + 'px';
    tip.style.top = Math.min(window.innerHeight - h - 12, y + 14) + 'px';
    tip.classList.add('show');
  }
  function tooltipForGraph(node, x, y) {
    if (!node) return showTip(0, 0, null);
    const sevs = SR.SEV.filter((s) => node.sev[s]).map((s) => '<span style="color:' + SR.SEV_COLOR[s] + '">' + node.sev[s] + ' ' + s + '</span>').join(' · ');
    showTip(x, y, '<b>' + esc(node.full || node.label) + '</b><div class="mono">' + esc({ file: 'source', weak: 'weakness', cat: 'OWASP category', sev: 'severity' }[node.type]) +
      ' · ' + node.count + ' finding(s)</div><div style="margin-top:4px">' + sevs + '</div><div class="mono" style="margin-top:4px">click for explanation</div>');
  }
  function tooltipForNode(node, x, y) {
    if (!node) return showTip(0, 0, null);
    const sevs = SR.SEV.filter((s) => node.severity && node.severity[s]).map((s) => '<span style="color:' + SR.SEV_COLOR[s] + '">' + node.severity[s] + ' ' + s + '</span>').join(' · ');
    showTip(x, y, '<b>' + esc(node.path || node.name) + (node.type === 'dir' ? '/' : '') + '</b><div class="mono">' + esc(SR.bytes(node.size)) +
      (node.lines ? ' · ' + SR.num(node.lines) + ' lines' : '') + (node.type === 'dir' ? ' · ' + SR.num(node.files) + ' files' : node.language ? ' · ' + esc(node.language) : '') +
      '</div>' + (sevs ? '<div style="margin-top:4px">' + sevs + '</div>' : '<div class="mono" style="margin-top:4px;color:#00ff9c">no findings</div>') +
      '<div class="mono" style="margin-top:4px">' + (node.type === 'dir' ? 'click to zoom in' : 'click for findings') + '</div>');
  }

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

  /* ================================================================== static bindings */
  function bindStatic() {
    $$('.tab').forEach((t) => t.addEventListener('click', () => openTab(t.dataset.tab)));
    $('#drawer-close').addEventListener('click', closeDrawer);
    $('#backdrop').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeDrawer(); });
    $('#btn-new').addEventListener('click', () => {
      if (S.es) S.es.close();
      show('setup');
      heroAnimation();
      setStatus('ok', 'ready');
    });
    $('#btn-cancel').addEventListener('click', async () => {
      if (!S.scanId) return;
      try { await SR.api('/api/scans/' + S.scanId + '/cancel', { method: 'POST', body: {} }); log('warn', 'Abort requested...'); }
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
          showResults(data, null, null);
          SR.toast('Report loaded: ' + data.meta.name, 'ok');
        } catch (err) {
          SR.toast(err.message, 'error');
        }
        ev.target.value = '';
      };
      reader.readAsText(file);
    });
    $('#f-cat').addEventListener('change', (ev) => { S.fState.cat = ev.target.value; S.fState.limit = 150; renderFindings(); });
    $('#f-q').addEventListener('input', SR.debounce((ev) => { S.fState.q = ev.target.value; S.fState.limit = 150; renderFindings(); }, 150));
    $('#f-tests-chip').addEventListener('click', (ev) => {
      ev.preventDefault();
      S.fState.hideTests = !S.fState.hideTests;
      $('#f-tests-chip').classList.toggle('on', S.fState.hideTests);
      renderFindings();
    });
    $('#f-more').addEventListener('click', () => { S.fState.limit += 300; renderFindings(); });
    $('#d-q').addEventListener('input', SR.debounce((ev) => { S.dState.q = ev.target.value; S.dState.limit = 200; renderDeps(); }, 150));
    $('#d-eco').addEventListener('change', (ev) => { S.dState.eco = ev.target.value; renderDeps(); });
    [['#d-vuln-chip', 'vuln'], ['#d-direct-chip', 'direct']].forEach((pair) => {
      $(pair[0]).addEventListener('click', (ev) => {
        ev.preventDefault();
        S.dState[pair[1]] = !S.dState[pair[1]];
        $(pair[0]).classList.toggle('on', S.dState[pair[1]]);
        renderDeps();
      });
    });
    $('#d-more').addEventListener('click', () => { S.dState.limit += 400; renderDeps(); });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
