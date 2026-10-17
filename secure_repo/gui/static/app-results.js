/* Secure Repo GUI - results header, actions and the overview tab. */
(function () {
  'use strict';
  const SR = window.SR;
  const A = SR.app;
  const $ = SR.$, $$ = SR.$$, esc = SR.esc, el = SR.el;
  const { SUPPRESSED, S } = A;

  /* ================================================================== results */
  function showResults(report, scanId, reportDir, options) {
    S.report = report;
    S.scanId = scanId;
    S.reportDir = reportDir;
    if (!options || !options.keepFilters) S.fState = { sev: new Set(SR.SEV), cat: '', q: '', hideTests: false, flow: false, suppressed: false, limit: 150 };
    A.show('results');
    const sum = report.summary, meta = report.meta;
    $('#res-name').textContent = meta.name;
    const chips = $('#res-chips');
    chips.textContent = '';
    if (sum.scores) {
      const sc = sum.scores, dn = sc.density;
      chips.appendChild(el('span', { class: 'meta-chip', title: 'Score of the production code on its own' }, ['production ', el('b', { text: sc.production.score + ' (' + sc.production.grade + ')' })]));
      chips.appendChild(el('span', { class: 'meta-chip', title: 'Score of the test code on its own' }, ['tests ', el('b', { text: sc.tests.score + ' (' + sc.tests.grade + ')' })]));
      if (dn.serious_per_kloc !== null) chips.appendChild(el('span', { class: 'meta-chip', title: 'Critical and high findings in production code per 1,000 lines (' + dn.kloc + ' KLOC analyzed)' }, ['density ', el('b', { text: dn.serious_per_kloc + ' / KLOC' })]));
    }
    if (sum.grade_cap) chips.appendChild(el('span', { class: 'meta-chip cap-chip', title: sum.grade_cap.message }, ['grade ', el('b', { text: 'capped to ' + sum.grade_cap.grade + ' · ' + sum.grade_cap.reason })]));
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
      card.addEventListener('click', () => { S.fState.sev = new Set([s]); openTab('findings'); A.renderFindings(); });
      cards.appendChild(card);
      SR.countUp(b, sum.by_severity[s] || 0, 1000);
    });
    renderActions();
    $('#n-findings').textContent = report.findings.filter((x) => !SUPPRESSED.has(x.status)).length;
    $('#n-deps').textContent = report.dependencies.length;
    renderOverview();
    A.renderFindingsFilters();
    A.renderFindings();
    A.renderDepsFilters();
    A.renderDeps();
    A.renderCompliance();
    A.renderExport();
    $('#footer').textContent = 'Secure Repo ' + report.tool.version + ' · ' + report.tool.rules + ' rules · by ' + report.tool.author +
      ' · read-only analysis · secrets redacted';
    const wanted = /(?:^|[#&])tab=(\w+)/.exec(window.location.hash || '');
    if (options && options.tab) openTab(options.tab);
    else openTab(wanted && $('#tab-' + wanted[1]) ? wanted[1] : 'overview');
  }

  function renderActions() {
    const box = $('#res-actions');
    box.textContent = '';
    if (S.scanId && !S.reportMode) {
      [['html', 'Download HTML report'], ['zip', 'Download full evidence (.zip)'], ['json', 'Download JSON']].forEach((d, i) => {
        box.appendChild(el('button', { class: 'btn' + (i === 0 ? ' primary' : ''), type: 'button', text: d[1], onclick: () => fetchDownload(d[0]) }));
      });
    } else {
      box.appendChild(el('button', { class: 'btn primary', type: 'button', text: 'Download JSON', onclick: downloadJSON }));
      box.appendChild(el('button', { class: 'btn', type: 'button', text: 'Print / Save as PDF', onclick: () => window.print() }));
    }
  }

  function fetchDownload(kind) {
    SR.downloadFile('/api/scans/' + S.scanId + '/download/' + kind).catch((err) => SR.toast(err.message, 'error'));
  }

  function downloadJSON() {
    SR.download((S.report.meta.name || 'report') + '_secure-repo.json', JSON.stringify(S.report, null, 2), 'application/json');
  }

  function openTab(name) {
    $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $$('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + name));
    if (name === 'neural') A.initNeural(); else if (S.neural) S.neural.stop();
    if (name === 'structure') A.initStructure();
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
      S.fState.sev = new Set([s]); openTab('findings'); A.renderFindings();
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
      row.addEventListener('click', () => A.openFileDrawer(f.file === '.' ? '.' : f.file));
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
        row.addEventListener('click', () => A.openRuleDrawer(w.rule));
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
    const analysis = r.analysis || {};
    const qualityCard = el('div', { class: 'card' }, [el('h3', { text: 'Analysis quality' })]);
    const engines = sum.by_engine || {};
    const emax = Math.max(1, ...Object.values(engines));
    const engineColor = { taint: '#ff2e97', ast: '#9d7bff', lexical: '#00e5ff', pattern: '#8892b0', dependency: '#ff8a00', hygiene: '#7ee787', custom: '#ffd23f' };
    Object.keys(engines).forEach((k) => qualityCard.appendChild(hbar(k === 'taint' ? 'taint (data flow)' : k, engines[k], emax, engineColor[k] || '#00e5ff')));
    const kn = analysis.knowledge || {};
    [['Noise discarded automatically', analysis.noise_total || 0], ['Suppressed (false positive / filtered)', sum.suppressed || 0],
      ['Triage decisions applied', kn.decisions || 0], ['Learned patterns matched', kn.learned_patterns || 0]].forEach((m) => {
      qualityCard.appendChild(el('div', { class: 'check yes' }, [el('i', { text: String(m[1]) }), el('span', { text: m[0] })]));
    });
    const na = analysis.not_analyzed;
    if (na) {
      const parts = [];
      if ((na.directories || []).length) parts.push(na.directories.length + ' folder(s) not entered');
      if ((na.intel || []).length) parts.push(na.intel.length + ' gap(s) in the dependency intelligence');
      if ((na.unparsed || []).length) parts.push(na.unparsed.length + ' manifest(s) could not be parsed');
      if ((na.minified || []).length) parts.push(na.minified.length + ' minified bundle(s) (reduced mode)');
      if ((na.too_large || []).length) parts.push(na.too_large.length + ' file(s) over the size limit');
      if (na.binary) parts.push(na.binary + ' binary file(s)');
      const box = el('div', { class: 'infl-box' }, [el('b', { text: 'Not analyzed' })]);
      if (!parts.length) parts.push('nothing was skipped');
      parts.forEach((p) => box.appendChild(el('div', { class: 'infl-row' }, [el('span', { text: '·' }), el('span', { text: p })])));
      (na.intel || []).slice(0, 6).forEach((note) => box.appendChild(el('div', { class: 'infl-row' }, [el('span', { text: '·' }), el('span', { text: note })])));
      (na.unparsed || []).slice(0, 6).forEach((d) => box.appendChild(el('div', { class: 'infl-row' }, [el('span', { text: d.path }), el('span', { text: d.error })])));
      (na.directories || []).slice(0, 6).forEach((d) => box.appendChild(el('div', { class: 'infl-row' }, [el('span', { text: d.path }), el('span', { text: d.reason })])));
      qualityCard.appendChild(box);
    }
    const infl = analysis.repo_influence;
    if (infl) {
      const rows = [['Audited repository', (infl.trusted ? 'TRUSTED' : 'NOT trusted') + ' - ' + infl.trust_reason]];
      (infl.ignored || []).forEach((i) => rows.push(['Ignored', i]));
      (infl.disabled_rules || []).forEach((r) => rows.push(['Rule off', r.rule_id + ' - ' + r.hidden + ' hidden (set by ' + r.from + ')']));
      (infl.severity_overrides || []).forEach((r) => rows.push(['Severity', r.rule_id + ' ' + r.from_severity + ' → ' + r.to_severity + ' (set by ' + r.from + ')']));
      if (infl.excluded_by_config && infl.excluded_by_config.files) rows.push(['Excluded', infl.excluded_by_config.files + ' file(s) never analyzed']);
      if (infl.inline) rows.push(['Inline', infl.inline + ' suppression comment(s) honoured']);
      if (infl.score_without_repo_content !== undefined && infl.active) rows.push(['Score', infl.score_with_repo_content + ' with the repo\'s own content · ' + infl.score_without_repo_content + ' without it']);
      const box = el('div', { class: 'infl-box' + (infl.material ? ' material' : '') }, [el('b', { text: infl.material ? 'REPOSITORY INFLUENCE - review before trusting this grade' : 'Repository influence' })]);
      rows.forEach((r) => box.appendChild(el('div', { class: 'infl-row' }, [el('span', { text: r[0] }), el('span', { text: r[1] })])));
      qualityCard.appendChild(box);
    }
    qualityCard.appendChild(el('div', { class: 'muted', style: { fontSize: '12px', marginTop: '8px' },
      text: 'Learning ' + (analysis.learning ? 'on' : 'off') + ' · config ' + (analysis.config || 'none') + ' · min confidence ' + (analysis.min_confidence || 'low') }));
    const notes = (r.meta.notes || []).map((n) => el('div', { class: 'muted', style: { fontSize: '12px' }, text: '• ' + n }));
    panel.appendChild(el('div', { class: 'grid-3' }, [sevCard, owCard, hygCard]));
    panel.appendChild(el('div', { class: 'grid-3', style: { marginTop: '18px' } }, [filesCard, weakCard, langCard]));
    if (r.analysis) panel.appendChild(el('div', { class: 'grid-2', style: { marginTop: '18px' } }, [qualityCard, lockCard(r)]));
    if (notes.length) panel.appendChild(el('div', { class: 'card', style: { marginTop: '18px' } }, [el('h3', { text: 'Notes' })].concat(notes)));
  }

  function lockCard(r) {
    const card = el('div', { class: 'card' }, [el('h3', { text: 'Virtual lockfile' })]);
    const res = (r.dependency_summary && r.dependency_summary.resolution) || {};
    const colors = { lockfile: '#00ff9c', manifest: '#7ee787', environment: '#00e5ff', registry: '#9d7bff', 'registry-graph': '#ff2e97', unresolved: '#ff8a00' };
    const max = Math.max(1, ...Object.values(res));
    Object.keys(res).forEach((k) => card.appendChild(hbar(k, res[k], max, colors[k] || '#8892b0')));
    const lock = r.lockfile || {};
    const pending = (lock.manifests || []).length;
    card.appendChild(el('p', { class: 'muted', style: { fontSize: '12px', marginTop: '10px' },
      text: pending ? pending + ' manifest(s) without lockfile were resolved virtually and checked; the lockfile guide explains how to create the real one.' : 'Every dependency is pinned by a manifest or lockfile.' }));
    return card;
  }

  A.showResults = showResults; A.renderActions = renderActions; A.fetchDownload = fetchDownload; A.downloadJSON = downloadJSON; A.openTab = openTab; A.hbar = hbar; A.renderOverview = renderOverview; A.lockCard = lockCard;
})();
