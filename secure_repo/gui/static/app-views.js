/* Secure Repo GUI - neural map, structure, findings, libraries, compliance and export tabs. */
(function () {
  'use strict';
  const SR = window.SR;
  const A = SR.app;
  const $ = SR.$, $$ = SR.$$, esc = SR.esc, el = SR.el;
  const { SUPPRESSED, STATUS_LABEL, S } = A;

  /* ---------------------------------------------------------------- neural */
  function initNeural() {
    const canvas = $('#neural-canvas');
    if (!S.neural) {
      S.neural = new SR.NeuralMap(canvas, {
        onSelect: (node) => { if (node) A.openNodeDrawer(node); },
        onHover: A.tooltipForGraph,
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
        maxDepth: 3, onHover: A.tooltipForNode, onSelect: (node) => A.openFileDrawer(node.path),
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
    $('#f-supp-n').textContent = S.report.findings.filter((x) => SUPPRESSED.has(x.status)).length;
    const items = S.report.findings.filter((x) => f.sev.has(x.severity) && (!f.cat || x.category === f.cat) && (!f.hideTests || !x.in_test) &&
      (f.suppressed || !SUPPRESSED.has(x.status)) && (!f.flow || x.engine === 'taint') &&
      (!q || (x.title + ' ' + x.file + ' ' + x.rule_id + ' ' + x.cwe + ' ' + x.snippet + ' ' + x.id).toLowerCase().indexOf(q) >= 0));
    const list = $('#findings-list');
    list.textContent = '';
    if (!items.length) {
      list.appendChild(el('div', { class: 'empty', text: 'No findings match the current filters.' }));
    }
    items.slice(0, f.limit).forEach((x) => {
      const row = el('div', { class: 'finding' });
      row.style.setProperty('--c', SR.SEV_COLOR[x.severity]);
      if (SUPPRESSED.has(x.status)) row.classList.add('suppressed');
      SR.setHTML(row, '<div>' + SR.sevTag(x.severity) + '</div><div style="min-width:0"><div class="ft">' + esc(x.title) +
        (x.engine === 'taint' ? '<span class="tag flow-tag">data flow</span>' : '') +
        (x.status && x.status !== 'open' ? '<span class="tag status-' + esc(x.status) + '">' + esc(STATUS_LABEL[x.status] || x.status) + '</span>' : '') +
        (x.in_test ? '<span class="tag">test</span>' : '') + '<span class="tag">' + esc(x.category) + '</span></div><div class="fl">' + esc(SR.where(x)) +
        '</div>' + (x.snippet ? '<div class="fs">' + esc(x.snippet) + '</div>' : '') + '</div><div class="fid">' + esc(x.id) + '<br>' + esc(x.cwe || '') +
        '<br><span class="conf conf-' + esc(x.confidence) + '">' + esc(x.confidence) + ' ' + esc(x.confidence_score || '') + '</span></div>');
      row.addEventListener('click', () => A.openFindingDrawer(x));
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
    SR.setHTML(table, '<thead><tr><th>Library</th><th>Version</th><th>Resolved by</th><th>Ecosystem</th><th>Type</th><th>Risk</th><th>Advisories / issues</th><th>License</th><th>Latest</th><th>Manifest</th></tr></thead>');
    const body = el('tbody');
    rows.slice(0, d.limit).forEach((x) => {
      const tr = el('tr', { class: 'click' });
      const risk = x.max_severity ? SR.sevTag(x.max_severity) : (x.issues.length ? '<span class="st warning">REVIEW</span>' : '<span class="st pass">OK</span>');
      const adv = x.vulnerabilities.slice(0, 3).map((v) => esc(v.id)).join(', ') + (x.vulnerabilities.length > 3 ? ' +' + esc(x.vulnerabilities.length - 3) : '') +
        (x.issues.length ? (x.vulnerabilities.length ? ' · ' : '') + esc(x.issues[0]) : '');
      const how = x.resolved_by || (x.source === 'registry' ? 'unresolved' : x.source);
      SR.setHTML(tr, '<td class="mono">' + esc(x.name) + (x.parent ? '<div class="muted" style="font-size:11px">via ' + esc(x.parent) + '</div>' : '') + '</td><td class="mono">' + esc(x.version || x.spec || '*') +
        (x.version && x.spec && x.spec !== x.version && x.direct ? '<div class="muted" style="font-size:11px">declared ' + esc(x.spec) + '</div>' : '') +
        '</td><td><span class="res res-' + esc(how) + '">' + esc(how) + '</span></td><td>' + esc(x.ecosystem) +
        '</td><td>' + (x.direct ? 'direct' : '<span class="muted">transitive</span>') + '</td><td>' + risk + '</td><td class="mono" style="max-width:320px">' + (adv || '<span class="muted">-</span>') +
        '</td><td class="mono">' + esc((x.licenses || []).join(', ') || '-') + '</td><td class="mono">' + esc(x.latest || '-') + '</td><td class="mono muted">' + esc(x.manifest) + '</td>');
      tr.addEventListener('click', () => A.openDepDrawer(x));
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

  const STATUS_WORDS = { pass: 'NO ISSUE FOUND', warning: 'REVIEW', fail: 'ISSUE FOUND', manual: 'MANUAL' };

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
        '</div><div class="fw-counts"><span class="st pass">NO ISSUE ' + esc(s.pass) + '</span><span class="st warning">REVIEW ' + esc(s.warning) + '</span><span class="st fail">ISSUE ' + esc(s.fail) +
        '</span><span class="st manual">MANUAL ' + esc(s.manual) + '</span></div></div></div><p class="muted" style="font-size:12px;margin:12px 0 0">' + esc(fw.description) + '</p><div class="controls">';
      fw.controls.forEach((c) => {
        html += '<div class="control"><div><span class="st ' + esc(c.status) + '">' + esc(STATUS_WORDS[c.status] || c.status.toUpperCase()) + '</span></div><div class="cid">' + esc(c.id) + '</div><div><b>' + esc(c.title) +
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
      ['lock', 'LOCK', 'Lockfile guide', 'Versions resolved for unpinned dependencies + how to create the real lockfile.'],
      ['vlock', 'JSON', 'Virtual lockfile', 'Machine-readable resolution of every unpinned dependency.'],
      ['quality', 'QA', 'Analysis quality', 'Engines, noise discarded, confidence and suppressed findings (audit trail).'],
    ];
    const grid = el('div', { class: 'export-grid' });
    const live = S.scanId && !S.reportMode;
    items.forEach((it) => {
      const card = el('div', { class: 'card export' }, [el('div', { class: 'ico', text: it[1] }), el('h4', { text: it[2] }), el('p', { text: it[3] })]);
      if (live) card.appendChild(el('button', { class: 'btn primary', type: 'button', text: 'Download', onclick: () => A.fetchDownload(it[0]) }));
      else if (it[0] === 'json') card.appendChild(el('button', { class: 'btn primary', type: 'button', text: 'Download', onclick: A.downloadJSON }));
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

  A.initNeural = initNeural; A.initStructure = initStructure; A.renderFindingsFilters = renderFindingsFilters; A.renderFindings = renderFindings; A.renderDepsFilters = renderDepsFilters; A.renderDeps = renderDeps; A.ring = ring; A.renderCompliance = renderCompliance; A.renderExport = renderExport;
})();
