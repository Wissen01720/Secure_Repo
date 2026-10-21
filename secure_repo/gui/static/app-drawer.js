/* Secure Repo GUI - side drawers (finding, rule, file, node, library) and tooltips. */
(function () {
  'use strict';
  const SR = window.SR;
  const A = SR.app;
  const $ = SR.$, esc = SR.esc, el = SR.el;
  const { STATUS_LABEL, S } = A;

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
    return (rule.references || []).map((u) => '<a href="' + esc(SR.safeUrl(u)) + '" target="_blank" rel="noopener noreferrer">' + esc(u) + '</a>').join('');
  }

  function vulnTable(vulns) {
    if (!vulns || !vulns.length) return '';
    return '<h5 class="why">Known vulnerabilities</h5><div class="table-wrap"><table class="data"><thead><tr><th>Advisory</th><th>Severity</th><th>Fixed in</th></tr></thead><tbody>' +
      vulns.map((v) => '<tr><td class="mono"><a href="' + esc(SR.safeUrl(v.url)) + '" target="_blank" rel="noopener noreferrer">' + esc(v.id) + '</a>' +
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
        '</dd><dt>CWE</dt><dd>' + esc(f.cwe || '-') + '</dd><dt>OWASP</dt><dd>' + esc((f.owasp || '-') + ' ' + (owasp.name || '') + ((S.report.owasp_2025 || {})[f.owasp] ? ' (2025: ' + S.report.owasp_2025[f.owasp].code + ' ' + S.report.owasp_2025[f.owasp].name + ')' : '')) + '</dd></dl>';
      if (f.snippet) html += '<div class="snippet">' + esc(f.snippet) + '</div>';
      if (f.detail) html += '<h5 class="where">Detail</h5><p>' + esc(f.detail) + '</p>';
      if (f.flow && f.flow.length) {
        html += '<h5 class="why">Data flow - untrusted source to sink</h5><ol class="flow">' + f.flow.map((step, i) =>
          '<li class="' + (i === 0 ? 'src' : (i === f.flow.length - 1 ? 'sink' : 'step')) + '"><span class="fl-line">L' + esc(step.line) + '</span><b>' +
          esc(step.label) + '</b><code>' + esc(step.code || '') + '</code></li>').join('') + '</ol>';
      }
      const reasons = (f.extra && f.extra.confidence_reasons) || [];
      html += '<h5 class="where">Confidence</h5><p><span class="conf conf-' + esc(f.confidence) + '">' + esc(f.confidence) + ' · ' +
        esc(f.confidence_score) + '/100</span> engine <b>' + esc(f.engine || 'pattern') + '</b>' + (reasons.length ? ' — ' + esc(reasons.join('; ')) : '') + '</p>';
      if (f.status && f.status !== 'open') {
        const t = f.triage || {};
        html += '<div class="triage-note status-' + esc(f.status) + '"><b>' + esc(STATUS_LABEL[f.status] || f.status) + '</b> ' + esc(t.reason || '') +
          (t.author ? ' <span class="muted">— ' + esc(t.author) + '</span>' : '') + (t.origin === 'learned-pattern' ? ' <span class="muted">(learned pattern)</span>' : '') + '</div>';
      }
      if (rule.description) html += '<h5 class="why">Why is this insecure?</h5><p>' + esc(rule.description) + '</p>';
      if (rule.recommendation) html += '<h5 class="fix">How to fix it</h5><p>' + esc(rule.recommendation) + '</p>';
      html += vulnTable(f.extra && f.extra.vulnerabilities);
      if (rule.references && rule.references.length) html += '<h5 class="refs">References</h5><div class="refs">' + refsHTML(rule) + '</div>';
      SR.setHTML(body, html);
      body.appendChild(triagePanel(f));
      const others = S.report.findings.filter((x) => x.rule_id === f.rule_id && x.id !== f.id);
      if (others.length) {
        body.appendChild(el('h5', { class: 'where', text: 'Other occurrences (' + others.length + ')' }));
        others.slice(0, 40).forEach((o) => body.appendChild(occRow(o)));
      }
    });
  }

  function triagePanel(f) {
    const panel = el('div', { class: 'triage-panel' });
    if (!S.scanId || S.reportMode) {
      panel.appendChild(el('p', { class: 'muted', text: 'Triage is available when the results come from a scan run in this GUI (or with "secure-repo triage mark" on the report folder).' }));
      return panel;
    }
    panel.appendChild(el('h5', { class: 'fix', text: 'Triage - teach Secure Repo' }));
    const reason = el('textarea', { rows: '2', placeholder: 'Reason / justification (required for false positives - it goes to the audit trail)' });
    const scope = el('select', {}, [
      el('option', { value: 'finding', text: 'Only this finding' }),
      el('option', { value: 'project-pattern', text: 'This code pattern in this project' }),
      el('option', { value: 'global-pattern', text: 'This code pattern in every project' })]);
    const buttons = el('div', { class: 'triage-buttons' });
    [['false_positive', 'False positive', 'good'], ['accepted_risk', 'Accept risk', 'warn'], ['confirmed', 'Confirm', 'bad'], ['open', 'Reopen', '']].forEach((b) => {
      if (b[0] === f.status) return;
      buttons.appendChild(el('button', { class: 'btn small ' + b[2], type: 'button', text: b[1], onclick: () => submitTriage(f, b[0], reason.value, scope.value) }));
    });
    panel.appendChild(reason);
    panel.appendChild(el('div', { class: 'row', style: { marginTop: '8px' } }, [el('span', { class: 'muted', style: { fontSize: '12px' }, text: 'Scope for false positives:' }), scope]));
    panel.appendChild(buttons);
    return panel;
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
          '</p><h5 class="where">Weaknesses in this category (' + esc(node.count) + ' findings)</h5>');
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

  async function submitTriage(f, status, reason, scope) {
    try {
      const data = await SR.api('/api/scans/' + S.scanId + '/triage', { method: 'POST', body: { finding_ids: [f.id], status: status, reason: reason, scope: status === 'false_positive' ? scope : 'finding' } });
      const learned = data.result.learned ? ' · ' + data.result.learned + ' similar finding(s) suppressed' : '';
      SR.toast(f.id + ' → ' + (STATUS_LABEL[status] || status) + learned + ' · score ' + data.result.score + '/100', 'ok');
      const keep = S.fState;
      A.showResults(data.report, S.scanId, S.reportDir, { keepFilters: true, tab: 'findings' });
      S.fState = keep;
      A.renderFindingsFilters();
      A.renderFindings();
      const updated = data.report.findings.find((x) => x.id === f.id);
      if (updated) openFindingDrawer(updated);
    } catch (err) {
      SR.toast(err.message, 'error');
    }
  }

  A.openDrawer = openDrawer; A.closeDrawer = closeDrawer; A.refsHTML = refsHTML; A.vulnTable = vulnTable; A.openFindingDrawer = openFindingDrawer; A.triagePanel = triagePanel; A.occRow = occRow; A.openRuleDrawer = openRuleDrawer; A.openFileDrawer = openFileDrawer; A.openNodeDrawer = openNodeDrawer; A.groupByRule = groupByRule; A.ruleRow = ruleRow; A.openListDrawer = openListDrawer; A.openDepDrawer = openDepDrawer; A.showTip = showTip; A.tooltipForGraph = tooltipForGraph; A.tooltipForNode = tooltipForNode; A.submitTriage = submitTriage;
})();
