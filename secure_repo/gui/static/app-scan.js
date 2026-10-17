/* Secure Repo GUI - starting a scan and following its live events. */
(function () {
  'use strict';
  const SR = window.SR;
  const A = SR.app;
  const $ = SR.$, el = SR.el;
  const { STAGE_WEIGHT, DEFAULT_STAGES, S } = A;

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
    A.show('scan');
    A.setStatus('busy', 'scan in progress');
    if (!S.boxLive) {
      S.boxLive = new SR.BoxMap($('#live-boxmap'), { live: true, maxDepth: 3, onHover: A.tooltipForNode });
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
    S.es = SR.stream('/api/scans/' + scanId + '/events', (raw) => {
      let ev;
      try { ev = JSON.parse(raw); } catch (e) { return; }
      handleEvent(ev);
    });
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

  function onFailed(message) {
    clearInterval(S.timer);
    if (S.es) S.es.close();
    A.setStatus('off', 'scan stopped');
    log('error', message);
    const box = $('#scan-failed');
    box.hidden = false;
    box.textContent = '';
    box.appendChild(el('b', { text: 'Scan stopped: ' }));
    box.appendChild(document.createTextNode(message));
    box.appendChild(el('div', { style: { marginTop: '10px' } }, [el('button', { class: 'btn small', type: 'button', text: 'Back to setup', onclick: () => A.show('setup') })]));
    $('#btn-cancel').disabled = true;
  }

  async function onComplete(ev) {
    clearInterval(S.timer);
    $('#scan-progress').style.width = '100%';
    $('#m-pct').textContent = '100%';
    $('#btn-cancel').disabled = true;
    log('ok', 'MISSION COMPLETE — reports stored in ' + (ev.report_dir || '-'));
    A.setStatus('ok', 'scan complete');
    if (S.es) S.es.close();
    try {
      const data = await SR.api('/api/scans/' + ev.scan_id + '/report');
      setTimeout(() => A.showResults(data.report, data.scan_id, data.report_dir), 900);
    } catch (err) {
      SR.toast(err.message, 'error');
    }
  }

  A.startScan = startScan; A.connectEvents = connectEvents; A.log = log; A.overallProgress = overallProgress; A.handleEvent = handleEvent; A.onFailed = onFailed; A.onComplete = onComplete;
})();
