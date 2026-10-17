/* Secure Repo GUI - shared constants and state (every other app-*.js file reads them from SR.app). */
(function () {
  'use strict';
  const SR = window.SR;
  const A = (SR.app = SR.app || {});

  const STAGE_WEIGHT = { acquire: 6, enumerate: 4, analyze: 44, dependencies: 5, resolve: 8, intel: 16, hygiene: 3, compliance: 3, scoring: 2, report: 9 };
  const SUPPRESSED = new Set(['false_positive', 'filtered', 'disabled_by_config', 'suppressed_inline']);
  const STATUS_LABEL = { open: 'open', confirmed: 'confirmed', accepted_risk: 'accepted risk', false_positive: 'false positive', filtered: 'filtered', disabled_by_config: 'rule disabled by config', suppressed_inline: 'suppressed inline' };
  const DEFAULT_STAGES = [
    { id: 'acquire', title: 'Acquiring source' }, { id: 'enumerate', title: 'Mapping repository structure' },
    { id: 'analyze', title: 'Static code, secret & config analysis' }, { id: 'dependencies', title: 'Discovering libraries & dependencies' }, { id: 'resolve', title: 'Resolving versions (virtual lockfile)' },
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
    fState: { sev: new Set(SR.SEV), cat: '', q: '', hideTests: false, flow: false, suppressed: false, limit: 150 },
    dState: { q: '', eco: '', vuln: false, direct: false, limit: 200 },
  };

  Object.assign(A, { STAGE_WEIGHT, SUPPRESSED, STATUS_LABEL, DEFAULT_STAGES, S });
})();
