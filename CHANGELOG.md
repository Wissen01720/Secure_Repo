# Changelog

All notable changes to Secure Repo are documented here.

## [1.4.0] - 2026-10-25

First refresh of the standards baseline the audits are measured against (reviewed 2026-10-25).

### Added
- **OWASP Top 10:2025** is now the primary OWASP framework (`--compliance owasp`): A03 Software Supply Chain Failures and
  A10 Mishandling of Exceptional Conditions are new, and SSRF is part of A01. Rules keep their stable 2021 codes;
  every finding now carries both (`owasp`, `owasp_2025`) and the rank of its weakness in the **MITRE 2025 CWE Top 25**
  (`cwe_top25`). The previous edition stays available as `owasp-2021`. Reports, CLI and GUI show the 2025 distribution.
- **OWASP Top 10 for LLM Applications (2025)** and **OWASP Top 10 for Agentic Applications (2026)** as compliance
  frameworks (`owasp-llm`, `owasp-agentic`). They are evaluated only when the repository uses AI libraries or an
  `SR-AI-*` rule fires; controls that code cannot show are marked MANUAL.
- **11 `SR-AI-*` rules**: model output executed as code, `trust_remote_code`, models loaded through pickle, agent
  frameworks with safety switches off, coding agents run without permission checks, unpinned MCP servers, untrusted
  input in system prompts, model output rendered as HTML, LLM keys shipped to the browser, hidden Unicode in agent
  instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`...), and shell commands inside agent tools.
- `SR-SEC-021` (Hugging Face, Groq, Replicate and xAI tokens), `SR-PY-026`/`SR-PY-027` (tarfile extraction filters,
  after the October 2026 CPython security releases), `SR-PY-028`/`SR-JS-029`/`SR-JAVA-011` (swallowed exceptions, the
  OWASP A10:2025 class) and `SR-DEP-011` (Python, Node.js, PHP or Ruby pinned past end of life in version files,
  Dockerfiles and CI). 193 rules in total. Rules can set `owasp_2025` and `scan_docs`.
- A weekly online audit of this repository (`dependency-audit.yml`) that fails on high advisories or dead runtimes.
- Compliance additions: PCI DSS 6.2.3, ISO 27001 A.5.21, NIST SSDF PS.2 and RV.2; framework versions now name the
  edition they follow (ISO 27001 with Amendment 1:2024, SSDF v1.1 with the v1.2 draft tracked, HIPAA's pending update).

### Changed
- **Python 3.11 or newer is required.** Python 3.10 reached end of life on 1 October 2026 (3.10.22 was its last
  release). CI now tests 3.11 and 3.14, `tomli` is no longer a dependency and the lock file was regenerated.
- External benchmark after the new rules: precision 62 % (75 % at medium/high confidence), recall 93 %.

### Audit of our own libraries
- OSV.dev reports no advisories for any locked library (`rich`, `defusedxml`, `markdown-it-py`, `mdurl`, `pygments`),
  and all of them are at their latest release.

## [1.3.1] - 2026-10-20

### Security
- **GUI HTML helper hardened:** `SR.setHTML` no longer assigns `innerHTML`. Markup is parsed in the context of the target
  element, stripped of scripts, frames, forms, `on*` attributes and non-web URLs, and attached as nodes, so a missed
  escape cannot run code (defence in depth on top of the strict CSP). Link targets coming from advisories and rule
  references are limited to `http(s)` (`SR.safeUrl`). Closes the code-scanning alert `SR-JS-002`; the repository now
  audits itself with no findings.

## [1.3.0] - 2026-10-16

### Added
- **New rules (175 in total):** `SR-JS-028` (Express app with sessions but no CSRF protection, project level),
  `SR-PY-025` (Django without `CsrfViewMiddleware`), SSRF through a variable in `got`/`needle` calls (`SR-JS-017`),
  and hardcoded session, cookie or encryption keys (`SR-JS-026`). External benchmark recall is now 93 %.
- **`--theme plain`** (or `SECURE_REPO_THEME=plain`): a sober console without the staged titles and glyphs.
- **OWASP Top 10:2025** shown next to the 2021 category in reports and in the GUI finding drawer.
- **Documentation restructure:** a short `README.md`, a Spanish `README.es.md` and a `docs/` folder (installation,
  CLI guide, analysis, reference, GUI, security model, troubleshooting, development, releasing).
- **Release tooling:** `.github/workflows/publish.yml` (PyPI Trusted Publishing, no stored token),
  `tools/release_notes.py`, ESLint check of the GUI scripts and a package build step in CI.

### Changed
- **Python 3.10 or newer** is required (3.9 is end of life).
- **Compliance wording is cautious:** NO ISSUE FOUND / REVIEW / ISSUE FOUND / MANUAL instead of PASS/FAIL; the
  disclaimer states that absence of findings does not show a control is satisfied. JSON keys are unchanged.
- **Package metadata:** the licence is declared as `LicenseRef-SecureRepo-Ethical-Source-Available` with the
  `LICENSE` file shipped; the single console command is `secure-repo` (the `securerepo` alias was removed).
- `scanner.py` is split into focused modules (`scan_common`, `scan_base`, `scan_analysis`, `scan_dependencies`,
  `scan_quality`) and the GUI `app.js` into `app-*.js` modules.

### Fixed
- Self-audit alerts: the GUI session token is no longer stored in Web Storage (it stays in the URL fragment and in
  memory); `defusedxml` is now a required dependency (no `xml.etree` fallback); a hash-pinned `requirements.lock`
  (with line continuations) is recognised as a lockfile; inline suppressions are exported to SARIF as `inSource`.
- Two scans running at the same time in the GUI no longer share network counters: each scan owns a network session
  bound to its context, so intelligence notes and statistics cannot mix.

## [1.2.5] - 2026-10-15

### Added
- **CI-friendly gates:** `--baseline report.json` makes `--fail-on` count only findings that are new (matched by
  fingerprint; SARIF `baselineState`), and `--since REF` analyzes only the files changed relative to a Git reference.
- **Private packages:** `[intel] private = [...]` / `--private` keep internal package names away from every
  registry and from OSV.dev; `--no-registry` skips package registries but keeps OSV advisories; `--check-confusion`
  (opt in) warns when a private name also exists publicly (new rule `SR-DEP-010`, 173 rules). A repository you audit
  cannot use the list to hide its dependencies.
- **Resilient network layer** (`core/netio.py`): retries with backoff for 429/5xx (honours `Retry-After`), 20 MB
  response limit, a 24-hour disk cache for registry and advisory-detail lookups (`--no-cache`), `--ca-bundle` and
  the `SECURE_REPO_CA_BUNDLE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` / `SSL_CERT_FILE` variables.
- **OSV pagination** (`next_page_token`) and one `try` per batch: a failing batch no longer discards all the
  vulnerability intelligence of the scan.
- Gaps are reported: failed batches, results cut by the pagination cap and the registry / graph / metadata limits
  (`--max-registry`, `--max-graph`, `--max-enrich`) appear under *What was NOT analyzed*, in the CLI, the GUI and
  `analysis.network` of the report.

### Security
- **Two built-in patterns were quadratic on hostile input.** The generic-credential detector took 36 seconds on one
  21 KB single-line file and the template-escaping rule (`SR-WEB-001`) over 100 seconds on a line of 120,000 braces:
  a repository could stall the audit. Both are now linear (0.3 s and 0.2 s on the same inputs), and a new test feeds
  every supported file type 12 kinds of hostile lines and fails above a time budget.

### Changed
- The compromised and deprecated package lists moved to `secure_repo/data/packages.json` with a reason, date and source
  per entry; the unverified `python-jose` entry was dropped.
- `--fail-on` no longer counts false positives, filtered or disabled findings or accepted risks.

### Known limitation
- Two scans running at the same time in the GUI share the network counters, so their intelligence notes can mix.

## [1.2.4] - 2026-10-14

### Added
- **Measured accuracy on third-party code.** `secure-repo benchmark --external` audits NodeGoat, DVPWA,
  Vulnerable-Flask-App and `requests` at pinned commits and scores the findings against hand-written verdicts:
  precision 58 % over every finding (71 % for medium/high confidence), recall 82 % on 28 documented weaknesses. CI
  runs it and fails below 65 % / 80 %. The README badges show these numbers instead of the rule count.
- **Rules are data.** The 172 rules moved from Python to `secure_repo/ruledata/*.toml`. Every rule carries a positive
  and a negative example (secret-shaped values are built at run time from placeholders) and a test runs all of them
  (`secure-repo benchmark` reports it too). Malformed rule files fail with the file and rule name.
- **Production, test and density scores** next to the headline score, in the CLI, `summary.md` and the GUI; the
  penalty now also grows with the number of files a weakness appears in (attack surface).
- **Parallel analysis** (`-j/--jobs`): files are analyzed in worker processes; Django goes from 60 s to 15 s with an
  identical report. It falls back to one process if workers cannot start.
- README: support level by language, a limitations and threat-model section, how to add a rule.

### Changed
- `Development Status` classifier is now `4 - Beta`.
- Precision fixes found while labelling third-party code: `<!-- commented-out HTML -->` is no longer scanned,
  `jwt.decode(..., verify=False)` is no longer reported as a TLS problem, `pickle.loads(pickle.dumps(x))` round trips
  and placeholder URL passwords (`user:pass@host`) are ignored, `id-token: write` is no longer a credential, PyOpenSSL is
  no longer "deprecated", and plain-HTTP URLs in test code are not reported (`skip_in_tests`).
- The `ADD` rule for Dockerfiles uses a bounded repeat so every built-in pattern passes the ReDoS check.

### Not done
- Splitting `app.js` and `scanner.py` into smaller modules (C-41) was left for later; only the rules were moved to data.

## [1.2.3] - 2026-10-13

### Added
- **New JavaScript rules** found by auditing NodeGoat: `SR-JS-025` template auto-escaping disabled (swig, nunjucks,
  dust, Handlebars), `SR-JS-026` hardcoded session/cookie secret, `SR-JS-027` session cookie without `Secure`
  or with `HttpOnly` disabled (also when the setting is commented out). 172 rules in total.
- `findings/tests.md`: findings in test code are reported apart.
- **Damaged manifests are no longer silent:** a `package.json`, `pyproject.toml`, `pom.xml`... with a syntax error is
  listed under "What was NOT analyzed" (quality.md, CLI and GUI) instead of looking like "no dependencies".

### Changed
- **Fewer false positives, nothing hidden.** On Django, high-confidence SQL findings went from 52 to 0 and
  high-severity findings from 308 to 152 (the rest are in test code), with no finding removed except three
  workflow false positives.
  - `SR-CI-002` reports only inside `run:` / `script:` bodies, not under `env:` or `with:`.
  - `SR-PY-011` is capped at medium confidence without a confirmed untrusted source, and low for internal
    identifiers; the detail names the interpolated value and the evidence shows the whole multi-line call.
  - Bundled third-party libraries and `<pre>`/`<code>` examples are reported at low confidence and never trigger
    the grade cap; test-code findings are one severity level lower.
  - `Dockerfile.db`, `Makefile.dev`... are no longer "sensitive files".
- **Rule IDs match their languages:** `SR-JS-010/019/020/021` and `SR-JAVA-002/007` became `SR-GEN-008..013`. Old IDs
  keep working in configuration, `nosec` comments and triage; fingerprints did not change.

### Fixed
- The CI failed on Linux because two CLI tests depended on the terminal width.
- Printing to a Windows character device (`> NUL`) crashed on a symbol the console could not encode; it now
  degrades instead. Closed input (`EOFError`) ends with a clear message instead of a traceback.

## [1.2.2] - 2026-10-12

### Security
- **Report CSP by hash:** `report.html` allows scripts only by SHA-256 hash instead of `'unsafe-inline'`, so
  anything injected later (an escaping bug, an edited file) does not run. Checked in a real browser.
- **Reports leave the audited repository by default:** they are written to the Secure Repo data folder
  (`.../SecureRepo/reports`). If `-o` points inside a Git repository, the folder is also added to
  `.git/info/exclude`, not just to its own `.gitignore`.
- A test now fails when the GUI builds markup by concatenation without escaping (`esc()`); the remaining unescaped
  numeric interpolations were fixed.

### Build and tooling
- **CI:** GitHub Actions on Linux, Windows and macOS (Python 3.9 and 3.13), `ruff` and `mypy`, a coverage gate,
  and a dogfood job that audits the repository and uploads SARIF. Actions are pinned by commit SHA.
- **Dependabot** for `pip` and `github-actions`; `ruff`, `mypy` and `coverage` configured in `pyproject.toml`.
- **One source of dependencies:** `requirements.txt` was replaced by a hashed, universal `requirements.lock`
  generated from `pyproject.toml`; the launchers and the in-place updater install it with `--require-hashes`.
- **Launchers** (`run.sh`, `run.bat`) write `.venv/.installed` only after a successful install and check every
  step's exit code, so a failed first run is retried instead of leaving a broken environment.
- Test coverage rose from 54 % to about 75 %: the CLI, the local web server flow, 30 manifest/lockfile formats
  (plus malformed and hostile inputs) and the vulnerability-intelligence client (batching, 429, timeouts).

### Fixed
- `secure-repo benchmark` reported a wrong line number for missed detections (a stale loop variable, found by lint).

## [1.2.1] - 2026-10-11

### Security
- **Grade cap:** an open critical finding in production code caps the grade at D (59), an open high one at C (74).
  The uncapped score is reported alongside.
- **ReDoS protection:** custom rule patterns and allowlist values prone to catastrophic backtracking are rejected.
- **GUI:** the session token is accepted only in the `X-SR-Token` header; the event stream and downloads now use
  authenticated `fetch`. Internal errors no longer leak exception text.
- **CSV exports** neutralize formula injection in every cell.

### Fixed
- One-line source files (Python, etc.) are no longer skipped as "minified"; minified JS/TS/CSS gets a reduced
  analysis (secrets and critical findings) instead of none.
- Folders called `build`, `dist`, `target`, `vendor`... are skipped only with evidence, not by name alone.

### Added
- "What was NOT analyzed" section in `quality.md`, the CLI and the GUI.
- Report folders carry millisecond timestamps and `latest.txt` points to the newest.

## [1.2.0] - 2026-10-11

### Security
- **The audited repository can no longer shape its own result.** Its `.securerepo.toml`,
  `.securerepo/triage.json` and `nosec` comments are applied only for the working tree of a local Git repository;
  for remote repositories (including private ones), other branches and plain folders they are ignored and the
  report says so (`--trust-repo-config` / `--ignore-repo-config` override this).
- When repository-controlled content is applied, it is fully disclosed: disabled rules, severity overrides,
  excluded files, allow-listed and silenced findings, and the grade **with and without** that content.
- Rules disabled by configuration are no longer deleted: their findings are kept with status
  `disabled_by_config` and listed in `findings/suppressed.md`.
- `nosec` is honoured only inside real comments (never inside strings), may name the rule it applies to
  (`# nosec SR-PY-005 reason`), and every inline suppression is recorded as `suppressed_inline`.
- The `securerepo:ignore-file` marker was removed: a file can no longer exclude itself. Files carrying it are
  analyzed and listed in the report. Secure Repo's own exclusions now live in its `.securerepo.toml`.
- Config path checks use path components instead of a string prefix.

### Added
- **Private and organization repositories:** when a remote asks for authentication, the CLI and the GUI request
  an access token (hidden input). The token is kept in memory only and sent to Git as an authorization header
  scoped to the repository host; it never appears in URLs, process arguments, logs or reports.
- `--ask-token` and `--token-env VARIABLE` for `scan` and `branches`; CI support through `SECURE_REPO_GIT_TOKEN`,
  `GH_TOKEN`/`GITHUB_TOKEN`, `GITLAB_TOKEN`, `BITBUCKET_TOKEN` and `AZURE_DEVOPS_PAT`.
- **Update notifications:** every new commit published to the official repository is announced at start-up, in
  the CLI (boot sequence and *UPDATE* panel listing what's new) and in the GUI (banner). After an update is
  installed, a one-time *UPDATE INSTALLED* notice is shown.
- **In-place updates** from `[U]` in the main console, `secure-repo update` or the GUI, without re-cloning:
  fast-forward for cloned installations (local edits are never overwritten), `pip install --upgrade` of the exact
  upstream commit for pip installations.
- `secure-repo update --check` (exit code 10 when an update is available) and `--no-update-check`.
- `CHANGELOG.md`.

## [1.1.0] - 2026-09-27

### Added
- Layered analysis engine, triage knowledge base, project configuration, benchmark and virtual lockfile.

## [1.0.0] - 2026-09-26

### Added
- First release: CLI and GUI, detection rules, library analysis, structure maps, reports and compliance audit.
