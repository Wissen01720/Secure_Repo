# Changelog

All notable changes to Secure Repo are documented here.

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
