# Changelog

All notable changes to Secure Repo are documented here.

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
