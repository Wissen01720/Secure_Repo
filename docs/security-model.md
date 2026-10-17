# Privacy, trust model and limitations

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)

## Privacy & data handling

- Source code **never leaves your machine**.
- In online mode only **package names and versions** are sent over HTTPS to `api.osv.dev` and `api.deps.dev`
  (and to `repo.packagist.org` / `pub.dev` to resolve PHP and Dart version ranges). `--offline` disables every
  network request; versions can still be resolved from the installed environment.
- Triage decisions are stored locally in your user data folder (`%APPDATA%\SecureRepo` on Windows,
  `~/Library/Application Support/SecureRepo` on macOS, `~/.local/share/secure-repo` on Linux, or
  `SECURE_REPO_HOME`). They are written into a repository only when you run `secure-repo triage export --to-repo`.
- Secrets are **masked** (`AKIA****************`) in every output; card numbers are truncated.
- Remote repositories are cloned to a temporary folder that is **deleted** after the scan.
- Reports are written only to the folder you choose, protected by a `.gitignore` that ignores everything.
- The GUI session token travels only in the `X-SR-Token` header (never in a URL), and internal errors never send
  exception text to the browser.

### Private packages, registries and networks

Secure Repo sends package names and versions to OSV.dev and deps.dev (and Packagist / pub.dev to resolve ranges). If
the names of your internal packages must not leave your machine, say so:

```toml
# .securerepo.toml (applied for your own local repository) or ~/.../SecureRepo/config.toml
[intel]
private = ["@acme/*", "acme-*", "com.acme:*"]
```

or `--private '@acme/*'` (repeatable). Private packages are not resolved, not enriched and not sent to OSV.dev. A
repository you audit cannot use this list to hide its own dependencies: its `.securerepo.toml` is ignored unless you
trust it. `--check-confusion` is an explicit opt-in that *does* look the private names up in the public registry
(sending them) to warn about **dependency confusion** (`SR-DEP-010`): an internal name that also exists publicly.

| Option | Effect |
|---|---|
| `--no-registry` | No package-registry queries at all (deps.dev, Packagist, pub.dev); OSV.dev advisories for pinned versions still run. `--offline` turns off every request. |
| `--ca-bundle PATH` | Certificate authority for HTTPS lookups behind a TLS-inspecting proxy. Also read from `SECURE_REPO_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `SSL_CERT_FILE` (in that order). |
| `--no-cache` | Lookups are cached on disk for 24 hours (advisory searches never are, so new vulnerabilities show up the same day). |
| `--max-registry N`, `--max-graph N`, `--max-enrich N` | Limits (300, 120, 250). When one is hit, the report says how many dependencies were left out. |

Lookups are retried with backoff on HTTP 429 / 5xx, responses are limited to 20 MB, OSV pagination is followed, and a
failed batch is reported under *What was NOT analyzed* instead of cancelling the rest.

## Suppressing findings

| Mechanism | Effect |
|---|---|
| `# nosec SR-PY-005 reason` or `// nosec SR-JS-001 reason` in a **comment** | Suppress that rule on that line. Always listed in `findings/suppressed.md`. A bare `# nosec` still works, but it silences every rule on the line and the report flags it. Text inside a string (`"nosec"`) never counts. |
| `--exclude "path/*"` or `[scan] exclude` in `.securerepo.toml` | Do not scan matching paths. Every excluded file is listed in the report. |
| `--no-tests` | Skip files that look like tests or fixtures. |
| Triage (CLI menu, GUI or `secure-repo triage mark`) | Mark a finding as false positive / accepted risk, optionally for the whole code pattern. Kept in the audit trail. |
| `.securerepo.toml` (`secure-repo init-config`) | Disable rules, override severities, allow-list paths or values, set a minimum confidence, add custom rules. |
| `--min-confidence medium` | Hide low-confidence findings (they stay in `findings/suppressed.md` as *filtered*). |

The legacy `securerepo:ignore-file` marker was **removed**: a file inside the audited repository can no longer
exclude itself from the analysis. Files carrying it are analyzed normally and listed in the report.

### Who controls the result? (trust model)

Whatever sits inside the audited repository is **untrusted input**: its own `.securerepo.toml`, its
`.securerepo/triage.json` and its `nosec` comments could otherwise be used to hide real vulnerabilities and get a
good grade.

| Audited target | Repository's own config, shared triage and `nosec` comments |
|---|---|
| Working tree of a **local Git repository** (your own project) | **Applied**, and always reported |
| Remote URL, another branch, or a folder that is not a Git repository | **Ignored**, and the report says what was ignored |

Override it with `--trust-repo-config` (always apply) or `--ignore-repo-config` (never apply). Your own user-level
configuration is always applied.

When repository-controlled content is applied, nothing is hidden: rules turned off keep their findings with status
`disabled_by_config`, severity overrides are listed (before → after), excluded files are counted and listed, and
the report shows two grades, **with** and **without** the repository's own content. If they differ by 10 points
or more, the CLI, the GUI and `quality.md` show a *REPOSITORY INFLUENCE* warning.

Dependency folders (`node_modules`, `vendor`, virtual environments, build output) are skipped automatically;
their libraries are still analyzed through the manifests and lockfiles.

## Limitations and threat model

Secure Repo is a static analyzer: it reads files and reasons about them. Treat its output as a prioritized list of
leads to review, not as a verdict.

**What it does not detect**

- Business-logic flaws, broken authorization or authentication at design level, race conditions and anything that
  only exists at run time (deployed configuration, cloud permissions, network exposure).
- Data flow across files or through frameworks it does not model: taint tracking is per file, and only for Python
  and JavaScript/TypeScript. Every other language relies on patterns.
- Secrets that were removed from the working tree but remain in Git history: only the checked-out files are read.
- Vulnerabilities in code that is not in the repository (installed packages, base images, generated artifacts).
- Obfuscated or dynamically generated code.

**What is skipped, always or conditionally** (every skip is listed under "What was NOT analyzed" in the report)

- Always: `.git`, `node_modules`, virtual environments, caches and the report folders themselves.
- Only with evidence: `build`, `dist`, `target`, `vendor`, `obj`, `coverage`, `Pods`... (listed in `.gitignore`, `vendor/` at
  the root or beside `go.mod` / `composer.json` / `Gemfile`, or full of build artifacts).
- Minified JavaScript, TypeScript and CSS: reduced analysis (secrets and critical findings only).
- Files above the size limit (default 2 MB, `--max-file-size`), binaries, symbolic links, lock files and source maps by type.
- Dependency manifests with a syntax error are reported as unparsed, not silently treated as empty.

**How the audited repository is treated.** Everything inside the target repository is untrusted input. Its own
`.securerepo.toml`, shared triage file and `nosec` comments change the result only when you audit a *local* Git
working tree (your own project); for remote repositories, other branches and plain folders they are ignored and the
report says so. Custom regular expressions are rejected when they could backtrack catastrophically, and report
files neutralize spreadsheet formulas.

**What leaves your machine.** Source code never does. In online mode package names and versions are sent to
`api.osv.dev` and `api.deps.dev` (and to `repo.packagist.org` / `pub.dev` to resolve ranges); the update check contacts
the GitHub API of this project. `--offline` disables dependency lookups; `--no-update-check` disables the update check.

**Compliance output is evidence, not certification.** A control marked PASS means the analyzer found nothing that
contradicts it in the code it could read, not that the control is satisfied.
