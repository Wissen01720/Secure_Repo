# Command and report reference

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)

## CLI command reference

| Command | Description |
|---|---|
| `secure-repo` | Interactive console (banner, boot sequence, menus). |
| `secure-repo scan [TARGET]` | Audit a path, the current directory (default `.`) or a Git URL. |
| `secure-repo branches [TARGET]` | Only list the branches of a local repository or a Git URL. |
| `secure-repo gui` | Launch the graphical interface. |
| `secure-repo rules [--search TEXT]` | List the detection rules (filter by id, language, CWE...). |
| `secure-repo frameworks` | List the compliance frameworks. |
| `secure-repo triage <list\|stats\|mark\|forget\|export\|import\|export-cases\|reset>` | Manage the triage knowledge base. |
| `secure-repo benchmark [--compare]` | Precision/recall on the built-in corpus and the examples of every rule. |
| `secure-repo benchmark --external [--fetch] [--dir DIR] [--min-precision P] [--min-recall R]` | Precision and recall measured on pinned third-party projects; exits 1 below the given floors. |
| `secure-repo init-config [PATH]` | Create a `.securerepo.toml` for a project. |
| `secure-repo update [--check] [-y]` | Check for and install a new version of Secure Repo (no re-cloning). |
| `secure-repo --no-update-check ...` | Skip the start-up update check for this run. |
| `secure-repo --version` | Show the version. |

`scan` options:

| Flag | Default | Description |
|---|---|---|
| `-b, --branch NAME` | picker / current | Branch to audit. Skips the interactive picker. |
| `--compliance [LIST]` | off | Enable the compliance audit. Without a value: all frameworks. Values: `owasp` (Top 10:2025), `owasp-2021`, `owasp-llm`, `owasp-agentic`, `pci-dss`, `iso27001`, `soc2`, `gdpr`, `hipaa`, `nist-ssdf`. The two AI lists are included in `all` only when the repository uses AI libraries. |
| `--offline` | off | No network requests (no OSV.dev / deps.dev). |
| `--no-enrich` | off | Skip license / latest-version lookups but keep vulnerability lookups. |
| `-o, --output DIR` | `<data folder>/reports` | Where report folders are created. By default **outside** the audited repository (see below). |
| `-y, --yes` | off | Confirm you are authorized to audit the target (required when not interactive). |
| `--no-tests` | off | Do not analyze files that look like tests or fixtures. |
| `--max-file-size KB` | `2048` | Skip larger files. |
| `--theme plain` (global) | hacker | Sober console: no banner art, animations or mission-style wording. Also `SECURE_REPO_THEME=plain`. |
| `-j, --jobs N` | `0` (automatic) | Worker processes for file analysis (up to 8 automatically, only for repositories of 400+ files). `1` forces a single process. The report is identical either way; Django (7,000 files) takes about 15 s instead of 60 s on 12 cores. |
| `--exclude GLOB` | - | Exclude paths (repeatable), e.g. `--exclude "legacy/*"`. |
| `--auditor NAME` | - | Name recorded in the audit trail of the reports. |
| `--fail-on SEVERITY` | - | Exit with code 3 when findings of this severity or worse exist. |
| `--plain` | off | Line-by-line output instead of the live dashboard. |
| `--no-anim` | off | Disable animations. |
| `--no-menu` | off | Do not show the post-scan menu. |
| `--open` | off | Open the HTML report when finished. |
| `--min-confidence LEVEL` | `low` | Filter findings below `medium`/`high` (kept as *filtered* in the audit trail). |
| `--trust-repo-config` | auto | Apply the audited repository's own `.securerepo.toml`, shared triage and `nosec` comments even for remote repositories or other branches. |
| `--ignore-repo-config` | auto | Never apply them, not even for your local working tree. |
| `--ask-token` | off | Ask for the access token of a private https repository (hidden input). |
| `--token-env VARIABLE` | - | Read the access token from that environment variable (CI). |
| `--no-learning` | off | Ignore the triage knowledge base. |
| `--no-resolve` | off | Do not resolve versions of unpinned dependencies. |
| `--private GLOB` | - | Package names that never leave your machine (repeatable). See *Private packages, registries and networks*. |
| `--no-registry` | off | Do not query package registries (OSV.dev still runs). |
| `--check-confusion` | off | Opt in: look private names up publicly to flag dependency confusion. |
| `--ca-bundle PATH` | - | CA bundle for HTTPS lookups (TLS-inspecting proxies). |
| `--no-cache` | off | Do not cache lookups on disk. |
| `--max-registry N` / `--max-graph N` / `--max-enrich N` | 300 / 120 / 250 | Limits of the dependency intelligence; the report says when they are reached. |
| `--baseline REPORT_JSON` | - | Earlier `report.json`: `--fail-on` counts only findings that are new. |
| `--since REF` | - | Analyze only files changed relative to a Git reference. |
| `--engine layered\|patterns` | `layered` | Choose the analysis engine. |

`branches` also accepts `--ask-token` and `--token-env VARIABLE`.

`gui` options: `--port N` (default: random free port), `--no-browser`, `-o/--output DIR`, `--offline`.

## The report folder

Every scan creates an organized, timestamped folder (names sort chronologically, to the millisecond;
`latest.txt` in the output folder names the newest one).

Reports contain code snippets and the weakness map of the audited project, so by default they are written
**outside** the audited repository, in the Secure Repo data folder: `%APPDATA%/SecureRepo/reports` on Windows,
`~/Library/Application Support/SecureRepo/reports` on macOS, `~/.local/share/secure-repo/reports` on Linux (or
`$SECURE_REPO_HOME/reports`). If you choose a folder inside a Git repository with `-o`, Secure Repo also adds it to
that repository's `.git/info/exclude`, in addition to the folder's own `.gitignore`.

```
reports/
├── .gitignore                       ← "*": reports can never be committed by accident
└── my-api_main_20260926-213000/
    ├── README.txt                   ← index of the folder
    ├── report.html                  ← interactive report (neural map, boxes, explanations) - works offline
    ├── report.json                  ← complete machine-readable results
    ├── report.sarif                 ← SARIF 2.1.0 (GitHub code scanning, Azure DevOps, IDEs)
    ├── summary.md                   ← executive summary
    ├── quality.md                   ← engines used, noise discarded, confidence, suppressed findings,
    │                                      and the influence of the audited repository on the result
    ├── findings/
    │   ├── critical.md  high.md  medium.md  low.md  info.md   (with data-flow traces)
    │   ├── by-category/<category>.md
    │   ├── suppressed.md            ← false positives / filtered findings with reason, author, date
    │   └── findings.csv
    ├── dependencies/
    │   ├── inventory.csv            ← every library, direct and transitive, and how its version was resolved
    │   ├── inventory.json
    │   ├── vulnerabilities.md       ← advisories, CVSS, fixed versions
    │   ├── virtual-lock.json        ← versions resolved for dependencies without lockfile
    │   ├── lockfile-guide.md        ← commands to create the real lockfile + proposed pins
    │   └── sbom.cdx.json            ← CycloneDX 1.5 SBOM
    ├── structure/
    │   ├── tree.txt                 ← repository tree annotated with findings
    │   ├── structure.json
    │   └── languages.md
    ├── compliance/                  ← only when the compliance audit is enabled
    │   ├── compliance.json
    │   └── <framework>.md
    ├── logs/scan.log                ← chronological log of every step and every triage decision
    └── MANIFEST.sha256              ← SHA-256 of every file (integrity / chain of custody)
```

Treat these folders as **confidential**: they describe weaknesses of the audited software.
