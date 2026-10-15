<div align="center">

# SECURE//REPO

**Repository security auditor with a hacker-style CLI and a neural-map GUI.**

Static code analysis · secret detection · library & supply-chain intelligence · repository structure mapping ·
optional compliance evidence (OWASP, PCI DSS, ISO 27001, SOC 2, GDPR, HIPAA, NIST SSDF)

![Python](https://img.shields.io/badge/python-3.9%2B-00e5ff?style=flat-square)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-00ff9c?style=flat-square)
![Precision](https://img.shields.io/badge/precision%20on%20third--party%20code-71%25-ff2e97?style=flat-square)
![Recall](https://img.shields.io/badge/recall%20on%20documented%20weaknesses-82%25-ff2e97?style=flat-square)
![License](https://img.shields.io/badge/license-Ethical%20Source--Available-9d7bff?style=flat-square)

<img src="docs/images/cli-banner.svg" alt="Secure Repo CLI banner and boot sequence" width="900">

</div>

---

## Table of contents

1. [What Secure Repo does](#what-secure-repo-does)
2. [Rules of engagement](#rules-of-engagement)
3. [Requirements](#requirements)
4. [Installation (Windows, macOS, Linux)](#installation)
5. [Updating Secure Repo](#updating-secure-repo)
6. [CLI field guide - step by step](#cli-field-guide)
7. [Private and organization repositories](#private-and-organization-repositories)
8. [Analysis engine & false-positive reduction](#analysis-engine--false-positive-reduction)
9. [CLI command reference](#cli-command-reference)
10. [The report folder](#the-report-folder)
11. [Graphical interface (GUI)](#graphical-interface-gui)
12. [What is analyzed](#what-is-analyzed)
13. [Compliance audit](#compliance-audit)
14. [Privacy & data handling](#privacy--data-handling)
15. [Suppressing findings](#suppressing-findings)
16. [Limitations and threat model](#limitations-and-threat-model)
17. [Troubleshooting](#troubleshooting)
18. [Project layout](#project-layout)
19. [License](#license)

---

## What Secure Repo does

| Capability | Details |
|---|---|
| **Runs where you are** | Launched inside a Git repository it detects it automatically and audits it. Outside a repository you give it a Git URL or a path. |
| **Branch recon** | Lists every branch (local + remote-tracking, or remote via `git ls-remote`) and lets you pick the one to audit - in the CLI **and** the GUI. Other branches are exported with `git archive`, so your working tree is never touched. |
| **Static analysis** | 172 detection rules for Python, JavaScript/TypeScript, Java/Kotlin, C#, PHP, Go, Ruby, C/C++, Rust, Shell/PowerShell, Dockerfiles, Kubernetes, Terraform/CloudFormation and CI/CD pipelines. |
| **Layered engine** | Comments and strings are masked, Python is analyzed on its syntax tree with taint tracking, JavaScript/TypeScript get a data-flow pass. Findings confirmed by data flow show the **source → sink** trace. |
| **Learns from you** | Mark false positives, accepted risks or confirmed findings; decisions, learned code patterns and per-rule statistics are re-applied on every scan. |
| **Secrets** | Cloud keys, tokens, private keys, connection strings, high-entropy credentials, sensitive files (`.env`, keystores, dumps, Terraform state) and payment card numbers (Luhn). Always **redacted** in the output. |
| **Every library** | Parses 25+ manifest and lock formats across PyPI, npm/yarn/pnpm, Go, crates.io, RubyGems, Packagist, Maven/Gradle, NuGet and Pub. Every library is inventoried and checked against **OSV.dev** (CVE/GHSA/malware advisories) and **deps.dev** (license, latest version), plus built-in lists of compromised and deprecated packages. |
| **Virtual lockfile** | Projects without a lockfile get their versions resolved from the installed environment or the registries (plus transitive dependencies), so they can still be checked precisely. |
| **Structure map** | Repository structure rendered as **boxes** - live in the terminal while scanning, as an interactive treemap in the GUI. |
| **Neural map (GUI)** | Insecure points shown as a connected neural network: *files → weaknesses → OWASP categories → severity*. Click any node for a plain-English explanation of **why it is insecure** and **how to fix it**. |
| **Live process view** | Every stage, file and finding is streamed as it happens (terminal dashboard / GUI pipeline + log). |
| **Organized evidence** | Each CLI run creates a timestamped folder with HTML, JSON, SARIF, Markdown, CSV, CycloneDX SBOM, compliance evidence, logs and a SHA-256 integrity manifest. |
| **Optional compliance audit** | Toggle it on/off in the CLI or GUI. Maps technical evidence to 7 frameworks to help you **meet** your obligations. |
| **Private repositories** | Organization and private repositories are supported. The tool asks for an access token when the remote requires it; the token stays in memory only and is never written to disk, logs or reports. |
| **Always up to date** | Every new release is announced at start-up. Install it from the menu (`[U]`), with `secure-repo update` or from the GUI, without re-cloning. |
| **Cross-platform** | Pure Python + Git. Windows, macOS and every mainstream Linux distribution. |

---

## Rules of engagement

> **Only audit repositories you own or have explicit, written permission to assess.**

Secure Repo is built for defenders and it enforces that posture:

- It **never executes** the audited code, never installs its dependencies and never exploits a finding.
- It asks you to **confirm your authorization** before every engagement (`--yes` confirms it in automation).
- Detected secrets are **redacted** in the terminal, the GUI and every report.
- Git runs hardened: hooks disabled, `ext::` transport blocked, shallow clones, LFS downloads skipped.

Using the tool to steal information or for any malicious purpose is forbidden by the [license](LICENSE).

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.9 or newer | <https://www.python.org/downloads/> (on Windows tick *"Add python.exe to PATH"*) |
| Git | 2.20 or newer | <https://git-scm.com/downloads> - needed for branches and remote repositories |
| Internet | optional | Only for vulnerability intelligence. Everything else works with `--offline`. |
| Browser | any modern one | Only for the GUI and the HTML report |

Python dependencies: [`rich`](https://github.com/Textualize/rich) (and `tomli` on Python < 3.11). Nothing else.

---

## Installation

### Option A - one-step launchers (recommended)

The launchers create a private virtual environment next to the project on the first run, install the
dependencies from the hashed `requirements.lock` (`pip --require-hashes`), install Secure Repo in it and forward every
argument you pass. The environment is only trusted once `.venv/.installed` exists, and that marker is written
only after every install step succeeded: if the first run fails (for example without network access) nothing is
left half-installed and the next run simply tries again.

**Windows (PowerShell or CMD)**

```powershell
git clone https://github.com/Wissen01720/Secure_Repo.git
cd Secure_Repo
.\run.bat
```

**macOS / Linux**

```bash
git clone https://github.com/Wissen01720/Secure_Repo.git
cd Secure_Repo
chmod +x run.sh
./run.sh
```

To audit **another** repository with the launcher, run it from inside that repository:

```bash
cd ~/projects/my-api
~/tools/Secure_Repo/run.sh            # macOS / Linux
C:\tools\Secure_Repo\run.bat          # Windows
```

### Option B - install the `secure-repo` command

```bash
git clone https://github.com/Wissen01720/Secure_Repo.git
cd Secure_Repo
python -m pip install .          # use "py -m pip install ." on Windows if "python" is not on PATH
secure-repo --version
```

Tip: `pipx install .` installs it in an isolated environment and makes `secure-repo` available everywhere.

### Option C - run from source

```bash
python -m pip install --require-hashes -r requirements.lock
python -m secure_repo
```

---

## Updating Secure Repo

Every time a new version is published, Secure Repo announces it:

- **CLI**: the boot sequence shows `[ WARN ] Updates ... NEW VERSION x.y.z AVAILABLE`, an **UPDATE** panel lists
  what's new, and the main console shows a highlighted `[U] INSTALL UPDATE` option.
- **GUI**: a banner below the top bar offers *What's new* and *Install update*.
- **After installing**, the next start shows a one-time **UPDATE INSTALLED** notice with the changes it included.

Install the update **without re-cloning** in any of these ways:

```bash
secure-repo            # then choose [U] in the main console
secure-repo update     # shows what's new and asks for confirmation (-y to skip it)
secure-repo update --check   # only check (exit code 10 = update available)
```

| Installation type | How the update is installed |
|---|---|
| Cloned repository (`run.sh` / `run.bat` / `pip install -e .`) | Fast-forward of the tracked branch. Dependencies are reinstalled only when `pyproject.toml` or `requirements.lock` changed. Local edits are never overwritten: the update stops and asks you to commit or stash them. |
| `pip install` | `pip install --upgrade` of the exact upstream commit from GitHub. On Windows, if the running executable is locked, the upgrade finishes automatically when you close Secure Repo. |

Restart Secure Repo after updating to load the new version. Checks are cached for 6 hours, take a few seconds at
most and never block the tool. They are skipped in CI, and you can disable them with `--no-update-check` or
`SECURE_REPO_NO_UPDATE_CHECK=1`. The list of changes of every release is in [CHANGELOG.md](CHANGELOG.md).

---

## CLI field guide

The CLI is the heart of Secure Repo. This section walks you through a full engagement.

### Step 1 - Launch the console

Open a terminal (Windows Terminal, PowerShell, macOS Terminal, iTerm2, GNOME Terminal, ...) and run:

```bash
secure-repo
```

You will see the banner, an ASCII figure and the **boot sequence**, which checks the engine, the detection
signatures, Git, the vulnerability intelligence mode, your platform and whether the current directory is a Git
repository.

> Tip: `secure-repo --no-anim` skips the animations. They are disabled automatically when the output is not a
> terminal or when the `CI` environment variable is set.

### Step 2 - Choose what to audit in the main console

```
──────────────────────────── ⟦ MAIN CONSOLE ⟧ ────────────────────────────
  [1]  Audit THIS repository  →  /home/you/projects/my-api  @ main
  [2]  Audit a REMOTE repository by Git URL (https / ssh)
  [3]  Audit a LOCAL repository or folder by path
  [4]  Launch the GRAPHICAL interface (GUI)
  [5]  Settings  [compliance: OFF · intel: ON · output: ~/.local/share/secure-repo/reports]
  [6]  List detection rules (172)
  [7]  Usage guide
  [U]  INSTALL UPDATE  1.2.0 → 1.3.0  (3 change(s)) - no re-cloning needed
  [0]  Exit

[?] root@secure-repo:~# (1):
```

| Option | When to use it |
|---|---|
| **1** | You launched Secure Repo inside a repository. It was detected automatically. |
| **2** | Audit a repository you have not cloned: paste `https://github.com/owner/repo.git` or `git@github.com:owner/repo.git`. |
| **3** | Audit another folder on disk (Git or not). |
| **4** | Open the GUI in your browser. |
| **U** | Install the newest version of Secure Repo. It is highlighted when an update is available; otherwise it checks for updates. |
| **5** | Enable the compliance audit, offline mode, test-file handling, max file size, output folder, exclusions, auditor name, animations, minimum confidence, learning from triage, the analysis engine and virtual lockfile resolution. |

### Step 3 - Confirm your authorization

Before the first scan of a target, Secure Repo shows the **rules of engagement** and asks:

```
[?] I confirm I am authorized to audit <target> [y/n] (n):
```

Answer `y` only if you own the repository or have written permission.

### Step 4 - Branch recon: pick a branch

Secure Repo enumerates the branches and prints them. For remote URLs it uses `git ls-remote` (nothing is
downloaded yet); for local repositories it lists local and remote-tracking branches.

<img src="docs/images/cli-menu-branches.svg" alt="Main console and branch recon" width="900">

- **Private or organization repository?** If the remote asks for authentication, Secure Repo explains which
  token to create and asks for it (hidden input). See [Private and organization repositories](#private-and-organization-repositories).
- Press **Enter** to accept the highlighted default (the branch you are on, or the remote default branch).
- Or type the **number** or the **name** of a branch.
- Local repository, current branch → the working tree is scanned (uncommitted changes included).
- Local repository, another branch → the branch is exported with `git archive` to a temporary folder.
- Remote repository → a shallow clone (`--depth 1`) of that single branch is made in a temporary folder and
  deleted afterwards.
- A folder that is not a Git repository is scanned as-is.

### Step 5 - Optional compliance audit

```
[?] Run the optional compliance audit as well? [y/n] (n):
```

Answer `y` and choose the frameworks (numbers separated by commas, or `all`). You can also turn it on
permanently for the session in **Settings**.

### Step 6 - Watch the live operation

While the scan runs, the terminal shows a live dashboard:

<img src="docs/images/cli-live-dashboard.svg" alt="Live operation dashboard" width="900">

| Panel | What it tells you |
|---|---|
| **LIVE OPERATION** | Target, branch, elapsed time and the file being analyzed right now. |
| **ATTACK SURFACE PIPELINE** | The 10 stages: acquire source → map structure → code/secret/config analysis → libraries → version resolution (virtual lockfile) → vulnerability intelligence → hygiene → compliance → scoring → reports. `[+]` done, spinner = running, `[-]` skipped. |
| **STRUCTURE MAP** | One box per top-level directory with its progress bar and the number of findings (`▲`). The border takes the color of the worst severity inside. |
| **ACTIVITY FEED** | Every step and every critical/high/medium finding, as it happens. |
| **Footer** | Live counters per severity and files processed. |

Press `Ctrl+C` at any time to abort; temporary files are cleaned up.

### Step 7 - Read the mission report

When the scan ends you get the full picture:

<img src="docs/images/cli-mission-report.svg" alt="Mission report" width="900">

- **Security posture**: score 0-100, grade A-F and severity histogram.
- **OWASP Top 10 (2021)** distribution.
- **Analysis quality**: findings per engine, noise discarded automatically and suppressed findings.
- **Top findings** with ID, severity, location, confidence and CWE (`→ data flow` marks taint-confirmed findings).
- **Libraries & supply chain**: vulnerable, compromised, deprecated or unpinned libraries with advisories and
  the latest available version.
- **Compliance audit** scores (when enabled).
- **Repository structure map** as boxes, with the worst severity per directory.
- **Evidence locker**: the tree of the report folder that was just created.

### Step 8 - Post-scan actions

```
──────────────────────────── ⟦ POST-SCAN ACTIONS ⟧ ────────────────────────────
  [1]  Browse findings & explanations
  [2]  Triage findings - mark false positives / accepted risk (the engine learns)
  [3]  Repository structure (boxes + tree)
  [4]  Full library inventory + virtual lockfile
  [5]  Compliance details
  [6]  Analysis quality (engines, noise discarded, suppressed findings)
  [7]  Open interactive HTML report in the browser
  [8]  Open the report folder
  [9]  Explore these results in the GUI
  [0]  Back to main menu
```

In **Browse findings** you can filter by severity (`critical`, `high`, ...), type `suppressed`, search by text,
or type a finding ID such as `SR-0004` to read:

- the evidence (secrets redacted) and the confidence score with its reasons,
- **DATA FLOW** - for taint-confirmed findings, every step from the untrusted source to the sink,
- **WHY IS THIS INSECURE?** - a plain-English explanation of the risk,
- **HOW TO FIX** - the recommended remediation,
- CWE and OWASP references, and for libraries the advisories with the fixed versions.

In **Triage findings** type one or more IDs, choose *false positive*, *accept risk*, *confirmed* or *open again*,
give a reason and - for false positives - a scope (this finding, this code pattern in the project, or everywhere).
The score and every report file in the folder are regenerated immediately.

### Step 9 - Non-interactive mode (scripts & CI/CD)

Everything in the menus is also available as flags:

```bash
# audit the repository in the current directory (asks for the branch if the terminal is interactive)
secure-repo scan

# audit a remote repository, a specific branch, with the compliance audit for two frameworks
secure-repo scan https://github.com/owner/repo.git -b develop --compliance pci-dss,gdpr

# CI pipeline: no prompts, no network, fail the job on high or critical findings
secure-repo scan . --yes --offline --plain --no-menu --fail-on high
```

Exit codes: `0` success · `1` error · `2` invalid usage · `3` findings at/above `--fail-on` · `130` aborted.

---

## Private and organization repositories

Private repositories, and repositories of organizations that require authentication, need an **access token**
with read access.

| Host | Token to create | Username used |
|---|---|---|
| GitHub | Fine-grained token with *Contents: Read* on the repository, or a classic token with `repo`. If the organization enforces SAML SSO, also click *Configure SSO → Authorize*. | `x-access-token` |
| GitLab | Personal, project or group access token with `read_repository` | `oauth2` |
| Bitbucket | Repository access token with *Repositories: Read* | `x-token-auth` |
| Azure DevOps | Personal access token with *Code (Read)* | `pat` |

**Interactive (CLI and GUI).** Just paste the `https://` URL. When the remote answers "authentication required",
Secure Repo shows what to create and asks for the token: hidden input in the terminal, a password field in the
GUI. A rejected token is reported and you can try again.

**Scripts and CI.** Never write the token on the command line, because it would stay in your shell history. Use:

```bash
export SECURE_REPO_GIT_TOKEN=...      # any host (or GH_TOKEN / GITHUB_TOKEN, GITLAB_TOKEN, BITBUCKET_TOKEN,
                                      # AZURE_DEVOPS_PAT for that provider)
secure-repo scan https://github.com/my-org/private-api.git -b main --yes

secure-repo scan https://github.com/my-org/private-api.git --token-env MY_SECRET_VAR --yes
secure-repo scan https://github.com/my-org/private-api.git --ask-token
```

**How the token is protected**

- It is kept **in memory only** for the session and dropped when the scan ends. It is never saved to disk, logs,
  reports or the cloned repository's configuration.
- It is handed to Git as an `Authorization` header **scoped to the repository host**, through environment
  variables. It never appears in the URL or in process arguments.
- Error messages are scrubbed. A URL with embedded credentials (`https://user:token@host/...`) is cleaned before
  anything is shown or stored.
- SSH URLs (`git@github.com:org/repo.git`) use your SSH key or agent instead of a token.
- A remote repository is always an **untrusted target**: its own configuration, shared triage and `nosec` comments
  are ignored (see the trust model below).

---

## Analysis engine & false-positive reduction

Findings go through several layers:

1. **Lexical masking.** Comments, docstrings and string contents are blanked before code patterns run, including multi-line ones.
2. **Python syntax tree and taint tracking.** Imports and aliases are resolved and arguments are inspected. Constant commands and queries, `Loader=SafeLoader`, `usedforsecurity=False` and randomness outside a security context are ignored. Untrusted data (`request.*`, route parameters, `input()`, `sys.argv`) is followed through variables until it reaches a sink.
3. **JavaScript/TypeScript data flow.** The flow is tracked per function scope. Constant sinks such as `el.innerHTML = ''` are discarded, flows from `req.*`, `location.*` and `event.data` are escalated, and `RegExp.exec` is not confused with `child_process.exec`.
4. **Confidence model.** Each finding gets a 0-100 score that combines the engine, the location (tests, examples, generated code) and your triage history. Use `--min-confidence medium|high` to filter.

Findings confirmed by data flow show the full **source → sink trace** in the CLI, the GUI, the Markdown reports and SARIF `codeFlows`.

### How accurate is it? (measured on third-party code)

The built-in corpus is written by the rule authors, so its 100 % only proves that the rules fit their own
examples. The number that matters is measured on code the authors did not write. `secure-repo benchmark --external`
audits four public projects pinned to an exact commit, and every finding is reviewed by hand (the verdicts are plain
data in `secure_repo/benchmark/extdata/*.toml`, so they can be disputed).

| Project | Kind | Findings reviewed | Precision (all) | Precision (medium+ confidence) | Documented weaknesses found |
|---|---|---:|---:|---:|---:|
| NodeGoat (JavaScript) | vulnerable by design | 36 | 64 % | 100 % | 9 of 12 |
| DVPWA (Python) | vulnerable by design | 10 | 70 % | 100 % | 6 of 7 |
| Vulnerable-Flask-App (Python) | vulnerable by design | 24 | 75 % | 75 % | 8 of 9 |
| requests (Python) | clean, mature library | 16 | 12 % (all but two are test fixtures) | 12 % | n/a |
| **Total** | | **86** | **58 %** | **71 %** | **23 of 28 (82 %)** |

How to read it, honestly:

- **Precision** is the share of reported findings that are real weaknesses. Counting *every* finding, including
  low-confidence ones and findings in test code, it is 58 %; counting only findings of medium or high confidence it is
  71 %. In `requests`, a library audited for years, nothing is reported in its production code: the false positives are
  throw-away test certificates, URL-parsing test data and pickle/TLS tests.
- **Recall** is the share of weaknesses that really exist in the vulnerable projects and that were found at the exact
  line. The five misses are an SSRF whose URL travels through a variable, a hardcoded encryption key whose value looks
  like an identifier, CSRF protection commented out (two projects) and plain-text password handling: absent settings and
  logic flaws that no rule covers yet.
- 28 weaknesses and 86 findings in four projects is a small sample. Treat the numbers as a floor of evidence, not as a
  guarantee, and expect results to differ in your code. The benchmark runs in CI and fails if precision (medium+
  confidence) drops below 65 % or recall below 80 %; every new finding must be labelled before it can pass.
- Rules are tested one by one as well: each of the 172 rules ships a positive and a negative example in its data file
  (`secure_repo/ruledata/`), and the test suite runs all of them.

```bash
secure-repo benchmark                        # built-in corpus + the examples of every rule
secure-repo benchmark --external --fetch     # download the pinned projects and measure (needs git)
```

### Teach Secure Repo (learning loop)

- **Triage.** Mark findings as *confirmed*, *accepted risk* or *false positive* from the post-scan menu, from the GUI finding panel, or with `secure-repo triage mark <report-folder> SR-0004 --status false_positive --reason "..." --scope project-pattern`. A reason is required.
- **Stable fingerprints.** Decisions are re-applied automatically on every scan, even after lines move.
- **Learned patterns.** With scope `project-pattern` or `global-pattern`, the same code shape is suppressed everywhere.
- **Rule statistics.** Rules you often mark as false positives lose confidence automatically: `secure-repo triage stats`.
- **Team sharing.** Share decisions with `secure-repo triage export --to-repo .`, which writes `.securerepo/triage.json`. Other commands: `export`, `import`, `forget`, `reset`.
- **Audit trail.** Suppressed findings never affect the score or the compliance audit, but they stay in `findings/suppressed.md` with their reason, author and date.
- **Project tuning.** `secure-repo init-config` creates `.securerepo.toml`, where you can disable rules, override severities, allow-list paths or values, set a minimum confidence and write **custom rules**.
- **Benchmark.** `secure-repo benchmark --compare` measures precision and recall against the built-in labeled corpus (written by the rule authors, so treat it as a regression test: the layered engine scores 100 % / 100 %, versus 55 % / 67 % for the legacy pattern-only engine, `--engine patterns`). The real-world numbers are in *How accurate is it?* above. `secure-repo triage export-cases` turns your false positives into regression cases.

### Virtual lockfile

When a project has no lockfile, versions are resolved in this order: **lockfile → installed environment** (`node_modules`, virtualenvs, `vendor/`; works offline) **→ registry** (the version the declared range installs today; semver, PEP 440, Cargo, RubyGems, Composer, Pub and Maven/NuGet ranges) **→ dependency graph** (transitive packages from deps.dev).

All resolved versions are checked against OSV. `SR-DEP-009` warns when a range still admits vulnerable releases. The report adds `dependencies/virtual-lock.json` and `dependencies/lockfile-guide.md`, which contains the commands to create the real lockfile and the proposed pins.

---

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
| `--compliance [LIST]` | off | Enable the compliance audit. Without a value: all frameworks. Values: `owasp`, `pci-dss`, `iso27001`, `soc2`, `gdpr`, `hipaa`, `nist-ssdf`. |
| `--offline` | off | No network requests (no OSV.dev / deps.dev). |
| `--no-enrich` | off | Skip license / latest-version lookups but keep vulnerability lookups. |
| `-o, --output DIR` | `<data folder>/reports` | Where report folders are created. By default **outside** the audited repository (see below). |
| `-y, --yes` | off | Confirm you are authorized to audit the target (required when not interactive). |
| `--no-tests` | off | Do not analyze files that look like tests or fixtures. |
| `--max-file-size KB` | `2048` | Skip larger files. |
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
| `--engine layered\|patterns` | `layered` | Choose the analysis engine. |

`branches` also accepts `--ask-token` and `--token-env VARIABLE`.

`gui` options: `--port N` (default: random free port), `--no-browser`, `-o/--output DIR`, `--offline`.

---

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

---

## Graphical interface (GUI)

```bash
secure-repo gui
```

The GUI is a local web application. Secure Repo starts a server on `127.0.0.1`, prints the URL and opens your
browser. Close it with `Ctrl+C` in the terminal.

1. **Select target** - *This repository* (auto-detected), *Remote Git URL* or *Local folder*.
2. **Discover branches** - the same branch recon as the CLI; pick one from the list.
3. **Engagement options** - online intelligence, optional compliance audit (choose frameworks), test files, learning
   from triage, minimum confidence, analysis engine, max file size, auditor name, and the authorization
   confirmation.
4. **Initiate scan** - watch the pipeline, the live log and the **live structure map**: boxes light up as files are
   analyzed and turn orange/red when findings appear.
5. **Results** - overview, neural map, structure boxes, findings, libraries, compliance and export.
6. **Triage** - open any finding and mark it as false positive, accepted risk or confirmed; the score, the lists
   and the report folder are updated instantly and the decision is remembered for the next scans.

| | |
|---|---|
| <img src="docs/images/gui-overview.png" alt="Overview" width="440"> | <img src="docs/images/gui-neural-map.png" alt="Neural map" width="440"> |
| **Overview** - score, severity distribution, OWASP Top 10, hygiene, most exposed files and top weaknesses. | **Neural map** - files → weaknesses → OWASP categories → severity, with animated signal pulses. |
| <img src="docs/images/gui-neural-highlight.png" alt="Highlighted activation path" width="440"> | <img src="docs/images/gui-explanation.png" alt="Explanation drawer" width="440"> |
| **Activation paths** - search or click a node to light up everything connected to it. | **Explanations** - why it is insecure, how to fix it, evidence and references. |
| <img src="docs/images/gui-structure-boxes.png" alt="Structure boxes" width="440"> | <img src="docs/images/gui-compliance.png" alt="Compliance" width="440"> |
| **Structure** - nested boxes sized by bytes or lines and colored by risk. Click a folder to zoom in. | **Compliance** - per-framework score and every control with its evidence. |
| <img src="docs/images/gui-data-flow.png" alt="Data-flow trace" width="440"> | <img src="docs/images/gui-triage.png" alt="Triage panel" width="440"> |
| **Data flow** - the path of untrusted data from its source to the dangerous sink, with confidence reasons. | **Triage** - teach Secure Repo: false positive, accepted risk or confirmed, with reason and scope. |
| <img src="docs/images/gui-libraries.png" alt="Libraries" width="440"> | |
| **Libraries** - every library, how its version was resolved (lockfile, manifest, environment, registry, graph) and its advisories. | |

Neural map controls: click a node for its explanation · scroll to zoom · drag to pan · double-click to fit ·
switch between *Neural layers* and *Organic* (force-directed) layouts · filter by severity · toggle pulses.

**Downloads**: HTML report, full evidence ZIP, JSON, SARIF, Markdown summary, CycloneDX SBOM, CSV files, lockfile
guide, virtual lockfile and analysis-quality report, plus *Print / Save as PDF*. You can also re-open any `report.json` with **Load report**.

**GUI security model**: listens on `127.0.0.1` only · random per-session token (sent in the URL fragment, never
logged) · `Host` header validation against DNS rebinding · strict Content-Security-Policy with zero third-party
resources · the downloadable HTML report blocks all network access.

---

## What is analyzed

**Languages & technologies**: Python, JavaScript, TypeScript, Vue, Svelte, HTML templates (Jinja, EJS,
Handlebars, Razor, Thymeleaf, Twig), Java, Kotlin, Scala, Groovy, C#, PHP, Go, Ruby, Rust, C, C++,
Objective-C, Swift, Shell, PowerShell, Batch, Dockerfile, Docker Compose, Kubernetes, Terraform, CloudFormation,
GitHub Actions, GitLab CI, Android manifests, iOS plists, `.env`/INI/YAML/TOML/properties configuration.

**Weakness families**: injection (SQL, NoSQL, OS command, code, template, file inclusion), XSS, insecure
deserialization, SSRF, path traversal, open redirect, CSRF, weak cryptography and randomness, TLS/certificate
validation bypasses, hardcoded credentials and tokens, sensitive files, personal/payment data, debug and
permissive configurations, over-privileged containers, public cloud resources, CI/CD injection and unpinned
actions, memory-unsafe C functions, sensitive logging and repository security hygiene.

**Library ecosystems**:

| Ecosystem | Manifests / lockfiles |
|---|---|
| Python (PyPI) | `requirements*.txt`, `pyproject.toml` (PEP 621, Poetry, dependency groups), `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`, `setup.py`, `setup.cfg` |
| JavaScript (npm) | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 & Berry), `pnpm-lock.yaml` |
| Go | `go.mod` |
| Rust (crates.io) | `Cargo.toml`, `Cargo.lock` |
| Ruby (RubyGems) | `Gemfile`, `Gemfile.lock` |
| PHP (Packagist) | `composer.json`, `composer.lock` |
| Java (Maven) | `pom.xml` (with property resolution), `build.gradle(.kts)`, `libs.versions.toml` |
| .NET (NuGet) | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `Directory.Packages.props`, `packages.lock.json` |
| Dart (Pub) | `pubspec.yaml`, `pubspec.lock` |

For each library Secure Repo reports: version, direct/transitive, scope, source (registry/VCS/URL/path),
whether it is locked, known vulnerabilities (OSV), compromised/malicious or deprecated status, license and the
latest version (deps.dev).

---

### Support level by language

Not every language gets the same depth of analysis. Rule counts are the rules written *for* that language; the
43 language-agnostic rules (secrets, TLS, CORS, weak crypto, hardcoded credentials...) apply to every file on top.

| Level | Languages | What it means |
|---|---|---|
| **Deep** | Python (25 rules), JavaScript / TypeScript (24 rules) | Syntax-tree analysis with taint tracking from request data to sinks inside a file (Python), data-flow engine (JS/TS), comments and strings masked. Highest precision and the only languages where findings are confirmed by a source-to-sink path. |
| **Patterns with masking** | Java / Kotlin / Scala / Groovy (10), PHP (9), Go (7), Ruby (7), C# (6), C / C++ (7) | Regular-expression rules that run on comment- and string-masked code. They find known dangerous APIs, not data flow; expect more false positives and misses than in the deep tier. |
| **Basic** | Rust (3), Swift, Dart, Lua, Perl, Elixir, Solidity | A few rules plus the language-agnostic ones. |
| **Configuration and infrastructure** | Dockerfile, Docker Compose, Kubernetes, Terraform, CloudFormation, GitHub Actions / GitLab CI / other CI, shell and PowerShell, `.env` / INI / YAML / TOML | Dedicated checks (the Dockerfile analyzer understands stages and `USER`; workflow rules understand `run:` blocks). |
| **Dependencies** | 30 manifest and lock formats across PyPI, npm, Go, crates.io, RubyGems, Packagist, Maven/Gradle, NuGet, Pub | Advisories from OSV.dev, version resolution for the virtual lockfile, license and supply-chain checks. |

## Compliance audit

The audit is **optional** - enable it with `--compliance`, from *Settings* in the CLI or with the toggle in the
GUI. Each control receives **PASS**, **WARNING**, **FAIL** or **MANUAL** (needs human verification) with the
evidence that supports it.

| Framework | Scope evaluated |
|---|---|
| OWASP Top 10 (2021) | A01-A10 |
| PCI DSS 4.0.1 | 2.2.6, 3.5.1, 3.6.1, 4.2.1, 6.2.4, 6.3.1-6.3.3, 8.3.2, 8.6.2, 10.2.1, 11.3.1 |
| ISO/IEC 27001:2022 Annex A | A.5.32, A.8.4, A.8.8, A.8.9, A.8.12, A.8.15, A.8.20, A.8.24-A.8.26, A.8.28, A.8.29, A.8.32 |
| SOC 2 (TSC) | CC6.1, CC6.6, CC6.7, CC6.8, CC7.1, CC7.2, CC8.1, C1.1 |
| GDPR | Art. 5(1)(f), 25, 30, 32(1)(a), 32(1)(b), 32(1)(d), 33 |
| HIPAA Security Rule | 164.308(a)(1)(ii)(A), 164.308(a)(5)(ii)(B), 164.312(a)(1), (a)(2)(iv), (b), (c)(1), (d), (e)(1) |
| NIST SSDF (SP 800-218) | PO.1, PO.3, PS.1, PS.3, PW.4, PW.5, PW.7, PW.9, RV.1 |

The results are **technical evidence that helps you comply** - they are not a certification, attestation or
legal opinion and they do not replace a qualified auditor. The audit itself respects audit principles: it is
read-only, reproducible (commit SHA recorded), attributable (auditor name), time-stamped and tamper-evident
(`MANIFEST.sha256`).

---

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

### Honest scoring and blind spots

- **Grade cap.** An open critical finding in production code caps the grade at **D (max 59)**, and an open high
  one at **C (max 74)**, however clean the rest of the repository is. Findings in tests, suppressed or accepted
  findings never trigger the cap. The report shows the score you would have had without it.
- **What was NOT analyzed.** `quality.md`, the CLI and the GUI list every skipped folder (with the reason), minified
  bundles (analyzed in a reduced mode: secrets and critical findings only), files over the size limit, binaries and
  dependency manifests with a syntax error (their libraries are missing from the inventory).
- **Folders named `build`, `dist`, `target`, `vendor`...** are skipped only with evidence (listed in `.gitignore`,
  `vendor/` at the root or next to `go.mod`/`composer.json`/`Gemfile`, or full of build artifacts). A source folder
  that merely has one of those names is analyzed. `node_modules`, `.git` and similar are always skipped.
- **Regex safety.** Custom rule patterns and allowlist values that could cause catastrophic backtracking (ReDoS)
  are rejected with an error instead of hanging the scan.
- **CSV safety.** Cells starting with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheets never run them.

### Fewer false positives (how confidence and severity are calibrated)

Nothing is hidden: every adjustment below lowers confidence or severity and says why in the finding's
*confidence reasons*.

- **Bundled third-party libraries** (a `jquery-3.6.0.js` or a `materialize.js` copied into `static/js/`, recognised by
  file name, by a `/*! Library vX.Y` banner, or by a `vendor/`-style folder) are reported at low confidence, marked as
  third-party, weigh half in the score and never trigger the grade cap. Update the library instead of editing it.
- **Documentation examples:** code inside `<pre>`/`<code>` blocks of HTML templates, and files under `docs/`,
  `tutorial/`, `examples/`, `samples/`, is reported at low confidence.
- **Test code** is reported in its own file (`findings/tests.md`), one severity level lower, and weighs half.
- **SQL built by formatting** (`SR-PY-011`) is capped at medium confidence unless an untrusted source is confirmed,
  and drops to low when only internal identifiers (`self.*`, `quote_name()`, numbers) are interpolated. The finding
  names the interpolated value and shows the whole multi-line call as evidence.
- **GitHub Actions expressions** (`SR-CI-002`) are reported only inside `run:` and `github-script` `script:` bodies,
  never under `env:` or `with:`, which is the mitigation the rule itself recommends.
- **File names:** `Dockerfile.db`, `Makefile.dev`... are variants of a tool file, not database or key files.

### Stable rule IDs

A rule's ID reflects the languages it applies to. Rules that used to carry a misleading prefix were renamed to
language-neutral IDs (`SR-JS-010/019/020/021` -> `SR-GEN-008/009/010/011`, `SR-JAVA-002/007` -> `SR-GEN-012/013`).
The old IDs keep working in `.securerepo.toml`, in `nosec` comments and in your triage history, and fingerprints of
existing decisions are unchanged.

---

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

---

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

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `git is not installed or not on PATH` | Install Git and open a new terminal. |
| Private repository: branch discovery fails | Configure your Git credentials first (SSH key, Git Credential Manager or `gh auth login`), check that `git ls-remote <url>` works, or use an SSH URL. |
| `Vulnerability intelligence unavailable` | No internet or a proxy blocks it. Set `HTTPS_PROXY`, or run with `--offline`. |
| Strange characters on old Windows consoles | Use Windows Terminal, or run with `--plain`. |
| `secure-repo` command not found | Use `python -m secure_repo`, the launchers, or add Python's `Scripts`/`bin` folder to `PATH`. |
| GUI says "Invalid or missing session token" | Open the exact URL printed in the terminal (it contains `#token=...`). |
| Private repository: "Authentication required" | Enter an access token when asked, or set `SECURE_REPO_GIT_TOKEN`. See [Private and organization repositories](#private-and-organization-repositories). |
| The token is rejected | Check the scope (read access to the repository), the expiry and, for GitHub organizations with SAML SSO, that the token is authorized for the organization. |
| `Local changes ... prevent a safe update` | You edited files of your Secure Repo clone. Run `git stash` (or commit) in the Secure Repo folder, then update again. |
| No update notice appears | Checks are cached for 6 hours. Run `secure-repo update --check` to force one; they are skipped in CI and with `--no-update-check`. |
| Scan is slow on huge repositories | Use `--exclude` for generated folders and a lower `--max-file-size`. |
| A finding is a false positive | Triage it (post-scan menu option 2, the GUI panel or `secure-repo triage mark`) with scope *project-pattern* so similar code is suppressed too. |
| I want the old behaviour | `--engine patterns` runs the legacy regular-expression engine; `--no-learning` ignores your triage history. |

---

## Project layout

```
Secure_Repo/
├── secure_repo/
│   ├── cli/          banner & ASCII art, live dashboard, menus, result views, entry point
│   ├── core/         scanner, updater, 172 rules, lexical masking, Python AST/taint and JS data-flow engines,
│   │                 dependency parsers, version resolver (virtual lockfile), vulnerability intelligence,
│   │                 triage knowledge base, confidence model, compliance frameworks, scoring
│   ├── ruledata/     the detection rules as TOML (pattern, explanation and positive/negative examples)
│   ├── benchmark/    labeled corpus, rule-example runner and the external benchmark manifests
│   ├── report/       report folder writer, Markdown, SARIF, CycloneDX, CSV, self-contained HTML
│   └── gui/          local server + static web app (neural map, box map, UI)
├── tests/            pytest suite (CLI, GUI server, dependency parsers, intelligence, regression tests)
├── docs/images/      screenshots used in this README
├── .github/          CI workflow (3 platforms, lint, types, self-audit) and Dependabot
├── requirements.lock hashed, universal lock of the runtime dependencies (generated from pyproject.toml)
├── run.sh / run.bat  one-step launchers
├── CHANGELOG.md      release notes
├── LICENSE           Secure Repo Ethical Source-Available License
└── SECURITY.md       how to report a vulnerability in Secure Repo
```

### Development

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov        # tests + coverage gate (pyproject.toml: [tool.coverage.report] fail_under)
ruff check .                  # lint, including security rules (S)
mypy secure_repo              # types (modules with known type debt are listed in pyproject.toml)
```

### Adding or changing a rule

Rules are data, not code: edit the table of the rule (or add one) in `secure_repo/ruledata/<prefix>.toml`. A rule
needs an ID, title, severity, CWE/OWASP, a pattern (regular expression) or an engine that owns it, a description, a
recommendation and **at least one positive and one negative example**:

```toml
[[rule]]
id = 'SR-PY-099'
title = 'Example rule'
severity = 'high'
category = 'Injection'
languages = ['@PY']                 # '@PY', '@JS', '@CODE' are language groups; '*' means every file
pattern = '\bdangerous_call\s*\('
description = 'Why this is dangerous.'
recommendation = 'What to do instead.'

[[rule.example]]
kind = 'positive'
code = 'dangerous_call(user_input)'

[[rule.example]]
kind = 'negative'
code = 'safe_call(user_input)'
```

Secret-shaped examples must not contain real-looking tokens: write `AKIA<<upper:16>>` and the test runner builds the
value at run time (`<<alnum:N>>`, `<<hex:N>>`, `<<digits:N>>`, `<<b64url:N>>`, `<<lit:text>>`). Then run
`python -m pytest tests/test_rules_data.py`. Patterns that could backtrack catastrophically are rejected by the tests.

Continuous integration (`.github/workflows/ci.yml`) runs lint, types and the tests on Linux, Windows and macOS
with Python 3.9 and 3.13, and then audits this repository with Secure Repo itself (`--fail-on high`), uploading the
SARIF report to GitHub code scanning. Every action is pinned to a full commit SHA and the workflow has read-only
permissions; Dependabot proposes weekly updates for the Python dependencies and the actions.

Regenerate the lock after changing the dependencies in `pyproject.toml`:

```bash
uv pip compile pyproject.toml --universal --generate-hashes --python-version 3.9 -o requirements.lock
```

---

## License

Copyright © 2026 **Wissen01720**. All rights reserved.

Secure Repo is distributed under the **Secure Repo Ethical Source-Available License**: you may use it, study it
and use its reports (also inside your company) for lawful, authorized security work. You may **not** use it to
access code without permission, steal or misuse the information it finds, attack systems, remove the
attribution, claim authorship, sell it or publish modified versions without permission. Read the full
[LICENSE](LICENSE).
