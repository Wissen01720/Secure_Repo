# Command-line guide

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)

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
  [6]  List detection rules (175)
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

<img src="images/cli-menu-branches.svg" alt="Main console and branch recon" width="900">

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

<img src="images/cli-live-dashboard.svg" alt="Live operation dashboard" width="900">

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

<img src="images/cli-mission-report.svg" alt="Mission report" width="900">

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

**Adopting it in an existing project without failing on day one.** `--fail-on high` fails on every old finding, which
is why gates get switched off. Two options make the gate about *new* problems only:

```bash
# 1. once, on main: keep the report as the baseline (the report folder is outside the repository by default)
secure-repo scan . --yes --plain --no-menu -o ci-reports
cp "ci-reports/$(cat ci-reports/latest.txt)/report.json" baseline.json      # commit it, or store it as a CI artifact

# 2. on every pull request: fail only on findings whose fingerprint is not in the baseline
secure-repo scan . --yes --plain --no-menu --baseline baseline.json --fail-on high

# or analyze only the files the pull request changed (fast on big repositories)
secure-repo scan . --yes --plain --no-menu --since origin/main --fail-on high
```

The report marks every finding as `new` or `existing` (`summary.baseline`, `extra.baseline`, and SARIF `baselineState`).
`--fail-on` never counts false positives, filtered or disabled findings or accepted risks, with or without a baseline.
`--since REF` needs the working tree of a local Git repository (in CI: `fetch-depth: 0` or `git fetch origin main`) and
still reports repository-level facts such as a missing SECURITY.md.

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
