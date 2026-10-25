# How the analysis works

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)

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
| NodeGoat (JavaScript) | vulnerable by design | 43 | 70 % | 100 % | 12 of 12 |
| DVPWA (Python) | vulnerable by design | 11 | 64 % | 100 % | 6 of 7 |
| Vulnerable-Flask-App (Python) | vulnerable by design | 27 | 78 % | 78 % | 8 of 9 |
| requests (Python) | clean, mature library | 16 | 12 % (all but two are test fixtures) | 12 % | n/a |
| **Total** | | **97** | **62 %** | **75 %** | **26 of 28 (93 %)** |

How to read it, honestly:

- **Precision** is the share of reported findings that are real weaknesses. Counting *every* finding, including
  low-confidence ones and findings in test code, it is 62 %; counting only findings of medium or high confidence it is
  75 %. In `requests`, a library audited for years, nothing is reported in its production code: the false positives are
  throw-away test certificates, URL-parsing test data and pickle/TLS tests.
- **Recall** is the share of weaknesses that really exist in the vulnerable projects and that were found at the exact
  line. The two misses are a CSRF middleware commented out in an aiohttp application (the CSRF rules cover Express
  and Django only) and plain-text password handling, a logic flaw that no rule covers. Be careful with NodeGoat's 12 of 12:
  five of its weaknesses are caught by rules (`SR-JS-025` to `SR-JS-028`, SSRF through `needle`, encryption-key names)
  that were written after reading NodeGoat's code, so that figure is tuned, not independent. The untuned signal is
  DVPWA and Vulnerable-Flask-App (14 of 16). **The benchmark guides the rules, so recall is optimistic for the projects
  it was built from.**
- 28 weaknesses and 89 findings in four projects is a small sample. Treat the numbers as a floor of evidence, not as a
  guarantee, and expect results to differ in your code. The benchmark runs in CI and fails if precision (medium+
  confidence) drops below 65 % or recall below 80 %; every new finding must be labelled before it can pass.
- Rules are tested one by one as well: each of the 193 rules ships a positive and a negative example in its data file
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

## Honest scoring and blind spots

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

## Fewer false positives (how confidence and severity are calibrated)

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

## Stable rule IDs

A rule's ID reflects the languages it applies to. Rules that used to carry a misleading prefix were renamed to
language-neutral IDs (`SR-JS-010/019/020/021` -> `SR-GEN-008/009/010/011`, `SR-JAVA-002/007` -> `SR-GEN-012/013`).
The old IDs keep working in `.securerepo.toml`, in `nosec` comments and in your triage history, and fingerprints of
existing decisions are unchanged.

## Compliance audit

The audit is **optional** - enable it with `--compliance`, from *Settings* in the CLI or with the toggle in the
GUI. Each control receives **PASS**, **WARNING**, **FAIL** or **MANUAL** (needs human verification) with the
evidence that supports it. The wording is deliberately cautious: **NO ISSUE FOUND** means that nothing the static
analysis could read contradicts the control, not that the control is satisfied (processes, run-time configuration
and anything outside the repository are invisible to it); **REVIEW** needs a human look; **ISSUE FOUND** links the
findings that contradict the control; **MANUAL** cannot be assessed from code. The *evidence score* is the share of
automatable controls with no issue found, not a compliance percentage.

| Framework | Scope evaluated |
|---|---|
| OWASP Top 10:2025 | A01-A10 of the 2025 edition, including the new A03 Software Supply Chain Failures and A10 Mishandling of Exceptional Conditions. Rules keep their stable 2021 codes (reports show both, for example A03:2021 Injection is A05:2025, and SSRF now belongs to A01:2025); the previous edition stays available as `owasp-2021` |
| OWASP Top 10 for LLM Applications (2025) | LLM01-LLM10. Checked from code: prompt injection patterns, model output executed or rendered, exposed keys, model supply chain, excessive agency. The rest is marked MANUAL. Only offered when the repository uses AI libraries (or an `SR-AI-*` rule fires) |
| OWASP Top 10 for Agentic Applications (2026) | ASI01-ASI10. Checked from code: tool permissions, code execution, MCP server supply chain, agent instruction files. Governance and runtime controls are marked MANUAL. Same applicability rule as the LLM list |
| PCI DSS 4.0.1 | 2.2.6, 3.5.1, 3.6.1, 4.2.1, 6.2.3, 6.2.4, 6.3.1-6.3.3, 8.3.2, 8.6.2, 10.2.1, 11.3.1 |
| ISO/IEC 27001:2022 Annex A (with Amendment 1:2024) | A.5.21, A.5.32, A.8.4, A.8.8, A.8.9, A.8.12, A.8.15, A.8.20, A.8.24-A.8.26, A.8.28, A.8.29, A.8.32 |
| SOC 2 (TSC) | CC6.1, CC6.6, CC6.7, CC6.8, CC7.1, CC7.2, CC8.1, C1.1 |
| GDPR | Art. 5(1)(f), 25, 30, 32(1)(a), 32(1)(b), 32(1)(d), 33 |
| HIPAA Security Rule | 164.308(a)(1)(ii)(A), 164.308(a)(5)(ii)(B), 164.312(a)(1), (a)(2)(iv), (b), (c)(1), (d), (e)(1) |
| NIST SSDF (SP 800-218 v1.1) | PO.1, PO.3, PS.1, PS.2, PS.3, PW.4, PW.5, PW.7, PW.9, RV.1, RV.2. Version 1.2 is a draft (December 2025); it is followed and will be adopted when final |


## Standards and sources tracked

The knowledge behind the reports is reviewed against the published standards with each release. Current baseline (reviewed 2026-10-25):

| Source | Edition used | Notes |
|---|---|---|
| OWASP Top 10 | 2025 (2021 mapped) | SSRF merged into A01; A03 and A10 are new |
| OWASP Top 10 for LLM Applications | 2025 (v2.0) | |
| OWASP Top 10 for Agentic Applications | 2026 | published December 2025 |
| MITRE CWE Top 25 | 2025 | each finding shows its rank when its weakness class is listed |
| PCI DSS | 4.0.1 | the current revision; future-dated requirements have applied since 31 March 2025 |
| ISO/IEC 27001 | 2022 + Amendment 1:2024 | no newer edition |
| NIST SSDF | SP 800-218 v1.1 | v1.2 is a public draft |
| HIPAA Security Rule | current rule | the January 2025 proposed update is not final |
| Language runtimes | end-of-life dates of Python, Node.js, PHP and Ruby | see `secure_repo/core/runtimes.py` |

The results are **technical evidence that helps you comply** - they are not a certification, attestation or
legal opinion and they do not replace a qualified auditor. The audit itself respects audit principles: it is
read-only, reproducible (commit SHA recorded), attributable (auditor name), time-stamped and tamper-evident
(`MANIFEST.sha256`).
