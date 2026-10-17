# Development

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)


```
Secure_Repo/
├── secure_repo/
│   ├── cli/          banner & ASCII art, live dashboard, menus, result views, entry point, themes
│   ├── core/         the scanner is split in focused modules: scanner.py (orchestration and report),
│   │                 scan_analysis.py (files), scan_dependencies.py (libraries), scan_quality.py (trust, config,
│   │                 baseline, hygiene), scan_base.py / scan_common.py (shared state and options);
│   │                 plus the engines (lexer, pyast, jsflow, webchecks), dependency parsers, resolver,
│   │                 netio.py (the only module that talks to public services), triage, confidence,
│   │                 compliance frameworks and scoring
│   ├── ruledata/     the 175 detection rules as TOML (pattern, explanation, positive and negative examples)
│   ├── data/         versioned package lists (compromised / deprecated) with source and date
│   ├── benchmark/    labeled corpus, rule-example runner and the external benchmark (extdata/ manifests)
│   ├── report/       report folder writer, Markdown, SARIF, CycloneDX, CSV, self-contained HTML
│   └── gui/          local server + static web app (one JavaScript file per view: app-*.js)
├── tests/            pytest suite (CLI, GUI server, parsers, intelligence, rules and regression tests)
├── tools/            release helpers (CHANGELOG section -> GitHub release notes)
├── docs/             this documentation and its screenshots (docs/images)
├── .github/          CI (3 platforms, lint, types, GUI lint, package build, accuracy benchmark, self-audit),
│                     the PyPI publishing workflow and Dependabot
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
npx eslint@8.57.0 --no-eslintrc -c .github/eslintrc.gui.json secure_repo/gui/static/*.js   # undefined names in the GUI
```

The supported Python versions are 3.10 and newer (tested on 3.10 and 3.13 in CI).

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
with Python 3.10 and 3.13, and then audits this repository with Secure Repo itself (`--fail-on high`), uploading the
SARIF report to GitHub code scanning. Every action is pinned to a full commit SHA and the workflow has read-only
permissions; Dependabot proposes weekly updates for the Python dependencies and the actions.

Regenerate the lock after changing the dependencies in `pyproject.toml`:

```bash
uv pip compile pyproject.toml --universal --generate-hashes --python-version 3.10 -o requirements.lock
```
