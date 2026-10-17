# Troubleshooting

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)


| Problem | Solution |
|---|---|
| `git is not installed or not on PATH` | Install Git and open a new terminal. |
| Private repository: branch discovery fails | Configure your Git credentials first (SSH key, Git Credential Manager or `gh auth login`), check that `git ls-remote <url>` works, or use an SSH URL. |
| `Vulnerability intelligence unavailable` | No internet or a proxy blocks it. Set `HTTPS_PROXY`, or run with `--offline`. |
| Certificate errors behind a corporate proxy | Your network inspects TLS: pass `--ca-bundle company-ca.pem` or set `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`. |
| A report says some dependencies were not checked | See *What was NOT analyzed*: a batch failed after retries or a limit was reached (`--max-registry` ...). Run again; successful lookups are cached. |
| Strange characters on old Windows consoles | Use Windows Terminal, or run with `--plain`. |
| `secure-repo` command not found | Use `python -m secure_repo`, the launchers, or add Python's `Scripts`/`bin` folder to `PATH`. |
| GUI says "Invalid or missing session token" | Open the exact URL printed in the terminal (it contains `#token=...`). |
| Private repository: "Authentication required" | Enter an access token when asked, or set `SECURE_REPO_GIT_TOKEN`. See [Private and organization repositories](cli-guide.md#private-and-organization-repositories). |
| The token is rejected | Check the scope (read access to the repository), the expiry and, for GitHub organizations with SAML SSO, that the token is authorized for the organization. |
| `Local changes ... prevent a safe update` | You edited files of your Secure Repo clone. Run `git stash` (or commit) in the Secure Repo folder, then update again. |
| No update notice appears | Checks are cached for 6 hours. Run `secure-repo update --check` to force one; they are skipped in CI and with `--no-update-check`. |
| Scan is slow on huge repositories | Use `--exclude` for generated folders and a lower `--max-file-size`. |
| A finding is a false positive | Triage it (post-scan menu option 2, the GUI panel or `secure-repo triage mark`) with scope *project-pattern* so similar code is suppressed too. |
| I want the old behaviour | `--engine patterns` runs the legacy regular-expression engine; `--no-learning` ignores your triage history. |
