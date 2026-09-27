# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a vulnerability

If you find a vulnerability in Secure Repo itself, please report it **privately**:

1. Open a [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository, or
2. Contact the maintainer, **Wissen01720**, through the GitHub profile.

Please include the version, your operating system, reproduction steps and the impact you observed.
Do not open public issues for security problems and do not include real secrets or third-party data in your report.

## Design principles

- **Read-only:** the code being audited is never executed, built or installed.
- **Local first:** source code never leaves the machine. In online mode only package names and versions are sent
  to [OSV.dev](https://osv.dev) and [deps.dev](https://deps.dev). `--offline` disables every network request.
- **Secrets are redacted** in every report, log and screen.
- **Git hardening:** hooks are disabled, the `ext::` transport is blocked, clones are shallow and Git LFS
  downloads are skipped.
- **GUI isolation:** the web interface only listens on `127.0.0.1`, requires a random per-session token, validates
  the `Host` header (DNS-rebinding protection) and ships a strict Content-Security-Policy without third-party
  resources.
