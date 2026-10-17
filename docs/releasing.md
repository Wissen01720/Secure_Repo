# Releasing

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)

How a version reaches users. Nothing here runs by itself except the checks of CI; every outward step (a tag, a GitHub
release, a PyPI upload) is a deliberate action of the maintainer.

## Versions

- The version lives in two places that must agree: `secure_repo/__init__.py` (`__version__`) and `pyproject.toml`
  (`version`). A test and the publish workflow fail when the release tag does not match.
- Releases follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`. Each release has a section in
  [CHANGELOG.md](../CHANGELOG.md) (Keep a Changelog layout) before it is tagged.
- Tags are named `vMAJOR.MINOR.PATCH` and point at the commit that bumped the version.

## Cutting a release

1. Make sure `main` is green in CI (lint, types, tests on Linux/Windows/macOS, accuracy benchmark, self-audit).
2. Update `CHANGELOG.md`, the version in both files, and the numbers quoted in the README if the benchmark moved.
3. Commit, push, wait for CI.
4. Tag and publish the release (the notes are the matching CHANGELOG section):

   ```bash
   git tag -a v1.3.0 -m "Secure Repo 1.3.0"
   git push origin v1.3.0
   gh release create v1.3.0 --title "Secure Repo 1.3.0" --notes-file <(python tools/release_notes.py 1.3.0)
   ```

   `tools/release_notes.py 1.3.0` prints the CHANGELOG section of that version.

## Publishing to PyPI (Trusted Publishing)

`.github/workflows/publish.yml` uploads the package when a GitHub release is **published**. It uses PyPI
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OpenID Connect): no API token is stored in the
repository. One-time setup, done by the maintainer:

1. On pypi.org, create a **pending publisher** (Account → Publishing) with: project name `secure-repo`, owner
   `Wissen01720`, repository `Secure_Repo`, workflow `publish.yml`, environment `pypi`.
2. In the GitHub repository, create the environment **pypi** (Settings → Environments) and, if you want a manual
   gate, add yourself as a required reviewer.
3. Publish a release. The workflow builds the sdist and wheel, runs `twine check`, verifies that the tag matches the
   package version, and uploads them. After the first upload, `pipx install secure-repo` works.

The package metadata declares the licence as `LicenseRef-SecureRepo-Ethical-Source-Available` and ships the `LICENSE`
file. PyPI shows it as a custom licence; it is *source-available*, not OSI-approved open source.

## Branch protection

Recommended settings for `main` (Settings → Branches): require the CI checks (`Lint and types`, the test matrix,
`Accuracy on third-party code`, `Audit this repository with Secure Repo`) before merging, and block force pushes and
deletion. A single maintainer who pushes directly to `main` can keep "include administrators" off; contributors
should go through pull requests.
