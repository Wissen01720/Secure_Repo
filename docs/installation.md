# Installation and updates

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10 or newer | <https://www.python.org/downloads/> (on Windows tick *"Add python.exe to PATH"*) |
| Git | 2.20 or newer | <https://git-scm.com/downloads> - needed for branches and remote repositories |
| Internet | optional | Only for vulnerability intelligence. Everything else works with `--offline`. |
| Browser | any modern one | Only for the GUI and the HTML report |

Python dependencies: [`rich`](https://github.com/Textualize/rich) (and `tomli` on Python < 3.11). Nothing else.

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
`SECURE_REPO_NO_UPDATE_CHECK=1`. The list of changes of every release is in [CHANGELOG.md](../CHANGELOG.md).
