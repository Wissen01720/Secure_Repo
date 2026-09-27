# securerepo:ignore-file - deliberately vulnerable fixtures, written as text to temp dirs and never executed.
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def isolated_knowledge(tmp_path, monkeypatch):
    """Every test gets its own empty triage knowledge base (never the user's real one)."""
    home = tmp_path / "secure-repo-home"
    monkeypatch.setenv("SECURE_REPO_HOME", str(home))
    return str(home)


def write(root, rel, content):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return path


# Secret-shaped values are assembled at runtime so that this repository never contains them literally.
FAKE_AWS_KEY = "AKIA" + "Z7Q2" + "LMNP" + "4RST" + "UVWX"
FAKE_GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0" + "k1L2m3N4o5P6q7R8s9T0"


@pytest.fixture()
def vulnerable_repo(tmp_path):
    root = str(tmp_path / "vulnerable")
    write(root, "app/main.py", "\n".join([
        "import os, pickle, subprocess, yaml",
        f'AWS_ACCESS = "{FAKE_AWS_KEY}"',
        'DB_PASSWORD = "Sup3rS3cretPassw0rd!"',
        "def run(cmd, data):",
        '    subprocess.call("ls " + cmd, shell=True)',
        "    obj = pickle.loads(data)",
        '    cfg = yaml.load(open("c.yml"))',
        '    cursor.execute(f"SELECT * FROM t WHERE id = {cmd}")',
        '    return eval(cmd)',
        'MESSAGE = "never use eval() on user input"',
        "safe = eval(literal)  # nosec - reviewed",
    ]) + "\n")
    write(root, "web/index.js", "\n".join([
        "document.getElementById('x').innerHTML = location.hash;",
        f"const token = '{FAKE_GH_TOKEN}';",
        "db.query('SELECT * FROM users WHERE id = ' + req.params.id);",
    ]) + "\n")
    write(root, "requirements.txt", "flask==0.12.2\nrequests>=2.0\n--index-url http://mirror.example.org/simple\n")
    write(root, "package.json", '{\n  "dependencies": {\n    "lodash": "4.17.15",\n    "event-stream": "3.3.6",\n'
                                '    "mylib": "github:someone/mylib"\n  }\n}\n')
    write(root, "Dockerfile", "FROM python:latest\nRUN curl -sL https://get.example.io | sh\n")
    write(root, ".env", "API_TOKEN=abcd1234efgh5678ijkl\n")
    write(root, "docs/guide.md", "Example: `eval(user_input)` is dangerous.\n")
    return root


@pytest.fixture()
def git_repo(tmp_path):
    root = str(tmp_path / "gitrepo")
    write(root, "src/app.py", "print('hello')\n")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")

    def git(*args):
        subprocess.run(["git", *args], cwd=root, env=env, check=True, capture_output=True)

    git("init", "-q")
    git("add", "-A")
    git("commit", "-qm", "init")
    git("branch", "feature")
    git("checkout", "-q", "feature")
    write(root, "src/feature.py", "import pickle\nx = pickle.loads(blob)\n")
    git("add", "-A")
    git("commit", "-qm", "feature")
    git("checkout", "-q", "-")
    return root
