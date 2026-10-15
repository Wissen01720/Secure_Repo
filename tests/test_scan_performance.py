"""Hostile files must not make the analysis blow up: every built-in regex has to stay (near) linear (C-07)."""
import time

import pytest

from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import write

SIZE = 120_000
FILLERS = {
    "plain": "x" * SIZE,
    "key_like": "password_" * (SIZE // 9),
    "dotted": "a.b." * (SIZE // 4),
    "quotes": "'" * SIZE,
    "double_quotes": '"a": ' * (SIZE // 5),
    "brackets": "(" * SIZE,
    "braces": "{" * SIZE,
    "comment_openers": "<!--" * (SIZE // 4),
    "slashes": "/*" * (SIZE // 2),
    "equals": "token=" * (SIZE // 6),
    "urls": "http://a:b@" * (SIZE // 11),
    "backslashes": "\\" * SIZE,
}
EXTENSIONS = ("py", "js", "ts", "vue", "html", "yml", "java", "kt", "cs", "php", "rb", "go", "rs", "c", "cpp", "swift", "sh",
              "ps1", "bat", "json", "xml", "md", "tf", "env", "ini", "properties", "toml", "gradle", "sql", "txt")


@pytest.mark.parametrize("name", sorted(FILLERS))
def test_a_single_hostile_line_is_analyzed_in_reasonable_time(tmp_path, name):
    root = str(tmp_path / "r")
    for extension in EXTENSIONS:
        write(root, f"hostile/{name}.{extension}", FILLERS[name] + "\n")
    started = time.time()
    scanner = Scanner(ScanOptions(offline=True, trust_repo_config=False, learning=False, jobs=1), EventBus())
    scanner.run(Target.parse(root), write_reports=False)
    elapsed = time.time() - started
    assert elapsed < 25, f"{name}: {elapsed:.1f}s for {len(EXTENSIONS)} files of {SIZE} characters"


def test_generic_credential_detection_is_linear_on_long_identifiers():
    from secure_repo.core import checks

    started = time.time()
    checks.find_generic_credentials("x" * 300_000 + "\n", "Python")
    checks.find_generic_credentials(("a" * 60 + "password" + "b" * 60 + "='value1234'\n") * 2000, "Python")
    assert time.time() - started < 5
    value = "".join(["Zr8!", "kd92", "Lq0x"])                 # assembled: no credential-shaped literal in the repository
    found = checks.find_generic_credentials(f"my_db_password = '{value}'\nCLIENT_SECRET: \"{value}\"\n", "Python")
    assert {key for _o, key, _v, _e in found} == {"my_db_password", "CLIENT_SECRET"}
