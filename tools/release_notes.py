"""Print the CHANGELOG.md section of one version (used as the body of a GitHub release).

usage: python tools/release_notes.py 1.3.0
"""
import os
import re
import sys


def section(version: str, path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.S | re.M)
    if not match:
        raise SystemExit(f"CHANGELOG.md has no section for version {version}")
    return match.group(1).strip() + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.stdout.write(section(sys.argv[1].lstrip("v"), os.path.join(root, "CHANGELOG.md")))
