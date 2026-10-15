"""Parallel file analysis must be indistinguishable from the sequential one, and must degrade gracefully (C-42)."""
import os

import pytest

from secure_repo.core import scanner as scanner_module
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import ScanCancelled, Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import FAKE_AWS_KEY, write

VULNERABLE_PY = ("import os, pickle\nfrom flask import request\n\ndef run():\n    os.system(request.args.get('c'))\n"
                 "    return pickle.loads(request.data)\n")


@pytest.fixture()
def repo(tmp_path):
    root = str(tmp_path / "r")
    for index in range(24):
        write(root, f"app/mod{index}.py", VULNERABLE_PY if index % 3 == 0 else "def f(x):\n    return x\n")
    for index in range(8):
        write(root, f"web/page{index}.js", "document.getElementById('x').innerHTML = location.hash;\n" if index % 2 else
              "const ok = 1;\n")
    write(root, "tests/test_mod.py", VULNERABLE_PY)
    write(root, "config/settings.py", f"AWS_KEY = '{FAKE_AWS_KEY}'\n")
    write(root, ".env", "MODE=production\n")                                           # sensitive file
    write(root, "static/bundle.js", "var a=1;" * 4000 + "\n")                        # minified bundle
    write(root, "static/jquery-3.6.0.js", "function go(c){ return eval(c); }\n")       # bundled library
    write(root, "docs/notes.md", "Run `os.system(cmd)` carefully.\n")
    with open(os.path.join(root, "data.bin"), "wb") as handle:                          # binary
        handle.write(bytes(range(256)) * 20)
    write(root, "requirements.txt", "flask>=2.0\n")
    return root


def run(root, **options):
    scanner = Scanner(ScanOptions(offline=True, trust_repo_config=True, learning=False, resolve_versions=False,
                                  **options), EventBus())
    report, _ = scanner.run(Target.parse(root), write_reports=False)
    return report, scanner


def comparable(report):
    return sorted((f["rule_id"], f["file"], f["line"], f["severity"], f["confidence"], f["status"], f["snippet"],
                   f["detail"]) for f in report["findings"])


def test_parallel_and_sequential_runs_produce_the_same_report(repo):
    sequential, _ = run(repo, jobs=1)
    parallel, scanner = run(repo, jobs=2, parallel_threshold=1)
    assert comparable(sequential) == comparable(parallel) and len(sequential["findings"]) > 20
    assert any("2 worker processes" in line for line in scanner.log_lines)
    for key in ("engines", "noise", "not_analyzed", "languages"):
        left = sequential["analysis"].get(key, sequential.get(key))
        right = parallel["analysis"].get(key, parallel.get(key))
        assert left == right, key
    assert sequential["summary"]["score"] == parallel["summary"]["score"]
    assert sequential["summary"]["by_severity"] == parallel["summary"]["by_severity"]
    assert sequential["structure"]["lines"] == parallel["structure"]["lines"]
    assert parallel["analysis"]["not_analyzed"]["minified"] == ["static/bundle.js"]


def test_worker_count_follows_the_options():
    scanner = Scanner(ScanOptions(jobs=4, parallel_threshold=100), EventBus())
    assert scanner._worker_count(50) == 1          # too few files to pay for starting workers
    assert scanner._worker_count(100) == 4
    assert scanner._worker_count(2) == 1
    assert Scanner(ScanOptions(jobs=1, parallel_threshold=1), EventBus())._worker_count(10_000) == 1
    auto = Scanner(ScanOptions(jobs=0, parallel_threshold=1), EventBus())._worker_count(10_000)
    assert 1 <= auto <= scanner_module.MAX_AUTO_JOBS


def test_the_scan_falls_back_to_one_process_when_workers_cannot_start(repo, monkeypatch):
    class Broken:
        def __init__(self, *args, **kwargs):
            raise OSError("no processes available")

    monkeypatch.setattr(scanner_module, "ProcessPoolExecutor", Broken)
    expected, _ = run(repo, jobs=1)
    report, scanner = run(repo, jobs=3, parallel_threshold=1)
    assert comparable(report) == comparable(expected)
    assert any("Parallel analysis is unavailable" in line for line in scanner.log_lines)


def test_a_cancelled_parallel_scan_stops(repo):
    scanner = Scanner(ScanOptions(offline=True, trust_repo_config=True, learning=False, jobs=2, parallel_threshold=1),
                      EventBus())
    scanner.cancelled = True
    with pytest.raises(ScanCancelled):
        scanner.run(Target.parse(repo), write_reports=False)


def test_process_file_hands_back_findings_and_counter_deltas(repo):
    worker = Scanner(ScanOptions(offline=True, learning=False), EventBus())
    worker.trusted = True
    info = next(i for i in scanner_module.enumerate_files(repo) if i.rel == "app/mod0.py")
    outcome = worker._process_file(info, collect=True)
    assert outcome["scanned"] and outcome["lines"] == 6 and outcome["skip"] is None
    assert {f.rule_id for f in outcome["findings"]} >= {"SR-PY-005", "SR-PY-002"}
    assert worker.findings == []                                   # collected findings are handed over, not duplicated
    assert outcome["engines"]["python_ast"] == 1
