"""The external benchmark: manifests are valid and the scoring logic is right (C-08, C-58)."""
import os
import re

import pytest

from secure_repo.benchmark import external
from secure_repo.core.rules import RULES_BY_ID
from tests.conftest import write

CACHE = os.environ.get("SECURE_REPO_BENCH_CACHE", "")


def test_manifests_are_well_formed_and_reference_real_rules():
    manifests = external.load_manifests()
    assert {m.name for m in manifests} >= {"nodegoat", "dvpwa", "flask-vuln", "requests"}
    assert {m.kind for m in manifests} == {"vulnerable", "clean"}
    for manifest in manifests:
        assert re.fullmatch(r"[0-9a-f]{40}", manifest.commit), manifest.name
        assert manifest.repo.startswith("https://github.com/"), manifest.name
        identifiers = [k.id for k in manifest.known]
        assert len(identifiers) == len(set(identifiers)), manifest.name
        for known in manifest.known:
            assert all(rule in RULES_BY_ID for rule in known.rules), known.id
            assert known.file and known.title
        for verdict in manifest.verdicts:
            assert verdict.rule in RULES_BY_ID, (manifest.name, verdict.rule)
            assert verdict.verdict in ("TP", "FP") and verdict.file
            if verdict.verdict == "FP":
                assert verdict.note, f"{manifest.name}: an FP verdict needs a reason ({verdict.rule} {verdict.file})"
    clean = [m for m in manifests if m.kind == "clean"]
    assert clean and all(not m.known for m in clean)


def test_the_benchmark_covers_several_vulnerable_projects_and_a_clean_one():
    manifests = external.load_manifests()
    assert sum(len(m.known) for m in manifests) >= 25
    assert sum(1 for m in manifests if m.kind == "vulnerable") >= 3


def make_manifest(kind="vulnerable"):
    return external.Manifest(
        name="demo", repo="https://github.com/example/demo.git", commit="0" * 40, kind=kind, language="Python",
        known=[external.Known(id="D-1", title="eval of request data", file="app.py", rules=["SR-PY-001"], line=4),
               external.Known(id="D-2", title="something no rule covers", file="app.py", rules=[], line=9)],
        verdicts=[external.Verdict(rule="SR-PY-001", file="app.py", verdict="TP"),
                  external.Verdict(rule="SR-PY-009", file="app.py", verdict="FP", note="not security relevant")])


def test_scoring_counts_true_and_false_positives_recall_and_unlabeled_findings(tmp_path):
    root = str(tmp_path / "demo")
    write(root, "app.py", "import random\n\ndef run(expr):\n    return eval(expr)\n\ndef pick():\n    return random.random()\n")
    write(root, "tool.py", "import pickle\n\ndef load(blob):\n    return pickle.loads(blob)\n")      # no verdict for this one
    result = external.evaluate(make_manifest(), root)
    assert result.tp == 1 and result.tp_production == 1
    assert result.fp == 0 or result.fp == 1
    assert result.found == ["D-1 eval of request data (app.py)"]
    assert len(result.missed) == 1 and result.missed[0].startswith("D-2")
    assert result.recall == 0.5
    assert any(item.startswith("SR-PY-002 tool.py") for item in result.unlabeled)


def test_a_verdict_with_a_line_only_applies_to_that_line(tmp_path):
    root = str(tmp_path / "demo")
    write(root, "app.py", "def a(x):\n    return eval(x)\n\ndef b(x):\n    return eval(x)\n")
    manifest = make_manifest()
    manifest.known = []
    manifest.verdicts = [external.Verdict(rule="SR-PY-001", file="app.py", verdict="TP", line=2),
                         external.Verdict(rule="SR-PY-001", file="app.py", verdict="FP", note="test double", line=5)]
    result = external.evaluate(manifest, root)
    assert (result.tp, result.fp, result.unlabeled) == (1, 1, [])


def test_totals_and_per_language_grouping():
    first, second = external.RepoResult(make_manifest()), external.RepoResult(make_manifest("clean"))
    first.tp, first.fp, first.tp_confident, first.fp_confident, first.found, first.missed = 8, 2, 8, 1, ["a", "b", "c"], ["d"]
    second.tp, second.fp, second.tp_confident, second.fp_confident = 1, 1, 1, 1
    total = external.totals([first, second])
    assert (total["tp"], total["fp"]) == (9, 3) and total["precision"] == pytest.approx(0.75)
    assert total["precision_confident"] == pytest.approx(9 / 11) and total["recall"] == pytest.approx(0.75)
    assert external.by_language([first, second])[0][0] == "Python"
    assert external.RepoResult(make_manifest()).precision == 1.0 and external.RepoResult(make_manifest()).recall is None


def test_a_missing_checkout_is_reported_clearly(tmp_path):
    with pytest.raises(FileNotFoundError, match="--fetch"):
        external.run(str(tmp_path))


@pytest.mark.skipif(not CACHE, reason="set SECURE_REPO_BENCH_CACHE to a folder with the pinned repositories")
def test_measured_numbers_on_third_party_code_stay_above_the_floor():
    results = external.run(CACHE)
    total = external.totals(results)
    assert total["unlabeled"] == 0, [u for r in results for u in r.unlabeled]
    assert total["precision_confident"] >= 0.65 and total["recall"] >= 0.80
