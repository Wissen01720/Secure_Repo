"""Vulnerability intelligence with simulated OSV.dev / deps.dev responses: batching, errors, scoring (C-38)."""
import io
import json
import urllib.error

import pytest

from secure_repo.core import intel
from secure_repo.core.events import EventBus
from secure_repo.core.models import Dependency


def dep(name, version="1.0.0", ecosystem="PyPI", direct=True, source="registry"):
    return Dependency(name=name, ecosystem=ecosystem, version=version, spec=version, manifest="requirements.txt",
                      direct=direct, source=source)


class FakeNetwork:
    """Replaces intel._http_json and records every call."""

    def __init__(self, batch=None, details=None, metadata=None, fail=None):
        self.calls, self.batch, self.details, self.metadata, self.fail = [], batch or {}, details or {}, metadata or {}, fail

    def __call__(self, url, payload=None, timeout=20, cache=False):
        self.calls.append((url, payload))
        if self.fail:
            raise self.fail
        if url == intel.OSV_BATCH_URL:
            results = []
            for query in payload["queries"]:
                ids = self.batch.get((query["package"]["name"], query["version"]), [])
                results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
            return {"results": results}
        if url.startswith(intel.OSV_VULN_URL):
            vuln_id = url[len(intel.OSV_VULN_URL):]
            if vuln_id in self.details:
                return self.details[vuln_id]
            raise urllib.error.URLError("boom")
        for key, value in self.metadata.items():
            if url.endswith(key):
                return value
        raise urllib.error.URLError("not found")


ADVISORY = {
    "id": "GHSA-aaaa", "aliases": ["CVE-2024-0001"], "summary": "Remote code execution",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"package": {"name": "Flask"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}],
    "references": [{"url": "https://example.org/advisory"}], "published": "2024-01-01T00:00:00Z",
}


def test_cvss_scores_match_the_specification():
    assert intel.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert intel.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert intel.cvss3_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") == 1.8
    assert intel.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert intel.cvss3_score("garbage") is None and intel.cvss3_score("CVSS:3.1/AV:X") is None


@pytest.mark.parametrize("score,severity", [(9.8, "critical"), (7.0, "high"), (5.5, "medium"), (2.0, "low"), (0.0, "info"),
                                            (None, "medium")])
def test_score_to_severity_bands(score, severity):
    assert intel.score_to_severity(score) == severity


def test_normalize_vulnerability_collects_fix_versions_and_severity():
    vuln = intel.normalize_vulnerability(ADVISORY, "flask")
    assert vuln["severity"] == "critical" and vuln["cvss"] == 9.8 and vuln["fixed"] == ["2.2.5"]
    assert vuln["url"].endswith("GHSA-aaaa") and vuln["references"] == ["https://example.org/advisory"]
    malware = intel.normalize_vulnerability({"id": "MAL-2024-1", "summary": "malicious"}, "x")
    assert malware["severity"] == "critical"
    labelled = intel.normalize_vulnerability({"id": "X", "database_specific": {"severity": "MODERATE"}}, "x")
    assert labelled["severity"] == "medium" and labelled["references"]


def test_osv_lookup_attaches_deduplicated_advisories(monkeypatch):
    network = FakeNetwork(batch={("flask", "1.0.0"): ["GHSA-aaaa", "CVE-2024-0001"]},
                          details={"GHSA-aaaa": ADVISORY, "CVE-2024-0001": dict(ADVISORY, id="CVE-2024-0001",
                                                                                aliases=["GHSA-aaaa"])})
    monkeypatch.setattr(intel, "_http_json", network)
    deps = [dep("flask"), dep("flask"), dep("requests", "2.0.0"), dep("local", source="path"), dep("x", ecosystem="Unknown")]
    queried, vulnerable = intel.osv_lookup(deps, EventBus())
    assert (queried, vulnerable) == (2, 2)                              # only registry packages of known ecosystems
    assert [len(d.vulnerabilities) for d in deps] == [1, 1, 0, 0, 0]    # the alias pair collapses into one advisory
    assert len([c for c in network.calls if c[0] == intel.OSV_BATCH_URL]) == 1


def test_osv_lookup_batches_in_chunks_of_500(monkeypatch):
    network = FakeNetwork()
    monkeypatch.setattr(intel, "_http_json", network)
    deps = [dep(f"pkg{i}") for i in range(1203)]
    assert intel.osv_lookup(deps, EventBus()) == (1203, 0)
    sizes = [len(payload["queries"]) for url, payload in network.calls if url == intel.OSV_BATCH_URL]
    assert sizes == [500, 500, 203]


def test_osv_lookup_survives_a_failed_detail_download(monkeypatch):
    network = FakeNetwork(batch={("flask", "1.0.0"): ["GHSA-missing"]})
    monkeypatch.setattr(intel, "_http_json", network)
    deps = [dep("flask")]
    assert intel.osv_lookup(deps, EventBus()) == (1, 1)
    assert deps[0].vulnerabilities[0]["id"] == "GHSA-missing"
    assert "unavailable" in deps[0].vulnerabilities[0]["summary"].lower()


def test_osv_lookup_with_nothing_to_query_makes_no_request(monkeypatch):
    network = FakeNetwork()
    monkeypatch.setattr(intel, "_http_json", network)
    assert intel.osv_lookup([dep("local", source="path")], EventBus()) == (0, 0)
    assert network.calls == []


@pytest.mark.parametrize("error", [
    urllib.error.HTTPError("https://api.osv.dev", 429, "Too Many Requests", {}, io.BytesIO(b"")),
    urllib.error.URLError("timed out"), TimeoutError("timed out")])
def test_batch_errors_propagate_so_the_caller_can_degrade(monkeypatch, error):
    monkeypatch.setattr(intel, "_http_json", FakeNetwork(fail=error))
    with pytest.raises((urllib.error.URLError, OSError)):
        intel.osv_lookup([dep("flask")], EventBus())


def test_vulnerability_ids_only(monkeypatch):
    monkeypatch.setattr(intel, "_http_json", FakeNetwork(batch={("flask", "1.0.0"): ["GHSA-aaaa"]}))
    found = intel.osv_vulnerability_ids([("PyPI", "flask", "1.0.0"), ("PyPI", "requests", "2.0.0"), ("Nope", "x", "1")])
    assert found == {("PyPI", "flask", "1.0.0"): ["GHSA-aaaa"]}


def test_depsdev_enrichment_fills_license_and_latest(monkeypatch):
    metadata = {
        "/packages/flask": {"versions": [{"versionKey": {"version": "3.0.0"}, "isDefault": True}]},
        "/versions/1.0.0": {"licenses": ["BSD-3-Clause"]},
    }
    monkeypatch.setattr(intel, "_http_json", FakeNetwork(metadata=metadata))
    deps = [dep("flask"), dep("unreachable", "9.9.9"), dep("transitive", direct=False)]
    assert intel.depsdev_enrich(deps, EventBus()) == 1                 # one lookup failed, one dependency is transitive
    assert deps[0].latest == "3.0.0" and deps[0].licenses == ["BSD-3-Clause"]
    assert deps[1].latest is None and deps[2].licenses == []


def test_http_json_sends_a_post_with_identifying_headers(monkeypatch):
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, size=-1):
            return b'{"ok": true}'

    def fake_urlopen(request, timeout=None, context=None):
        seen.update(method=request.get_method(), headers=dict(request.header_items()), body=request.data,
                    timeout=timeout, tls=context is not None)
        return Response()

    monkeypatch.setattr(intel.urllib.request, "urlopen", fake_urlopen)
    assert intel._http_json("https://api.osv.dev/x", {"a": 1}, timeout=7) == {"ok": True}
    assert seen["method"] == "POST" and json.loads(seen["body"]) == {"a": 1} and seen["timeout"] == 7 and seen["tls"]
    assert seen["headers"]["User-agent"].startswith("secure-repo/")
    intel._http_json("https://api.osv.dev/y")
    assert seen["method"] == "GET" and seen["body"] is None


def test_known_bad_packages():
    assert intel.known_bad(dep("event-stream", "3.3.6", "npm"))[0] == "SR-DEP-002"
    assert intel.known_bad(dep("event-stream", "4.0.0", "npm")) is None
    assert intel.known_bad(dep("flatmap-stream", "0.1.0", "npm"))[0] == "SR-DEP-002"      # every version is compromised
    assert intel.known_bad(dep("request", "2.88.0", "npm"))[0] == "SR-DEP-003"
    assert intel.known_bad(dep("request", "2.88.0", "npm", direct=False)) is None         # only direct use is flagged
    assert intel.known_bad(dep("flask")) is None


def test_major_version_parsing():
    assert intel.major("v12.3.4") == 12 and intel.major("3") == 3 and intel.major("x") is None and intel.major(None) is None
