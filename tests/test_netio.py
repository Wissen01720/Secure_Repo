"""Network layer (C-31, C-33, C-35, C-36): retries, pagination, cache, size limits, CA bundle. No real network."""
import io
import json
import os
import urllib.error

import pytest

from secure_repo.core import intel, netio
from secure_repo.core.events import EventBus
from secure_repo.core.models import Dependency


@pytest.fixture(autouse=True)
def fresh_network(tmp_path, monkeypatch):
    monkeypatch.setattr(netio, "_sleep", lambda seconds: slept.append(seconds))
    slept.clear()
    for variable in netio.CA_ENVIRONMENT:
        monkeypatch.delenv(variable, raising=False)
    netio.configure(cache_dir=str(tmp_path / "cache"), ca_bundle="", cache=True, retries=3, backoff=0.5,
                    max_bytes=20 * 1024 * 1024)
    yield
    netio.configure(cache_dir="", ca_bundle="", cache=True)


slept = []


class FakeResponse:
    def __init__(self, body):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


def http_error(code, retry_after=None):
    headers = {"Retry-After": retry_after} if retry_after else {}
    return urllib.error.HTTPError("https://api.osv.dev/x", code, "err", headers, io.BytesIO(b""))


def script(monkeypatch, *outcomes):
    """urlopen returns / raises the given outcomes in order and records the requests."""
    calls = []
    queue = list(outcomes)

    def fake(request, timeout=None, context=None):
        calls.append(request)
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)

    monkeypatch.setattr(netio.urllib.request, "urlopen", fake)
    return calls


# ---------------------------------------------------------------------- retries
def test_transient_errors_are_retried_with_exponential_backoff(monkeypatch):
    calls = script(monkeypatch, http_error(503), urllib.error.URLError("reset"), {"ok": 1})
    assert netio.http_json("https://api.osv.dev/x") == {"ok": 1}
    assert len(calls) == 3 and slept == [0.5, 1.0]
    assert netio.STATS.retries == 2 and netio.STATS.failures == 0


def test_rate_limits_honour_retry_after_but_never_wait_too_long(monkeypatch):
    script(monkeypatch, http_error(429, "4"), http_error(429, "9999"), {"ok": 1})
    assert netio.http_json("https://api.osv.dev/x") == {"ok": 1}
    assert slept == [4.0, netio.MAX_RETRY_AFTER]


def test_the_error_is_raised_after_the_last_attempt(monkeypatch):
    calls = script(monkeypatch, http_error(500), http_error(502), http_error(503))
    with pytest.raises(urllib.error.HTTPError):
        netio.http_json("https://api.osv.dev/x")
    assert len(calls) == 3 and netio.STATS.failures == 1


def test_client_errors_are_not_retried(monkeypatch):
    calls = script(monkeypatch, http_error(404), {"ok": 1})
    with pytest.raises(urllib.error.HTTPError) as error:
        netio.http_json("https://api.deps.dev/v3/systems/pypi/packages/none")
    assert error.value.code == 404 and len(calls) == 1 and slept == []


def test_malformed_json_is_a_value_error_and_is_not_retried(monkeypatch):
    calls = script(monkeypatch, b"<html>proxy login</html>", {"ok": 1})
    with pytest.raises(ValueError):
        netio.http_json("https://api.osv.dev/x")
    assert len(calls) == 1


# ---------------------------------------------------------------------- size limit
def test_oversized_responses_are_rejected_without_being_read_whole(monkeypatch):
    netio.configure(max_bytes=64)
    script(monkeypatch, b'{"data": "' + b"x" * 500 + b'"}')
    with pytest.raises(netio.NetworkError, match="larger than 64 bytes"):
        netio.http_json("https://api.osv.dev/x")
    assert netio.STATS.oversized == 1


# ---------------------------------------------------------------------- cache
def test_cached_lookups_do_not_touch_the_network_again(monkeypatch):
    calls = script(monkeypatch, {"license": "MIT"})
    assert netio.http_json("https://api.deps.dev/v3/x", cache=True) == {"license": "MIT"}
    assert netio.http_json("https://api.deps.dev/v3/x", cache=True) == {"license": "MIT"}
    assert len(calls) == 1 and netio.STATS.cache_hits == 1


def test_cache_entries_expire_and_can_be_switched_off(monkeypatch):
    script(monkeypatch, {"n": 1}, {"n": 2}, {"n": 3}, {"n": 4})
    assert netio.http_json("https://x.example/a", cache=True) == {"n": 1}
    netio.configure(cache_ttl=-1)                         # everything is already too old
    assert netio.http_json("https://x.example/a", cache=True) == {"n": 2}
    netio.configure(cache=False, cache_ttl=3600)
    assert netio.http_json("https://x.example/a", cache=True) == {"n": 3}
    assert netio.http_json("https://x.example/a", cache=True) == {"n": 4}


def test_uncached_calls_and_distinct_payloads_never_share_entries(monkeypatch):
    script(monkeypatch, {"n": 1}, {"n": 2}, {"n": 3})
    assert netio.http_json("https://x.example/b", {"q": 1}, cache=True) == {"n": 1}
    assert netio.http_json("https://x.example/b", {"q": 2}, cache=True) == {"n": 2}
    assert netio.http_json("https://x.example/b", {"q": 1}) == {"n": 3}      # vulnerability searches skip the cache


def test_clear_cache_removes_the_entries(monkeypatch):
    script(monkeypatch, {"n": 1})
    netio.http_json("https://x.example/c", cache=True)
    assert netio.clear_cache() == 1 and netio.clear_cache() == 0


# ---------------------------------------------------------------------- certificate authority
def test_ca_bundle_precedence(tmp_path, monkeypatch):
    explicit, env = tmp_path / "explicit.pem", tmp_path / "env.pem"
    assert netio.ca_bundle_path() == ""
    monkeypatch.setenv("SSL_CERT_FILE", str(env))
    assert netio.ca_bundle_path() == str(env)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "requests.pem"))
    assert netio.ca_bundle_path() == str(tmp_path / "requests.pem")           # REQUESTS_CA_BUNDLE beats SSL_CERT_FILE
    monkeypatch.setenv("SECURE_REPO_CA_BUNDLE", str(tmp_path / "own.pem"))
    assert netio.ca_bundle_path() == str(tmp_path / "own.pem")
    netio.configure(ca_bundle=str(explicit))
    assert netio.ca_bundle_path() == str(explicit)                            # the flag beats every variable


def test_a_missing_or_broken_bundle_is_reported_clearly(tmp_path):
    netio.configure(ca_bundle=str(tmp_path / "missing.pem"))
    with pytest.raises(netio.NetworkError, match="not found"):
        netio.ssl_context()
    broken = tmp_path / "broken.pem"
    broken.write_text("this is not a certificate", encoding="utf-8")
    netio.configure(ca_bundle=str(broken))
    with pytest.raises(netio.NetworkError, match="could not be loaded"):
        netio.ssl_context()


def test_a_valid_bundle_builds_the_context(tmp_path):
    import ssl

    pem = ssl.get_default_verify_paths().cafile
    if not pem or not os.path.isfile(pem):
        pytest.skip("this platform has no PEM file for the system certificate store")
    netio.configure(ca_bundle=pem)
    assert netio.ssl_context().verify_mode == ssl.CERT_REQUIRED


# ---------------------------------------------------------------------- OSV pagination and failing batches
def dep(name, version="1.0.0", **kw):
    return Dependency(name=name, ecosystem="PyPI", version=version, spec=version, manifest="requirements.txt", **kw)


def osv_script(monkeypatch, handler):
    calls = []

    def fake(url, payload=None, timeout=20, cache=False):
        calls.append((url, payload))
        return handler(url, payload)

    monkeypatch.setattr(intel, "_http_json", fake)
    return calls


def test_osv_pagination_follows_next_page_token_until_the_end(monkeypatch):
    def handler(url, payload):
        query = payload["queries"][0]
        page = query.get("page_token")
        if page is None:
            return {"results": [{"vulns": [{"id": "GHSA-1"}], "next_page_token": "p2"}]}
        if page == "p2":
            return {"results": [{"vulns": [{"id": "GHSA-2"}], "next_page_token": "p3"}]}
        return {"results": [{"vulns": [{"id": "GHSA-3"}]}]}

    calls = osv_script(monkeypatch, handler)
    assert intel.osv_vulnerability_ids([("PyPI", "django", "1.0.0")]) == {("PyPI", "django", "1.0.0"): ["GHSA-1", "GHSA-2", "GHSA-3"]}
    assert len(calls) == 3 and calls[2][1]["queries"][0]["page_token"] == "p3"


def test_pagination_only_requeries_the_packages_that_have_more_pages(monkeypatch):
    def handler(url, payload):
        results = []
        for query in payload["queries"]:
            if query["package"]["name"] == "big" and not query.get("page_token"):
                results.append({"vulns": [{"id": "A"}], "next_page_token": "t"})
            else:
                results.append({"vulns": [{"id": "B"}] if query["package"]["name"] == "big" else []})
        return {"results": results}

    calls = osv_script(monkeypatch, handler)
    found = intel.osv_vulnerability_ids([("PyPI", "big", "1"), ("PyPI", "small", "1"), ("PyPI", "tiny", "1")])
    assert found == {("PyPI", "big", "1"): ["A", "B"]}
    assert [len(c[1]["queries"]) for c in calls] == [3, 1]


def test_a_never_ending_pagination_is_cut_and_reported(monkeypatch):
    page_key, page = "next_page_" + "token", "again"
    osv_script(monkeypatch, lambda url, payload: {"results": [{"vulns": [{"id": "X"}], page_key: page}]})
    found = intel.osv_vulnerability_ids([("PyPI", "loop", "1")])
    assert found[("PyPI", "loop", "1")] == ["X"]
    assert any("more advisories than the" in note for note in netio.STATS.notes)


def test_a_failing_batch_does_not_cancel_the_others(monkeypatch):
    state = {"calls": 0}

    def handler(url, payload):
        state["calls"] += 1
        if state["calls"] == 2:
            raise urllib.error.URLError("proxy reset")
        return {"results": [{"vulns": [{"id": "OK"}]} for _ in payload["queries"]]}

    osv_script(monkeypatch, handler)
    keys = [("PyPI", f"p{i}", "1") for i in range(1200)]          # three batches of 500, 500 and 200
    found = intel.osv_vulnerability_ids(keys)
    assert len(found) == 700                                      # batch 2 (500 packages) is missing, the rest is there
    assert any("batch 2 of 3 failed" in note and "500 package versions" in note for note in netio.STATS.notes)


def test_when_every_batch_fails_the_error_reaches_the_caller(monkeypatch):
    def handler(url, payload):
        raise urllib.error.URLError("offline")

    osv_script(monkeypatch, handler)
    with pytest.raises(urllib.error.URLError):
        intel.osv_vulnerability_ids([("PyPI", "a", "1")])


def test_private_packages_are_never_sent_to_osv(monkeypatch):
    calls = osv_script(monkeypatch, lambda url, payload: {"results": [{} for _ in payload["queries"]]})
    deps = [dep("flask"), dep("acme-core", private=True)]
    intel.osv_lookup(deps, EventBus())
    sent = [q["package"]["name"] for _url, payload in calls if payload for q in payload["queries"]]
    assert sent == ["flask"]


def test_enrichment_limit_is_reported(monkeypatch):
    osv_script(monkeypatch, lambda url, payload: {"versions": []})
    deps = [dep(f"lib{i}") for i in range(7)]
    intel.depsdev_enrich(deps, EventBus(), limit=5)
    assert any("2 direct libraries" in note and "--max-enrich" in note for note in netio.STATS.notes)


def test_public_existence_check(monkeypatch):
    def handler(url, payload):
        if url.endswith("/ghost"):
            raise urllib.error.HTTPError(url, 404, "not found", {}, io.BytesIO(b""))
        if url.endswith("/flaky"):
            raise urllib.error.URLError("down")
        return {"packageKey": {}}

    osv_script(monkeypatch, handler)
    assert intel.exists_publicly(dep("six")) is True
    assert intel.exists_publicly(dep("ghost")) is False
    assert intel.exists_publicly(dep("flaky")) is None
    assert intel.exists_publicly(Dependency(name="x", ecosystem="Unknown", version="1", spec="1", manifest="m")) is None


# ---------------------------------------------------------------------- package lists as data
def test_package_lists_are_versioned_data_with_sources():
    data = intel.load_package_data()
    assert data["schema"] == 1 and data["reviewed"]
    for names in data["compromised"].values():
        for name, entry in names.items():
            assert entry["reason"] and "versions" in entry and "date" in entry and "source" in entry, name
    assert intel.COMPROMISED["npm"]["event-stream"] == {"3.3.6"} and intel.COMPROMISED["npm"]["flatmap-stream"] == set()
    assert "pyopenssl" not in intel.DEPRECATED["PyPI"] and "python-jose" not in intel.DEPRECATED["PyPI"]
    assert data["compromised"]["npm"]["event-stream"]["source"].startswith("https://")
