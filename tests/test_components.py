import pytest

from secure_repo.core import checks, compliance, deps, gitops, intel
from secure_repo.core.rules import RULES, RULES_BY_ID
from secure_repo.core.scoring import compute_score
from secure_repo.report.html import safe_json_for_script


def test_rules_are_well_formed():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for rule in RULES:
        assert rule.severity in ("critical", "high", "medium", "low", "info")
        assert rule.description and rule.recommendation, rule.id
        if rule.pattern:
            assert rule.regex is not None


def test_cvss_calculator_matches_reference_scores():
    assert intel.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert intel.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert intel.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert intel.score_to_severity(9.8) == "critical"
    assert intel.score_to_severity(None) == "medium"


def test_luhn_and_card_detection():
    assert checks.luhn_ok("4539578763621486")
    assert not checks.luhn_ok("4539578763621487")
    found = checks.find_card_numbers("x = '4111111111111111'")
    assert found and found[0][2] is True  # well-known test card


def test_generic_credentials_ignore_placeholders():
    text = 'password = "changeme"\napi_key = os.environ["KEY"]\ntoken = "${TOKEN}"\nsecret = "Zx9!kQ2#pL7@"\n'
    values = [value for _o, _k, value, _e in checks.find_generic_credentials(text, "Python")]
    assert values == ["Zx9!kQ2#pL7@"]


def test_redaction_masks_tokens():
    token = "gh" + "p_" + "A" * 36
    assert token not in checks.redact_text(f"token = '{token}'")


def test_dockerfile_analysis():
    results = list(checks.analyze_dockerfile("FROM node:latest AS build\nFROM build\nUSER root\n"))
    ids = [r[0] for r in results]
    assert "SR-DOCKER-001" in ids and "SR-DOCKER-002" in ids


def test_requirements_parser_and_insecure_index():
    issues = []
    parsed = deps.parse_requirements("django==4.2.1\nflask>=2\n-i http://pypi.local/simple\n", "requirements.txt", issues)
    assert [(d.name, d.version) for d in parsed] == [("django", "4.2.1"), ("flask", None)]
    assert issues and issues[0].rule_id == "SR-DEP-006"


def test_package_lock_v3_parser():
    text = '{"packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"}, ' \
           '"node_modules/a/node_modules/@scope/b": {"version": "1.0.0", "dev": true}}}'
    parsed = deps.parse_package_lock(text, "package-lock.json", [])
    assert {(d.name, d.version) for d in parsed} == {("lodash", "4.17.21"), ("@scope/b", "1.0.0")}


def test_pom_parser_resolves_properties_and_blocks_entities():
    pom = """<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><jackson.version>2.9.8</jackson.version></properties>
  <dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency></dependencies>
</project>"""
    parsed = deps.parse_pom(pom, "pom.xml", [])
    assert parsed[0].name == "com.fasterxml.jackson.core:jackson-databind"
    assert parsed[0].version == "2.9.8"


def test_go_mod_and_gemfile_lock():
    go = "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.1.0 // indirect\n)\n"
    parsed = deps.parse_go_mod(go, "go.mod", [])
    assert [(d.name, d.version, d.direct) for d in parsed] == [
        ("github.com/gin-gonic/gin", "1.9.0", True), ("golang.org/x/net", "0.1.0", False)]
    lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n    nokogiri (1.14.0-x86_64-linux)\n"
    gems = deps.parse_gemfile_lock(lock, "Gemfile.lock", [])
    assert {(d.name, d.version) for d in gems} == {("rails", "7.0.4"), ("nokogiri", "1.14.0")}


def test_known_bad_packages():
    from secure_repo.core.models import Dependency

    bad = intel.known_bad(Dependency("event-stream", "npm", "3.3.6", "3.3.6", "package.json"))
    assert bad and bad[0] == "SR-DEP-002"
    assert intel.known_bad(Dependency("event-stream", "npm", "4.0.1", "4.0.1", "package.json")) is None


def test_git_input_validation_blocks_injection():
    for bad in ("--upload-pack=touch /tmp/x", "ext::sh -c id", "file:///etc", "https://x y"):
        with pytest.raises(gitops.GitError):
            gitops.validate_url(bad)
    for bad in ("-b", "a..b", "x y", "a:b"):
        with pytest.raises(gitops.GitError):
            gitops.validate_branch(bad)
    assert gitops.validate_url("git@github.com:owner/repo.git")
    assert gitops.is_git_url("https://github.com/owner/repo")


def test_scoring_is_monotonic():
    clean = compute_score([])
    bad = compute_score([{"rule_id": "X", "severity": "critical"}])
    worse = compute_score([{"rule_id": "X", "severity": "critical"}, {"rule_id": "Y", "severity": "high"}])
    assert clean["score"] == 100 and clean["grade"] == "A"
    assert clean["penalty"] < bad["penalty"] < worse["penalty"]  # the penalty keeps growing...
    assert bad["score"] <= 59 and worse["score"] <= 59           # ...while an open critical caps the grade at D


def test_compliance_statuses():
    findings = [{"id": "SR-0001", "rule_id": "SR-SEC-001", "title": "AWS", "severity": "critical", "file": "a.py",
                 "line": 1, "tags": ["secrets"], "owasp": "A07"}]
    hygiene = {k: True for k in compliance.HYGIENE_LABELS}
    result = compliance.evaluate(findings, hygiene, ["pci-dss"])
    controls = {c["id"]: c["status"] for c in result["frameworks"][0]["controls"]}
    assert controls["8.6.2"] == "fail"
    assert controls["4.2.1"] == "pass"
    assert controls["10.2.1"] == "manual"


def test_report_json_is_safe_inside_script_tags():
    payload = safe_json_for_script({"x": "</script><script>alert(1)</script>"})
    assert "</script" not in payload and "<" not in payload


def test_every_rule_documents_owasp_or_other():
    for rule in RULES:
        assert rule.owasp in {"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "OTHER"}, rule.id
    assert RULES_BY_ID["SR-DEP-001"].category == "Vulnerable Dependency"
