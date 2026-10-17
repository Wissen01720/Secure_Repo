"""Optional compliance audit: maps technical evidence to control frameworks.

The audit is evidence-based and read-only. It helps teams *meet* their
obligations; it is not a certification and never replaces a qualified auditor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Sequence

from secure_repo.core.models import OWASP_TOP10, SEVERITIES, SEVERITY_RANK

DISCLAIMER = (
    "This automated assessment produces technical evidence to support compliance efforts. It is not a "
    "certification, attestation or legal opinion, and it does not replace an audit performed by a qualified, "
    "independent assessor. NO ISSUE FOUND means that nothing the static analysis could read contradicts the "
    "control; it does not show that the control is satisfied (processes, configuration at run time and "
    "anything outside the repository are invisible to it). Controls marked MANUAL require human verification "
    "of processes and documentation. "
    "The analysis was read-only: no code from the target was executed, detected secrets are redacted in every "
    "report, and (in online mode) only package names and versions were sent to public vulnerability databases."
)

HYGIENE_LABELS = {
    "security_policy": "Security policy (SECURITY.md)",
    "gitignore_secrets": ".gitignore excludes secret files",
    "dependency_updates": "Automated dependency updates (Dependabot/Renovate)",
    "license": "License file",
    "ci": "Continuous integration pipeline",
    "codeowners": "Code owners (CODEOWNERS)",
    "lockfiles": "Dependency lockfiles present",
    "inventory": "Software component inventory (SBOM) generated",
}


@dataclass
class Control:
    id: str
    title: str
    description: str
    tags: Sequence[str] = ()
    owasp: Sequence[str] = ()
    hygiene: Sequence[str] = ()
    manual: bool = False
    guidance: str = ""
    evidence_note: str = ""


@dataclass
class Framework:
    id: str
    name: str
    version: str
    description: str
    controls: list[Control] = field(default_factory=list)


FRAMEWORKS: dict[str, Framework] = {}


def _register(framework: Framework) -> None:
    FRAMEWORKS[framework.id] = framework


_register(Framework(
    "owasp", "OWASP Top 10", "2021",
    "The ten most critical web application security risks, used as a baseline by most regulations.",
    [Control(code, f"{code}: {info['name']}", info["description"], owasp=(code,))
     for code, info in OWASP_TOP10.items() if code != "OTHER"],
))

_register(Framework("pci-dss", "PCI DSS", "4.0.1",
    "Payment Card Industry Data Security Standard - requirements relevant to secure software.", [
    Control("2.2.6", "System security parameters are configured to prevent misuse",
            "Debug modes, permissive CORS, privileged containers and insecure defaults are disabled.",
            tags=("config", "container", "iac")),
    Control("3.5.1", "PAN is rendered unreadable anywhere it is stored",
            "No primary account numbers are stored in source code, fixtures or logs.", tags=("pii",)),
    Control("3.6.1", "Cryptographic keys are protected against disclosure",
            "Private keys and secrets are not stored in the repository.", tags=("secrets",)),
    Control("4.2.1", "Strong cryptography protects data during transmission",
            "TLS is enforced and certificate validation is never disabled.", tags=("transport",)),
    Control("6.2.4", "Software engineering techniques prevent common software attacks",
            "Code is free of injection, XSS, deserialization, access-control and memory-safety flaws.",
            tags=("injection", "xss", "deserialization", "access-control", "ssrf", "memory", "auth")),
    Control("6.3.1", "Security vulnerabilities are identified and managed",
            "Known vulnerabilities are tracked and there is a vulnerability disclosure process.",
            tags=("vulnerable-dependency",), hygiene=("security_policy",)),
    Control("6.3.2", "Inventory of bespoke and third-party software components is maintained",
            "A complete inventory (SBOM) of third-party libraries exists and versions are locked.",
            hygiene=("inventory", "lockfiles")),
    Control("6.3.3", "Known vulnerabilities are addressed by installing patches",
            "No third-party components with known critical/high vulnerabilities are in use.",
            tags=("vulnerable-dependency",)),
    Control("8.3.2", "Strong cryptography renders authentication factors unreadable",
            "Passwords are hashed with strong, salted, slow algorithms.", tags=("crypto",)),
    Control("8.6.2", "Passwords for application and system accounts are not hard coded",
            "No credentials appear in scripts, configuration or source files.", tags=("secrets",)),
    Control("10.2.1", "Audit logs are enabled and active",
            "Security events are logged without leaking sensitive data.", tags=("logging",), manual=True,
            guidance="Verify that authentication, authorization and admin events are logged and retained."),
    Control("11.3.1", "Internal vulnerability scans are performed",
            "Vulnerability scans are run regularly and after significant changes.", hygiene=("ci",),
            evidence_note="This Secure Repo scan provides point-in-time evidence."),
]))

_register(Framework("iso27001", "ISO/IEC 27001", "2022 Annex A",
    "Information security management - technological controls relevant to software development.", [
    Control("A.5.32", "Intellectual property rights", "Licenses of the product and its components are known.",
            tags=("license",), hygiene=("license",)),
    Control("A.8.4", "Access to source code", "Read/write access to source code and sensitive paths is controlled.",
            hygiene=("codeowners",), manual=True,
            guidance="Confirm branch protection, least-privilege repository access and review of access rights."),
    Control("A.8.8", "Management of technical vulnerabilities",
            "Vulnerabilities in used components are identified and remediated in a timely manner.",
            tags=("vulnerable-dependency",), hygiene=("dependency_updates",)),
    Control("A.8.9", "Configuration management", "Secure configurations are defined and enforced.",
            tags=("config", "iac", "container")),
    Control("A.8.12", "Data leakage prevention", "Secrets and personal data are not exposed in the repository.",
            tags=("secrets", "pii"), hygiene=("gitignore_secrets",)),
    Control("A.8.15", "Logging", "Logs are produced and protected and do not contain sensitive data.",
            tags=("logging",)),
    Control("A.8.20", "Networks security", "Network exposure is restricted and traffic protected.",
            tags=("transport",)),
    Control("A.8.24", "Use of cryptography", "Approved, strong cryptographic algorithms are used.",
            tags=("crypto",)),
    Control("A.8.25", "Secure development life cycle", "Rules for secure development are established and applied.",
            hygiene=("security_policy", "ci")),
    Control("A.8.26", "Application security requirements", "Authentication and authorization are enforced.",
            tags=("auth", "access-control")),
    Control("A.8.28", "Secure coding", "Secure coding principles are applied to software development.",
            tags=("injection", "xss", "deserialization", "memory", "ssrf")),
    Control("A.8.29", "Security testing in development and acceptance",
            "Security testing is performed during development.", hygiene=("ci",),
            evidence_note="Static analysis and dependency scanning were performed by Secure Repo."),
    Control("A.8.32", "Change management", "Changes are reviewed and controlled.", hygiene=("ci", "codeowners")),
]))

_register(Framework("soc2", "SOC 2", "Trust Services Criteria 2017 (rev. 2022)",
    "AICPA criteria for security, availability and confidentiality - Common Criteria mapped to code evidence.", [
    Control("CC6.1", "Logical access security", "Credentials are protected and access is restricted.",
            tags=("secrets", "access-control", "auth")),
    Control("CC6.6", "Boundary protection", "External exposure of services is restricted.", tags=("iac", "config")),
    Control("CC6.7", "Transmission of data is protected", "Data in transit is encrypted.", tags=("transport",)),
    Control("CC6.8", "Prevention of unauthorized or malicious software",
            "Third-party software is vetted and free from known vulnerabilities or malware.",
            tags=("supply-chain", "vulnerable-dependency")),
    Control("CC7.1", "Detection of configuration changes and vulnerabilities",
            "Vulnerability detection is automated.", hygiene=("dependency_updates", "ci")),
    Control("CC7.2", "Monitoring of system components", "Security events are logged and monitored.",
            tags=("logging",), manual=True, guidance="Verify alerting, log retention and incident monitoring."),
    Control("CC8.1", "Change management", "Changes are authorized, tested and approved.",
            hygiene=("ci", "codeowners")),
    Control("C1.1", "Confidential information is identified and protected",
            "Confidential data such as secrets and personal data is protected.", tags=("pii", "secrets")),
]))

_register(Framework("gdpr", "GDPR", "Regulation (EU) 2016/679",
    "EU General Data Protection Regulation - technical and organisational measures (Art. 5, 25, 32).", [
    Control("Art.5(1)(f)", "Integrity and confidentiality",
            "Personal data is protected against unauthorised access and accidental loss.",
            tags=("secrets", "pii", "crypto")),
    Control("Art.25", "Data protection by design and by default",
            "Systems avoid collecting or exposing personal data unnecessarily (e.g. in logs).",
            tags=("pii", "logging", "config")),
    Control("Art.32(1)(a)", "Pseudonymisation and encryption of personal data",
            "Strong encryption protects data at rest and in transit.", tags=("crypto", "transport")),
    Control("Art.32(1)(b)", "Ongoing confidentiality, integrity, availability and resilience",
            "Processing systems are protected against common attacks.",
            tags=("injection", "xss", "vulnerable-dependency", "access-control", "auth")),
    Control("Art.32(1)(d)", "Regular testing of security measures",
            "Effectiveness of security measures is regularly tested.", hygiene=("ci",),
            evidence_note="This scan is a record of technical testing."),
    Control("Art.30", "Records of processing activities", "Processing activities are documented.", manual=True,
            guidance="Maintain a record of processing; not verifiable from source code."),
    Control("Art.33", "Personal data breach notification", "Breaches can be detected and notified within 72h.",
            hygiene=("security_policy",), manual=True,
            guidance="Verify the incident response and breach notification procedure."),
]))

_register(Framework("hipaa", "HIPAA Security Rule", "45 CFR Part 164 Subpart C",
    "US Health Insurance Portability and Accountability Act - technical safeguards for ePHI.", [
    Control("164.308(a)(1)(ii)(A)", "Risk analysis", "Risks to ePHI are assessed.",
            evidence_note="This scan contributes technical risk evidence."),
    Control("164.308(a)(5)(ii)(B)", "Protection from malicious software",
            "Procedures guard against malicious and vulnerable software.",
            tags=("supply-chain", "vulnerable-dependency")),
    Control("164.312(a)(1)", "Access control", "Only authorized persons and software can access ePHI.",
            tags=("access-control", "auth", "secrets")),
    Control("164.312(a)(2)(iv)", "Encryption and decryption", "ePHI is encrypted with strong algorithms.",
            tags=("crypto",)),
    Control("164.312(b)", "Audit controls", "Activity in systems containing ePHI is recorded.", tags=("logging",),
            manual=True, guidance="Verify audit logging of ePHI access."),
    Control("164.312(c)(1)", "Integrity", "ePHI is protected from improper alteration.",
            tags=("injection", "deserialization", "supply-chain")),
    Control("164.312(d)", "Person or entity authentication", "Identity is verified before access.",
            tags=("auth", "secrets")),
    Control("164.312(e)(1)", "Transmission security", "ePHI transmitted over networks is protected.",
            tags=("transport",)),
]))

_register(Framework("nist-ssdf", "NIST SSDF", "SP 800-218 v1.1",
    "Secure Software Development Framework practices verifiable from a repository.", [
    Control("PO.1", "Define security requirements for software development",
            "Security requirements and a disclosure policy are documented.", hygiene=("security_policy",)),
    Control("PO.3", "Implement supporting toolchains", "Automated toolchains run security checks.",
            hygiene=("ci",)),
    Control("PS.1", "Protect all forms of code from unauthorized access and tampering",
            "Code is access-controlled and free of embedded secrets.", tags=("secrets",), hygiene=("codeowners",)),
    Control("PS.3", "Archive and protect each software release",
            "Dependencies and build inputs are pinned and reproducible.", tags=("supply-chain",),
            hygiene=("lockfiles",)),
    Control("PW.4", "Reuse existing, well-secured software", "Third-party components are secure and maintained.",
            tags=("vulnerable-dependency",)),
    Control("PW.5", "Adhere to secure coding practices", "Code avoids common vulnerability classes.",
            tags=("injection", "xss", "crypto", "deserialization", "memory", "ssrf", "auth", "access-control")),
    Control("PW.7", "Review and/or analyze human-readable code", "Code is analyzed for vulnerabilities.",
            evidence_note="Static analysis performed by Secure Repo."),
    Control("PW.9", "Configure software to have secure settings by default", "Defaults are secure.",
            tags=("config", "container", "iac")),
    Control("RV.1", "Identify and confirm vulnerabilities on an ongoing basis",
            "Vulnerabilities are continuously monitored and reported.",
            hygiene=("dependency_updates", "security_policy")),
]))


def list_frameworks() -> list[dict]:
    return [{"id": f.id, "name": f.name, "version": f.version, "description": f.description,
             "controls": len(f.controls)} for f in FRAMEWORKS.values()]


def resolve_frameworks(selection: Sequence[str] | None) -> list[str]:
    if not selection or "all" in selection:
        return list(FRAMEWORKS)
    chosen = []
    for item in selection:
        key = item.strip().lower()
        if key in ("pci", "pcidss"):
            key = "pci-dss"
        if key in ("iso", "iso-27001"):
            key = "iso27001"
        if key in ("nist", "ssdf"):
            key = "nist-ssdf"
        if key in FRAMEWORKS and key not in chosen:
            chosen.append(key)
    return chosen


def _describe(findings: list[dict]) -> str:
    counts = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    parts = [f"{counts[s]} {s}" for s in SEVERITIES if counts.get(s)]
    return f"{len(findings)} related finding(s): " + ", ".join(parts)


def evaluate(findings: list[dict], hygiene: dict[str, bool], selection: Sequence[str] | None) -> dict:
    results = []
    for framework_id in resolve_frameworks(selection):
        framework = FRAMEWORKS[framework_id]
        controls = []
        tally = {"pass": 0, "warning": 0, "fail": 0, "manual": 0}
        for control in framework.controls:
            related = [f for f in findings
                       if (control.tags and set(control.tags) & set(f.get("tags", [])))
                       or (control.owasp and f.get("owasp") in control.owasp)]
            related.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 9))
            evidence: list[str] = []
            status = "pass"
            significant = [f for f in related if f["severity"] != "info"]
            if significant:
                worst = significant[0]["severity"]
                status = "fail" if worst in ("critical", "high") else "warning"
                evidence.append(_describe(significant))
                for finding in significant[:3]:
                    where = "(repository)" if finding["file"] in ("", ".") else (
                        finding["file"] + (f":{finding['line']}" if finding.get("line") else ""))
                    evidence.append(f"{finding['rule_id']} {finding['title']} at {where}")
            elif control.tags or control.owasp:
                evidence.append("No related weaknesses detected by automated analysis.")
            for fact in control.hygiene:
                present = hygiene.get(fact, False)
                evidence.append(f"{HYGIENE_LABELS.get(fact, fact)}: {'present' if present else 'missing'}")
                if not present and status == "pass":
                    status = "warning"
            if control.evidence_note:
                evidence.append(control.evidence_note)
            if control.manual and status == "pass":
                status = "manual"
            if control.guidance:
                evidence.append("Manual verification: " + control.guidance)
            tally[status] += 1
            controls.append({
                "id": control.id, "title": control.title, "description": control.description,
                "status": status, "evidence": evidence, "findings": [f["id"] for f in significant][:200],
            })
        automated = tally["pass"] + tally["warning"] + tally["fail"]
        score = round(100 * (tally["pass"] + 0.5 * tally["warning"]) / automated) if automated else 100
        results.append({"id": framework.id, "name": framework.name, "version": framework.version,
                        "description": framework.description, "score": score, "summary": tally,
                        "controls": controls})
    return {"enabled": True, "frameworks": results, "disclaimer": DISCLAIMER}
