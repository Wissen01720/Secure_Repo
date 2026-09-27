# securerepo:ignore-file  (this file only contains detection signatures and their documentation)
"""Detection signatures used by the static analyzer.

Every rule documents *why* the pattern is dangerous and *how* to fix it; that
text is surfaced in the CLI, in the GUI explanation panel and in the reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

# ---------------------------------------------------------------------------
# Language groups
# ---------------------------------------------------------------------------
PY = ("Python",)
JS = ("JavaScript", "TypeScript", "Vue", "Svelte")
WEB = JS + ("HTML",)
JVM = ("Java", "Kotlin", "Scala", "Groovy")
CS = ("C#", "VB.NET", "F#")
PHP = ("PHP",)
GO = ("Go",)
RB = ("Ruby",)
CC = ("C", "C++", "Objective-C")
RS = ("Rust",)
SHELLISH = ("Shell", "Dockerfile", "YAML", "Makefile", "PowerShell", "Batch", "Groovy")
IAC = ("Terraform", "HCL", "JSON", "YAML")
CONFIG = ("Env", "INI", "Config", "Properties", "YAML", "TOML")
CODE = PY + JS + JVM + CS + PHP + GO + RB + CC + RS + ("Swift", "Dart", "Lua", "Perl", "Elixir", "Solidity")
ANY = ("*",)

WORKFLOW_PATH = r"(^|/)\.github/workflows/[^/]+\.ya?ml$"
CI_PATH = r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|\.circleci/config\.ya?ml|Jenkinsfile)$"


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    owasp: str
    description: str
    recommendation: str
    pattern: str = ""
    languages: Tuple[str, ...] = ANY
    path: str = ""
    exclude: str = ""
    keywords: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    confidence: str = "medium"
    scan_comments: bool = False
    redact: bool = False
    source: str = "code"
    references: Tuple[str, ...] = ()
    flags: int = 0
    needs_strings: bool = False  # the pattern must see string contents (URLs, algorithm names, '*'...)
    _regex: Optional[Pattern] = field(default=None, repr=False, compare=False)
    _path_re: Optional[Pattern] = field(default=None, repr=False, compare=False)
    _exclude_re: Optional[Pattern] = field(default=None, repr=False, compare=False)

    @property
    def regex(self) -> Optional[Pattern]:
        if self.pattern and self._regex is None:
            self._regex = re.compile(self.pattern, re.MULTILINE | self.flags)
        return self._regex

    @property
    def exclude_re(self) -> Optional[Pattern]:
        if self.exclude and self._exclude_re is None:
            self._exclude_re = re.compile(self.exclude)
        return self._exclude_re

    @property
    def view(self) -> str:
        """Which lexical view the pattern runs on: raw text, comments masked, or comments+strings masked."""
        if self.source == "secret" or self.scan_comments:
            return "raw"
        return "strings" if self.needs_strings else "code"

    def applies_to(self, language: str, rel_path: str) -> bool:
        if self.path:
            if self._path_re is None:
                self._path_re = re.compile(self.path, re.IGNORECASE)
            if not self._path_re.search(rel_path):
                return False
        return "*" in self.languages or language in self.languages

    def reference_links(self) -> List[str]:
        links = list(self.references)
        if self.cwe.startswith("CWE-"):
            links.insert(0, f"https://cwe.mitre.org/data/definitions/{self.cwe[4:]}.html")
        if self.owasp and self.owasp.startswith("A"):
            links.append(f"https://owasp.org/Top10/{OWASP_SLUGS.get(self.owasp, '')}")
        return links

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity, "category": self.category,
            "cwe": self.cwe, "owasp": self.owasp, "description": self.description,
            "recommendation": self.recommendation, "tags": list(self.tags),
            "confidence": self.confidence, "references": self.reference_links(),
            "languages": list(self.languages), "source": self.source,
        }


OWASP_SLUGS = {
    "A01": "A01_2021-Broken_Access_Control/", "A02": "A02_2021-Cryptographic_Failures/",
    "A03": "A03_2021-Injection/", "A04": "A04_2021-Insecure_Design/",
    "A05": "A05_2021-Security_Misconfiguration/", "A06": "A06_2021-Vulnerable_and_Outdated_Components/",
    "A07": "A07_2021-Identification_and_Authentication_Failures/",
    "A08": "A08_2021-Software_and_Data_Integrity_Failures/",
    "A09": "A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10": "A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}

_I = re.IGNORECASE


def _secret(rule_id, title, severity, pattern, keywords, description, recommendation=None, **kw) -> Rule:
    return Rule(
        id=rule_id, title=title, severity=severity, category="Secrets", cwe=kw.pop("cwe", "CWE-798"),
        owasp=kw.pop("owasp", "A07"), description=description,
        recommendation=recommendation or (
            "Revoke and rotate this credential immediately, remove it from the source code and the Git "
            "history (e.g. git filter-repo), and load it at runtime from a secret manager or environment "
            "variable that is never committed."),
        pattern=pattern, keywords=keywords, tags=kw.pop("tags", ("secrets",)), scan_comments=True,
        redact=kw.pop("redact", True), source="secret", confidence=kw.pop("confidence", "high"), **kw)


RULES: List[Rule] = [
    # ------------------------------------------------------------------ Secrets
    _secret("SR-SEC-001", "AWS access key ID", "critical",
            r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16})\b",
            ("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa"),
            "An Amazon Web Services access key identifier is embedded in the repository. Anyone with read "
            "access to the code (or its history, forks and CI logs) can pair it with the secret key to act on "
            "your AWS account, leading to data theft or large unexpected bills.",
            exclude=r"EXAMPLE"),
    _secret("SR-SEC-002", "AWS secret access key", "critical",
            r"(?i)aws.{0,25}?['\"]([0-9a-zA-Z/+]{40})['\"]", ("aws",),
            "A 40-character value assigned near an AWS identifier looks like an AWS secret access key. "
            "Secret keys grant full programmatic access with the permissions of the owning IAM identity.",
            exclude=r"(?i)EXAMPLEKEY|[0-9a-f]{40}", confidence="medium"),
    _secret("SR-SEC-003", "GitHub token", "critical",
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
            ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
            "A GitHub personal access / OAuth / app token is hardcoded. Tokens can read or modify private "
            "repositories, packages and workflows, enabling supply-chain attacks."),
    _secret("SR-SEC-004", "GitLab personal access token", "critical",
            r"\bglpat-[A-Za-z0-9_\-]{20,}\b", ("glpat-",),
            "A GitLab personal access token is present in the code. It grants API access with the privileges "
            "of the user that created it."),
    _secret("SR-SEC-005", "Slack token", "high", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", ("xox",),
            "A Slack API token allows reading and posting messages, listing users and exfiltrating "
            "conversations from the workspace."),
    _secret("SR-SEC-006", "Slack incoming webhook", "medium",
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
            ("hooks.slack.com",),
            "Incoming webhook URLs let anyone post arbitrary messages into a Slack channel, which can be abused "
            "for phishing inside your organisation."),
    _secret("SR-SEC-007", "Google API key", "high", r"\bAIza[0-9A-Za-z\-_]{35}\b", ("aiza",),
            "A Google Cloud / Firebase API key is hardcoded. Unrestricted keys can be used to consume paid "
            "APIs on your billing account or access project data."),
    _secret("SR-SEC-008", "Stripe live secret key", "critical", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b",
            ("_live_",),
            "A live Stripe secret key grants access to payments, refunds and customer payment data. Its "
            "exposure is a direct financial and PCI DSS incident."),
    _secret("SR-SEC-009", "Private key material", "critical",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
            ("private key",),
            "A private key (TLS, SSH, PGP or signing key) is stored in the repository. Whoever obtains it can "
            "impersonate your servers, decrypt traffic or sign malicious artifacts.",
            "Treat the key as compromised: revoke/replace it, remove it from history, and store keys in a "
            "hardware module, key vault or CI secret store.", redact=False),
    _secret("SR-SEC-010", "Hardcoded JSON Web Token", "medium",
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", ("eyj",),
            "A signed JWT is embedded in the source. If it is still valid it can be replayed to authenticate "
            "as the subject it was issued for.", confidence="medium"),
    _secret("SR-SEC-011", "Credentials inside a connection string", "high",
            r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|rediss?|amqps?|mssql|sqlserver|ftp|sftp|smtp)://[^:\s/'\"@]+:([^@\s'\"/]{3,})@",
            ("://",),
            "A database / broker URI contains a username and password. The credentials are readable by anyone "
            "with access to the repository and usually reach production data stores.",
            exclude=r"(?i)://[^:\s]*:(?:\$\{|\{\{|<|%\(|password@|pass@|passwd@|pwd@|secret@|\*+@|x+@|changeme|example)"),
    _secret("SR-SEC-012", "SendGrid API key", "high", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
            ("sg.",),
            "SendGrid keys allow sending e-mail as your domain, enabling convincing phishing campaigns."),
    _secret("SR-SEC-013", "AI provider API key", "high",
            r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b",
            ("sk-",),
            "An API key for a large-language-model provider is hardcoded. It can be abused to run workloads on "
            "your account and to access stored data such as files or conversation logs."),
    _secret("SR-SEC-014", "npm access token", "critical", r"\bnpm_[A-Za-z0-9]{36}\b", ("npm_",),
            "npm tokens can publish new versions of your packages. A leaked token is a classic entry point for "
            "supply-chain malware."),
    _secret("SR-SEC-015", "PyPI upload token", "critical", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b",
            ("pypi-",),
            "PyPI API tokens allow uploading packages under your account, enabling supply-chain compromise."),
    _secret("SR-SEC-016", "Azure storage account key", "critical",
            r"DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{40,}",
            ("accountkey=",),
            "An Azure Storage connection string with the account key grants full read/write access to every "
            "blob, queue and table in the account."),
    _secret("SR-SEC-017", "Telegram bot token", "high", r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b", (":aa",),
            "Telegram bot tokens allow full control of the bot, including reading every message it receives."),
    _secret("SR-SEC-018", "Credentials embedded in URL", "high",
            r"\bhttps?://[^\s:/@'\"]+:([^\s:/@'\"]{3,})@[^\s'\"]+", ("://",),
            "HTTP basic-auth credentials are embedded in a URL. URLs are logged by proxies, browsers and CI "
            "systems, spreading the credential far beyond the code base.",
            exclude=r"(?i)://[^:\s]*:(?:\$\{|\{\{|<|%\(|password@|pass@|token@|\*+@|x+@|changeme)"),
    Rule(id="SR-SEC-019", title="Hardcoded credential", severity="high", category="Secrets", cwe="CWE-798",
         owasp="A07", source="secret", tags=("secrets",), redact=True, confidence="medium",
         description="A variable whose name indicates a password, token or secret is assigned a literal value. "
                     "Hardcoded credentials cannot be rotated without a code change, are shared with everyone "
                     "who can read the repository and frequently end up in public forks, logs and build "
                     "artifacts.",
         recommendation="Remove the literal, rotate the credential and read it at runtime from environment "
                        "variables or a secret manager (Vault, AWS/GCP/Azure secret services, Doppler, "
                        "1Password, etc.). Add a pre-commit secret scanner to prevent regressions."),
    Rule(id="SR-SEC-020", title="Sensitive file committed to the repository", severity="high",
         category="Secrets", cwe="CWE-538", owasp="A05", source="secret", tags=("secrets",),
         description="A file that typically stores secrets (environment files, private keys, keystores, "
                     "credential stores, database dumps or infrastructure state) is tracked in the "
                     "repository. Its contents are exposed to anyone with read access and persist in the Git "
                     "history even after deletion.",
         recommendation="Delete the file from the repository and its history, rotate any secret it contained, "
                        "add the pattern to .gitignore and distribute a sanitized template (e.g. .env.example) "
                        "instead."),
    # ---------------------------------------------------------------- Personal / payment data
    Rule(id="SR-PII-001", title="Payment card number in source", severity="high", category="Sensitive Data",
         cwe="CWE-359", owasp="A02", source="secret", tags=("pii",), redact=True, scan_comments=True,
         description="A number that passes the Luhn checksum and matches a card-brand prefix was found. "
                     "Storing primary account numbers (PAN) in code or fixtures violates PCI DSS requirement 3 "
                     "and exposes cardholder data.",
         recommendation="Remove real card numbers. Use the official test numbers of your payment provider "
                        "inside clearly marked test fixtures, and never persist PAN unencrypted."),
    Rule(id="SR-PII-002", title="Social Security Number in source", severity="medium", category="Sensitive Data",
         cwe="CWE-359", owasp="A02", source="secret", tags=("pii",), redact=True, scan_comments=True,
         pattern=r"(?i)\b(?:ssn|social[_ ]?security(?:[_ ]?number)?)\b[^\n]{0,40}?\b(\d{3}-\d{2}-\d{4})\b",
         keywords=("ssn", "social"),
         description="A value formatted as a US Social Security Number appears next to an SSN label. Personal "
                     "identifiers in source code or fixtures are personal data under GDPR/CCPA and HIPAA.",
         recommendation="Replace it with synthetic data generated at test time and purge the real value from "
                        "history."),
    # ---------------------------------------------------------------- Python
    Rule(id="SR-PY-001", title="Dynamic code execution (eval/exec)", severity="high", category="Injection",
         cwe="CWE-95", owasp="A03", languages=PY, tags=("injection",), keywords=("eval", "exec"),
         pattern=r"(?<![\w.])(eval|exec)\s*\(",
         description="eval()/exec() execute arbitrary Python code. If any part of the argument can be "
                     "influenced by a user, file or network input, an attacker gains remote code execution "
                     "with the privileges of the process.",
         recommendation="Remove dynamic evaluation. Use ast.literal_eval() for literals, json for data, or an "
                        "explicit dispatch table for dynamic behaviour."),
    Rule(id="SR-PY-002", title="Insecure deserialization (pickle & friends)", severity="high",
         category="Deserialization", cwe="CWE-502", owasp="A08", languages=PY, tags=("deserialization",),
         keywords=("pickle", "dill", "marshal", "shelve"),
         pattern=r"\b(?:pickle|cPickle|_pickle|dill|marshal|jsonpickle|shelve)\.(?:loads?|Unpickler|decode|open)\s*\(",
         description="pickle, dill, marshal, shelve and jsonpickle can instantiate arbitrary objects while "
                     "loading. Deserializing data from an untrusted source leads directly to remote code "
                     "execution.",
         recommendation="Only unpickle data you produced and integrity-protected (e.g. HMAC). Prefer safe "
                        "formats such as JSON, MessagePack or protobuf for untrusted input."),
    Rule(id="SR-PY-003", title="Unsafe YAML loading", severity="high", category="Deserialization",
         cwe="CWE-502", owasp="A08", languages=PY, tags=("deserialization",), keywords=("yaml.",),
         pattern=r"\byaml\.(?:unsafe_load|load_all|load)\s*\((?![^)\n]{0,200}(?:Safe|CSafe|Base)Loader)",
         description="yaml.load() with the default/full/unsafe loader can construct arbitrary Python objects "
                     "from tags like !!python/object/apply, allowing code execution from a crafted YAML file.",
         recommendation="Use yaml.safe_load() / yaml.safe_load_all() or pass Loader=yaml.SafeLoader."),
    Rule(id="SR-PY-004", title="subprocess call with shell=True", severity="high", category="Injection",
         cwe="CWE-78", owasp="A03", languages=PY, tags=("injection",), keywords=("shell",),
         pattern=r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]{0,400}?shell\s*=\s*True",
         description="shell=True passes the command through /bin/sh or cmd.exe. Any interpolated value "
                     "containing shell metacharacters (;, |, &&, $()) results in OS command injection.",
         recommendation="Pass the command as a list of arguments with shell=False (the default) and validate "
                        "inputs. Use shlex.quote() only when a shell is truly unavoidable."),
    Rule(id="SR-PY-005", title="OS command execution via os module", severity="medium", category="Injection",
         cwe="CWE-78", owasp="A03", languages=PY, tags=("injection",), keywords=("os.",),
         pattern=r"\bos\.(?:system|popen|popen2|popen3|spawnl|spawnlp|spawnv|spawnvp|execl|execlp|execv|execvp)\s*\(",
         description="os.system()/os.popen() always invoke a shell. Building the command from variables "
                     "enables command injection and makes argument escaping error-prone.",
         recommendation="Replace with subprocess.run([...], shell=False, check=True) using an argument list."),
    Rule(id="SR-PY-006", title="TLS certificate verification disabled", severity="high",
         category="Transport Security", cwe="CWE-295", owasp="A07", languages=PY, tags=("transport",),
         keywords=("verify",), pattern=r"\bverify\s*=\s*False\b",
         description="Disabling certificate verification (requests/httpx verify=False) accepts any "
                     "certificate, so a network attacker can transparently intercept and modify HTTPS traffic "
                     "(man-in-the-middle).",
         recommendation="Keep verification enabled. For private CAs pass verify='/path/to/ca-bundle.pem'."),
    Rule(id="SR-PY-007", title="Unverified SSL context", severity="high", category="Transport Security",
         cwe="CWE-295", owasp="A07", languages=PY, tags=("transport",), keywords=("ssl", "check_hostname"),
         pattern=r"ssl\._create_unverified_context|ssl\.CERT_NONE|check_hostname\s*=\s*False|_create_default_https_context\s*=",
         description="The SSL context skips certificate or hostname validation, which removes the "
                     "authentication guarantee of TLS and enables man-in-the-middle attacks.",
         recommendation="Use ssl.create_default_context() and keep CERT_REQUIRED with hostname checking."),
    Rule(id="SR-PY-008", title="Weak hash algorithm (MD5/SHA-1)", severity="medium", category="Cryptography",
         cwe="CWE-328", owasp="A02", languages=PY, tags=("crypto",), keywords=("md5", "sha1", "md4"),
         pattern=r"\bhashlib\.(?:md5|sha1)\s*\((?![^)\n]*usedforsecurity\s*=\s*False)|\bhashlib\.new\s*\(\s*['\"](?:md5|sha1|md4)['\"]",
         description="MD5 and SHA-1 are broken for collision resistance. Using them for signatures, integrity "
                     "checks or password storage allows forgeries and fast brute-force attacks.",
         recommendation="Use SHA-256/SHA-3 for integrity, HMAC for authentication and Argon2/bcrypt/scrypt "
                        "for passwords. Mark non-security uses with usedforsecurity=False."),
    Rule(id="SR-PY-009", title="Non-cryptographic random generator", severity="low", category="Cryptography",
         cwe="CWE-338", owasp="A02", languages=PY, tags=("crypto",), keywords=("random.",), confidence="low",
         pattern=r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample)\s*\(",
         description="The random module is a predictable Mersenne Twister. If used for tokens, passwords, "
                     "session IDs or nonces, attackers can predict future values.",
         recommendation="Use the secrets module (secrets.token_urlsafe, secrets.choice) for anything "
                        "security-sensitive."),
    Rule(id="SR-PY-010", title="Debug mode enabled", severity="medium", category="Misconfiguration",
         cwe="CWE-489", owasp="A05", languages=PY, tags=("config",), keywords=("debug",),
         pattern=r"\.run\s*\([^)\n]{0,200}debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b",
         description="Debug mode exposes stack traces, configuration and, in Flask/Werkzeug, an interactive "
                     "console that allows arbitrary code execution if reachable.",
         recommendation="Drive debug mode from an environment variable that defaults to False in production."),
    Rule(id="SR-PY-011", title="SQL query built with string formatting", severity="high", category="Injection",
         cwe="CWE-89", owasp="A03", languages=PY, tags=("injection",),
         keywords=("execute", "raw", "text(", "extra"),
         pattern=r"\.(?:execute|executemany|executescript|raw|extra)\s*\(\s*(?:f['\"]|['\"][^'\"\n]*['\"]\s*(?:%(?!\s*\()|\+|\.format\s*\())|\btext\s*\(\s*f['\"]",
         description="The SQL statement is assembled with f-strings, % formatting, .format() or "
                     "concatenation. Attacker-controlled values can change the query structure (SQL "
                     "injection), leaking or destroying data.",
         recommendation="Use parameterized queries: cursor.execute('... WHERE id = %s', (value,)) or ORM "
                        "query builders with bound parameters."),
    Rule(id="SR-PY-012", title="Insecure temporary file (mktemp)", severity="medium", category="Access Control",
         cwe="CWE-377", owasp="A01", languages=PY, tags=("access-control",), keywords=("mktemp",),
         pattern=r"\btempfile\.mktemp\s*\(|(?<![\w.])mktemp\s*\(",
         description="tempfile.mktemp() returns a name without creating the file, opening a race window in "
                     "which an attacker can create a symlink and hijack the file.",
         recommendation="Use tempfile.NamedTemporaryFile(), mkstemp() or TemporaryDirectory()."),
    Rule(id="SR-PY-013", title="Template auto-escaping disabled", severity="medium",
         category="Cross-Site Scripting", cwe="CWE-79", owasp="A03", languages=PY, tags=("xss", "injection"),
         keywords=("autoescape", "mark_safe", "markup("),
         pattern=r"autoescape\s*=\s*False|\bmark_safe\s*\(|\bMarkup\s*\(\s*f?['\"][^'\"\n]*(?:\{|%s)",
         description="Disabling auto-escaping or marking dynamic strings as safe renders them as raw HTML. "
                     "User-controlled content then executes as script in victims' browsers (XSS).",
         recommendation="Keep autoescape=True (or select_autoescape()) and only mark_safe() constant, "
                        "reviewed markup."),
    Rule(id="SR-PY-014", title="XML parser vulnerable to entity attacks", severity="low",
         category="Misconfiguration", cwe="CWE-611", owasp="A05", languages=PY, tags=("injection",),
         keywords=("xml", "lxml"), confidence="low",
         pattern=r"^\s*(?:from|import)\s+(?:xml\.(?:etree|dom|sax)|lxml)\b",
         description="The standard XML parsers can be abused with entity-expansion (billion laughs) and, "
                     "depending on configuration, external entity (XXE) payloads when parsing untrusted XML.",
         recommendation="Parse untrusted XML with defusedxml, or disable DTD/entity resolution explicitly."),
    Rule(id="SR-PY-015", title="SSH host key verification disabled", severity="medium",
         category="Transport Security", cwe="CWE-295", owasp="A07", languages=PY, tags=("transport",),
         keywords=("autoaddpolicy", "warningpolicy"), pattern=r"\b(?:AutoAddPolicy|WarningPolicy)\s*\(",
         description="Paramiko's AutoAddPolicy/WarningPolicy trust unknown host keys, so a man-in-the-middle "
                     "can impersonate the SSH server and capture credentials.",
         recommendation="Load known hosts (load_system_host_keys) and use RejectPolicy."),
    Rule(id="SR-PY-016", title="Hardcoded framework secret key", severity="high", category="Secrets",
         cwe="CWE-798", owasp="A07", languages=PY, tags=("secrets",), source="secret", redact=True,
         keywords=("secret_key",),
         pattern=r"(?:\bSECRET_KEY|\bapp\.secret_key|\bapp\.config\[\s*['\"]SECRET_KEY['\"]\s*\])\s*=\s*['\"]([^'\"]{4,})['\"]",
         description="The Django/Flask SECRET_KEY signs sessions, CSRF tokens and password-reset links. "
                     "Knowing it lets an attacker forge sessions and, with some serializers, execute code.",
         recommendation="Load SECRET_KEY from the environment or a secret manager and rotate the exposed key."),
    Rule(id="SR-PY-017", title="Wildcard ALLOWED_HOSTS", severity="medium", category="Misconfiguration",
         cwe="CWE-183", owasp="A05", languages=PY, tags=("config",), keywords=("allowed_hosts",),
         pattern=r"ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]",
         description="ALLOWED_HOSTS = ['*'] disables Host header validation, enabling cache poisoning and "
                     "password-reset poisoning attacks.",
         recommendation="List the exact production host names."),
    Rule(id="SR-PY-018", title="File path built from request data", severity="high", category="Access Control",
         cwe="CWE-22", owasp="A01", languages=PY, tags=("access-control", "injection"), keywords=("request.",),
         pattern=r"\b(?:open|send_file|send_from_directory|FileResponse)\s*\([^)\n]{0,200}request\.(?:args|form|values|GET|POST|files|json|data|query_params)",
         description="A filesystem path derived from request parameters allows path traversal (../../) to read "
                     "or overwrite arbitrary files on the server.",
         recommendation="Map user input to an allow-list of files, or normalise the path and verify it stays "
                        "inside the intended base directory (werkzeug.utils.safe_join)."),
    Rule(id="SR-PY-019", title="Server-side request with user-controlled URL", severity="high", category="SSRF",
         cwe="CWE-918", owasp="A10", languages=PY, tags=("ssrf",), keywords=("request.",),
         pattern=r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request)\s*\([^)\n]{0,200}request\.(?:args|form|values|GET|POST|json|query_params)|\burlopen\s*\([^)\n]{0,200}request\.(?:args|form|values|GET|POST)",
         description="The server fetches a URL taken from the incoming request. Attackers can make it call "
                     "internal services, cloud metadata endpoints (169.254.169.254) or local files.",
         recommendation="Validate URLs against an allow-list of hosts/schemes, resolve and block private IP "
                        "ranges and disable redirects."),
    Rule(id="SR-PY-020", title="Insecure cookie flags", severity="medium", category="Misconfiguration",
         cwe="CWE-614", owasp="A05", languages=PY, tags=("config", "auth"), keywords=("secure", "httponly"),
         pattern=r"\b(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|secure|httponly)\s*=\s*False",
         description="Cookies without Secure/HttpOnly can be sent over plaintext HTTP or read by injected "
                     "JavaScript, enabling session hijacking.",
         recommendation="Set Secure, HttpOnly and SameSite on session and CSRF cookies."),
    Rule(id="SR-PY-021", title="CSRF protection disabled", severity="medium", category="Access Control",
         cwe="CWE-352", owasp="A01", languages=PY, tags=("access-control",), keywords=("csrf",),
         pattern=r"@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False|\bcsrf\s*=\s*False",
         description="Endpoints without CSRF protection can be triggered by any web page the victim visits, "
                     "performing state-changing actions with the victim's session.",
         recommendation="Keep CSRF middleware enabled; exempt only token-authenticated APIs that do not rely "
                        "on cookies."),
    # ---------------------------------------------------------------- JavaScript / TypeScript
    Rule(id="SR-JS-001", title="Dynamic code execution (eval / Function)", severity="high", category="Injection",
         cwe="CWE-95", owasp="A03", languages=WEB, tags=("injection",), keywords=("eval", "function"),
         pattern=r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(",
         description="eval() and new Function() compile strings into code. Any attacker-controlled fragment "
                     "results in script injection in the browser or remote code execution in Node.js.",
         recommendation="Replace with JSON.parse, explicit lookup tables or safe expression libraries."),
    Rule(id="SR-JS-002", title="Unsafe HTML sink (innerHTML)", severity="medium", category="Cross-Site Scripting",
         cwe="CWE-79", owasp="A03", languages=WEB, tags=("xss", "injection"),
         keywords=("innerhtml", "outerhtml", "insertadjacenthtml"),
         pattern=r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)|\.insertAdjacentHTML\s*\(",
         description="Assigning strings to innerHTML/outerHTML parses them as HTML. If the string contains "
                     "unescaped user data, attackers can inject scripts (DOM-based XSS).",
         recommendation="Use textContent / createElement, or sanitize with DOMPurify before inserting HTML."),
    Rule(id="SR-JS-003", title="document.write usage", severity="medium", category="Cross-Site Scripting",
         cwe="CWE-79", owasp="A03", languages=WEB, tags=("xss", "injection"), keywords=("document.write",),
         pattern=r"\bdocument\.(?:write|writeln)\s*\(",
         description="document.write() injects raw HTML into the page and is a classic DOM XSS sink.",
         recommendation="Build DOM nodes explicitly and set text with textContent."),
    Rule(id="SR-JS-004", title="React dangerouslySetInnerHTML", severity="medium", category="Cross-Site Scripting",
         cwe="CWE-79", owasp="A03", languages=JS, tags=("xss", "injection"), keywords=("dangerouslysetinnerhtml",),
         pattern=r"dangerouslySetInnerHTML",
         description="dangerouslySetInnerHTML bypasses React's automatic escaping. Unsanitized content leads "
                     "to stored or reflected XSS.",
         recommendation="Render text normally or sanitize the HTML with DOMPurify before passing it."),
    Rule(id="SR-JS-005", title="Vue v-html directive", severity="medium", category="Cross-Site Scripting",
         cwe="CWE-79", owasp="A03", languages=("Vue", "HTML"), tags=("xss", "injection"), keywords=("v-html",),
         pattern=r"\bv-html\s*=",
         description="v-html renders raw HTML and disables Vue's escaping, enabling XSS with untrusted data.",
         recommendation="Use text interpolation ({{ }}) or sanitize the value before binding it."),
    Rule(id="SR-JS-006", title="Angular security bypass", severity="medium", category="Cross-Site Scripting",
         cwe="CWE-79", owasp="A03", languages=JS, tags=("xss", "injection"), keywords=("bypasssecuritytrust",),
         pattern=r"\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(",
         description="bypassSecurityTrust* disables Angular's built-in sanitization for the given value.",
         recommendation="Avoid the bypass or sanitize the value with a vetted sanitizer first."),
    Rule(id="SR-JS-007", title="Shell command built dynamically", severity="high", category="Injection",
         cwe="CWE-78", owasp="A03", languages=JS, tags=("injection",), keywords=("exec", "spawn"),
         pattern=r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^,)\n]*\+\s*\w)|\bspawn(?:Sync)?\s*\([^)]{0,300}shell\s*:\s*true",
         description="child_process.exec() runs the string through a shell. Interpolating variables into the "
                     "command allows OS command injection.",
         recommendation="Use execFile()/spawn() with an argument array and shell:false, and validate inputs."),
    Rule(id="SR-JS-008", title="Request data flows into command execution", severity="critical",
         category="Injection", cwe="CWE-78", owasp="A03", languages=JS, tags=("injection",), keywords=("req.",),
         pattern=r"\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\([^)\n]{0,200}req\.(?:query|params|body|headers|cookies)",
         description="HTTP request parameters are passed directly to a process-execution API, giving remote "
                     "attackers command execution on the server.",
         recommendation="Never pass request data to shells. Use strict allow-lists and argument arrays."),
    Rule(id="SR-JS-009", title="String passed to setTimeout/setInterval", severity="medium", category="Injection",
         cwe="CWE-95", owasp="A03", languages=JS, tags=("injection",), keywords=("settimeout", "setinterval"),
         pattern=r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]",
         description="Passing a string to setTimeout/setInterval evaluates it like eval().",
         recommendation="Pass a function reference instead of a string."),
    Rule(id="SR-JS-010", title="TLS certificate validation disabled", severity="high",
         category="Transport Security", cwe="CWE-295", owasp="A07",
         languages=JS + ("Env", "Shell", "JSON", "YAML", "Dockerfile", "INI"), tags=("transport",),
         keywords=("rejectunauthorized", "node_tls_reject_unauthorized", "strictssl", "strict-ssl"),
         pattern=r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*[\]:=,]\s*['\"]?0|strictSSL\s*:\s*false|strict-ssl\s*=\s*false",
         description="Certificate validation is turned off for Node.js/npm connections, allowing any "
                     "intermediary to intercept or tamper with HTTPS traffic.",
         recommendation="Keep validation on; trust private CAs with the ca option or NODE_EXTRA_CA_CERTS."),
    Rule(id="SR-JS-011", title="SQL query built with concatenation", severity="high", category="Injection",
         cwe="CWE-89", owasp="A03", languages=JS, tags=("injection",),
         keywords=("query", "execute", "raw"),
         pattern=r"\.(?:query|execute|raw|whereRaw)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"\n]*['\"]\s*\+)|\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(",
         description="The SQL text is built with template literals or concatenation, so request data can "
                     "alter the query (SQL injection).",
         recommendation="Use placeholders (? / $1) with parameter arrays, or tagged templates such as "
                        "Prisma's $queryRaw`...` that bind values safely."),
    Rule(id="SR-JS-012", title="Sensitive token stored in Web Storage", severity="medium", category="Insecure Design",
         cwe="CWE-922", owasp="A04", languages=WEB, tags=("auth",), keywords=("localstorage", "sessionstorage"),
         pattern=r"(?i)(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"`][^'\"`]*(?:token|jwt|secret|password|passwd|auth|session)",
         description="Anything in localStorage/sessionStorage is readable by every script on the origin, so a "
                     "single XSS bug exfiltrates the stored tokens.",
         recommendation="Keep session tokens in HttpOnly, Secure, SameSite cookies."),
    Rule(id="SR-JS-013", title="postMessage with wildcard origin", severity="medium",
         category="Integrity", cwe="CWE-345", owasp="A08", languages=WEB, tags=("access-control",),
         keywords=("postmessage",), pattern=r"\.postMessage\s*\([^)\n]{0,200},\s*['\"]\*['\"]",
         description="Sending postMessage to '*' delivers the data to whatever origin currently occupies the "
                     "target window, leaking it to malicious frames.",
         recommendation="Specify the exact target origin and validate event.origin on receipt."),
    Rule(id="SR-JS-014", title="Weak hash or cipher in Node.js crypto", severity="medium", category="Cryptography",
         cwe="CWE-327", owasp="A02", languages=JS, tags=("crypto",), keywords=("createhash", "createcipher"),
         pattern=r"(?i)createHash\s*\(\s*['\"](?:md5|sha1|md4)['\"]|createCipher\s*\(|createCipheriv\s*\(\s*['\"](?:des|des-ede3?|rc4|bf|aes-\d+-ecb)",
         description="MD5/SHA-1 hashes and DES/RC4/ECB ciphers are cryptographically broken, and the "
                     "deprecated createCipher derives keys insecurely without an IV.",
         recommendation="Use SHA-256+, AES-GCM or ChaCha20-Poly1305 with random IVs and crypto.scrypt/argon2 "
                        "for passwords."),
    Rule(id="SR-JS-015", title="Math.random used for secrets", severity="medium", category="Cryptography",
         cwe="CWE-338", owasp="A02", languages=WEB, tags=("crypto",), keywords=("math.random",),
         pattern=r"(?i)(?:token|secret|password|passwd|salt|nonce|otp|session|apikey)[^\n]{0,40}Math\.random\s*\(|Math\.random\s*\(\s*\)[^\n]{0,40}(?:token|secret|password|salt|nonce|otp)",
         description="Math.random() is not cryptographically secure; values used as tokens or passwords can be "
                     "predicted.",
         recommendation="Use crypto.getRandomValues() in browsers or crypto.randomBytes()/randomUUID() in Node."),
    Rule(id="SR-JS-016", title="File path built from request data", severity="high", category="Access Control",
         cwe="CWE-22", owasp="A01", languages=JS, tags=("access-control", "injection"), keywords=("req.",),
         pattern=r"\b(?:readFile|readFileSync|createReadStream|sendFile|download|unlink|unlinkSync|writeFile|writeFileSync)\s*\([^)\n]{0,200}req\.(?:query|params|body)",
         description="Request parameters are used as filesystem paths, allowing path traversal to read or "
                     "overwrite arbitrary files.",
         recommendation="Resolve against a fixed root, reject '..' and absolute paths, or use an allow-list."),
    Rule(id="SR-JS-017", title="Server-side request with user-controlled URL", severity="high", category="SSRF",
         cwe="CWE-918", owasp="A10", languages=JS, tags=("ssrf",), keywords=("req.",),
         pattern=r"\b(?:axios(?:\.\w+)?|fetch|got|needle|superagent\.\w+|https?\.get|https?\.request)\s*\([^)\n]{0,120}req\.(?:query|params|body)",
         description="The server issues HTTP requests to URLs taken from the client, enabling SSRF against "
                     "internal services and cloud metadata endpoints.",
         recommendation="Allow-list destinations, block private address ranges and disable redirects."),
    Rule(id="SR-JS-018", title="Open redirect", severity="medium", category="Access Control", cwe="CWE-601",
         owasp="A01", languages=JS, tags=("access-control",), keywords=("redirect",),
         pattern=r"\bres\.redirect\s*\([^)\n]{0,120}req\.(?:query|params|body)",
         description="Redirecting to a URL supplied in the request lets attackers craft trusted-looking links "
                     "that forward victims to phishing sites.",
         recommendation="Redirect only to relative paths or an allow-list of destinations."),
    Rule(id="SR-JS-019", title="MongoDB $where operator", severity="medium", category="Injection", cwe="CWE-943",
         owasp="A03", languages=JS + PY + PHP, tags=("injection",), keywords=("$where",),
         pattern=r"['\"]?\$where['\"]?\s*:",
         description="$where executes JavaScript inside the database; combined with user input it enables "
                     "NoSQL injection and denial of service.",
         recommendation="Use standard query operators and validate input types."),
    Rule(id="SR-JS-020", title="Permissive CORS policy", severity="medium", category="Misconfiguration",
         cwe="CWE-942", owasp="A05", languages=CODE, tags=("config",),
         keywords=("access-control-allow-origin", "origin", "cors"),
         pattern=r"Access-Control-Allow-Origin['\"]?\s*[,:=]\s*['\"]\*['\"]|\borigin\s*:\s*['\"]\*['\"]|\bcors\s*\(\s*\)|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*['\"]\*['\"]",
         description="A wildcard CORS policy lets any website read responses from this API. Combined with "
                     "credentials or internal-only endpoints it exposes data cross-origin.",
         recommendation="Allow only the specific trusted origins and avoid combining credentials with '*'."),
    Rule(id="SR-JS-021", title="JWT signature verification weakened", severity="high", category="Authentication",
         cwe="CWE-347", owasp="A07", languages=CODE, tags=("auth",),
         keywords=("none", "verify_signature", "verify", "ignoreexpiration"),
         pattern=r"(?i)algorithms?['\"]?\s*[:=]\s*\[?\s*['\"]none['\"]|verify_signature['\"]?\s*:\s*False|\bjwt\.decode\s*\([^)\n]{0,200}verify\s*=\s*False|ignoreExpiration\s*:\s*true",
         description="Accepting the 'none' algorithm or skipping signature/expiry checks lets attackers forge "
                     "or replay tokens and impersonate any user.",
         recommendation="Pin the expected algorithm (e.g. RS256/ES256), always verify signatures and expiry."),
    Rule(id="SR-JS-022", title="target=_blank without rel=noopener", severity="info", category="Misconfiguration",
         cwe="CWE-1022", owasp="A05", languages=WEB, tags=("config",), keywords=("_blank",), confidence="low",
         pattern=r"target\s*=\s*['\"{]_blank['\"}](?![^>\n]*rel\s*=\s*['\"{][^'\"}]*noopener)",
         description="Links opening a new tab without rel='noopener' give the new page a handle to "
                     "window.opener (reverse tabnabbing) in older browsers.",
         recommendation="Add rel='noopener noreferrer' to external links."),
    # ---------------------------------------------------------------- Templates / HTML
    Rule(id="SR-WEB-001", title="Template output escaping bypassed", severity="medium",
         category="Cross-Site Scripting", cwe="CWE-79", owasp="A03", languages=("HTML", "PHP", "Ruby", "Vue"),
         tags=("xss", "injection"), keywords=("safe", "{{{", "<%-", "{!!", "html.raw", "utext"),
         pattern=r"\{\{[^}\n]*\|\s*safe\s*\}\}|\{\{\{[^}\n]+\}\}\}|<%-\s|\{!!\s*[^!\n]+!!\}|@Html\.Raw\s*\(|\bth:utext\s*=",
         description="Raw/unescaped template output (|safe, {{{ }}}, <%-, {!! !!}, Html.Raw, th:utext) renders "
                     "data as HTML. Untrusted values become stored or reflected XSS.",
         recommendation="Use the escaped form of the output tag and sanitize any HTML that must be rendered."),
    Rule(id="SR-WEB-002", title="Resource loaded over plaintext HTTP", severity="medium",
         category="Transport Security", cwe="CWE-319", owasp="A02", languages=("HTML",), tags=("transport",),
         keywords=("http://",),
         pattern=r"<(?:form|script|iframe|link|img|embed|object)\b[^>\n]{0,200}(?:action|src|href|data)\s*=\s*['\"]http://(?!localhost|127\.0\.0\.1)",
         description="Scripts, forms or frames served over HTTP can be modified in transit, letting a network "
                     "attacker inject code or capture submitted data.",
         recommendation="Serve every resource over HTTPS and enable HSTS."),
    # ---------------------------------------------------------------- JVM
    Rule(id="SR-JAVA-001", title="OS command execution", severity="high", category="Injection", cwe="CWE-78",
         owasp="A03", languages=JVM, tags=("injection",), keywords=("exec", "processbuilder"),
         pattern=r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\([^)\n]{0,200}\+",
         description="Runtime.exec()/ProcessBuilder with dynamic strings can run attacker-influenced commands.",
         recommendation="Use fixed executables with argument arrays and validate every parameter."),
    Rule(id="SR-JAVA-002", title="SQL query built with concatenation", severity="high", category="Injection",
         cwe="CWE-89", owasp="A03", languages=JVM + CS, tags=("injection",),
         keywords=("execute", "preparestatement", "createquery", "createnativequery", "addbatch"),
         pattern=r"\b(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|addBatch)\s*\(\s*['\"][^'\"\n]*['\"]\s*\+",
         description="Concatenating values into SQL/JPQL text allows SQL injection, even when the result is "
                     "passed to prepareStatement().",
         recommendation="Use PreparedStatement placeholders (?) or named parameters with setParameter()."),
    Rule(id="SR-JAVA-003", title="Insecure deserialization", severity="high", category="Deserialization",
         cwe="CWE-502", owasp="A08", languages=JVM, tags=("deserialization",),
         keywords=("objectinputstream", "xmldecoder", "xstream", "defaulttyping"),
         pattern=r"new\s+ObjectInputStream\s*\(|\bXMLDecoder\s*\(|\bnew\s+XStream\s*\(\s*\)|enableDefaultTyping\s*\(|activateDefaultTyping\s*\(",
         description="Java native deserialization, XMLDecoder, unrestricted XStream and Jackson default typing "
                     "can instantiate gadget chains that execute code while reading attacker data.",
         recommendation="Avoid native deserialization of untrusted data; use JSON without polymorphic typing "
                        "or ObjectInputFilter allow-lists."),
    Rule(id="SR-JAVA-004", title="Weak cipher or ECB mode", severity="high", category="Cryptography",
         cwe="CWE-327", owasp="A02", languages=JVM, tags=("crypto",), keywords=("cipher.getinstance",),
         pattern=r"Cipher\.getInstance\s*\(\s*['\"](?:DES|DESede|RC2|RC4|Blowfish|AES|AES/ECB[^'\"]*|[^'\"]*/ECB/[^'\"]*)['\"]",
         description="DES/3DES/RC4 are broken and 'AES' alone defaults to ECB mode, which leaks patterns of the "
                     "plaintext and provides no integrity.",
         recommendation="Use AES/GCM/NoPadding with a unique random IV per message."),
    Rule(id="SR-JAVA-005", title="Weak hash algorithm", severity="medium", category="Cryptography",
         cwe="CWE-328", owasp="A02", languages=JVM, tags=("crypto",), keywords=("messagedigest", "digestutils"),
         pattern=r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD2|MD4|MD5|SHA-?1)['\"]|DigestUtils\.(?:md5|sha1|shaHex|md5Hex|sha1Hex)\s*\(",
         description="MD5 and SHA-1 are vulnerable to collisions and too fast for password hashing.",
         recommendation="Use SHA-256+ for integrity and bcrypt/Argon2/PBKDF2 for passwords."),
    Rule(id="SR-JAVA-006", title="Certificate or hostname validation bypass", severity="high",
         category="Transport Security", cwe="CWE-295", owasp="A07", languages=JVM, tags=("transport",),
         keywords=("hostname", "trustall", "getacceptedissuers"),
         pattern=r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|\bTrustAll\w*|setHostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true|getAcceptedIssuers\s*\(\s*\)\s*\{\s*return\s+null",
         description="Trust-all managers and permissive hostname verifiers accept any certificate, removing "
                     "TLS server authentication.",
         recommendation="Use the platform default TrustManager and HostnameVerifier; pin certificates if needed."),
    Rule(id="SR-JAVA-007", title="Predictable random generator", severity="low", category="Cryptography",
         cwe="CWE-338", owasp="A02", languages=JVM + CS, tags=("crypto",), keywords=("random",),
         confidence="low", pattern=r"new\s+(?:java\.util\.)?Random\s*\(",
         description="java.util.Random / System.Random are predictable and unsuitable for tokens or keys.",
         recommendation="Use SecureRandom (Java) or RandomNumberGenerator (.NET) for security values."),
    Rule(id="SR-JAVA-008", title="XML parser factory (XXE review)", severity="low", category="Misconfiguration",
         cwe="CWE-611", owasp="A05", languages=JVM, tags=("injection",), keywords=("factory.newinstance",),
         confidence="low",
         pattern=r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\s*\(",
         description="Java XML factories resolve external entities by default, enabling XXE (file disclosure, "
                     "SSRF) when parsing untrusted XML unless hardened.",
         recommendation="Enable FEATURE_SECURE_PROCESSING and set disallow-doctype-decl to true."),
    Rule(id="SR-JAVA-009", title="CSRF protection disabled (Spring)", severity="medium", category="Access Control",
         cwe="CWE-352", owasp="A01", languages=JVM, tags=("access-control",), keywords=("csrf",),
         pattern=r"\.csrf\s*\(\s*\)\s*\.disable\s*\(\)|csrf\s*\(\s*(?:\w+\s*->\s*\w+\.disable\(\)|AbstractHttpConfigurer::disable)\s*\)",
         description="Disabling Spring Security CSRF protection exposes cookie-authenticated endpoints to "
                     "cross-site request forgery.",
         recommendation="Keep CSRF enabled for browser sessions; disable only for stateless token APIs."),
    Rule(id="SR-JAVA-010", title="All actuator endpoints exposed", severity="medium", category="Misconfiguration",
         cwe="CWE-200", owasp="A05", languages=("Properties", "YAML"), tags=("config",),
         keywords=("exposure",),
         pattern=r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*['\"]?\*|^\s*include\s*:\s*['\"]\*['\"]",
         description="Exposing every Spring Boot actuator endpoint can leak environment variables, heap dumps "
                     "and allow configuration changes.",
         recommendation="Expose only health/info publicly and protect the rest with authentication."),
    # ---------------------------------------------------------------- .NET
    Rule(id="SR-CS-001", title="Insecure .NET deserialization", severity="high", category="Deserialization",
         cwe="CWE-502", owasp="A08", languages=CS, tags=("deserialization",),
         keywords=("formatter", "typenamehandling", "netdatacontractserializer"),
         pattern=r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|ObjectStateFormatter)\b|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)",
         description="BinaryFormatter and similar serializers (or Json.NET TypeNameHandling) deserialize "
                     "arbitrary types, a well-known remote code execution vector.",
         recommendation="Use System.Text.Json or DataContractSerializer with known types only."),
    Rule(id="SR-CS-002", title="SQL command built with concatenation", severity="high", category="Injection",
         cwe="CWE-89", owasp="A03", languages=CS, tags=("injection",), keywords=("command", "sqlraw", "sqlcommand"),
         pattern=r"new\s+(?:SqlCommand|OleDbCommand|OdbcCommand|MySqlCommand|NpgsqlCommand|SqliteCommand)\s*\(\s*(?:\$@?\"|@?\"[^\"\n]*\"\s*\+)|\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlCommand)\s*\(\s*(?:\$\"|\"[^\"\n]*\"\s*\+)",
         description="Interpolated or concatenated SQL text allows SQL injection.",
         recommendation="Use SqlParameter / FromSqlInterpolated / parameterized Dapper queries."),
    Rule(id="SR-CS-003", title="Certificate validation bypass", severity="high", category="Transport Security",
         cwe="CWE-295", owasp="A07", languages=CS, tags=("transport",),
         keywords=("certificatevalidationcallback", "dangerousacceptany"),
         pattern=r"ServerCertificate(?:Custom)?ValidationCallback\s*\+?=|DangerousAcceptAnyServerCertificateValidator",
         description="Custom certificate validation callbacks often return true unconditionally, disabling TLS "
                     "server authentication.",
         recommendation="Remove the callback or validate the chain and thumbprint explicitly."),
    Rule(id="SR-CS-004", title="Weak .NET cryptography", severity="medium", category="Cryptography",
         cwe="CWE-327", owasp="A02", languages=CS, tags=("crypto",), keywords=("md5", "sha1", "des", "rc2", "ecb"),
         pattern=r"\b(?:MD5|SHA1|DES|TripleDES|RC2)(?:CryptoServiceProvider|Managed|\.Create)\b|CipherMode\.ECB",
         description="MD5, SHA-1, DES, 3DES, RC2 and ECB mode are deprecated and cryptographically weak.",
         recommendation="Use SHA-256+, AesGcm and Rfc2898DeriveBytes/Argon2 for passwords."),
    Rule(id="SR-CS-005", title="Process started with dynamic arguments", severity="medium", category="Injection",
         cwe="CWE-78", owasp="A03", languages=CS, tags=("injection",), keywords=("process",),
         pattern=r"Process\.Start\s*\([^)\n]{0,200}\+|new\s+ProcessStartInfo\s*\([^)\n]{0,200}\+",
         description="Building process arguments by concatenation can allow argument or command injection.",
         recommendation="Use ProcessStartInfo.ArgumentList and validate each argument."),
    # ---------------------------------------------------------------- PHP
    Rule(id="SR-PHP-001", title="Dynamic code evaluation", severity="high", category="Injection", cwe="CWE-95",
         owasp="A03", languages=PHP, tags=("injection",), keywords=("eval", "assert", "create_function"),
         pattern=r"(?<![\w>$])(?:eval|assert|create_function)\s*\(",
         description="eval(), assert() with strings and create_function() execute PHP code built at runtime.",
         recommendation="Remove dynamic evaluation and use explicit control flow."),
    Rule(id="SR-PHP-002", title="OS command execution", severity="high", category="Injection", cwe="CWE-78",
         owasp="A03", languages=PHP, tags=("injection",),
         keywords=("system", "exec", "passthru", "popen", "proc_open", "`"),
         pattern=r"(?<![\w>$:])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`\n]*\$[^`\n]*`",
         description="Shell execution functions and backticks run OS commands; variables inside them allow "
                     "command injection.",
         recommendation="Avoid shelling out; otherwise use escapeshellarg() on every argument and allow-lists."),
    Rule(id="SR-PHP-003", title="unserialize() on data", severity="high", category="Deserialization",
         cwe="CWE-502", owasp="A08", languages=PHP, tags=("deserialization",), keywords=("unserialize",),
         pattern=r"(?<![\w>$])unserialize\s*\(",
         description="unserialize() on attacker data triggers magic methods (POP chains) leading to code "
                     "execution or file operations.",
         recommendation="Use json_decode(), or unserialize($x, ['allowed_classes' => false])."),
    Rule(id="SR-PHP-004", title="SQL query with request superglobals", severity="critical", category="Injection",
         cwe="CWE-89", owasp="A03", languages=PHP, tags=("injection",), keywords=("$_",),
         pattern=r"(?:mysql_query|mysqli_query|pg_query|->query|->exec|->prepare)\s*\([^;\n]{0,300}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)",
         description="Request superglobals are placed directly into SQL, a textbook SQL injection.",
         recommendation="Use PDO/mysqli prepared statements with bound parameters."),
    Rule(id="SR-PHP-005", title="File inclusion from request data", severity="critical", category="Injection",
         cwe="CWE-98", owasp="A03", languages=PHP, tags=("injection", "access-control"), keywords=("$_",),
         pattern=r"\b(?:include|require)(?:_once)?\b[^;\n]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)",
         description="include/require with request data enables local and remote file inclusion, frequently "
                     "escalating to remote code execution.",
         recommendation="Map requested pages to a fixed allow-list of files."),
    Rule(id="SR-PHP-006", title="Reflected output of request data", severity="high",
         category="Cross-Site Scripting", cwe="CWE-79", owasp="A03", languages=PHP, tags=("xss", "injection"),
         keywords=("$_",), exclude=r"htmlspecialchars|htmlentities|intval|esc_html|esc_attr|strip_tags",
         pattern=r"\b(?:echo|print)\b[^;\n]{0,200}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)",
         description="Echoing request parameters without encoding produces reflected XSS.",
         recommendation="Encode output with htmlspecialchars($v, ENT_QUOTES, 'UTF-8')."),
    Rule(id="SR-PHP-007", title="Weak password hashing", severity="high", category="Cryptography",
         cwe="CWE-916", owasp="A02", languages=PHP, tags=("crypto",), keywords=("md5", "sha1"),
         pattern=r"(?i)\b(?:md5|sha1)\s*\(\s*\$\w*(?:pass|pwd)",
         description="Unsalted fast hashes make stolen password databases trivial to crack.",
         recommendation="Use password_hash() with PASSWORD_ARGON2ID or PASSWORD_BCRYPT."),
    Rule(id="SR-PHP-008", title="cURL TLS verification disabled", severity="high", category="Transport Security",
         cwe="CWE-295", owasp="A07", languages=PHP, tags=("transport",), keywords=("curlopt_ssl_verify",),
         pattern=r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|CURLOPT_SSL_VERIFYHOST\s*,\s*0",
         description="Turning off peer/host verification in cURL allows man-in-the-middle interception.",
         recommendation="Keep verification enabled and configure CURLOPT_CAINFO for private CAs."),
    Rule(id="SR-PHP-009", title="Error display enabled", severity="low", category="Misconfiguration",
         cwe="CWE-209", owasp="A05", languages=PHP + ("INI",), tags=("config",), keywords=("display_errors",),
         pattern=r"(?i)ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(?:1|on|true)|^\s*display_errors\s*=\s*On",
         description="Displaying errors to users reveals paths, queries and stack traces useful to attackers.",
         recommendation="Log errors server-side and set display_errors=Off in production."),
    # ---------------------------------------------------------------- Go
    Rule(id="SR-GO-001", title="TLS verification disabled (InsecureSkipVerify)", severity="high",
         category="Transport Security", cwe="CWE-295", owasp="A07", languages=GO, tags=("transport",),
         keywords=("insecureskipverify",), pattern=r"InsecureSkipVerify\s*:\s*true",
         description="InsecureSkipVerify accepts any certificate chain and host name, enabling MITM attacks.",
         recommendation="Remove it; add private CAs to RootCAs instead."),
    Rule(id="SR-GO-002", title="Command executed through a shell", severity="medium", category="Injection",
         cwe="CWE-78", owasp="A03", languages=GO, tags=("injection",), keywords=("exec.command",),
         pattern=r"exec\.Command(?:Context)?\s*\(\s*(?:ctx\s*,\s*)?['\"](?:sh|bash|zsh|/bin/sh|/bin/bash|cmd|cmd\.exe|powershell|pwsh)['\"]",
         description="Running commands via sh -c / cmd /c reintroduces shell parsing and command injection.",
         recommendation="Invoke the binary directly with separate arguments."),
    Rule(id="SR-GO-003", title="SQL query built with fmt.Sprintf/concatenation", severity="high",
         category="Injection", cwe="CWE-89", owasp="A03", languages=GO, tags=("injection",),
         keywords=("query", "exec", "raw", "where"),
         pattern=r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Where)\s*\(\s*(?:ctx\s*,\s*)?(?:fmt\.Sprintf\s*\(|['\"`][^'\"`\n]*['\"`]\s*\+)",
         description="Formatting values into SQL text allows SQL injection.",
         recommendation="Use placeholders ($1, ?) and pass values as arguments."),
    Rule(id="SR-GO-004", title="Weak cryptographic package", severity="medium", category="Cryptography",
         cwe="CWE-327", owasp="A02", languages=GO, tags=("crypto",), keywords=("crypto/",),
         pattern=r"['\"]crypto/(?:md5|sha1|des|rc4)['\"]",
         description="crypto/md5, sha1, des and rc4 provide broken primitives.",
         recommendation="Use crypto/sha256, crypto/aes with cipher.NewGCM, or x/crypto/argon2."),
    Rule(id="SR-GO-005", title="math/rand imported", severity="low", category="Cryptography", cwe="CWE-338",
         owasp="A02", languages=GO, tags=("crypto",), keywords=("math/rand",), confidence="low",
         pattern=r"['\"]math/rand(?:/v2)?['\"]",
         description="math/rand is deterministic and must not generate secrets, tokens or keys.",
         recommendation="Use crypto/rand for security-sensitive randomness."),
    Rule(id="SR-GO-006", title="HTTP server without TLS", severity="low", category="Transport Security",
         cwe="CWE-319", owasp="A02", languages=GO, tags=("transport",), keywords=("listenandserve",),
         confidence="low", pattern=r"\bhttp\.ListenAndServe\s*\(",
         description="The server listens over plaintext HTTP. Unless TLS is terminated upstream, credentials "
                     "and data travel unencrypted.",
         recommendation="Use ListenAndServeTLS or terminate TLS at a trusted proxy."),
    # ---------------------------------------------------------------- Ruby
    Rule(id="SR-RB-001", title="Dynamic code evaluation", severity="high", category="Injection", cwe="CWE-95",
         owasp="A03", languages=RB, tags=("injection",), keywords=("eval",),
         pattern=r"(?<![\w.])eval\s*[\( ]|\b(?:instance_eval|class_eval|module_eval)\s*\(?\s*['\"]",
         description="eval and string-based *_eval execute Ruby code built at runtime.",
         recommendation="Use blocks, public_send with allow-lists or explicit dispatch."),
    Rule(id="SR-RB-002", title="Shell command with interpolation", severity="high", category="Injection",
         cwe="CWE-78", owasp="A03", languages=RB, tags=("injection",), keywords=("#{",),
         pattern=r"\b(?:system|exec|spawn|IO\.popen|Open3\.\w+)\s*\(?[^\n]{0,200}#\{|%x[\(\[\{][^\n]*#\{|`[^`\n]*#\{[^`\n]*`",
         description="Interpolating values into shell commands allows command injection.",
         recommendation="Pass arguments separately: system('cmd', arg1, arg2)."),
    Rule(id="SR-RB-003", title="Unsafe YAML/Marshal load", severity="high", category="Deserialization",
         cwe="CWE-502", owasp="A08", languages=RB, tags=("deserialization",), keywords=("yaml", "psych", "marshal"),
         pattern=r"\b(?:YAML|Psych)\.(?:load|unsafe_load)\b(?!_file)|\bMarshal\.(?:load|restore)\b",
         description="YAML.load (Psych < 4) and Marshal.load can instantiate arbitrary objects, leading to "
                     "remote code execution.",
         recommendation="Use YAML.safe_load with permitted_classes, and never Marshal.load untrusted data."),
    Rule(id="SR-RB-004", title="Output escaping bypassed", severity="medium", category="Cross-Site Scripting",
         cwe="CWE-79", owasp="A03", languages=RB, tags=("xss", "injection"), keywords=("html_safe", "raw", "<%=="),
         pattern=r"\.html_safe\b|<%==|(?<![\w.])raw\s*\(",
         description="html_safe/raw mark strings as trusted HTML and disable Rails escaping.",
         recommendation="Escape by default; use sanitize() with an allow-list for rich text."),
    Rule(id="SR-RB-005", title="SQL string interpolation (ActiveRecord)", severity="high", category="Injection",
         cwe="CWE-89", owasp="A03", languages=RB, tags=("injection",), keywords=("#{",),
         pattern=r"\.(?:where|find_by_sql|order|group|having|joins|select|pluck|execute|delete_all|update_all)\s*\(\s*['\"][^'\"\n]*#\{",
         description="Interpolating values into ActiveRecord SQL fragments allows SQL injection.",
         recommendation="Use hash conditions or placeholders: where('id = ?', id)."),
    Rule(id="SR-RB-006", title="Mass assignment with permit!", severity="medium", category="Insecure Design",
         cwe="CWE-915", owasp="A04", languages=RB, tags=("access-control",), keywords=("permit!",),
         pattern=r"\.permit!",
         description="permit! allows every request parameter to be mass-assigned, including admin flags.",
         recommendation="Whitelist attributes with permit(:field1, :field2)."),
    # ---------------------------------------------------------------- C / C++
    Rule(id="SR-C-001", title="Use of gets()", severity="critical", category="Memory Safety", cwe="CWE-242",
         owasp="OTHER", languages=CC, tags=("memory",), keywords=("gets",),
         pattern=r"(?<![\w.>])gets\s*\(",
         description="gets() cannot limit input length; every call is an exploitable stack buffer overflow.",
         recommendation="Use fgets(buf, sizeof buf, stdin) or getline()."),
    Rule(id="SR-C-002", title="Unbounded string copy/format", severity="medium", category="Memory Safety",
         cwe="CWE-120", owasp="OTHER", languages=CC, tags=("memory",),
         keywords=("strcpy", "strcat", "sprintf", "wcscpy", "wcscat"),
         pattern=r"(?<![\w.>])(?:strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat|lstrcpy|lstrcat|StrCpy|StrCat)\s*\(",
         description="These functions do not check destination buffer sizes, causing buffer overflows when the "
                     "source is longer than expected.",
         recommendation="Use snprintf, strlcpy/strlcat or safer C++ std::string APIs."),
    Rule(id="SR-C-003", title="Command execution in native code", severity="medium", category="Injection",
         cwe="CWE-78", owasp="A03", languages=CC, tags=("injection",), keywords=("system", "popen", "winexec", "shellexecute"),
         pattern=r"(?<![\w.>])(?:system|popen|_popen|_wsystem|WinExec|ShellExecuteA|ShellExecuteW|ShellExecute)\s*\(",
         description="system()/popen() spawn a shell; dynamic arguments allow command injection.",
         recommendation="Use execve/posix_spawn/CreateProcess with fixed paths and argument vectors."),
    Rule(id="SR-C-004", title="Format string from variable", severity="medium", category="Memory Safety",
         cwe="CWE-134", owasp="OTHER", languages=CC, tags=("memory",), keywords=("printf", "syslog"),
         pattern=r"(?<![\w.>])(?:printf|vprintf)\s*\(\s*[A-Za-z_][\w\->.\[\]]*\s*\)|(?<![\w.>])(?:fprintf|sprintf|syslog|dprintf)\s*\(\s*[^,\n]+,\s*[A-Za-z_][\w\->.\[\]]*\s*\)",
         description="Passing a non-literal as the format string lets attackers use %n/%x to read or write "
                     "memory.",
         recommendation="Always use a literal format: printf(\"%s\", value)."),
    Rule(id="SR-C-005", title="Unbounded scanf %s", severity="medium", category="Memory Safety", cwe="CWE-120",
         owasp="OTHER", languages=CC, tags=("memory",), keywords=("scanf",),
         pattern=r"\b(?:scanf|sscanf|fscanf)\s*\([^;\n]*\"[^\"\n]*%s",
         description="%s without a width reads unlimited input into a fixed buffer.",
         recommendation="Specify a maximum width (e.g. %63s) or use fgets."),
    Rule(id="SR-C-006", title="Predictable rand()", severity="low", category="Cryptography", cwe="CWE-338",
         owasp="A02", languages=CC, tags=("crypto",), keywords=("rand",), confidence="low",
         pattern=r"(?<![\w.>])(?:rand|srand)\s*\(",
         description="rand() is predictable and unsuitable for keys, tokens or nonces.",
         recommendation="Use getrandom(), arc4random() or BCryptGenRandom()."),
    # ---------------------------------------------------------------- Rust
    Rule(id="SR-RS-001", title="unsafe block", severity="low", category="Memory Safety", cwe="CWE-119",
         owasp="OTHER", languages=RS, tags=("memory",), keywords=("unsafe",), confidence="low",
         pattern=r"\bunsafe\s*\{",
         description="unsafe blocks opt out of Rust's memory-safety guarantees; bugs inside them can cause "
                     "memory corruption.",
         recommendation="Minimise unsafe code, document invariants and fuzz/test it (cargo-geiger, Miri)."),
    Rule(id="SR-RS-002", title="TLS validation disabled (Rust)", severity="high", category="Transport Security",
         cwe="CWE-295", owasp="A07", languages=RS, tags=("transport",), keywords=("danger",),
         pattern=r"danger_accept_invalid_certs\s*\(\s*true|danger_accept_invalid_hostnames\s*\(\s*true",
         description="Accepting invalid certificates or host names disables TLS authentication.",
         recommendation="Remove the danger_* options and add custom root certificates if required."),
    # ---------------------------------------------------------------- Mobile
    Rule(id="SR-MOB-001", title="Risky Android WebView settings", severity="medium", category="Misconfiguration",
         cwe="CWE-749", owasp="A05", languages=("Java", "Kotlin"), tags=("config",),
         keywords=("setjavascriptenabled", "setallowfileaccess", "addjavascriptinterface", "universalaccess"),
         pattern=r"setJavaScriptEnabled\s*\(\s*true|setAllowFileAccess\s*\(\s*true|setAllowUniversalAccessFromFileURLs\s*\(\s*true|addJavascriptInterface\s*\(",
         description="Enabling JavaScript/file access or exposing Java objects to WebView content allows "
                     "malicious pages to access local files or invoke native code.",
         recommendation="Load only trusted content, disable file access and avoid addJavascriptInterface."),
    Rule(id="SR-MOB-002", title="Insecure Android manifest flags", severity="medium", category="Misconfiguration",
         cwe="CWE-489", owasp="A05", languages=("XML",), tags=("config",),
         keywords=("debuggable", "allowbackup", "cleartexttraffic"),
         pattern=r"android:debuggable\s*=\s*['\"]true|android:allowBackup\s*=\s*['\"]true|android:usesCleartextTraffic\s*=\s*['\"]true",
         description="Debuggable builds, unrestricted backups and cleartext traffic expose app data and "
                     "network communication.",
         recommendation="Set debuggable=false, allowBackup=false (or use backup rules) and disable cleartext."),
    Rule(id="SR-MOB-003", title="iOS App Transport Security disabled", severity="medium",
         category="Transport Security", cwe="CWE-319", owasp="A02", languages=("XML",), tags=("transport",),
         keywords=("nsallowsarbitraryloads",), pattern=r"<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>",
         description="NSAllowsArbitraryLoads allows plaintext HTTP and weak TLS for all connections.",
         recommendation="Remove the global exception and add narrowly-scoped domain exceptions if needed."),
    Rule(id="SR-MOB-004", title="World-readable/writable file mode", severity="high", category="Access Control",
         cwe="CWE-732", owasp="A01", languages=("Java", "Kotlin"), tags=("access-control",),
         keywords=("mode_world",), pattern=r"MODE_WORLD_(?:READABLE|WRITEABLE)",
         description="Files created world-readable/writable can be accessed by any other app on the device.",
         recommendation="Use MODE_PRIVATE and share data via ContentProviders with permissions."),
    # ---------------------------------------------------------------- Shell & scripts
    Rule(id="SR-SH-001", title="Remote script piped into a shell", severity="high", category="Supply Chain",
         cwe="CWE-494", owasp="A08", languages=SHELLISH, tags=("supply-chain",),
         keywords=("curl", "wget", "iwr", "invoke-webrequest", "irm", "invoke-restmethod"),
         pattern=r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b|\b(?:iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b[^|\n]*\|\s*(?:iex|Invoke-Expression)\b",
         description="Downloading and executing a script in one step runs whatever the server (or a network "
                     "attacker) returns, without integrity verification.",
         recommendation="Download to a file, verify a pinned checksum or signature, then execute."),
    Rule(id="SR-SH-002", title="World-writable permissions (777)", severity="medium", category="Access Control",
         cwe="CWE-732", owasp="A01", languages=SHELLISH + CODE, tags=("access-control",), keywords=("777", "rwx"),
         pattern=r"\bchmod\s+(?:-R\s+)?0?777\b|\bchmod\s+(?:-R\s+)?a\+rwx\b|\bchmod(?:Sync)?\s*\([^)\n]*0o?777\b",
         description="Mode 777 lets every local user modify or replace the files, enabling privilege "
                     "escalation and tampering.",
         recommendation="Grant the minimum permissions required (e.g. 750/640) to the owning user/group."),
    Rule(id="SR-SH-003", title="TLS verification disabled in tooling", severity="medium",
         category="Transport Security", cwe="CWE-295", owasp="A07", languages=SHELLISH, tags=("transport",),
         keywords=("--insecure", "-k", "no-check-certificate", "sslverify", "git_ssl_no_verify", "trusted-host",
                   "strict-ssl", "skipcertificatecheck"),
         pattern=r"\bcurl\b[^\n]*\s(?:-k|--insecure)\b|\bwget\b[^\n]*--no-check-certificate|\bgit\s+config\b[^\n]*http\.sslVerify\s+false|GIT_SSL_NO_VERIFY|\bpip3?\b[^\n]*--trusted-host|npm\s+config\s+set\s+strict-ssl\s+false|-SkipCertificateCheck",
         description="Build and deployment scripts that skip certificate checks can be fed malicious "
                     "artifacts by anyone on the network path.",
         recommendation="Keep TLS verification on and install the correct CA bundle instead."),
    Rule(id="SR-SH-004", title="PowerShell dynamic execution / policy bypass", severity="medium",
         category="Injection", cwe="CWE-95", owasp="A03", languages=("PowerShell", "Batch", "YAML"),
         tags=("injection",), keywords=("invoke-expression", "iex", "executionpolicy"),
         pattern=r"\b(?:Invoke-Expression|iex)\b\s*[\(\$'\"]|-ExecutionPolicy\s+(?:Bypass|Unrestricted)",
         description="Invoke-Expression evaluates strings as code, and bypassing the execution policy disables "
                     "a script-signing safeguard.",
         recommendation="Call commands directly with parameters and keep a restrictive execution policy."),
    Rule(id="SR-SH-005", title="eval of shell variables", severity="medium", category="Injection", cwe="CWE-95",
         owasp="A03", languages=("Shell",), tags=("injection",), keywords=("eval",),
         pattern=r"(?<![\w.])eval\s+[\"']?\$",
         description="eval on variable content re-parses it as shell code, enabling injection.",
         recommendation="Use arrays and direct command invocation instead of eval."),
    Rule(id="SR-SH-006", title="Passwordless sudo for all commands", severity="high", category="Access Control",
         cwe="CWE-250", owasp="A01", languages=ANY, tags=("access-control", "config"), keywords=("nopasswd",),
         pattern=r"NOPASSWD\s*:\s*ALL",
         description="Granting passwordless sudo for every command turns any compromise of that account into "
                     "full root access.",
         recommendation="Restrict sudo rules to specific commands and require authentication."),
    # ---------------------------------------------------------------- Containers
    Rule(id="SR-DOCKER-001", title="Unpinned container base image", severity="low", category="Supply Chain",
         cwe="CWE-1357", owasp="A08", languages=("Dockerfile",), tags=("supply-chain", "container"),
         description="Base images referenced without a tag or with :latest change silently between builds, "
                     "making builds non-reproducible and able to pull in compromised or vulnerable layers.",
         recommendation="Pin a specific version tag and preferably the image digest (image:1.2.3@sha256:...)."),
    Rule(id="SR-DOCKER-002", title="Container runs as root", severity="medium", category="Misconfiguration",
         cwe="CWE-250", owasp="A05", languages=("Dockerfile",), tags=("config", "container"),
         description="Without a non-root USER the application runs as UID 0; a container escape or file-write "
                     "bug then has root privileges.",
         recommendation="Create an unprivileged user and add 'USER appuser' before the entrypoint."),
    Rule(id="SR-DOCKER-003", title="ADD from remote URL", severity="medium", category="Supply Chain",
         cwe="CWE-494", owasp="A08", languages=("Dockerfile",), tags=("supply-chain", "container"),
         keywords=("add",), flags=_I, pattern=r"^\s*ADD\s+(?:--\S+\s+)*https?://",
         description="ADD <url> downloads content without integrity verification at build time.",
         recommendation="Use curl with checksum verification in a RUN step, or ADD --checksum=sha256:..."),
    Rule(id="SR-DOCKER-004", title="Secret passed through ENV/ARG", severity="high", category="Secrets",
         cwe="CWE-798", owasp="A07", languages=("Dockerfile",), tags=("secrets", "container"),
         source="secret", redact=True, keywords=("env", "arg"), flags=_I,
         exclude=r"=\s*\$\{?\w+\}?\s*$",
         pattern=r"^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)\w*(?:\s*=\s*|\s+)(\S+)",
         description="Values set with ENV/ARG are stored in image layers and visible via 'docker history' to "
                     "anyone who can pull the image.",
         recommendation="Use BuildKit secrets (RUN --mount=type=secret) and inject runtime secrets at deploy "
                        "time."),
    Rule(id="SR-DOCKER-005", title="SSH port exposed", severity="low", category="Misconfiguration",
         cwe="CWE-284", owasp="A05", languages=("Dockerfile",), tags=("config", "container"), keywords=("expose",),
         flags=_I, pattern=r"^\s*EXPOSE\s+(?:[\d/a-z\s]*\s)?22(?:/tcp)?\b",
         description="Running SSH inside containers increases attack surface and credential sprawl.",
         recommendation="Use 'docker exec' / 'kubectl exec' for debugging instead of an SSH daemon."),
    Rule(id="SR-K8S-001", title="Privileged container", severity="high", category="Misconfiguration",
         cwe="CWE-250", owasp="A05", languages=("YAML", "JSON"), tags=("config", "container", "iac"),
         keywords=("privileged",), pattern=r"\bprivileged['\"]?\s*:\s*true\b",
         description="Privileged containers have all capabilities and device access; a compromise equals host "
                     "compromise.",
         recommendation="Remove privileged: true and grant only the specific capabilities required."),
    Rule(id="SR-K8S-002", title="Privilege escalation or root user allowed", severity="medium",
         category="Misconfiguration", cwe="CWE-250", owasp="A05", languages=("YAML", "JSON"),
         tags=("config", "container", "iac"), keywords=("allowprivilegeescalation", "runasuser", "runasnonroot"),
         pattern=r"allowPrivilegeEscalation['\"]?\s*:\s*true|runAsUser['\"]?\s*:\s*0\b|runAsNonRoot['\"]?\s*:\s*false",
         description="The workload may run as root or gain more privileges than its parent process.",
         recommendation="Set runAsNonRoot: true, allowPrivilegeEscalation: false and a non-zero runAsUser."),
    Rule(id="SR-K8S-003", title="Host namespace sharing", severity="medium", category="Misconfiguration",
         cwe="CWE-668", owasp="A05", languages=("YAML", "JSON"), tags=("config", "container", "iac"),
         keywords=("hostnetwork", "hostpid", "hostipc", "network_mode", "pid"),
         pattern=r"\bhost(?:Network|PID|IPC)['\"]?\s*:\s*true|\bnetwork_mode\s*:\s*['\"]?host\b|^\s*pid\s*:\s*['\"]?host\b",
         description="Sharing host network/PID/IPC namespaces breaks container isolation.",
         recommendation="Remove host namespace sharing unless strictly required and documented."),
    Rule(id="SR-K8S-004", title="Docker socket mounted", severity="high", category="Misconfiguration",
         cwe="CWE-250", owasp="A05", languages=("YAML", "JSON", "Dockerfile", "Shell"),
         tags=("config", "container"), keywords=("docker.sock",), pattern=r"/var/run/docker\.sock",
         description="Access to the Docker socket is equivalent to root on the host.",
         recommendation="Avoid mounting the socket; use rootless builders (Kaniko, BuildKit) instead."),
    Rule(id="SR-K8S-005", title="Dangerous Linux capability", severity="medium", category="Misconfiguration",
         cwe="CWE-250", owasp="A05", languages=("YAML", "JSON"), tags=("config", "container", "iac"),
         keywords=("sys_admin", "sys_ptrace", "net_admin"),
         pattern=r"\b(?:CAP_)?(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN)\b",
         description="SYS_ADMIN, SYS_PTRACE and NET_ADMIN grant near-root abilities inside the container.",
         recommendation="Drop ALL capabilities and add back only the minimal required set."),
    # ---------------------------------------------------------------- Infrastructure as Code
    Rule(id="SR-IAC-001", title="Network rule open to the internet", severity="medium",
         category="Infrastructure as Code", cwe="CWE-284", owasp="A01", languages=IAC, tags=("iac", "config"),
         keywords=("0.0.0.0/0", "::/0"), pattern=r"['\"](?:0\.0\.0\.0/0|::/0)['\"]",
         description="A security group / firewall rule allows traffic from any IP address. Exposed admin or "
                     "database ports are rapidly discovered and attacked.",
         recommendation="Restrict CIDR ranges to known networks or place services behind a load balancer/VPN."),
    Rule(id="SR-IAC-002", title="Publicly accessible storage bucket", severity="high",
         category="Infrastructure as Code", cwe="CWE-732", owasp="A01", languages=IAC, tags=("iac", "access-control"),
         keywords=("public", "block_public", "restrict_public"),
         pattern=r"\bacl\s*=\s*['\"]public-read(?:-write)?['\"]|['\"]?AccessControl['\"]?\s*:\s*['\"]?Public(?:Read|ReadWrite)|block_public_(?:acls|policy)\s*=\s*false|restrict_public_buckets\s*=\s*false",
         description="Public bucket ACLs or disabled public-access blocks are a leading cause of large data "
                     "leaks.",
         recommendation="Keep buckets private, enable Block Public Access and serve content via signed URLs "
                        "or a CDN."),
    Rule(id="SR-IAC-003", title="Encryption at rest disabled", severity="medium", category="Infrastructure as Code",
         cwe="CWE-311", owasp="A02", languages=IAC, tags=("iac", "crypto"), keywords=("encrypt",), flags=_I,
         pattern=r"\b(?:encrypted|storage_encrypted|encryption_enabled|enable_encryption|kms_encrypted|encrypt_at_rest)['\"]?\s*[=:]\s*false\b",
         description="Storage without encryption at rest exposes data if disks, snapshots or backups leak.",
         recommendation="Enable encryption (ideally with customer-managed KMS keys)."),
    Rule(id="SR-IAC-004", title="Publicly accessible database", severity="high", category="Infrastructure as Code",
         cwe="CWE-284", owasp="A01", languages=IAC, tags=("iac", "access-control"), keywords=("publicly",),
         pattern=r"\bpublicly_accessible\s*[=:]\s*true|['\"]?PubliclyAccessible['\"]?\s*:\s*['\"]?true",
         description="The database instance is reachable from the internet.",
         recommendation="Disable public accessibility and connect through private networking."),
    Rule(id="SR-IAC-005", title="Audit logging disabled", severity="low", category="Infrastructure as Code",
         cwe="CWE-778", owasp="A09", languages=IAC, tags=("iac", "logging"), keywords=("logging", "log_file"),
         pattern=r"\b(?:enable_logging|logging_enabled|enable_log_file_validation)\s*[=:]\s*false",
         description="Disabling audit logs removes the evidence needed to detect and investigate incidents.",
         recommendation="Enable logging and log-file validation and ship logs to a central store."),
    Rule(id="SR-IAC-006", title="IAM policy grants all actions", severity="high", category="Infrastructure as Code",
         cwe="CWE-269", owasp="A01", languages=IAC, tags=("iac", "access-control"), keywords=("action",),
         pattern=r"['\"]?Action['\"]?\s*[:=]\s*\[?\s*['\"]\*['\"]|\bactions\s*=\s*\[\s*['\"]\*['\"]",
         description="Wildcard IAM actions violate least privilege; a leaked credential gets full control.",
         recommendation="Grant only the specific actions and resources that are required."),
    # ---------------------------------------------------------------- CI/CD
    Rule(id="SR-CI-001", title="pull_request_target trigger", severity="medium", category="CI/CD",
         cwe="CWE-829", owasp="A08", path=WORKFLOW_PATH, tags=("supply-chain", "ci"),
         keywords=("pull_request_target",), pattern=r"\bpull_request_target\b",
         description="pull_request_target runs with repository secrets and write permissions; checking out and "
                     "running the fork's code in it allows secret theft (\"pwn request\").",
         recommendation="Use pull_request for untrusted code or never check out the PR head in this trigger."),
    Rule(id="SR-CI-002", title="Workflow script injection", severity="high", category="CI/CD", cwe="CWE-94",
         owasp="A03", path=WORKFLOW_PATH, tags=("injection", "ci"), keywords=("github.",),
         pattern=r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|pages\.[^}]*page_name|commits\.[^}]*(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))|workflow_run\.head_branch)|head_ref)\s*\}\}",
         description="Attacker-controlled GitHub context values (issue titles, PR bodies, branch names) are "
                     "expanded directly into the workflow. Inside run: steps they become shell commands.",
         recommendation="Pass the value through an environment variable (env: TITLE: ${{ ... }}) and quote it."),
    Rule(id="SR-CI-003", title="Third-party action not pinned to a commit SHA", severity="low", category="CI/CD",
         cwe="CWE-829", owasp="A08", path=WORKFLOW_PATH, tags=("supply-chain", "ci"), keywords=("uses",),
         pattern=r"^\s*-?\s*uses\s*:\s*['\"]?(?!\./|docker://)[\w.-]+/[\w./-]+@(?![0-9a-f]{40}\b)[^\s'\"#]+",
         description="Tags and branches are mutable; if the action's repository is compromised the new code "
                     "runs with your workflow's secrets.",
         recommendation="Pin actions to a full commit SHA and let Dependabot keep them updated."),
    Rule(id="SR-CI-004", title="Workflow grants write-all permissions", severity="medium", category="CI/CD",
         cwe="CWE-250", owasp="A01", path=WORKFLOW_PATH, tags=("access-control", "ci"), keywords=("write-all",),
         pattern=r"permissions\s*:\s*write-all",
         description="write-all gives the GITHUB_TOKEN write access to every scope.",
         recommendation="Declare the minimal permissions per job (e.g. contents: read)."),
    Rule(id="SR-CI-005", title="Secret printed in CI logs", severity="high", category="CI/CD", cwe="CWE-532",
         owasp="A09", path=CI_PATH, tags=("logging", "secrets", "ci"), keywords=("secrets.",),
         pattern=r"\becho\b[^\n]*\$\{\{\s*secrets\.",
         description="Echoing secrets can expose them in build logs (masking is best-effort and fails for "
                     "transformed values).",
         recommendation="Never print secrets; pass them via environment variables to the tools that need them."),
    # ---------------------------------------------------------------- Generic
    Rule(id="SR-GEN-001", title="Deprecated SSL/TLS protocol version", severity="medium",
         category="Transport Security", cwe="CWE-326", owasp="A02", languages=CODE + CONFIG, tags=("transport", "crypto"),
         keywords=("ssl", "tls"),
         pattern=r"\b(?:SSLv2|SSLv3|TLSv1(?![._]?[23])|TLSv1_1|PROTOCOL_TLSv1(?:_1)?\b|PROTOCOL_SSLv\d|VersionTLS1[01]\b|VersionSSL30|SslProtocols\.(?:Ssl\d|Tls(?:11)?\b))",
         description="SSLv2/SSLv3 and TLS 1.0/1.1 have known cryptographic weaknesses (POODLE, BEAST) and are "
                     "prohibited by PCI DSS and modern baselines.",
         recommendation="Require TLS 1.2 or later (prefer TLS 1.3)."),
    Rule(id="SR-GEN-002", title="Weak cipher / ECB mode", severity="medium", category="Cryptography",
         cwe="CWE-327", owasp="A02", languages=CODE, tags=("crypto",), keywords=("ecb", ".new"),
         pattern=r"\bMODE_ECB\b|\b(?:DES|DES3|ARC4|ARC2|Blowfish)\.new\s*\(|\bAES/ECB/",
         description="ECB mode leaks plaintext structure and legacy ciphers are breakable.",
         recommendation="Use authenticated encryption such as AES-GCM or ChaCha20-Poly1305."),
    Rule(id="SR-GEN-003", title="Sensitive data written to logs", severity="low", category="Logging",
         cwe="CWE-532", owasp="A09", languages=CODE, tags=("logging", "pii"), confidence="low",
         keywords=("password", "passwd", "secret", "token", "api_key", "apikey", "credit", "card", "cvv", "ssn"),
         pattern=r"(?i)(?:\b(?:log|logger|logging|console|log4j|slf4j|winston|Log)\.(?:debug|info|warn|warning|error|log|trace|fatal|critical|exception)|System\.out\.print(?:ln)?|fmt\.Print(?:ln|f)?)\s*\([^)\n]{0,150}\b(?:password|passwd|pwd|secret|token|api_?key|credit_?card|card_?number|cvv|ssn)\b",
         description="Log statements appear to include credentials or personal data. Logs are widely "
                     "replicated and retained, so the data escapes its intended protection (GDPR/PCI issue).",
         recommendation="Remove sensitive fields from log messages or mask them with a logging filter."),
    Rule(id="SR-GEN-004", title="Cleartext HTTP endpoint", severity="low", category="Transport Security",
         cwe="CWE-319", owasp="A02", languages=CODE, tags=("transport",), keywords=("http://",), confidence="low",
         pattern=r"['\"`]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|[\w.-]*example\.(?:com|org|net)|[\w.-]*\.(?:local|test|invalid|localhost)\b|schemas\.|www\.w3\.org|json-schema\.org|xmlns|java\.sun\.com|maven\.apache\.org|purl\.org|ns\.adobe\.com|schemas\.microsoft\.com|www\.apache\.org/licenses|opensource\.org|creativecommons\.org)[^'\"`\s]+['\"`]",
         description="Hardcoded http:// URLs send data without encryption or server authentication.",
         recommendation="Use https:// endpoints and enforce TLS."),
    Rule(id="SR-GEN-005", title="Security-related TODO/FIXME", severity="info", category="Code Quality",
         cwe="CWE-546", owasp="A04", languages=CODE, tags=("hygiene",), scan_comments=True,
         keywords=("todo", "fixme", "hack", "xxx"),
         pattern=r"(?i)\b(?:TODO|FIXME|HACK|XXX)\b[^\n]{0,80}\b(?:security|insecure|vuln\w*|auth\w*|password|crypt\w*|sanitiz\w*|escap\w*|xss|csrf|injection|hardcoded)\b",
         description="A comment indicates a known, unresolved security concern in this area of the code.",
         recommendation="Track the item in your issue tracker and resolve it before release."),
    Rule(id="SR-GEN-006", title="Service bound to all interfaces", severity="low", category="Misconfiguration",
         cwe="CWE-1327", owasp="A05", languages=CODE, tags=("config",), keywords=("0.0.0.0",), confidence="low",
         pattern=r"['\"]0\.0\.0\.0['\"]",
         description="Binding to 0.0.0.0 exposes the service on every network interface, including public "
                     "ones, which may be unintended for admin or development servers.",
         recommendation="Bind to 127.0.0.1 or a specific interface unless public exposure is intended."),
    Rule(id="SR-GEN-007", title="Debug flag enabled in configuration", severity="medium",
         category="Misconfiguration", cwe="CWE-489", owasp="A05", languages=CONFIG, tags=("config",),
         keywords=("debug",), flags=_I,
         pattern=r"^\s*(?:debug|app_debug|flask_debug|django_debug)\s*[:=]\s*['\"]?(?:true|1|on|yes)['\"]?\s*$",
         description="Debug settings in configuration files tend to reach production, exposing internals.",
         recommendation="Keep debug off by default and enable it only in local overrides."),
    # ---------------------------------------------------------------- Data-flow rules (semantic engines)
    Rule(id="SR-PY-022", title="Server-side template injection", severity="critical", category="Injection",
         cwe="CWE-1336", owasp="A03", languages=PY, tags=("injection",), source="code",
         description="User-controlled text is compiled as a Jinja/Flask template. Template expressions can read "
                     "configuration and secrets and usually escalate to remote code execution.",
         recommendation="Never build templates from user input: render a fixed template and pass the data as "
                        "context variables (render_template('page.html', value=value))."),
    Rule(id="SR-PY-023", title="Open redirect", severity="medium", category="Access Control", cwe="CWE-601",
         owasp="A01", languages=PY, tags=("access-control",), source="code",
         description="The redirect destination comes from the request, so attackers can craft links on your "
                     "domain that forward victims to phishing pages.",
         recommendation="Redirect only to relative paths or to an allow-list of trusted hosts (e.g. validate with "
                        "url_has_allowed_host_and_scheme)."),
    Rule(id="SR-PY-024", title="Reflected cross-site scripting", severity="high", category="Cross-Site Scripting",
         cwe="CWE-79", owasp="A03", languages=PY, tags=("xss", "injection"), source="code",
         description="A route returns a string built from request data. Flask/Django send it as HTML without "
                     "escaping, so injected markup executes in the victim's browser.",
         recommendation="Render through an auto-escaping template, return JSON, or escape the value with "
                        "markupsafe.escape()."),
    Rule(id="SR-JS-023", title="Reflected cross-site scripting (response)", severity="medium",
         category="Cross-Site Scripting", cwe="CWE-79", owasp="A03", languages=JS, tags=("xss", "injection"),
         description="Request data is written straight into an HTTP response body, where browsers interpret it as "
                     "HTML.",
         recommendation="Use res.json() for data or render through an escaping template engine; escape any value "
                        "that must be embedded in HTML."),
    Rule(id="SR-JS-024", title="Regular expression built from user input", severity="medium", category="Injection",
         cwe="CWE-1333", owasp="A03", languages=JS, tags=("injection",),
         description="new RegExp() compiles attacker-controlled patterns, enabling regular-expression denial of "
                     "service (catastrophic backtracking) and logic bypasses.",
         recommendation="Escape user input before embedding it in a pattern, or use plain string matching."),
    # ---------------------------------------------------------------- Dependencies (generated)
    Rule(id="SR-DEP-001", title="Library with known vulnerabilities", severity="high",
         category="Vulnerable Dependency", cwe="CWE-1395", owasp="A06", source="dependency",
         tags=("vulnerable-dependency", "supply-chain"),
         description="The declared library version is affected by publicly disclosed vulnerabilities "
                     "(CVE/GHSA/OSV advisories). Attackers actively scan for applications using vulnerable "
                     "components because exploits are often public.",
         recommendation="Upgrade to a version that includes the fix listed in the advisory, then regenerate "
                        "your lockfile and re-run the tests."),
    Rule(id="SR-DEP-002", title="Compromised or malicious package", severity="critical",
         category="Vulnerable Dependency", cwe="CWE-506", owasp="A08", source="dependency",
         tags=("vulnerable-dependency", "supply-chain"),
         description="This package/version is known to have been hijacked, sabotaged or published with "
                     "malicious code (e.g. credential stealers, cryptominers).",
         recommendation="Remove it immediately, rotate credentials available to affected machines and audit "
                        "build systems that installed it."),
    Rule(id="SR-DEP-003", title="Deprecated or unmaintained package", severity="medium",
         category="Vulnerable Dependency", cwe="CWE-1104", owasp="A06", source="dependency",
         tags=("supply-chain",),
         description="The package is deprecated or unmaintained, so newly discovered vulnerabilities will not "
                     "be fixed.",
         recommendation="Migrate to the maintained replacement suggested in the finding."),
    Rule(id="SR-DEP-004", title="Dependencies not locked", severity="low", category="Supply Chain",
         cwe="CWE-829", owasp="A08", source="dependency", tags=("supply-chain",),
         description="Dependencies are declared with version ranges and no lockfile pins the exact versions. "
                     "Builds may silently install newer, untested or compromised releases.",
         recommendation="Commit a lockfile (package-lock.json, poetry.lock, Cargo.lock, Gemfile.lock, "
                        "composer.lock...) or pin exact versions with hashes."),
    Rule(id="SR-DEP-005", title="Dependency fetched from VCS or URL", severity="medium", category="Supply Chain",
         cwe="CWE-829", owasp="A08", source="dependency", tags=("supply-chain",),
         description="The dependency is installed directly from a Git repository or URL, bypassing registry "
                     "provenance and vulnerability databases. Mutable references can change without notice.",
         recommendation="Consume a released registry version, or pin the VCS reference to an immutable commit "
                        "hash."),
    Rule(id="SR-DEP-006", title="Package source over insecure HTTP", severity="high", category="Supply Chain",
         cwe="CWE-494", owasp="A08", source="dependency", tags=("supply-chain", "transport"),
         description="A package index or artifact is downloaded over plaintext HTTP (or with TLS checks "
                     "disabled), so packages can be replaced in transit.",
         recommendation="Use HTTPS package sources exclusively."),
    Rule(id="SR-DEP-007", title="Outdated library (major version behind)", severity="info",
         category="Vulnerable Dependency", cwe="CWE-1104", owasp="A06", source="dependency",
         tags=("supply-chain",),
         description="A newer major version exists. Older major lines stop receiving security patches first.",
         recommendation="Plan an upgrade to the latest major version and review its changelog."),
    Rule(id="SR-DEP-008", title="License requires legal review", severity="info", category="License",
         cwe="", owasp="OTHER", source="dependency", tags=("license",),
         description="The library is distributed under a copyleft or non-standard license whose obligations "
                     "(source disclosure, attribution, network use) may conflict with how the software is "
                     "distributed.",
         recommendation="Have the license reviewed and record the decision in your third-party inventory."),
    Rule(id="SR-DEP-009", title="Version range admits vulnerable releases", severity="low",
         category="Vulnerable Dependency", cwe="CWE-1395", owasp="A06", source="dependency",
         tags=("vulnerable-dependency", "supply-chain"),
         description="The version that resolves today is not vulnerable, but the declared range also accepts older "
                     "releases with known advisories. Environments with stale caches, mirrors or lockfile-less "
                     "installs may still receive a vulnerable version.",
         recommendation="Raise the lower bound of the range to a fixed version and commit a lockfile."),
    # ---------------------------------------------------------------- Repository hygiene (generated)
    Rule(id="SR-HYG-001", title="No security policy (SECURITY.md)", severity="low", category="Repository Hygiene",
         cwe="CWE-1059", owasp="A04", source="hygiene", tags=("hygiene",),
         description="Without a security policy researchers do not know how to report vulnerabilities "
                     "privately, which leads to public disclosure or unreported issues.",
         recommendation="Add SECURITY.md describing supported versions and a private reporting channel."),
    Rule(id="SR-HYG-002", title="Secrets not excluded by .gitignore", severity="medium",
         category="Repository Hygiene", cwe="CWE-538", owasp="A05", source="hygiene", tags=("hygiene", "secrets"),
         description="The repository lacks .gitignore rules for environment and key files, making accidental "
                     "commits of secrets likely.",
         recommendation="Ignore .env*, *.pem, *.key, credential files and local configuration."),
    Rule(id="SR-HYG-003", title="No automated dependency updates", severity="info", category="Repository Hygiene",
         cwe="CWE-1104", owasp="A06", source="hygiene", tags=("hygiene", "supply-chain"),
         description="No Dependabot/Renovate configuration was found, so vulnerable dependencies may go "
                     "unnoticed.",
         recommendation="Enable Dependabot or Renovate security updates."),
    Rule(id="SR-HYG-004", title="No license file", severity="info", category="Repository Hygiene", cwe="",
         owasp="OTHER", source="hygiene", tags=("hygiene", "license"),
         description="Without a LICENSE the terms of use are unclear, a gap for intellectual-property "
                     "compliance.",
         recommendation="Add a LICENSE file that states the terms under which the code may be used."),
    Rule(id="SR-HYG-005", title="No continuous integration checks", severity="info", category="Repository Hygiene",
         cwe="", owasp="A08", source="hygiene", tags=("hygiene",),
         description="No CI pipeline was found, so tests and security checks are not enforced on changes.",
         recommendation="Add a CI workflow that runs tests, linters and a security scan on every change."),
    Rule(id="SR-HYG-006", title="No code owners defined", severity="info", category="Repository Hygiene", cwe="",
         owasp="A01", source="hygiene", tags=("hygiene",),
         description="Without CODEOWNERS there is no enforced reviewer for sensitive paths.",
         recommendation="Add a CODEOWNERS file and require code-owner review on protected branches."),
]

# Patterns that must read inside string literals (algorithm names, URLs, wildcards, keys...).
NEEDS_STRINGS = {
    "SR-PY-008", "SR-PY-013", "SR-PY-017", "SR-JS-010", "SR-JS-012", "SR-JS-013", "SR-JS-014", "SR-JS-015",
    "SR-JS-019", "SR-JS-020", "SR-JS-021", "SR-JS-022", "SR-JAVA-004", "SR-JAVA-005", "SR-PHP-009", "SR-GO-002",
    "SR-GO-004", "SR-GO-005", "SR-C-005", "SR-GEN-001", "SR-GEN-002", "SR-GEN-003", "SR-GEN-004", "SR-GEN-006",
}
for _rule in RULES:
    if _rule.id in NEEDS_STRINGS:
        _rule.needs_strings = True

RULES_BY_ID: Dict[str, Rule] = {rule.id: rule for rule in RULES}
PATTERN_RULES: List[Rule] = [rule for rule in RULES if rule.pattern]
TOKEN_RULES: List[Rule] = [rule for rule in PATTERN_RULES if rule.source == "secret" and rule.redact]


def get_rule(rule_id: str) -> Rule:
    return RULES_BY_ID[rule_id]
