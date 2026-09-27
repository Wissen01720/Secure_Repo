# securerepo:ignore-file  (detector implementations; contains patterns, not secrets)
"""Detectors that need more logic than a single regular expression."""

from __future__ import annotations

import math
import re
from typing import Iterable, List, Optional, Tuple

from secure_repo.core.rules import TOKEN_RULES

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def mask(value: str) -> str:
    """Keep a short prefix so the owner can identify the secret, hide the rest."""
    if len(value) <= 6:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 16)


def redact_text(text: str) -> str:
    """Mask every known token format and generic credential values inside a snippet."""
    for rule in TOKEN_RULES:
        regex = rule.regex
        if regex is None:
            continue

        def _sub(match: "re.Match[str]") -> str:
            if match.lastindex:
                start, end = match.span(1)
                if start >= 0:
                    whole = match.group(0)
                    offset = match.start(0)
                    return whole[: start - offset] + mask(match.group(1)) + whole[end - offset:]
            return mask(match.group(0))

        text = regex.sub(_sub, text)
    text = _GENERIC_QUOTED.sub(lambda m: m.group(0).replace(m.group("val"), mask(m.group("val"))), text)
    text = _GENERIC_UNQUOTED.sub(lambda m: m.group(0).replace(m.group("val"), mask(m.group("val"))), text)
    return text


# ---------------------------------------------------------------------------
# Generic hardcoded credentials
# ---------------------------------------------------------------------------
_KEY_WORDS = (r"password|passwd|passphrase|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token|"
              r"access[_\-]?token|refresh[_\-]?token|client[_\-]?secret|private[_\-]?key|secret[_\-]?key|token|"
              r"credentials?")
_GENERIC_QUOTED = re.compile(
    r"(?i)(?P<key>[A-Za-z0-9_.\-]*(?:" + _KEY_WORDS + r")[A-Za-z0-9_.\-]*)['\"]?\s*(?::=|=>|=|:)\s*"
    r"[rbuf]?(?P<q>['\"`])(?P<val>[^'\"`\r\n]{4,200})(?P=q)")
_GENERIC_UNQUOTED = re.compile(
    r"(?im)^\s*(?:export\s+)?(?P<key>[A-Za-z0-9_.\-]*(?:" + _KEY_WORDS + r")[A-Za-z0-9_.\-]*)\s*[:=]\s*"
    r"(?P<val>[^\s'\"#`$<{\[][^\s#]{3,200})\s*(?:#.*)?$")

_KEY_EXCLUDE = re.compile(
    r"(?i)(url|uri|endpoint|path|file|dir|name|type|field|header|param|env|var|_id$|length|len$|size|count|"
    r"prefix|suffix|format|regex|pattern|label|placeholder|hint|message|msg|text|error|policy|expir|ttl|"
    r"timeout|min|max|mode|enabled|required|validator|input|button|column|table|tokeniz|reset|confirm|"
    r"strength|hash|rounds|algorithm|method|provider|storage|store|cache|class|kind|limit|style|icon|key_id|"
    r"index|version|scope|usage|mask|tokens$|policy|rotation|question|forgot|visible|show|toggle|display|"
    r"schema|route|template|selector|attr|event|action|handler|callback|status|state|type_)")

_PLACEHOLDER = re.compile(
    r"(?i)^(?:\$\{?|\{\{|<|%\(|%s|\[|process\.env|os\.environ|env\(|getenv|config\(|settings\.|"
    r"x{3,}|\*{3,}|\.{3,}|-{3,}|your|change|replace|example|sample|dummy|test|fake|placeholder|redacted|"
    r"none$|null$|nil$|undefined$|true$|false$|todo|tbd|secret$|password$|passwd$|pass$|token$|string$|"
    r"str$|required|optional|default|enter|insert|put|mysecret|supersecret|s3cr3t$|abc123$|12345|qwerty|"
    r"admin$|root$|user$|guest$|foo|bar$|baz$|dev$|local$|localhost|value$|key$|api[_-]?key$)")

DOC_LANGUAGES = {"Markdown", "reStructuredText", "Text", "HTML"}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_placeholder(key: str, value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 4 or " " in stripped:
        return True
    if _PLACEHOLDER.search(stripped):
        return True
    if stripped.lower() == key.lower() or stripped.lower().replace("-", "_") == key.lower():
        return True
    if len(set(stripped)) <= 2:
        return True
    if re.fullmatch(r"[a-z]+(?:[._:/][a-z]+)+", stripped):  # i18n keys / dotted identifiers
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]+", stripped) and "_" in stripped:  # constant/env-var names
        return True
    if "://" in stripped or stripped.startswith(("/", "./", "../", "~")):
        return True
    if re.search(r"\.(?:json|ya?ml|txt|pem|key|crt|env|cfg|ini|py|js|ts)$", stripped, re.I):
        return True
    return False


def find_generic_credentials(text: str, language: str) -> List[Tuple[int, str, str, float]]:
    """Return (offset, key, value, entropy) tuples of probable hardcoded credentials."""
    results = []
    seen_offsets = set()
    patterns = [_GENERIC_QUOTED]
    if language in {"Env", "INI", "Config", "Properties", "YAML", "TOML", "Shell", "Dockerfile"}:
        patterns.append(_GENERIC_UNQUOTED)
    for pattern in patterns:
        for match in pattern.finditer(text):
            key = match.group("key")
            value = match.group("val")
            if _KEY_EXCLUDE.search(key):
                continue
            if _is_placeholder(key, value):
                continue
            offset = match.start("val")
            if offset in seen_offsets:
                continue
            seen_offsets.add(offset)
            results.append((offset, key, value, shannon_entropy(value)))
    return results


# ---------------------------------------------------------------------------
# Payment cards
# ---------------------------------------------------------------------------
_CARD_RE = re.compile(
    r"(?<![\w.\-])(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2[2-7]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})(?![\w.\-])"
    r"|(?<![\w.\-])(?:4\d{3}|5[1-5]\d{2}|6011)(?:[ -]\d{4}){3}(?![\w.\-])")
TEST_CARDS = {
    "4111111111111111", "4242424242424242", "4012888888881881", "5555555555554444", "5105105105105100",
    "378282246310005", "371449635398431", "6011111111111117", "6011000990139424", "4000056655665556",
    "5200828282828210", "4000000000000002", "4000000000000077", "4000000000009995", "2223003122003222",
}


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number][::-1]
    total = 0
    for index, digit in enumerate(digits):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def find_card_numbers(text: str) -> List[Tuple[int, str, bool]]:
    results = []
    for match in _CARD_RE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group(0))
        if len(set(digits)) == 1 or not luhn_ok(digits):
            continue
        results.append((match.start(), match.group(0), digits in TEST_CARDS))
    return results


# ---------------------------------------------------------------------------
# Sensitive files
# ---------------------------------------------------------------------------
SENSITIVE_FILE_PATTERNS = [
    (re.compile(r"(^|/)\.env(\.[\w.-]+)?$", re.I), "Environment file that usually stores secrets", "high",
     re.compile(r"\.(example|sample|template|dist|defaults?|schema|tpl)$", re.I)),
    (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), "SSH private key", "critical", None),
    (re.compile(r"\.(p12|pfx|jks|keystore|bks|ppk|kdbx|ovpn)$", re.I), "Keystore / credential container", "high", None),
    (re.compile(r"\.(pem|key)$", re.I), "Private key file", "critical", None),
    (re.compile(r"(^|/)\.(npmrc|pypirc|netrc|git-credentials|pgpass|dockercfg)$|(^|/)\.docker/config\.json$", re.I),
     "Package/registry credential configuration", "high", None),
    (re.compile(r"(^|/)(credentials|secrets?)\.(json|ya?ml|xml|ini|txt|toml|env)$|(^|/)\.aws/credentials$|"
                r"service[-_]?account[^/]*\.json$|(^|/)\.htpasswd$", re.I), "Credentials file", "high", None),
    (re.compile(r"\.tfstate(\.backup)?$", re.I), "Terraform state (stores secrets in plaintext)", "high", None),
    (re.compile(r"\.(sql|dump|bak|sqlite|sqlite3|db|mdb)$", re.I), "Database dump or backup file", "medium",
     re.compile(r"(^|/)(migrations?|schema|seeds?|sql)/|schema\.sql$|init\.sql$", re.I)),
]

_CONTENT_REQUIRED = {
    ".pem": re.compile(r"PRIVATE KEY"),
    ".key": re.compile(r"PRIVATE KEY|^[A-Za-z0-9+/=]{40,}$", re.M),
    ".npmrc": re.compile(r"(?i)_auth|_password|authtoken"),
    ".pypirc": re.compile(r"(?i)password"),
    "config.json": re.compile(r"(?i)\"auth\"\s*:"),
}


def match_sensitive_file(rel_path: str) -> Optional[Tuple[str, str, Optional[re.Pattern]]]:
    for pattern, label, severity, exclude in SENSITIVE_FILE_PATTERNS:
        if pattern.search(rel_path):
            if exclude is not None and exclude.search(rel_path):
                return None
            for suffix, required in _CONTENT_REQUIRED.items():
                if rel_path.lower().endswith(suffix):
                    return label, severity, required
            return label, severity, None
    return None


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------
_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?", re.I)
_USER_RE = re.compile(r"^\s*USER\s+(?P<user>\S+)", re.I)


def analyze_dockerfile(text: str) -> Iterable[Tuple[str, int, str, str]]:
    """Yield (rule_id, line_number, snippet, detail)."""
    stages = set()
    last_from_line = 0
    last_from_text = ""
    users: List[Tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = _FROM_RE.match(line)
        if match:
            image = match.group("image")
            alias = match.group("alias")
            last_from_line, last_from_text = number, line.strip()
            users = []
            if alias:
                stages.add(alias.lower())
            base = image.lower()
            if base == "scratch" or "$" in base or base in stages:
                continue
            if "@sha256:" in base:
                continue
            name_part = base.rsplit("/", 1)[-1]
            tag = name_part.split(":", 1)[1] if ":" in name_part else ""
            if not tag or tag == "latest":
                detail = f"Image '{image}' uses {'the :latest tag' if tag else 'no tag (implicit :latest)'}."
                yield "SR-DOCKER-001", number, line.strip(), detail
            continue
        user = _USER_RE.match(line)
        if user:
            users.append((number, user.group("user")))
    if last_from_line:
        if not users:
            yield ("SR-DOCKER-002", last_from_line, last_from_text,
                   "The final build stage has no USER instruction, so the container runs as root.")
        else:
            number, user = users[-1]
            if user.split(":")[0] in {"root", "0"}:
                yield "SR-DOCKER-002", number, f"USER {user}", "The final USER instruction switches to root."
