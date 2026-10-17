"""Scan options, constants and helpers shared by the scanner modules."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from secure_repo.core import triage

# Inline suppression directives are only honoured inside real comments of trusted targets, and they are always
# recorded in the report (status "suppressed_inline"). Optionally followed by rule IDs: ``# nosec SR-PY-005 reason``.
TEST_SEVERITY_STEP = {"critical": "high", "high": "medium", "medium": "low"}
MARKUP_EXTENSIONS = (".html", ".htm", ".xhtml", ".ejs", ".hbs", ".handlebars", ".jinja", ".jinja2", ".j2", ".twig",
                    ".erb", ".cshtml", ".razor", ".vue", ".svelte", ".php", ".jsp", ".mustache", ".njk")
MAX_EVIDENCE_LINES = 6      # lines of a multi-line call shown as evidence
EVIDENCE_LIMIT = 320        # characters
DIRECTIVE_RE = re.compile(r"(?i)\bnosec\b|securerepo:ignore\b(?!-file)|noqa:\s*secure")
RULE_ID_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,4}\b")
COMMENT_START_RE = re.compile(r"#|//|--|<!--|/\*|\brem\b|::", re.IGNORECASE)
IGNORE_FILE_MARKER = "securerepo:ignore-file"
# Only these languages are ever minified in practice. A one-line .py/.php/.go file is NOT minified code: it is
# either hostile or generated, and must be analyzed in full.
MINIFIABLE_LANGUAGES = {"JavaScript", "TypeScript", "CSS"}
COMMENT_PREFIXES = ("#", "//", "/*", "* ", "*/", "--", "<!--", ";", "rem ", "REM ", "::")
MAX_PER_RULE_PER_FILE = 50


@dataclass
class ScanOptions:
    offline: bool = False
    compliance: bool = False
    frameworks: List[str] = field(default_factory=lambda: ["all"])
    max_file_size: int = 2 * 1024 * 1024
    exclude: List[str] = field(default_factory=list)
    include_tests: bool = True
    enrich: bool = True
    auditor: str = ""
    output_dir: str = field(default_factory=lambda: triage.default_output_dir())
    min_confidence: str = "low"
    learning: bool = True          # apply the triage knowledge base (decisions, learned patterns, rule stats)
    resolve_versions: bool = True  # virtual lockfile resolution for unpinned dependencies
    semantic: bool = True          # lexical masking + syntax tree + data flow (False = legacy pattern-only engine)
    # Does the audited repository's own configuration (.securerepo.toml, .securerepo/triage.json, nosec comments)
    # get authority over the result? None = automatic: only for the working tree of a local Git repository.
    trust_repo_config: Optional[bool] = None
    private: List[str] = field(default_factory=list)  # package-name globs that are never sent to any service
    no_registry: bool = False      # do not resolve versions or fetch metadata from package registries (OSV still runs)
    check_confusion: bool = False  # opt in: look private names up in the public registry (sends those names)
    ca_bundle: str = ""            # certificate authority bundle for HTTPS lookups (corporate TLS inspection)
    cache: bool = True             # keep registry / advisory lookups on disk for 24 hours
    max_registry: int = 300        # direct dependencies resolved against the registries
    max_graph: int = 120           # direct dependencies whose transitive graph is expanded
    max_enrich: int = 250          # direct dependencies that get license / latest-version metadata
    baseline: str = ""             # report.json of an earlier run: --fail-on then counts only findings that are new
    since: str = ""                # Git reference: analyze only the files that changed relative to it
    jobs: int = 0                  # worker processes for file analysis: 0 = automatic, 1 = single process
    parallel_threshold: int = 400  # below this many files a single process is faster than starting workers

    def to_dict(self) -> Dict:
        return asdict(self)


class ScanCancelled(Exception):
    pass


def load_baseline(path: str) -> set:
    """Fingerprints of every finding of an earlier report.json (raises ValueError when the file is not a report)."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read the baseline report {path}: {exc}") from exc
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list) or (findings and not any(isinstance(f, dict) and f.get("fingerprint") for f in findings)):
        raise ValueError(f"{path} is not a Secure Repo report.json (no findings with fingerprints)")
    return {f["fingerprint"] for f in findings if isinstance(f, dict) and f.get("fingerprint")}

MAX_AUTO_JOBS = 8
