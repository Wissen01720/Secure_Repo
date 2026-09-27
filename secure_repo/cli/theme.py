"""Shared console, colors and small rendering helpers for the CLI."""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.text import Text
from rich.theme import Theme

NEON = "#00ff9c"
CYAN = "#00e5ff"
MAGENTA = "#ff2e97"
VIOLET = "#9d7bff"
DIM = "grey50"

SEVERITY_STYLE = {
    "critical": "bold #ff2e63",
    "high": "bold #ff8a00",
    "medium": "bold #ffd23f",
    "low": "bold #4dabf7",
    "info": "#8892b0",
}
SEVERITY_TAG = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}
STATUS_STYLE = {"pass": "bold #00ff9c", "warning": "bold #ffd23f", "fail": "bold #ff2e63", "manual": "bold #9d7bff"}

THEME = Theme({
    "neon": NEON, "cyan": CYAN, "magenta": MAGENTA, "violet": VIOLET, "muted": DIM,
    "ok": f"bold {NEON}", "warn": "bold #ffd23f", "err": "bold #ff2e63", "info": f"bold {CYAN}",
})


def _make_console() -> Console:
    if not sys.stdout.isatty() and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    no_color = bool(os.environ.get("NO_COLOR"))
    return Console(theme=THEME, highlight=False, no_color=no_color, soft_wrap=False)


console = _make_console()


def sev_badge(severity: str) -> Text:
    return Text(f"[{SEVERITY_TAG.get(severity, severity.upper()[:4])}]", style=SEVERITY_STYLE.get(severity, ""))


def prefix(kind: str) -> Text:
    mapping = {
        "ok": ("[+]", "ok"), "info": ("[*]", "info"), "warn": ("[!]", "warn"), "error": ("[x]", "err"),
        "run": ("[>]", "magenta"), "ask": ("[?]", "violet"),
    }
    symbol, style = mapping.get(kind, ("[*]", "info"))
    return Text(symbol, style=style)


def say(message, kind: str = "info") -> None:
    line = Text.assemble(prefix(kind), " ")
    line.append(message if isinstance(message, Text) else Text(str(message)))
    console.print(line)


def bar(fraction: float, width: int = 24, fill_style: str = NEON, empty_style: str = "grey23") -> Text:
    fraction = max(0.0, min(1.0, fraction))
    full = int(round(fraction * width))
    return Text("█" * full, style=fill_style) + Text("░" * (width - full), style=empty_style)
