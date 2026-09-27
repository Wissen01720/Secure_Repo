"""Real-time terminal dashboard shown while a scan is running."""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime
from typing import Deque, Dict, Optional

from rich import box
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from secure_repo.cli.theme import CYAN, DIM, MAGENTA, NEON, SEVERITY_STYLE, SEVERITY_TAG, bar, console, prefix
from secure_repo.core.events import STAGES
from secure_repo.core.models import SEVERITIES, SEVERITY_RANK

LEVEL_KIND = {"info": "info", "ok": "ok", "warn": "warn", "error": "error", "debug": "info"}


class LiveDashboard:
    def __init__(self, target: str, branch: str, plain: bool = False):
        self.target = target
        self.branch = branch
        self.plain = plain or not console.is_terminal
        self.lock = threading.Lock()
        self.started = time.time()
        self.stages: Dict[str, Dict] = {sid: {"title": title, "status": "pending", "detail": "", "start": 0.0,
                                              "end": 0.0} for sid, title in STAGES}
        self.progress: Dict[str, tuple] = {}
        self.feed: Deque[Text] = deque(maxlen=7)
        self.counts = {s: 0 for s in SEVERITIES}
        self.files_done = 0
        self.files_total = 0
        self.current_file = ""
        self.tops: Dict[str, Dict] = {}
        self.live: Optional[Live] = None
        self.finished = False

    # ------------------------------------------------------------------ events
    def _top(self, path: str) -> str:
        if path in ("", "."):
            return "(repository)"
        return path.split("/", 1)[0] if "/" in path else "(root files)"

    def handle(self, event: Dict) -> None:
        kind = event["type"]
        with self.lock:
            if kind == "stage":
                stage = self.stages.get(event["id"])
                if stage is None:
                    return
                stage["status"] = event["status"]
                stage["detail"] = event.get("detail", "")
                if event["status"] == "start":
                    stage["start"] = event["ts"]
                else:
                    stage["end"] = event["ts"]
                if self.plain:
                    self._plain_stage(stage)
                elif event["status"] in ("done", "skip"):
                    self._push(Text.assemble(prefix("ok" if event["status"] == "done" else "warn"), " ",
                                             (stage["title"], "bold white"), (f"  {stage['detail']}", DIM)))
            elif kind == "log":
                line = Text.assemble(prefix(LEVEL_KIND.get(event["level"], "info")), " ", (event["message"], "white"))
                if self.plain:
                    console.print(line)
                else:
                    self._push(line)
            elif kind == "progress":
                self.progress[event["stage"]] = (event["current"], event["total"], event.get("label", ""))
            elif kind == "structure":
                tree = event["tree"]
                root_files = 0
                for child in tree.get("children", []):
                    if child["type"] == "dir":
                        self.tops[child["name"]] = {"total": child["files"], "done": 0, "findings": 0, "risk": None}
                    else:
                        root_files += 1
                if root_files:
                    self.tops["(root files)"] = {"total": root_files, "done": 0, "findings": 0, "risk": None}
                self.files_total = event.get("files", 0)
            elif kind == "files":
                for path in event["paths"]:
                    top = self.tops.get(self._top(path))
                    if top:
                        top["done"] += 1
                self.files_done = event["done"]
                self.files_total = event["total"]
                if event["paths"]:
                    self.current_file = event["paths"][-1]
            elif kind == "finding":
                severity = event["severity"]
                self.counts[severity] = self.counts.get(severity, 0) + 1
                top = self.tops.setdefault(self._top(event["file"]), {"total": 0, "done": 0, "findings": 0, "risk": None})
                top["findings"] += 1
                if top["risk"] is None or SEVERITY_RANK[severity] < SEVERITY_RANK[top["risk"]]:
                    top["risk"] = severity
                if severity in ("critical", "high", "medium") or self.plain:
                    where = event["file"] if event["file"] not in ("", ".") else "(repository)"
                    where += f":{event['line']}" if event.get("line") else ""
                    line = Text.assemble(("[!] ", SEVERITY_STYLE[severity]),
                                         (f"{SEVERITY_TAG[severity]} ", SEVERITY_STYLE[severity]),
                                         (event["title"], "white"), ("  → ", DIM), (where, CYAN))
                    if self.plain:
                        console.print(line)
                    else:
                        self._push(line)
            elif kind == "done":
                self.finished = True
            elif kind == "error":
                line = Text.assemble(prefix("error"), " ", (event["message"], "bold #ff2e63"))
                if self.plain:
                    console.print(line)
                else:
                    self._push(line)

    def _push(self, text: Text) -> None:
        stamp = Text(datetime.now().strftime("%H:%M:%S "), style="grey42")
        self.feed.append(stamp + text)

    def _plain_stage(self, stage: Dict) -> None:
        status = stage["status"]
        kind = {"start": "run", "done": "ok", "skip": "warn", "error": "error"}.get(status, "info")
        detail = f" - {stage['detail']}" if stage["detail"] else ""
        console.print(Text.assemble(prefix(kind), " ", (f"{stage['title']} [{status}]{detail}", "white")))

    # ------------------------------------------------------------------ render
    def _pipeline(self) -> Panel:
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=3, no_wrap=True)
        table.add_column(min_width=30, ratio=5, no_wrap=True, overflow="ellipsis")
        table.add_column(ratio=4, no_wrap=True, overflow="ellipsis")
        table.add_column(width=7, justify="right", no_wrap=True)
        for sid, _title in STAGES:
            stage = self.stages[sid]
            status = stage["status"]
            if status == "start":
                icon: RenderableType = Spinner("dots", style=f"bold {MAGENTA}")
                title = Text(stage["title"], style=f"bold {MAGENTA}")
                current, total, _label = self.progress.get(sid, (0, 0, ""))
                if total:
                    detail = bar(current / total, 16, MAGENTA) + Text(f" {int(100 * current / total):3d}%", style="white")
                else:
                    detail = Text("working...", style=DIM)
                elapsed = time.time() - stage["start"]
            else:
                icon = {"pending": Text("[ ]", style="grey35"), "done": Text("[+]", style=f"bold {NEON}"),
                        "skip": Text("[-]", style="#ffd23f"), "error": Text("[x]", style="bold #ff2e63")}.get(
                    status, Text("[?]"))
                title = Text(stage["title"], style="grey50" if status == "pending" else "white")
                detail = Text(stage["detail"], style=DIM)
                elapsed = (stage["end"] - stage["start"]) if stage["end"] and stage["start"] else 0
            timing = Text(f"{elapsed:5.1f}s" if elapsed else "", style="grey42")
            table.add_row(icon, title, detail, timing)
        return Panel(table, title=Text(" ATTACK SURFACE PIPELINE ", style=f"bold {NEON}"), border_style="grey30",
                     box=box.ROUNDED, padding=(0, 1))

    def _boxes(self, max_boxes: int) -> Panel:
        if not self.tops:
            body: RenderableType = Text("waiting for repository map...", style=DIM)
        else:
            items = sorted(self.tops.items(), key=lambda kv: (-kv[1]["total"], kv[0]))
            shown, rest = items[:max_boxes], items[max_boxes:]
            panels = []
            for name, info in shown:
                total = max(info["total"], 1)
                fraction = min(1.0, info["done"] / total)
                color = SEVERITY_STYLE.get(info["risk"], "grey35").replace("bold ", "") if info["risk"] else (
                    NEON if fraction >= 1 else "grey35")
                content = Text(overflow="ellipsis", no_wrap=True)
                if info["total"]:
                    content.append(bar(fraction, 12, NEON if fraction >= 1 else CYAN))
                    content.append(f" {int(fraction * 100):3d}%\n", style="white")
                    content.append(f"{info['done']}/{info['total']} files", style=DIM)
                else:
                    content.append("repository-level\n", style="white")
                    content.append("hygiene checks", style=DIM)
                if info["findings"]:
                    content.append(f"  ▲{info['findings']}", style=SEVERITY_STYLE.get(info["risk"], "white"))
                label = name if len(name) <= 18 else name[:17] + "…"
                panels.append(Panel(content, title=Text(label, style="bold white"), title_align="left",
                                    border_style=color, box=box.SQUARE, width=24, padding=(0, 1)))
            if rest:
                remaining = sum(info["total"] for _n, info in rest)
                panels.append(Panel(Text(f"+{len(rest)} more\n{remaining} files", style=DIM), border_style="grey30",
                                    box=box.SQUARE, width=24, padding=(0, 1)))
            body = Columns(panels, padding=(0, 0))
        return Panel(body, title=Text(" STRUCTURE MAP ", style=f"bold {CYAN}"), border_style="grey30", box=box.ROUNDED)

    def _header(self) -> Panel:
        elapsed = time.time() - self.started
        text = Text()
        text.append("TARGET ", style=DIM)
        text.append(self.target, style=f"bold {CYAN}")
        text.append("   BRANCH ", style=DIM)
        text.append(self.branch or "n/a", style=f"bold {MAGENTA}")
        text.append("   ELAPSED ", style=DIM)
        text.append(f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}", style=f"bold {NEON}")
        if self.current_file and not self.finished:
            text.append("\n>> ", style=f"bold {NEON}")
            text.append(self.current_file[-90:], style="grey62")
        return Panel(text, title=Text(" ⟦ LIVE OPERATION ⟧ ", style=f"bold {NEON}"), border_style=NEON,
                     box=box.HEAVY, padding=(0, 1))

    def _footer(self) -> Text:
        text = Text(" ")
        for severity in SEVERITIES:
            text.append(f" {SEVERITY_TAG[severity].strip()} ", style=SEVERITY_STYLE[severity] + " reverse")
            text.append(f" {self.counts[severity]:<4}", style=SEVERITY_STYLE[severity])
        if self.files_total:
            text.append("   FILES ", style=DIM)
            text.append(f"{self.files_done}/{self.files_total}", style="bold white")
        return text

    def render(self) -> RenderableType:
        with self.lock:
            wide = console.width >= 150
            tall = console.height >= 40
            max_boxes = (8 if tall else 4) if wide else (6 if tall else 3)
            pipeline = self._pipeline()
            boxes = self._boxes(max_boxes)
            if wide:
                grid = Table.grid(expand=True)
                grid.add_column(ratio=5)
                grid.add_column(ratio=6)
                grid.add_row(pipeline, boxes)
                middle: RenderableType = grid
            else:
                middle = Group(pipeline, boxes)
            feed = Panel(Group(*self.feed) if self.feed else Text("...", style=DIM),
                         title=Text(" ACTIVITY FEED ", style=f"bold {MAGENTA}"), border_style="grey30",
                         box=box.ROUNDED, height=self.feed.maxlen + 2)
            return Group(self._header(), middle, feed, self._footer())

    # ------------------------------------------------------------------ context
    def __enter__(self) -> "LiveDashboard":
        if not self.plain:
            self.live = Live(get_renderable=self.render, console=console, refresh_per_second=10, transient=False,
                             redirect_stdout=False, redirect_stderr=False)
            self.live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self.live is not None:
            self.live.refresh()
            self.live.__exit__(*exc)
            self.live = None
