"""A tiny thread-safe publish/subscribe bus used to stream scan progress."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List

Event = Dict[str, Any]
Subscriber = Callable[[Event], None]

STAGES = [
    ("acquire", "Acquiring source"),
    ("enumerate", "Mapping repository structure"),
    ("analyze", "Static code, secret & config analysis"),
    ("dependencies", "Discovering libraries & dependencies"),
    ("resolve", "Resolving versions (virtual lockfile)"),
    ("intel", "Vulnerability intelligence lookup"),
    ("hygiene", "Repository security hygiene"),
    ("compliance", "Compliance audit"),
    ("scoring", "Risk scoring"),
    ("report", "Generating reports"),
]
STAGE_TITLES = dict(STAGES)


class EventBus:
    def __init__(self) -> None:
        self._subscribers: List[Subscriber] = []
        self._lock = threading.Lock()

    def subscribe(self, callback: Subscriber) -> None:
        with self._lock:
            self._subscribers.append(callback)

    def emit(self, event_type: str, **data: Any) -> None:
        event: Event = {"type": event_type, "ts": time.time()}
        event.update(data)
        with self._lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:  # a broken listener must never break the scan
                pass

    # Convenience helpers -------------------------------------------------
    def log(self, message: str, level: str = "info") -> None:
        self.emit("log", level=level, message=message)

    def stage(self, stage_id: str, status: str, detail: str = "") -> None:
        self.emit("stage", id=stage_id, title=STAGE_TITLES.get(stage_id, stage_id), status=status, detail=detail)

    def progress(self, stage_id: str, current: int, total: int, label: str = "") -> None:
        self.emit("progress", stage=stage_id, current=current, total=total, label=label)
