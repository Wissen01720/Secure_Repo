"""The only place that talks to public services (OSV.dev, deps.dev, Packagist, pub.dev).

* **bounded**: a response larger than ``max_bytes`` is rejected instead of being read into memory;
* **resilient**: 429 / 5xx / network errors are retried with exponential backoff (``Retry-After`` honoured);
* **cached**: successful GET-style lookups are kept on disk for a day, so repeated scans are fast and a flaky
  network hurts less (advisory *searches* are never cached: new vulnerabilities must show up the same day);
* **corporate-friendly**: ``--ca-bundle`` / ``SECURE_REPO_CA_BUNDLE`` / ``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE``
  select the certificate authority, for networks that inspect TLS;
* **isolated per scan**: settings and counters live in a :class:`NetworkSession` that is bound to the running scan
  through a context variable, so two scans at the same time (the GUI allows two) never mix their notes.

Only package names and versions ever pass through here; source code never does.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from collections.abc import Callable, Iterator

from secure_repo import __version__

USER_AGENT = f"secure-repo/{__version__} (+security audit tool)"
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRY_AFTER = 10.0
CA_ENVIRONMENT = ("SECURE_REPO_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE")


class NetworkError(OSError):
    """A lookup failed for a reason that retrying will not fix (oversized body, bad certificate file...)."""


@dataclass
class NetworkSettings:
    ca_bundle: str = ""
    cache: bool = True
    cache_ttl: int = 24 * 3600
    cache_dir: str = ""
    max_bytes: int = 20 * 1024 * 1024
    retries: int = 3                  # attempts per request
    backoff: float = 0.6              # seconds; doubles after every failed attempt


@dataclass
class NetworkStats:
    requests: int = 0
    cache_hits: int = 0
    retries: int = 0
    failures: int = 0
    oversized: int = 0
    notes: list[str] = field(default_factory=list)       # human-readable gaps ("2 OSV batches failed", limits...)

    def to_dict(self) -> dict:
        return {"requests": self.requests, "cache_hits": self.cache_hits, "retries": self.retries,
                "failures": self.failures, "oversized": self.oversized, "notes": list(self.notes)}


class NetworkSession:
    """Settings and counters of one scan."""

    def __init__(self, settings: NetworkSettings | None = None):
        self.settings = settings or NetworkSettings()
        self.stats = NetworkStats()
        self.lock = threading.Lock()

    def count(self, **amounts: int) -> None:
        with self.lock:
            for name, amount in amounts.items():
                setattr(self.stats, name, getattr(self.stats, name) + amount)

    def note(self, message: str) -> None:
        with self.lock:
            if message not in self.stats.notes:
                self.stats.notes.append(message)


_DEFAULT = NetworkSession()
_CURRENT: contextvars.ContextVar[NetworkSession] = contextvars.ContextVar("secure_repo_network", default=_DEFAULT)


def current() -> NetworkSession:
    return _CURRENT.get()


@contextlib.contextmanager
def active(session: NetworkSession) -> Iterator[NetworkSession]:
    """Bind ``session`` to the code running inside the ``with`` block (and the threads started from it)."""
    token = _CURRENT.set(session)
    try:
        yield session
    finally:
        _CURRENT.reset(token)


def in_context(function: Callable) -> Callable:
    """Wrap ``function`` so a worker thread runs it inside the caller's context (thread pools do not inherit it)."""
    context = contextvars.copy_context()

    def run(*args, **kwargs):
        return context.copy().run(function, *args, **kwargs)

    return run


def __getattr__(name: str):  # module-level SETTINGS / STATS always refer to the session of the running scan
    if name == "SETTINGS":
        return current().settings
    if name == "STATS":
        return current().stats
    raise AttributeError(name)


def _sleep(seconds: float) -> None:  # separate function so tests do not really wait
    time.sleep(seconds)


def configure(**changes) -> NetworkSettings:
    """Replace the settings of the current session and reset its counters."""
    session = current()
    session.settings = NetworkSettings(**{**session.settings.__dict__, **changes})
    session.stats = NetworkStats()
    return session.settings


def note(message: str) -> None:
    current().note(message)


# ---------------------------------------------------------------------- TLS
def ca_bundle_path() -> str:
    """The certificate bundle to trust: the explicit setting first, then the environment ('' = system store)."""
    explicit = current().settings.ca_bundle
    if explicit:
        return explicit
    for variable in CA_ENVIRONMENT:
        value = os.environ.get(variable, "").strip()
        if value:
            return value
    return ""


def validate_ca_bundle(path: str) -> None:
    if path and not os.path.isfile(path):
        raise NetworkError(f"CA bundle not found: {path}")


def ssl_context() -> ssl.SSLContext:
    path = ca_bundle_path()
    if not path:
        return ssl.create_default_context()
    validate_ca_bundle(path)
    try:
        return ssl.create_default_context(cafile=path)
    except (ssl.SSLError, OSError) as exc:
        raise NetworkError(f"CA bundle {path} could not be loaded: {exc}") from exc


# ---------------------------------------------------------------------- cache
def _cache_path(key: str) -> str:
    base = current().settings.cache_dir
    if not base:
        from secure_repo.core.triage import data_dir

        base = os.path.join(data_dir(), "cache", "intel")
    return os.path.join(base, key[:2], key + ".json")


def _cache_key(url: str, payload: dict | None) -> str:
    material = url + "\n" + (json.dumps(payload, sort_keys=True) if payload is not None else "")
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _cache_read(key: str):
    path = _cache_path(key)
    try:
        if time.time() - os.path.getmtime(path) > current().settings.cache_ttl:
            return None
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _cache_write(key: str, data) -> None:
    path = _cache_path(key)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(data, out)
        os.replace(temporary, path)
    except (OSError, TypeError, ValueError):
        pass  # a cache that cannot be written is only a missed optimisation


def clear_cache() -> int:
    """Delete the on-disk cache; returns the number of entries removed."""
    removed = 0
    base = os.path.dirname(os.path.dirname(_cache_path("00")))
    for folder, _dirs, names in os.walk(base):
        for name in names:
            try:
                os.remove(os.path.join(folder, name))
                removed += 1
            except OSError:
                pass
    return removed


# ---------------------------------------------------------------------- requests
def _retry_delay(error: Exception, attempt: int, backoff: float) -> float:
    delay = backoff * (2 ** attempt)
    if isinstance(error, urllib.error.HTTPError):
        header = error.headers.get("Retry-After") if error.headers else None
        if header and header.strip().isdigit():
            delay = max(delay, float(header))
    return min(delay, MAX_RETRY_AFTER)


def http_json(url: str, payload: dict | None = None, timeout: int = 20, cache: bool = False):
    """GET (or POST when ``payload`` is given) a JSON document, with limits, retries and an optional disk cache."""
    session = current()
    settings = session.settings
    key = _cache_key(url, payload) if cache and settings.cache else ""
    if key:
        cached = _cache_read(key)
        if cached is not None:
            session.count(cache_hits=1)
            return cached
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    attempts = max(1, settings.retries)
    last_error: Exception | None = None
    for attempt in range(attempts):
        request = urllib.request.Request(url, data=data, method="POST" if data else "GET", headers={
            "User-Agent": USER_AGENT, "Accept": "application/json", "Content-Type": "application/json"})
        session.count(requests=1)
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ssl_context()) as response:  # nosec - https
                body = response.read(settings.max_bytes + 1)
            if len(body) > settings.max_bytes:
                session.count(oversized=1)
                raise NetworkError(f"the response from {url.split('?')[0]} is larger than {settings.max_bytes} bytes")
            parsed = json.loads(body.decode("utf-8"))
            if key:
                _cache_write(key, parsed)
            return parsed
        except NetworkError:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRY_STATUS:
                raise
            last_error = exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last_error = exc
        if attempt + 1 < attempts:
            session.count(retries=1)
            _sleep(_retry_delay(last_error, attempt, settings.backoff))
    session.count(failures=1)
    raise last_error if last_error is not None else NetworkError(f"{url.split('?')[0]} could not be reached")
