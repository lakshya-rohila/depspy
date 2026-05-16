"""File-based cache under ~/.depspy/cache/."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def cache_dir() -> Path:
    p = Path.home() / ".depspy" / "cache"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get(key: str) -> dict[str, Any] | None:
    path = cache_dir() / f"{_safe_key(key)}.json"
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    expires = raw.get("expires", 0)
    if time.time() > expires:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    data = raw.get("data")
    if isinstance(data, dict):
        return data
    return None


def set_value(key: str, data: dict[str, Any], ttl: int = 3600) -> None:
    path = cache_dir() / f"{_safe_key(key)}.json"
    payload = {"expires": time.time() + ttl, "data": data}
    path.write_text(json.dumps(payload), encoding="utf-8")


def set(key: str, data: dict[str, Any], ttl: int = 3600) -> None:  # noqa: A001
    """Public API name from project spec (wraps ``set_value``)."""
    set_value(key, data, ttl)


def clear(older_than_hours: int | None = 24) -> int:
    """Remove cache entries. If ``older_than_hours`` is None, wipe all. Else remove stale files."""
    d = cache_dir()
    if not d.is_dir():
        return 0
    removed = 0
    if older_than_hours is None:
        for path in d.glob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed
    cutoff = time.time() - older_than_hours * 3600
    for path in d.glob("*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def _safe_key(key: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in key)
    return safe[:200] if len(safe) > 200 else safe
