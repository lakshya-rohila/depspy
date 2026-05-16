from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from depspy.core import cache
from depspy.core.resolver import DepNode, VulnRecord, is_outdated


@dataclass
class Vulnerability:
    id: str
    severity: str
    description: str
    fixed_in: str | None


@dataclass
class PyPIData:
    latest_version: str
    last_release_date: datetime | None
    is_yanked: bool
    days_since_update: int


def _cache_key(name: str, version: str) -> str:
    return f"depspy_{name}_{version}"


def _pypi_from_cache(c: dict[str, Any]) -> PyPIData:
    last = c.get("last_release_iso")
    last_dt = None
    if last:
        try:
            last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
        except ValueError:
            last_dt = None
    return PyPIData(
        latest_version=str(c.get("latest_version", "")),
        last_release_date=last_dt,
        is_yanked=bool(c.get("is_yanked", False)),
        days_since_update=int(c.get("days_since_update", 0)),
    )


async def fetch_pypi(session: httpx.AsyncClient, name: str, version: str) -> PyPIData | None:
    key = _cache_key(name, version)
    cached = cache.get(key)
    if cached and "latest_version" in cached:
        return _pypi_from_cache(cached)

    url = f"https://pypi.org/pypi/{name}/json"
    try:
        r = await session.get(url, timeout=20.0)
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception:
        return None

    info = data.get("info") or {}
    latest_version = str(info.get("version") or "")
    releases = data.get("releases") or {}
    rel_list = releases.get(version) or []
    is_yanked = any(bool(rel.get("yanked")) for rel in rel_list)
    last_dt: datetime | None = None
    for rel in rel_list:
        ts = rel.get("upload_time")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if last_dt is None or dt > last_dt:
                last_dt = dt
        except ValueError:
            continue

    days = 0
    if last_dt:
        days = max(0, int((datetime.now(timezone.utc) - last_dt).total_seconds() // 86400))

    payload = {
        "latest_version": latest_version,
        "last_release_iso": last_dt.isoformat() if last_dt else None,
        "is_yanked": is_yanked,
        "days_since_update": days,
    }
    cache.set(key, payload, ttl=3600)
    return PyPIData(
        latest_version=latest_version,
        last_release_date=last_dt,
        is_yanked=is_yanked,
        days_since_update=days,
    )


def _vulns_from_cache(raw: list[dict[str, Any]]) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for v in raw:
        out.append(
            Vulnerability(
                id=str(v.get("id", "")),
                severity=str(v.get("severity", "UNKNOWN")),
                description=str(v.get("description", "")),
                fixed_in=v.get("fixed_in"),
            )
        )
    return out


async def fetch_vulns(session: httpx.AsyncClient, name: str, version: str) -> list[Vulnerability]:
    key = f"depspy_osv_{name}_{version}"
    cached = cache.get(key)
    if cached and "vulns" in cached:
        return _vulns_from_cache(cached["vulns"])
    body = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    try:
        r = await session.post("https://api.osv.dev/v1/query", json=body, timeout=25.0)
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []
    vulns: list[Vulnerability] = []
    for vuln in data.get("vulns") or []:
        vid = str(vuln.get("id", "unknown"))
        summary = str(vuln.get("summary") or vuln.get("details") or "")[:500]
        sev = "UNKNOWN"
        fixed_in: str | None = None
        for a in vuln.get("affected") or []:
            for rng in a.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if "limit" in ev:
                        fixed_in = str(ev["limit"])
        db = vuln.get("database_specific") or {}
        if isinstance(db, dict) and "severity" in db:
            sev = str(db["severity"]).upper()
        vulns.append(Vulnerability(id=vid, severity=sev, description=summary, fixed_in=fixed_in))
    cache.set(key, {"vulns": [asdict(v) for v in vulns]}, ttl=3600)
    return vulns


async def scan_all(
    nodes: list[DepNode],
    on_progress: Callable[[int, int], None] | None = None,
    *,
    offline: bool = False,
    skip_vulns: bool = False,
    max_concurrency: int = 10,
) -> list[DepNode]:
    if offline:
        if on_progress:
            on_progress(len(nodes), len(nodes))
        return nodes

    sem = asyncio.Semaphore(max_concurrency)
    total = len(nodes)
    done = 0
    lock = asyncio.Lock()

    async def bump() -> None:
        nonlocal done
        async with lock:
            done += 1
            if on_progress:
                on_progress(done, total)

    async with httpx.AsyncClient(headers={"User-Agent": "depspy/0.1"}) as session:

        async def enrich(n: DepNode) -> None:
            if not n.version or n.version.startswith("("):
                await bump()
                return
            async with sem:
                try:
                    pypi = await fetch_pypi(session, n.name, n.version)
                    if pypi:
                        n.latest_version = pypi.latest_version
                        n.days_since_update = pypi.days_since_update
                        n.is_outdated = is_outdated(n.version, pypi.latest_version)
                    if not skip_vulns:
                        vulns = await fetch_vulns(session, n.name, n.version)
                        n.vulnerabilities = [
                            VulnRecord(
                                id=v.id,
                                severity=v.severity,
                                description=v.description,
                                fixed_in=v.fixed_in,
                            )
                            for v in vulns
                        ]
                        n.vuln_count = len(n.vulnerabilities)
                except Exception:
                    pass
                await bump()

        await asyncio.gather(*(enrich(n) for n in nodes))
    return nodes
