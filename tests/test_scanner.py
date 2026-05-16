from pathlib import Path

import httpx
import pytest

from depspy.core import cache
from depspy.core.scanner import fetch_pypi, fetch_vulns


@pytest.mark.asyncio
async def test_fetch_pypi_uses_cache(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    cache.set(
        "depspy_requests_2.0.0",
        {
            "latest_version": "9.9.9",
            "last_release_iso": None,
            "is_yanked": False,
            "days_since_update": 1,
        },
        ttl=3600,
    )

    transport = httpx.MockTransport(lambda request: httpx.Response(500))

    async with httpx.AsyncClient(transport=transport) as client:
        data = await fetch_pypi(client, "requests", "2.0.0")
    assert data is not None
    assert data.latest_version == "9.9.9"


@pytest.mark.asyncio
async def test_fetch_vulns_handles_errors(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    transport = httpx.MockTransport(lambda request: httpx.Response(500))
    async with httpx.AsyncClient(transport=transport) as client:
        vulns = await fetch_vulns(client, "does-not-exist-pkg-xyz", "0.0.0")
    assert vulns == []
