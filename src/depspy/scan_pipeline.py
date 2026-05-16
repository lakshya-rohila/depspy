"""Async scan pipeline used by CLI and the Textual loading screen."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

from depspy.core.resolver import (
    DepNode,
    attach_parents,
    build_workspace_tree,
    flatten_tree,
    get_installed_packages,
    resolve_tree,
)
from depspy.core.scanner import scan_all
from depspy.core.scorer import BloatReport, apply_bloat_contributions, calculate_bloat

StageCallback = Callable[[str, float], None]


async def run_scan_async(
    project_path: Path,
    *,
    package: str | None,
    env: bool,
    offline: bool,
    no_vulns: bool,
    on_stage: StageCallback | None = None,
) -> tuple[DepNode, BloatReport]:
    def stage(msg: str, frac: float) -> None:
        if on_stage:
            on_stage(msg, frac)

    stage("Resolving dependency graph…", 0.05)
    if package:
        installed = get_installed_packages()
        direct = frozenset({package})
        tree = resolve_tree(package, installed, direct)
    elif env:
        installed = get_installed_packages()
        names = sorted(installed.keys())
        children = [resolve_tree(n, installed, frozenset(), max_depth=2) for n in names]
        tree = DepNode(
            name="environment",
            version="",
            size_bytes=sum(c.size_bytes for c in children),
            install_date=None,
            children=children,
            depth=0,
            is_direct=False,
        )
    else:
        tree = build_workspace_tree(project_path)

    attach_parents(tree)
    nodes = flatten_tree(tree)

    stage("Scanning PyPI / OSV…", 0.15)
    last_emit = [0.0]

    def progress(cur: int, tot: int) -> None:
        frac = 0.15 + 0.75 * (cur / max(1, tot))
        if frac - last_emit[0] >= 0.02 or cur == tot:
            last_emit[0] = frac
            stage(f"Metadata & vulns ({cur}/{tot})…", min(0.9, frac))

    await scan_all(nodes, progress, offline=offline, skip_vulns=no_vulns)

    stage("Computing bloat score…", 0.92)
    report = calculate_bloat(nodes)
    apply_bloat_contributions(tree, report)
    stage("Done.", 1.0)
    return tree, report


def run_scan_blocking(
    project_path: Path,
    *,
    package: str | None,
    env: bool,
    offline: bool,
    no_vulns: bool,
    on_stage: StageCallback | None = None,
) -> tuple[DepNode, BloatReport]:
    return asyncio.run(
        run_scan_async(
            project_path,
            package=package,
            env=env,
            offline=offline,
            no_vulns=no_vulns,
            on_stage=on_stage,
        ),
    )
