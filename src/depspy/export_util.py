"""Build JSON-serializable export payloads (CLI + TUI)."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from depspy.core.resolver import DepNode, find_direct_deps, flatten_tree
from depspy.core.scorer import BloatReport


def build_export_dict(root: Path, tree: DepNode, report: BloatReport) -> dict[str, Any]:
    nodes = flatten_tree(tree)
    pkgs: list[dict[str, Any]] = []
    vulns: list[dict[str, Any]] = []
    for n in nodes:
        if not n.version or (n.depth == 0 and not n.version):
            continue
        deps = [c.name for c in n.children]
        vrows = [
            {
                "id": v.id,
                "severity": v.severity,
                "description": v.description,
                "fixed_in": v.fixed_in,
            }
            for v in n.vulnerabilities
        ]
        for v in n.vulnerabilities:
            vulns.append(
                {
                    "package": n.name,
                    "version": n.version,
                    "id": v.id,
                    "severity": v.severity,
                    "description": v.description,
                    "fixed_in": v.fixed_in,
                },
            )
        pkgs.append(
            {
                "name": n.name,
                "version": n.version,
                "latest_version": n.latest_version,
                "is_direct": n.is_direct,
                "size_bytes": n.size_bytes,
                "days_since_update": n.days_since_update,
                "vulnerabilities": vrows,
                "dependencies": deps,
                "depth": n.depth,
            },
        )
    return {
        "project": root.name,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version.split()[0],
        "summary": {
            "total_packages": sum(
                1 for n in nodes if n.version and not (n.depth == 0 and not n.version)
            ),
            "direct_deps": len(find_direct_deps(root)),
            "total_size_bytes": sum(n.size_bytes for n in nodes),
            "vulnerability_count": sum(n.vuln_count for n in nodes),
            "stale_count": len([n for n in nodes if n.days_since_update > 730]),
            "bloat_score": report.score,
            "bloat_rating": report.rating,
        },
        "packages": pkgs,
        "vulnerabilities": vulns,
    }
