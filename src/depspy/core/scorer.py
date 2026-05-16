from __future__ import annotations

from dataclasses import dataclass

from depspy.core.resolver import DepNode, flatten_tree


@dataclass
class BloatReport:
    score: float
    rating: str
    rating_label: str
    breakdown: dict[str, float]
    top_offenders: list[tuple[str, float, str]]


_WEIGHTS: dict[str, float] = {
    "total_size_mb": 0.25,
    "dep_count": 0.20,
    "avg_staleness_years": 0.20,
    "vuln_count": 0.25,
    "depth": 0.10,
}


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _norm_size_mb(mb: float) -> float:
    return _clamp01(mb / 500.0)


def _norm_dep_count(n: int) -> float:
    return _clamp01(n / 200.0)


def _norm_staleness_years(years: float) -> float:
    return _clamp01(years / 5.0)


def _norm_vuln_count(n: int) -> float:
    return _clamp01(n / 10.0)


def _norm_depth(d: int) -> float:
    return _clamp01((d - 1) / 9.0) if d >= 1 else 0.0


def _rating(score: float) -> tuple[str, str]:
    if score <= 20:
        return "PRISTINE", "✦ PRISTINE"
    if score <= 40:
        return "HEALTHY", "◈ HEALTHY"
    if score <= 60:
        return "MODERATE", "◉ MODERATE"
    if score <= 80:
        return "BLOATED", "⚠ BLOATED"
    return "CRITICAL", "☠ CRITICAL"


def calculate_bloat(nodes: list[DepNode]) -> BloatReport:
    valid = [
        n
        for n in nodes
        if n.version and not n.version.startswith("(") and n.name not in ("environment",)
    ]
    if not valid:
        return BloatReport(0.0, "PRISTINE", "✦ PRISTINE", {}, [])

    total_size = sum(n.size_bytes for n in valid) / (1024 * 1024)
    dep_count = len(valid)
    vuln_total = sum(n.vuln_count for n in valid)
    depths = [n.depth for n in valid]
    max_depth = max(depths) if depths else 0

    stale_days = [n.days_since_update for n in valid if n.days_since_update > 0]
    if stale_days:
        avg_days = sum(stale_days) / len(stale_days)
        avg_staleness_years = avg_days / 365.25
    else:
        avg_staleness_years = 0.0

    signals = {
        "total_size_mb": _norm_size_mb(total_size),
        "dep_count": _norm_dep_count(dep_count),
        "avg_staleness_years": _norm_staleness_years(avg_staleness_years),
        "vuln_count": _norm_vuln_count(vuln_total),
        "depth": _norm_depth(max_depth),
    }
    score = sum(signals[k] * w for k, w in _WEIGHTS.items()) * 100.0
    rating, label = _rating(score)

    offenders: list[tuple[str, float, str]] = []
    for n in valid:
        if n.depth == 0 and not n.version:
            continue
        contrib = (
            _norm_size_mb(n.size_bytes / (1024 * 1024)) * _WEIGHTS["total_size_mb"]
            + _norm_vuln_count(n.vuln_count) * _WEIGHTS["vuln_count"]
            + _norm_staleness_years(n.days_since_update / 365.25) * _WEIGHTS["avg_staleness_years"]
        )
        offenders.append((n.name, contrib * 100, "composite"))
    offenders.sort(key=lambda t: t[1], reverse=True)
    top = offenders[:5]

    return BloatReport(
        score=round(score, 1),
        rating=rating,
        rating_label=label,
        breakdown=signals,
        top_offenders=top,
    )


def rank_by_staleness(nodes: list[DepNode]) -> list[DepNode]:
    return sorted(nodes, key=lambda n: n.days_since_update, reverse=True)


def rank_by_size(nodes: list[DepNode]) -> list[DepNode]:
    return sorted(nodes, key=lambda n: n.size_bytes, reverse=True)


def rank_by_vulns(nodes: list[DepNode]) -> list[DepNode]:
    return sorted(nodes, key=lambda n: n.vuln_count, reverse=True)


def apply_bloat_contributions(tree: DepNode, report: BloatReport) -> None:
    """Populate ``bloat_contribution`` on nodes from per-node heuristics."""
    nodes = flatten_tree(tree)
    if not report.breakdown:
        return
    total_signal = sum(report.breakdown.values()) or 1.0
    for n in nodes:
        piece = (
            _norm_size_mb(n.size_bytes / (1024 * 1024)) * _WEIGHTS["total_size_mb"]
            + _norm_vuln_count(n.vuln_count) * _WEIGHTS["vuln_count"]
            + _norm_staleness_years(n.days_since_update / 365.25) * _WEIGHTS["avg_staleness_years"]
        )
        n.bloat_contribution = round(piece / total_signal * report.score, 2)
