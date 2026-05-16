from depspy.core.resolver import DepNode
from depspy.core.scorer import calculate_bloat


def test_bloat_bounded() -> None:
    nodes = [
        DepNode(
            "a",
            "1.0",
            50 * 1024 * 1024,
            None,
            [],
            1,
            True,
            vuln_count=0,
            days_since_update=30,
        ),
        DepNode(
            "b",
            "1.0",
            50 * 1024 * 1024,
            None,
            [],
            2,
            False,
            vuln_count=0,
            days_since_update=30,
        ),
    ]
    r = calculate_bloat(nodes)
    assert 0 <= r.score <= 100


def test_many_vulns_raises_score() -> None:
    low = [
        DepNode("a", "1.0", 1024, None, [], 1, True, vuln_count=0, days_since_update=10),
    ]
    high = [
        DepNode("a", "1.0", 1024, None, [], 1, True, vuln_count=25, days_since_update=10),
    ]
    assert calculate_bloat(high).score >= calculate_bloat(low).score


def test_pristine_low() -> None:
    nodes = [
        DepNode("a", "1.0", 1024, None, [], 1, True, vuln_count=0, days_since_update=0),
    ]
    r = calculate_bloat(nodes)
    assert r.score < 40
