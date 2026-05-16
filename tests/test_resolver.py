from pathlib import Path

from depspy.core.resolver import (
    DepNode,
    PackageInfo,
    attach_parents,
    detect_cycles,
    filter_dep_tree,
    find_direct_deps,
    flatten_tree,
    resolve_tree,
)


def test_find_direct_reads_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0"\ndependencies = ["requests>=2"]\n',
        encoding="utf-8",
    )
    names = find_direct_deps(tmp_path)
    assert "requests" in names


def test_resolve_tree_simple() -> None:
    installed = {
        "a": PackageInfo("a", "1", Path(), None, ["b"], 10),
        "b": PackageInfo("b", "2", Path(), None, [], 5),
    }
    tree = resolve_tree("a", installed)
    assert tree.name == "a"
    assert len(tree.children) == 1
    assert tree.children[0].name == "b"


def test_detect_cycles() -> None:
    a = DepNode("a", "1", 0, None, [], 0, False)
    b = DepNode("b", "1", 0, None, [], 0, False)
    a.children = [b]
    b.children = [a]
    cycles = detect_cycles(a)
    assert cycles


def test_filter_dep_tree() -> None:
    a = DepNode("a", "1", 0, None, [], 0, False)
    b = DepNode("b", "1", 0, None, [], 1, False)
    c = DepNode("pytest", "1", 0, None, [], 2, False)
    a.children = [b]
    b.children = [c]
    out = filter_dep_tree(a, "pytest")
    assert out.name == "a"
    assert len(out.children) == 1
    assert out.children[0].name == "b"


def test_attach_parents() -> None:
    a = DepNode("a", "1", 0, None, [], 0, False)
    b = DepNode("b", "1", 0, None, [], 1, False)
    a.children = [b]
    attach_parents(a)
    assert b.parent is a
    assert a.parent is None


def test_flatten_order() -> None:
    root = DepNode("r", "", 0, None, [], 0, False)
    c1 = DepNode("c1", "1", 0, None, [], 1, False)
    c2 = DepNode("c2", "1", 0, None, [], 1, False)
    root.children = [c1, c2]
    flat = flatten_tree(root)
    assert [n.name for n in flat] == ["r", "c1", "c2"]
