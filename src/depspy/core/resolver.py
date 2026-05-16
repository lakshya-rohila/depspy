from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

try:
    import importlib.metadata as im
except ImportError:  # pragma: no cover
    import importlib_metadata as im  # type: ignore


@dataclass
class VulnRecord:
    id: str
    severity: str
    description: str
    fixed_in: str | None = None


@dataclass
class DepNode:
    name: str
    version: str
    size_bytes: int
    install_date: datetime | None
    children: list[DepNode]
    depth: int
    is_direct: bool
    vuln_count: int = 0
    days_since_update: int = 0
    bloat_contribution: float = 0.0
    latest_version: str = ""
    is_outdated: bool = False
    parent: DepNode | None = None
    vulnerabilities: list[VulnRecord] = field(default_factory=list)


@dataclass
class PackageInfo:
    name: str
    version: str
    location: Path
    install_date: datetime | None
    dependencies: list[str]
    size_bytes: int = 0


def get_installed_packages() -> dict[str, PackageInfo]:
    """List installed distributions keyed by canonical project name."""
    out: dict[str, PackageInfo] = {}
    for dist in im.distributions():
        name = dist.metadata.get("Name")
        if not name:
            continue
        key = canonicalize_name(name)
        version = dist.version or "0"
        loc = _dist_location(dist)
        mtime = _dist_install_mtime(dist)
        deps: list[str] = []
        for req in dist.requires or []:
            try:
                deps.append(canonicalize_name(Requirement(req).name))
            except Exception:
                continue
        out[key] = PackageInfo(
            name=key,
            version=version,
            location=loc,
            install_date=mtime,
            dependencies=deps,
            size_bytes=_distribution_size_bytes(dist),
        )
    return out


def find_direct_deps(project_path: Path) -> list[str]:
    """Declared dependencies: requirements.txt → pyproject.toml → setup.cfg → setup.py."""
    path = project_path.resolve()
    for reader in (
        _read_requirements_txt,
        _read_pyproject_toml,
        _read_setup_cfg,
        _read_setup_py,
    ):
        names = reader(path)
        if names:
            return names
    return []


def resolve_tree(
    root_package: str,
    installed: dict[str, PackageInfo] | None = None,
    direct: frozenset[str] | None = None,
    *,
    max_depth: int | None = None,
    _seen_path: list[str] | None = None,
) -> DepNode:
    """Build a dependency subtree starting at ``root_package`` (canonical name)."""
    installed = installed or get_installed_packages()
    direct = direct or frozenset()
    key = canonicalize_name(root_package)
    _seen_path = _seen_path or []
    if key in _seen_path:
        # Cycle placeholder leaf
        return DepNode(
            name=key,
            version="(cycle)",
            size_bytes=0,
            install_date=None,
            children=[],
            depth=len(_seen_path),
            is_direct=key in direct,
        )
    info = installed.get(key)
    if info is None:
        return DepNode(
            name=key,
            version="(not installed)",
            size_bytes=0,
            install_date=None,
            children=[],
            depth=len(_seen_path),
            is_direct=key in direct,
        )
    if max_depth is not None and len(_seen_path) >= max_depth:
        size = info.size_bytes
        return DepNode(
            name=key,
            version=info.version,
            size_bytes=size,
            install_date=info.install_date,
            children=[],
            depth=len(_seen_path),
            is_direct=key in direct,
        )
    size = info.size_bytes
    children: list[DepNode] = []
    new_path = _seen_path + [key]
    for dep_key in info.dependencies:
        if dep_key not in installed:
            continue
        if dep_key in _seen_path:
            continue
        children.append(
            resolve_tree(
                dep_key,
                installed,
                direct,
                max_depth=max_depth,
                _seen_path=new_path,
            )
        )
    return DepNode(
        name=key,
        version=info.version,
        size_bytes=size,
        install_date=info.install_date,
        children=children,
        depth=len(_seen_path),
        is_direct=key in direct,
    )


def build_workspace_tree(project_path: Path) -> DepNode:
    """Synthetic root: directory name, children = direct deps subtrees."""
    root_name = canonicalize_name(project_path.resolve().name or "project")
    installed = get_installed_packages()
    direct_names = [canonicalize_name(n) for n in find_direct_deps(project_path)]
    direct_set = frozenset(direct_names)
    children = [
        resolve_tree(name, installed, direct_set) for name in direct_names if name in installed
    ]
    if not children and not direct_names:
        for key in sorted(installed.keys()):
            children.append(resolve_tree(key, installed, frozenset(), max_depth=2))
            if len(children) >= 24:
                break
    return DepNode(
        name=root_name,
        version="",
        size_bytes=sum(c.size_bytes for c in children),
        install_date=None,
        children=children,
        depth=0,
        is_direct=False,
    )


def detect_cycles(tree: DepNode) -> list[list[str]]:
    cycles: list[list[str]] = []

    def walk(node: DepNode, stack: list[str]) -> None:
        if node.name in stack:
            idx = stack.index(node.name)
            cyc = stack[idx:] + [node.name]
            if cyc not in cycles:
                cycles.append(cyc)
            return
        stack = stack + [node.name]
        for ch in node.children:
            walk(ch, stack)

    walk(tree, [])
    return cycles


def flatten_tree(tree: DepNode) -> list[DepNode]:
    out: list[DepNode] = []
    q: list[DepNode] = [tree]
    while q:
        n = q.pop(0)
        out.append(n)
        q.extend(n.children)
    return out


def attach_parents(root: DepNode) -> None:
    """Set ``parent`` on every node for reverse chains."""

    def walk(n: DepNode, parent: DepNode | None) -> None:
        n.parent = parent
        for c in n.children:
            walk(c, n)

    walk(root, None)


def reverse_dependents(root: DepNode) -> dict[str, frozenset[str]]:
    """Map package name -> set of parent package names that depend on it."""
    rev: dict[str, set[str]] = {}
    for n in flatten_tree(root):
        for c in n.children:
            rev.setdefault(c.name, set()).add(n.name)
    return {k: frozenset(v) for k, v in rev.items()}


def optional_only_package_names(project_path: Path) -> frozenset[str]:
    """Packages that appear only in ``[project.optional-dependencies]``, not in main deps."""
    py = project_path / "pyproject.toml"
    if not py.is_file():
        return frozenset()
    data = tomllib.loads(py.read_text(encoding="utf-8"))
    project = data.get("project") or {}
    main: set[str] = set()
    block = project.get("dependencies")
    if isinstance(block, list):
        for line in block:
            try:
                main.add(canonicalize_name(Requirement(str(line)).name))
            except Exception:
                continue
    optional_all: set[str] = set()
    opt = project.get("optional-dependencies")
    if isinstance(opt, dict):
        for group in opt.values():
            if not isinstance(group, Iterable):
                continue
            for line in group:
                try:
                    optional_all.add(canonicalize_name(Requirement(str(line)).name))
                except Exception:
                    continue
    return frozenset(optional_all - main)


def filter_dep_tree(root: DepNode, needle: str) -> DepNode:
    """Return a pruned copy: branches that match ``needle`` in name or have matching descendants."""
    nlow = needle.strip().lower()
    if not nlow:
        return root

    def copy_node(n: DepNode, kids: list[DepNode]) -> DepNode:
        return DepNode(
            name=n.name,
            version=n.version,
            size_bytes=n.size_bytes,
            install_date=n.install_date,
            children=kids,
            depth=n.depth,
            is_direct=n.is_direct,
            vuln_count=n.vuln_count,
            days_since_update=n.days_since_update,
            bloat_contribution=n.bloat_contribution,
            latest_version=n.latest_version,
            is_outdated=n.is_outdated,
            parent=None,
            vulnerabilities=list(n.vulnerabilities),
        )

    def recurse(n: DepNode) -> DepNode | None:
        kept_children: list[DepNode] = []
        for c in n.children:
            fc = recurse(c)
            if fc is not None:
                kept_children.append(fc)
        self_match = nlow in n.name.lower()
        if self_match or kept_children:
            nn = copy_node(n, kept_children)
            for ch in nn.children:
                ch.parent = nn
            return nn
        return None

    pruned = recurse(root)
    if pruned is None:
        return copy_node(root, [])
    attach_parents(pruned)
    return pruned


def _distribution_size_bytes(dist: im.Distribution) -> int:
    total = 0
    try:
        files = list(dist.files or [])
    except Exception:
        files = []
    for f in files[:40000]:
        try:
            p = f.locate()
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    if total:
        return total
    return _package_size_bytes_capped(_dist_location(dist))


def _dist_location(dist: im.Distribution) -> Path:
    try:
        loc = dist.locate_file("")
    except Exception:
        return Path()
    return Path(loc)


def _dist_install_mtime(dist: im.Distribution) -> datetime | None:
    try:
        files = list(dist.files or [])
    except Exception:
        files = []
    mtimes: list[float] = []
    for f in files[:5000]:
        try:
            p = f.locate()
            if p.is_file():
                mtimes.append(p.stat().st_mtime)
        except Exception:
            continue
    if not mtimes:
        try:
            meta = Path(dist._path) / "METADATA"  # type: ignore[attr-defined]
            if meta.is_file():
                mtimes.append(meta.stat().st_mtime)
        except Exception:
            return None
    if not mtimes:
        return None
    return datetime.fromtimestamp(max(mtimes), tz=timezone.utc)


def _package_size_bytes_capped(root: Path, cap_entries: int = 12000) -> int:
    if not root or not root.exists():
        return 0
    if root.is_file():
        try:
            return root.stat().st_size
        except OSError:
            return 0
    total = 0
    n = 0
    for p in root.rglob("*"):
        n += 1
        if n > cap_entries:
            break
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                continue
    return total


def _read_requirements_txt(project_path: Path) -> list[str]:
    req = project_path / "requirements.txt"
    if not req.is_file():
        return []
    names: list[str] = []
    for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r "):
            continue
        line = re.split(r"[#;]", line, maxsplit=1)[0].strip()
        if not line:
            continue
        try:
            names.append(canonicalize_name(Requirement(line).name))
        except Exception:
            continue
    return names


def _read_pyproject_toml(project_path: Path) -> list[str]:
    py = project_path / "pyproject.toml"
    if not py.is_file():
        return []
    data = tomllib.loads(py.read_text(encoding="utf-8"))
    names: list[str] = []
    project = data.get("project") or {}
    for key in ("dependencies", "optional-dependencies"):
        block = project.get(key)
        if key == "dependencies" and isinstance(block, list):
            for line in block:
                try:
                    names.append(canonicalize_name(Requirement(str(line)).name))
                except Exception:
                    continue
        elif key == "optional-dependencies" and isinstance(block, dict):
            for group in block.values():
                if not isinstance(group, Iterable):
                    continue
                for line in group:
                    try:
                        names.append(canonicalize_name(Requirement(str(line)).name))
                    except Exception:
                        continue
    return names


def _read_setup_cfg(project_path: Path) -> list[str]:
    path = project_path / "setup.cfg"
    if not path.is_file():
        return []
    try:
        import configparser

        cfg = configparser.ConfigParser()
        cfg.read(path, encoding="utf-8")
        if not cfg.has_section("options"):
            return []
        install = cfg.get("options", "install_requires", fallback="")
    except Exception:
        return []
    names: list[str] = []
    for part in install.splitlines():
        part = part.strip()
        if not part:
            continue
        try:
            names.append(canonicalize_name(Requirement(part).name))
        except Exception:
            continue
    return names


def _read_setup_py(project_path: Path) -> list[str]:
    """Best-effort: parse install_requires=... literals from setup.py."""
    path = project_path / "setup.py"
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
    if not m:
        return []
    blob = m.group(1)
    names: list[str] = []
    for quoted in re.findall(r"['\"]([^'\"]+)['\"]", blob):
        try:
            names.append(canonicalize_name(Requirement(quoted).name))
        except Exception:
            continue
    return names


def is_outdated(current: str, latest: str) -> bool:
    try:
        return Version(latest) > Version(current)
    except (InvalidVersion, ValueError):
        return latest != current and bool(latest)
