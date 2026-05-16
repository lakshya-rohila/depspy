from __future__ import annotations

import json
from pathlib import Path

from rich.text import Text
from textual import on
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Input, ProgressBar, Static, Tree

from depspy.core.resolver import (
    DepNode,
    filter_dep_tree,
    find_direct_deps,
    flatten_tree,
)
from depspy.core.scorer import BloatReport
from depspy.export_util import build_export_dict
from depspy.screens.detail_screen import DetailScreen

_SIGNAL_LABELS: dict[str, str] = {
    "total_size_mb": "Disk footprint",
    "dep_count": "Package count",
    "avg_staleness_years": "Avg staleness",
    "vuln_count": "Vulnerabilities",
    "depth": "Max depth",
}

_SORT_MODES: tuple[str, ...] = ("name", "vuln", "stale", "size")


def _spark_bar(fraction: float, width: int = 14) -> Text:
    x = max(0.0, min(1.0, fraction))
    filled = int(round(x * width))
    t = Text()
    t.append("█" * filled, style="bold #00d9a3")
    t.append("░" * (width - filled), style="#2a3142")
    t.append(f"  {x * 100:4.0f}%", style="#7b61ff")
    return t


class MainScreen(Screen[None]):
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("question_mark", "help", "Help", show=True),
        Binding("slash", "focus_filter", "Filter", show=True),
        Binding("s", "cycle_sort", "Sort", show=True),
        Binding("e", "export_json", "Export", show=True),
        Binding("x", "toggle_extras", "Extras", show=True),
        Binding("i", "open_detail", "Inspect", show=True),
    ]

    def __init__(
        self,
        dep_root: DepNode,
        scan_report: BloatReport,
        project_path: str,
        *,
        reverse_map: dict[str, frozenset[str]],
        extras_only: frozenset[str],
    ) -> None:
        super().__init__(id="main_screen")
        self._full_root = dep_root
        self._view_root = dep_root
        self.scan_report = scan_report
        self.project_path = project_path
        self.reverse_map = reverse_map
        self.extras_only = extras_only
        self._sort_index = 0
        self._extras_collapsed = False

    def compose(self):
        yield Static(self._header_text(), id="title")
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield Tree("dependencies", id="dep_tree")
                yield Input(placeholder="Filter packages (Enter)…", id="tree_filter")
            with VerticalScroll(id="right_scroll"):
                with Vertical(id="right_panel"):
                    yield Static("OVERVIEW", classes="section-title")
                    yield Static("", id="bloat_heading", markup=True)
                    yield ProgressBar(
                        total=100,
                        show_eta=False,
                        show_percentage=True,
                        id="bloat_bar",
                    )
                    yield Static("SUMMARY", classes="section-title")
                    yield DataTable(
                        id="summary_table",
                        zebra_stripes=True,
                        show_header=True,
                        cursor_type="none",
                    )
                    yield Static("SIGNAL MIX", classes="section-title")
                    yield DataTable(
                        id="breakdown_table",
                        zebra_stripes=True,
                        show_header=True,
                        cursor_type="none",
                    )
                    yield Static("TOP OFFENDERS", classes="section-title")
                    yield DataTable(
                        id="offenders_table",
                        zebra_stripes=True,
                        show_header=True,
                        cursor_type="none",
                    )
                    yield Static("STALENESS (TOP 5)", classes="section-title")
                    yield DataTable(
                        id="stale_table",
                        zebra_stripes=True,
                        show_header=True,
                        cursor_type="none",
                    )
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_right_panel()
        self._rebuild_tree_lazy()
        self.query_one("#dep_tree", Tree).focus()

    def _header_text(self) -> str:
        n = len(flatten_tree(self._view_root))
        mode = _SORT_MODES[self._sort_index % len(_SORT_MODES)]
        return (
            f"DEPSPY  ◈  {self.project_path}  ◈  {n} nodes  "
            f"[dim]/ filter  s sort({mode})  i detail  e export  x extras  ? help[/]"
        )

    def _refresh_right_panel(self) -> None:
        r = self.scan_report
        nodes = flatten_tree(self._view_root)
        self.query_one("#title", Static).update(self._header_text())
        heading = self.query_one("#bloat_heading", Static)
        heading.update(
            f"[accent]BLOAT SCORE[/]  [bloat]{r.score:.1f}/100[/]  {r.rating_label}",
        )
        bar = self.query_one("#bloat_bar", ProgressBar)
        bar.progress = min(100.0, float(r.score))
        self._fill_summary_table(nodes)
        self._fill_breakdown_table(r)
        self._fill_offenders_table(r)
        self._fill_stale_table(nodes)

    def _rebuild_tree_lazy(self) -> None:
        t = self.query_one("#dep_tree", Tree)
        t.clear()
        root = t.root
        label = f"{self._view_root.name} {self._view_root.version}".strip()
        root.set_label(label)
        root.data = self._view_root
        root.expand()
        for ch in self._view_root.children:
            self._add_lazy_branch(root, ch)

    def _add_lazy_branch(self, parent, node: DepNode) -> None:
        icon = "★ " if node.is_direct else ""
        status = "✓"
        if node.vuln_count:
            status = "☠"
        elif node.days_since_update > 730 or node.is_outdated:
            status = "⚠"
        label = f"{icon}{node.name} {node.version} {status}"
        has_kids = bool(node.children)
        branch = parent.add(label, data=node, expand=False)
        branch.allow_expand = has_kids
        if not has_kids:
            branch.expand()

    @on(Tree.NodeExpanded, "#dep_tree")
    def _lazy_expand(self, event: Tree.NodeExpanded) -> None:
        tnode = event.node
        dep = tnode.data
        if not isinstance(dep, DepNode) or not dep.children:
            return
        if len(tnode.children) > 0:
            return
        for ch in dep.children:
            self._add_lazy_branch(tnode, ch)

    def _sort_key(self, n: DepNode, mode: str) -> tuple:
        if mode == "vuln":
            return (-n.vuln_count, n.name.lower())
        if mode == "stale":
            return (-n.days_since_update, n.name.lower())
        if mode == "size":
            return (-n.size_bytes, n.name.lower())
        return (n.name.lower(),)

    def _apply_sort_to(self, n: DepNode, mode: str) -> None:
        n.children.sort(key=lambda x: self._sort_key(x, mode))
        for c in n.children:
            self._apply_sort_to(c, mode)

    def _fill_summary_table(self, nodes: list[DepNode]) -> None:
        tbl = self.query_one("#summary_table", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Metric", "Value")
        root = Path(self.project_path)
        direct = find_direct_deps(root)
        pkgs = [n for n in nodes if n.version and not n.version.startswith("(")]
        total_mb = sum(n.size_bytes for n in pkgs) / (1024 * 1024)
        vulns = sum(n.vuln_count for n in pkgs)
        stale = sum(1 for n in pkgs if n.days_since_update > 730)
        depths = [n.depth for n in pkgs]
        max_depth = max(depths) if depths else 0
        direct_nodes = sum(1 for n in pkgs if n.is_direct)
        transitive = max(0, len(pkgs) - direct_nodes)
        rows = [
            ("Nodes (total)", str(len(nodes))),
            ("Packages (with version)", str(len(pkgs))),
            ("Direct deps (manifest)", str(len(direct))),
            ("Direct (resolved nodes)", str(direct_nodes)),
            ("Transitive (approx.)", str(transitive)),
            ("Total size (sum)", f"{total_mb:.1f} MB"),
            ("Vulnerabilities (OSV)", str(vulns)),
            ("Stale (2y+)", str(stale)),
            ("Max depth", str(max_depth)),
        ]
        for metric, value in rows:
            tbl.add_row(metric, value)

    def _fill_breakdown_table(self, report: BloatReport) -> None:
        tbl = self.query_one("#breakdown_table", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Signal", "Mix (norm)", "Weight")
        weights = {
            "total_size_mb": 0.25,
            "dep_count": 0.20,
            "avg_staleness_years": 0.20,
            "vuln_count": 0.25,
            "depth": 0.10,
        }
        for key, frac in report.breakdown.items():
            label = _SIGNAL_LABELS.get(key, key)
            w = weights.get(key, 0.0)
            tbl.add_row(label, _spark_bar(frac), f"{w * 100:.0f}%")

    def _fill_offenders_table(self, report: BloatReport) -> None:
        tbl = self.query_one("#offenders_table", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("#", "Package", "Heuristic")
        for i, (name, score, _kind) in enumerate(report.top_offenders, start=1):
            tbl.add_row(str(i), name, f"{score:.1f}")

    def _fill_stale_table(self, nodes: list[DepNode]) -> None:
        tbl = self.query_one("#stale_table", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Package", "Days idle", "5y scale")
        pkgs = [n for n in nodes if n.version and not n.version.startswith("(")]
        ranked = sorted(pkgs, key=lambda n: n.days_since_update, reverse=True)[:5]
        five_y = 5 * 365
        for n in ranked:
            frac = min(1.0, n.days_since_update / five_y) if five_y else 0.0
            tbl.add_row(n.name, str(n.days_since_update), _spark_bar(frac, width=10))

    @on(Input.Submitted, "#tree_filter")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        needle = event.value.strip()
        if not needle:
            self._view_root = self._full_root
        else:
            self._view_root = filter_dep_tree(self._full_root, needle)
        mode = _SORT_MODES[self._sort_index % len(_SORT_MODES)]
        self._apply_sort_to(self._view_root, mode)
        self._rebuild_tree_lazy()
        self._refresh_right_panel()
        self.query_one("#dep_tree", Tree).focus()

    def action_focus_filter(self) -> None:
        self.query_one("#tree_filter", Input).focus()

    def action_cycle_sort(self) -> None:
        self._sort_index = (self._sort_index + 1) % len(_SORT_MODES)
        mode = _SORT_MODES[self._sort_index]
        self._apply_sort_to(self._view_root, mode)
        self._rebuild_tree_lazy()
        self._refresh_right_panel()
        self.app.notify(f"Sort: {mode}", title="depspy")

    def action_export_json(self) -> None:
        out = Path(self.project_path) / "depspy-export.json"
        payload = build_export_dict(Path(self.project_path), self._full_root, self.scan_report)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.app.notify(f"Wrote {out.name}", title="depspy export")

    def action_toggle_extras(self) -> None:
        if not self.extras_only:
            self.app.notify("No optional-only packages detected in pyproject.", title="depspy")
            return
        self._extras_collapsed = not self._extras_collapsed
        t = self.query_one("#dep_tree", Tree)
        for node in self._walk_tree_nodes(t.root):
            dep = node.data
            if isinstance(dep, DepNode) and dep.name in self.extras_only:
                if self._extras_collapsed:
                    node.collapse()
                else:
                    node.expand()
        state = "collapsed" if self._extras_collapsed else "expanded"
        self.app.notify(f"Optional-only branches {state}.", title="depspy")

    @staticmethod
    def _walk_tree_nodes(root):
        stack = [root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(n.children)

    def action_open_detail(self) -> None:
        t = self.query_one("#dep_tree", Tree)
        cur = t.cursor_node
        if cur is None or cur.data is None:
            self.app.notify("Select a package node first.", title="depspy")
            return
        dep = cur.data
        if not isinstance(dep, DepNode):
            return
        if not dep.version or dep.version.startswith("("):
            self.app.notify("Nothing to inspect for this node.", title="depspy")
            return
        self.app.push_screen(
            DetailScreen(dep, self.reverse_map, self.project_path),
        )

    def action_quit(self) -> None:
        self.app.exit()

    def action_help(self) -> None:
        self.app.notify(
            "[dim]/[/] filter  [dim]s[/] sort  [dim]i[/] inspect  [dim]e[/] export  "
            "[dim]x[/] extras  [dim]q[/] quit",
            title="depspy",
        )
