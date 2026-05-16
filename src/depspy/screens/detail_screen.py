"""Package deep-dive (metadata, reverse deps, upgrade hint, CVEs, chain)."""

from __future__ import annotations

from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Static

from depspy.core.resolver import DepNode


def _chain_labels(node: DepNode) -> list[str]:
    parts: list[DepNode] = []
    cur: DepNode | None = node
    while cur is not None:
        parts.append(cur)
        cur = cur.parent
    lines: list[str] = []
    for i, n in enumerate(reversed(parts)):
        indent = "  " * i
        ver = f" {n.version}" if n.version else ""
        lines.append(f"{indent}{n.name}{ver}")
    return lines


class DetailScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape", "dismiss", "Back", show=True),
        Binding("q", "dismiss", "Back", show=True),
    ]

    def __init__(
        self,
        node: DepNode,
        reverse_map: dict[str, frozenset[str]],
        project_path: str,
    ) -> None:
        super().__init__(id="detail_screen")
        self.node = node
        self.reverse_map = reverse_map
        self.project_path = project_path

    def compose(self):
        title = f"{self.node.name}  {self.node.version}".strip()
        yield Static(f"PACKAGE  {title}", id="detail_title")
        with Horizontal(id="detail_body"):
            with VerticalScroll(id="detail_left"):
                yield Static("", id="detail_meta", markup=True)
                yield Static("[accent]REVERSE DEPS[/]", classes="section-title")
                yield Static("", id="detail_reverse", markup=True)
                yield Static("[accent]UPGRADE[/]", classes="section-title")
                yield Static("", id="detail_upgrade", markup=True)
            with Vertical(id="detail_right"):
                yield Static("[accent]CHAIN FROM ROOT[/]", classes="section-title")
                yield Static("", id="detail_chain", markup=True)
                yield Static("[accent]CVE / OSV[/]", classes="section-title")
                yield DataTable(
                    id="detail_vulns",
                    zebra_stripes=True,
                    show_header=True,
                    cursor_type="none",
                )
        yield Footer()

    def on_mount(self) -> None:
        n = self.node
        mb = n.size_bytes / (1024 * 1024)
        meta_lines = [
            f"[accent]Version[/]  {n.version}",
            f"[accent]Latest[/]   {n.latest_version or '—'}",
            f"[accent]Size[/]     {mb:.2f} MB",
            f"[accent]Stale[/]    {n.days_since_update} days since PyPI release activity",
            f"[accent]Direct[/]   {'yes ★' if n.is_direct else 'no'}",
            f"[accent]Bloat Δ[/]  {n.bloat_contribution:.2f}",
        ]
        self.query_one("#detail_meta", Static).update("\n".join(meta_lines))

        parents = sorted(self.reverse_map.get(n.name, frozenset()))
        if parents:
            rev_txt = "\n".join(f"• {p}" for p in parents)
        else:
            rev_txt = "[dim]No other installed packages declare this dependency.[/]"
        self.query_one("#detail_reverse", Static).update(rev_txt)

        if n.latest_version and n.version and n.latest_version != n.version:
            cmd = f"pip install {n.name}=={n.latest_version}"
            self.query_one("#detail_upgrade", Static).update(
                f"[bloat]{cmd}[/]\n[dim]Run in your project venv.[/]",
            )
        else:
            self.query_one("#detail_upgrade", Static).update(
                "[dim]Already at latest (or unknown).[/]",
            )

        chain = "\n".join(_chain_labels(n))
        self.query_one("#detail_chain", Static).update(chain)

        tbl = self.query_one("#detail_vulns", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("ID", "Severity", "Fixed in", "Summary")
        if not n.vulnerabilities:
            tbl.add_row("—", "—", "—", "No OSV advisories for this version")
        else:
            for v in n.vulnerabilities:
                desc = (v.description[:80] + "…") if len(v.description) > 80 else v.description
                tbl.add_row(v.id, v.severity, v.fixed_in or "—", desc)

    def action_dismiss(self) -> None:
        self.dismiss()
