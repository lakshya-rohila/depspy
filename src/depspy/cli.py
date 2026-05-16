from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

from depspy import __version__
from depspy.core import cache
from depspy.core.resolver import DepNode
from depspy.core.scorer import BloatReport
from depspy.export_util import build_export_dict
from depspy.scan_pipeline import run_scan_async

_SUBCOMMANDS = frozenset({"scan", "clear-cache", "export", "version"})

cli = typer.Typer(
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()


def main() -> None:
    """Console entry: ``depspy`` defaults to ``depspy scan`` (bare ``depspy`` = scan cwd)."""
    argv = sys.argv[1:]
    if not argv:
        sys.argv = [sys.argv[0], "scan"]
    elif argv[0] == "--version":
        sys.argv = [sys.argv[0], "version"]
    elif argv[0] not in _SUBCOMMANDS and argv[0] not in ("-h", "--help"):
        sys.argv = [sys.argv[0], "scan", *argv]
    cli()


def get_color_support() -> str:
    if "COLORTERM" in os.environ and os.environ["COLORTERM"] in ("truecolor", "24bit"):
        return "truecolor"
    term = os.environ.get("TERM", "")
    if "256color" in term:
        return "256"
    if sys.platform == "win32":
        if "WT_SESSION" in os.environ:
            return "truecolor"
        return "basic"
    return "basic"


def _use_textual() -> bool:
    if os.environ.get("DEPSPY_FORCE_RICH"):
        return False
    if sys.platform == "win32" and "WT_SESSION" not in os.environ:
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()


def _splash() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]depspy[/] — Dependency Detective",
            border_style="cyan",
        )
    )


@cli.callback()
def main_callback() -> None:
    """depspy — analyze Python dependencies in the terminal."""


@cli.command("scan")
def scan_cmd(
    path: Path | None = typer.Argument(None, exists=True, file_okay=False, dir_okay=True),
    package: str | None = typer.Option(
        None,
        "--package",
        help="Analyze a single installed package by name.",
    ),
    env: bool = typer.Option(
        False,
        "--env",
        help="Analyze entire current environment as a flat tree.",
    ),
    no_vulns: bool = typer.Option(False, "--no-vulns", help="Skip OSV vulnerability lookups."),
    depth: int | None = typer.Option(None, "--depth", help="Max tree depth (reserved)."),
    theme: str | None = typer.Option(None, "--theme", help="Theme hint (reserved for Textual)."),
    offline: bool = typer.Option(False, "--offline", help="Use cache only; no network."),
) -> None:
    """Scan a project directory, a package, or the active environment."""
    del depth, theme  # reserved for parity with spec
    target = path.resolve() if path else Path.cwd().resolve()

    if _use_textual():
        from depspy.app import run_app

        try:
            run_app(
                str(target),
                package=package,
                env=env,
                offline=offline,
                no_vulns=no_vulns,
            )
        except KeyboardInterrupt:
            console.print("[yellow]Interrupted.[/]")
            raise typer.Exit(130) from None
        return

    async def run_scan() -> tuple[DepNode, BloatReport]:
        return await run_scan_async(
            target,
            package=package,
            env=env,
            offline=offline,
            no_vulns=no_vulns,
        )

    _splash()
    try:
        tree, report = asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted.[/]")
        raise typer.Exit(130) from None

    _print_rich_tree(tree, report)


def _print_rich_tree(tree: DepNode, report: BloatReport) -> None:
    console.print(f"\n[bold]Bloat:[/] {report.score:.1f}/100  [bold]{report.rating_label}[/]\n")
    t = Tree(f"[bold]{tree.name}[/] [dim]{tree.version}[/]")

    def add_nodes(parent: Tree, node: DepNode) -> None:
        label = f"{node.name} [cyan]{node.version}[/]"
        if node.vuln_count:
            label += f" [red]☠ {node.vuln_count} vulns[/]"
        if node.is_outdated:
            label += f" [yellow]↑ latest {node.latest_version}[/]"
        branch = parent.add(label)
        for ch in node.children:
            add_nodes(branch, ch)

    for ch in tree.children:
        add_nodes(t, ch)
    console.print(t)


@cli.command("clear-cache")
def clear_cache_cmd() -> None:
    """Remove cached PyPI/OSV responses."""
    n = cache.clear(older_than_hours=None)
    console.print(f"[green]Removed {n} cache file(s).[/]")


@cli.command("export")
def export_cmd(
    path: Path | None = typer.Argument(None, exists=True, file_okay=False, dir_okay=True),
    fmt: str = typer.Option("json", "--format", help="json or csv"),
    output: Path | None = typer.Option(
        None,
        "-o",
        "--output",
        help="Write to file instead of stdout.",
    ),
    no_vulns: bool = typer.Option(False, "--no-vulns"),
    offline: bool = typer.Option(False, "--offline"),
) -> None:
    """Export scan results without opening the TUI."""
    target = path.resolve() if path else Path.cwd().resolve()

    async def run_export() -> dict[str, Any]:
        tree, report = await run_scan_async(
            target,
            package=None,
            env=False,
            offline=offline,
            no_vulns=no_vulns,
        )
        return build_export_dict(target, tree, report)

    payload = asyncio.run(run_export())
    text = _format_export(payload, fmt)
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]Wrote {output}[/]")
    else:
        print(text)


def _format_export(payload: dict[str, Any], fmt: str) -> str:
    if fmt.lower() == "json":
        return json.dumps(payload, indent=2)
    if fmt.lower() == "csv":
        import csv
        from io import StringIO

        buf = StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "name",
                "version",
                "latest_version",
                "is_direct",
                "size_bytes",
                "days_since_update",
                "depth",
            ]
        )
        for p in payload.get("packages", []):
            w.writerow(
                [
                    p.get("name"),
                    p.get("version"),
                    p.get("latest_version"),
                    p.get("is_direct"),
                    p.get("size_bytes"),
                    p.get("days_since_update"),
                    p.get("depth"),
                ]
            )
        return buf.getvalue()
    raise typer.BadParameter("format must be json or csv")


@cli.command("version")
def version_cmd() -> None:
    """Show depspy version."""
    console.print(__version__)


if __name__ == "__main__":
    main()
