from __future__ import annotations

from textual.app import App
from textual.binding import Binding

from depspy.core.resolver import DepNode
from depspy.core.scorer import BloatReport
from depspy.screens.loading_screen import LoadingScreen


class DepSpyApp(App[None]):
    """Textual front-end for depspy."""

    theme = "textual-dark"
    CSS_PATH = "themes/app.tcss"
    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("question_mark", "help", "Help", show=True),
    ]

    def __init__(
        self,
        project_path: str,
        *,
        package: str | None = None,
        env: bool = False,
        offline: bool = False,
        no_vulns: bool = False,
    ) -> None:
        super().__init__()
        self.project_path = project_path
        self.scan_package = package
        self.scan_env = env
        self.scan_offline = offline
        self.scan_no_vulns = no_vulns
        self.dep_root: DepNode | None = None
        self.scan_report: BloatReport | None = None

    def on_mount(self) -> None:
        # Use push_screen — not switch_screen. switch_screen pops the stack top and
        # always calls _pop_result_callback on it; the default screen has no callback
        # (never push_screen'd), which raises IndexError on Textual 8.x.
        self.push_screen(LoadingScreen())

    def action_quit(self) -> None:
        self.exit()

    def action_help(self) -> None:
        self.notify("[q] quit  [?] help", title="depspy")


def run_app(
    project_path: str,
    *,
    package: str | None = None,
    env: bool = False,
    offline: bool = False,
    no_vulns: bool = False,
) -> None:
    DepSpyApp(
        project_path,
        package=package,
        env=env,
        offline=offline,
        no_vulns=no_vulns,
    ).run()
