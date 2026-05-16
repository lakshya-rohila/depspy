"""Full-screen scan progress — retro phosphor deck with centered DEPSPY logo."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from textual import on
from textual.binding import Binding
from textual.containers import Center, CenterMiddle, Vertical
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import Footer, ProgressBar, Static
from textual.worker import Worker, WorkerState

from depspy.core.resolver import optional_only_package_names, reverse_dependents
from depspy.scan_pipeline import run_scan_blocking
from depspy.screens.loading_anim import rain_markup
from depspy.screens.loading_art import DEPSPY_LOGO_MARKUP


class LoadingScreen(Screen[None]):
    """Runs resolver + scanner + scorer in a worker thread; deck aesthetics."""

    BINDINGS = [Binding("escape", "app.quit", "Quit", show=True)]

    COMPONENT_CLASSES: ClassVar[set[str]] = {"accent"}

    def __init__(self) -> None:
        super().__init__(id="loading_screen")

    def compose(self):
        with Vertical(id="loading_body"):
            with CenterMiddle(id="loading_center"):
                with Vertical(id="loading_panel"):
                    yield Static(
                        rain_markup(0),
                        id="loading_anim",
                        markup=True,
                        classes="loading-anim",
                    )
                    yield Static(DEPSPY_LOGO_MARKUP, id="loading_logo", markup=True)
                    yield Static(
                        "[#00ff9d]▶[/] [italic]Calibrating sensors…[/]",
                        id="loading_stage",
                        markup=True,
                        classes="loading-stage",
                    )
                    with Center():
                        yield ProgressBar(
                            total=100,
                            show_eta=False,
                            show_percentage=True,
                            id="loading_bar",
                        )
                    yield Static(
                        "[dim]Securing channel · PyPI · OSV[/]",
                        id="loading_sub",
                        markup=True,
                        classes="loading-sub",
                    )
                    yield Static(
                        "[dim]Esc[/] abort   ·   [dim]network scan may take a minute[/]",
                        id="loading_hint",
                        markup=True,
                        classes="loading-hint",
                    )
        yield Footer()

    def on_unmount(self) -> None:
        if getattr(self, "_anim_timer", None) is not None:
            self._anim_timer.stop()
            self._anim_timer = None

    def _tick_anim(self) -> None:
        self._anim_frame = (getattr(self, "_anim_frame", 0) + 1) % 24
        try:
            line = self.query_one("#loading_anim", Static)
        except NoMatches:
            return
        line.update(rain_markup(self._anim_frame))

    def on_mount(self) -> None:
        self._anim_frame = 0
        self._anim_timer = self.set_interval(0.11, self._tick_anim)
        self.run_worker(
            self._blocking_scan,
            thread=True,
            exclusive=True,
            name="depspy_scan",
        )

    def _blocking_scan(self) -> object:
        from depspy.app import DepSpyApp

        app = self.app
        if not isinstance(app, DepSpyApp):
            raise RuntimeError("LoadingScreen requires DepSpyApp")
        path = Path(app.project_path)

        def on_stage(msg: str, frac: float) -> None:
            def bump() -> None:
                self.query_one("#loading_stage", Static).update(f"[#00ff9d]▶[/] {msg}")
                self.query_one("#loading_bar", ProgressBar).progress = min(100.0, frac * 100.0)

            app.call_from_thread(bump)

        return run_scan_blocking(
            path,
            package=app.scan_package,
            env=app.scan_env,
            offline=app.scan_offline,
            no_vulns=app.scan_no_vulns,
            on_stage=on_stage,
        )

    @on(Worker.StateChanged)
    def scan_worker_finished(self, event: Worker.StateChanged) -> None:
        wn = getattr(event.worker, "node", None)
        if wn is not None and wn is not self:
            return
        if event.worker.name != "depspy_scan":
            return
        if event.worker.state == WorkerState.ERROR:
            err = event.worker.error
            self.app.notify(f"Scan failed: {err}", severity="error", timeout=10)
            self.app.exit(return_code=1)
            return
        if event.worker.state != WorkerState.SUCCESS:
            return
        result = event.worker.result
        if not isinstance(result, tuple) or len(result) != 2:
            return
        tree, report = result
        from depspy.app import DepSpyApp
        from depspy.screens.main_screen import MainScreen

        app = self.app
        assert isinstance(app, DepSpyApp)
        app.dep_root = tree
        app.scan_report = report
        rev = reverse_dependents(tree)
        extras = optional_only_package_names(Path(app.project_path))
        app.switch_screen(
            MainScreen(tree, report, app.project_path, reverse_map=rev, extras_only=extras),
        )
