"""Retro terminal branding for the loading screen."""

# CRT / phosphor deck — unicode frame + block letters
_LOGO_LINES: list[str] = [
    "[dim]╭────────────────────────────────────────────────────────────────────────╮[/dim]",
    "[dim]│[/dim]                                                                      [dim]│[/dim]",
    (
        "[dim]│[/dim]   [bold #00ff9d]██████╗ ███████╗██████╗ ███████╗██████╗ ██╗   ██╗[/bold #00ff9d]                 "
        "[dim]│[/dim]"
    ),
    (
        "[dim]│[/dim]   [bold #00ff9d]██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝[/bold #00ff9d]                 "
        "[dim]│[/dim]"
    ),
    (
        "[dim]│[/dim]   [bold #7b61ff]██║  ██║█████╗  ██████╔╝███████╗██████╔╝ ╚████╔╝[/bold #7b61ff]                  "
        "[dim]│[/dim]"
    ),
    (
        "[dim]│[/dim]   [bold #7b61ff]██║  ██║██╔══╝  ██╔═══╝ ╚════██║██╔═══╝   ╚██╔╝[/bold #7b61ff]                   "
        "[dim]│[/dim]"
    ),
    (
        "[dim]│[/dim]   [bold #00ff9d]██████╔╝███████╗██║     ███████║██║        ██║[/bold #00ff9d]                    "
        "[dim]│[/dim]"
    ),
    (
        "[dim]│[/dim]   [#4a5568]╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝        ╚═╝[/#4a5568]                    "
        "[dim]│[/dim]"
    ),
    "[dim]│[/dim]                                                                      [dim]│[/dim]",
    (
        "[dim]│[/dim]      [italic #88ffc2]▸  D E P E N D E N C Y   D E T E C T I V E  ◂[/italic #88ffc2]       "
        "[dim]│[/dim]"
    ),
    "[dim]│[/dim]                                                                      [dim]│[/dim]",
    "[dim]╰────────────────────────────────────────────────────────────────────────╯[/dim]",
]
DEPSPY_LOGO_MARKUP = "\n".join(_LOGO_LINES)
