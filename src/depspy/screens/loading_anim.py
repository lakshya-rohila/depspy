"""Matrix-style rain animation for the splash (original frames, not copied from external art)."""

from __future__ import annotations

# Glyphs suggest digital rain; palette matches the phosphor deck.
_GLYPHS = "·.:;+=*$#@01"
_DIM = "#3d4a63"
_BRIGHT = "#00ff9d"
_PURPLE = "#7b61ff"


def rain_markup(frame: int, width: int = 72) -> str:
    """Return Rich markup for one looping animation frame (single terminal row)."""
    n = len(_GLYPHS)
    parts: list[str] = []
    for i in range(width):
        idx = (i * 3 + frame * 2) % n
        g = _GLYPHS[idx]
        drift = (i + frame * 5) % 23
        if drift < 5:
            parts.append(f"[{_BRIGHT}]{g}[/]")
        elif drift < 8:
            parts.append(f"[{_PURPLE}]{g}[/]")
        else:
            parts.append(f"[{_DIM}]{g}[/]")
    return "".join(parts)
