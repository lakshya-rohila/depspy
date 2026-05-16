# 🕵️ DEPSPY — MASTER BUILD PROMPT
### The Complete Engineering Brief for a Cross-Platform, Publishable Python TUI Tool

---

## MISSION

Build `depspy` — a terminal-based Dependency Detective tool that any developer can install
with `pip install depspy` on macOS, Linux, or Windows. It analyzes Python projects and
produces a stunning, interactive TUI (Terminal User Interface) showing the full dependency
tree, security vulnerabilities, package staleness, and a "bloat score" — turning
pip install anxiety into actionable data.

---

## TECH STACK (NON-NEGOTIABLE)

| Layer | Choice | Why |
|---|---|---|
| TUI Framework | **Textual** (by Textualize) | Cross-platform, rich widgets, CSS theming, mouse support |
| Dependency parsing | **pip**, **importlib.metadata**, **packaging** | stdlib + standard pip ecosystem |
| Security data | **PyPI JSON API** + **OSV.dev API** | Free, no auth required |
| Tree rendering | **Rich** (via Textual) | Built-in, gorgeous tree widgets |
| HTTP | **httpx** (async) | Fast, async-native, no extra deps |
| Packaging | **pyproject.toml** + **hatchling** | Modern, PEP 517 compliant |
| CLI entry point | **typer** | Clean CLI with --help, flags, autocomplete |
| Caching | **diskcache** or flat JSON in `~/.depspy/cache/` | Avoid hammering APIs |

---

## PROJECT STRUCTURE

```
depspy/
├── pyproject.toml              ← Build config, metadata, entry points
├── README.md                   ← PyPI readme with screenshots
├── LICENSE                     ← MIT
├── src/
│   └── depspy/
│       ├── __init__.py
│       ├── __main__.py         ← Enables `python -m depspy`
│       ├── cli.py              ← Typer CLI: entry point, flags, args
│       ├── app.py              ← Textual App class (main TUI)
│       ├── screens/
│       │   ├── __init__.py
│       │   ├── main_screen.py      ← Tree + stats dashboard
│       │   ├── detail_screen.py    ← Single package deep-dive
│       │   └── help_screen.py      ← Keybindings overlay
│       ├── widgets/
│       │   ├── __init__.py
│       │   ├── dep_tree.py         ← Interactive dependency tree widget
│       │   ├── bloat_gauge.py      ← Animated bloat score bar
│       │   ├── vuln_panel.py       ← CVE/vulnerability list widget
│       │   ├── staleness_bar.py    ← Last-updated timeline widget
│       │   └── stats_footer.py     ← Bottom status bar
│       ├── core/
│       │   ├── __init__.py
│       │   ├── resolver.py         ← Walks dependency graph
│       │   ├── scanner.py          ← Calls PyPI + OSV APIs
│       │   ├── scorer.py           ← Calculates bloat score
│       │   └── cache.py            ← Local disk cache logic
│       └── themes/
│           ├── dark.tcss           ← Textual CSS: dark theme
│           └── light.tcss          ← Textual CSS: light theme
└── tests/
    ├── test_resolver.py
    ├── test_scorer.py
    └── test_scanner.py
```

---

## PHASE 1 — CORE ENGINE (`src/depspy/core/`)

### resolver.py
Build a recursive dependency walker:

```python
"""
Walk the installed package graph for a given project or environment.

Functions to implement:
- get_installed_packages() -> dict[str, PackageInfo]
  Uses importlib.metadata to list all installed packages with version,
  location on disk, install date (from file mtime), and declared dependencies.

- resolve_tree(root_package: str) -> DepNode
  Recursively builds a DepNode tree. Each node has:
    - name: str
    - version: str
    - size_bytes: int  (sum of all files in the package dir)
    - install_date: datetime
    - children: list[DepNode]
    - depth: int
    - is_direct: bool  (is it in requirements.txt / pyproject.toml?)

- find_direct_deps(project_path: Path) -> list[str]
  Reads requirements.txt, setup.cfg, pyproject.toml, setup.py (in that
  priority order) to find what the user explicitly declared.

- detect_cycles(tree: DepNode) -> list[list[str]]
  Returns list of circular dependency paths if any.

- flatten_tree(tree: DepNode) -> list[DepNode]
  Returns all nodes in BFS order for stats calculations.
"""
```

**DepNode dataclass:**
```python
@dataclass
class DepNode:
    name: str
    version: str
    size_bytes: int
    install_date: datetime | None
    children: list["DepNode"]
    depth: int
    is_direct: bool
    vuln_count: int = 0          # filled by scanner
    days_since_update: int = 0   # filled by scanner
    bloat_contribution: float = 0.0  # filled by scorer
    latest_version: str = ""     # filled by scanner
    is_outdated: bool = False
```

### scanner.py
Hit two APIs concurrently with httpx:

```python
"""
Async scanner that enriches DepNodes with live data.

PyPI JSON API:
  GET https://pypi.org/pypi/{package}/{version}/json
  Extract: latest_version, release dates, yanked status, classifiers,
           maintainer activity (last release date), download stats.

OSV.dev API (Google's Open Source Vulnerability DB):
  POST https://api.osv.dev/v1/query
  Body: {"package": {"name": pkg, "ecosystem": "PyPI"}, "version": ver}
  Extract: list of CVEs/GHSAs with severity, description, fixed_in version.

Functions:
- async scan_all(nodes: list[DepNode], on_progress: Callable) -> list[DepNode]
  Enriches all nodes concurrently (max 10 concurrent requests).
  Calls on_progress(current, total) after each batch for progress bar.

- async fetch_pypi(session, name, version) -> PyPIData | None
  Returns: latest_version, last_release_date, is_yanked, days_since_update

- async fetch_vulns(session, name, version) -> list[Vulnerability]
  Returns list of Vulnerability(id, severity, description, fixed_in)

- cache key format: f"depspy_{name}_{version}"
  TTL: 3600 seconds (1 hour) — use cache.py to check before fetching.
"""
```

### scorer.py
Calculate the "bloat score":

```python
"""
Bloat Score = weighted combination of signals, 0–100 scale.

Algorithm:
  weights = {
      "total_size_mb": 0.25,        # raw disk footprint
      "dep_count": 0.20,            # total transitive dep count
      "avg_staleness_years": 0.20,  # mean years since last update
      "vuln_count": 0.25,           # total CVEs found
      "depth": 0.10,                # max dependency depth
  }

  Each signal is normalized 0–1 against "typical" Python projects:
    - total_size_mb: 0=0MB, 1=500MB+
    - dep_count: 0=0 deps, 1=200+ deps
    - avg_staleness: 0=updated this year, 1=5+ years old
    - vuln_count: 0=none, 1=10+ vulns
    - depth: 0=depth 1, 1=depth 10+

  bloat_score = sum(normalized[signal] * weight[signal]) * 100

  Rating thresholds:
    0–20:   "✦ PRISTINE"   (green)
    21–40:  "◈ HEALTHY"    (cyan)
    41–60:  "◉ MODERATE"   (yellow)
    61–80:  "⚠ BLOATED"    (orange)
    81–100: "☠ CRITICAL"   (red)

Functions:
- calculate_bloat(nodes: list[DepNode]) -> BloatReport
  Returns BloatReport with score, rating, breakdown dict per signal,
  and top 5 worst offenders (packages contributing most to score).

- rank_by_staleness(nodes) -> list[DepNode]
  Sort by days_since_update descending.

- rank_by_size(nodes) -> list[DepNode]
  Sort by size_bytes descending.

- rank_by_vulns(nodes) -> list[DepNode]
  Sort by vuln_count descending.
"""
```

### cache.py
```python
"""
Simple file-based cache in ~/.depspy/cache/
Files: {cache_key}.json with {"expires": timestamp, "data": ...}

Functions:
- get(key: str) -> dict | None
- set(key: str, data: dict, ttl: int = 3600)
- clear(older_than_hours: int = 24)
- cache_dir() -> Path  # ~/.depspy/cache/
"""
```

---

## PHASE 2 — CLI (`src/depspy/cli.py`)

```python
"""
Build with Typer. The CLI is the entry point for the `depspy` command.

Commands:

  depspy                          ← Analyze current directory
  depspy scan [PATH]              ← Analyze specific project path
  depspy scan --package PKGNAME   ← Analyze a single installed package
  depspy scan --env               ← Analyze entire current venv/env
  depspy clear-cache              ← Wipe ~/.depspy/cache/
  depspy export --format json|csv ← Export results without TUI
  depspy --version                ← Show version

Flags for `scan`:
  --no-vulns          Skip vulnerability API calls (faster)
  --depth INT         Max tree depth to render (default: unlimited)
  --theme dark|light  Force color theme
  --offline           Use cache only, no API calls

On run:
  1. Validate path / package exists
  2. Show a startup splash (Rich panel, 1 second)
  3. Start Textual App with resolved args
"""
```

---

## PHASE 3 — TUI (`src/depspy/app.py` + screens/ + widgets/)

### Visual Design DNA
The TUI must feel like a **hacker's cockpit** — dark terminal aesthetic with neon accents,
not a boring grid of text. Think: Midnight Commander meets k9s meets a sci-fi dashboard.

Color palette (define in dark.tcss):
```
--bg:           #0d0f14    (near-black, slight blue tint)
--panel:        #13161f    (slightly lighter panels)
--border:       #1e2433    (subtle borders)
--accent:       #00d9a3    (neon mint — primary highlight)
--accent2:      #7b61ff    (violet — secondary)
--danger:       #ff4757    (red — vulns, critical)
--warn:         #ffa502    (amber — warnings, staleness)
--ok:           #2ed573    (green — safe, pristine)
--text:         #c8d3e8    (soft blue-white body text)
--muted:        #4a5568    (gray — secondary info)
--tree-indent:  #1e2433    (tree line color)
```

Typography (use Rich markup):
- Headers: UPPERCASE, letter-spaced, accent color
- Package names: bold white
- Versions: accent color
- CVE ids: danger red, monospace
- Sizes: amber, right-aligned

### app.py — Main Textual App

```python
"""
class DepSpyApp(App):
    CSS_PATH = ["themes/dark.tcss"]
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("?", "help", "Help"),
        ("t", "toggle_theme", "Theme"),
        ("e", "export", "Export"),
        ("r", "refresh", "Refresh"),
        ("f", "filter", "Filter"),
        ("s", "sort_menu", "Sort"),
        ("enter", "expand_node", "Expand"),
        ("escape", "back", "Back"),
    ]

    Lifecycle:
    1. on_mount: Show LoadingScreen with animated spinner + progress bar
       while resolver + scanner run in a background worker thread.
       Progress messages: "Reading dependencies...", "Scanning PyPI...",
       "Checking vulnerabilities...", "Calculating bloat score..."
    2. After loading: Switch to MainScreen
    3. on key events: handle navigation
"""
```

### screens/main_screen.py

```
LAYOUT (3-panel):
┌─────────────────────────────────────────────────────────────────────┐
│  DEPSPY  ◈  project-name  ◈  v1.2.3  ◈  42 packages  ◈  [theme] [?]│  ← Header
├──────────────────────────┬──────────────────────────────────────────┤
│                          │  BLOAT SCORE                             │
│   DEPENDENCY TREE        │  ████████████░░░░░░  67/100  ⚠ BLOATED  │
│                          │                                          │
│  ▼ your-project          │  QUICK STATS                             │
│    ▼ requests 2.31.0 ✓   │  Total packages    42                    │
│        urllib3 2.0.1 ✓   │  Direct deps        8                    │
│        certifi 2023 ✓    │  Transitive deps   34                    │
│        charset ✓         │  Total size       127 MB                 │
│    ▼ fastapi 0.100 ✓     │  Vulnerabilities    3 ⚠                  │
│        starlette ✓       │  Stale (2y+)        7                    │
│        pydantic ✓        │  Max depth          6                    │
│        anyio ✓           │                                          │
│    ▷ numpy 1.24 ✓        │  TOP OFFENDERS (by bloat)               │
│    ▷ pandas 2.0 ⚠ VULN   │  1. numpy      38 MB  ░░ size           │
│    ▷ boto3  ☠ 3 CVEs     │  2. boto3       3 CVEs ░░ vulns         │
│    ▷ PIL    ⚠ stale 4y   │  3. PIL         stale 4y                 │
│    ▷ click  ✓            │                                          │
│    ...                   │  VULNERABILITY SUMMARY                   │
│                          │  ● GHSA-xxxx-yyyy HIGH  requests         │
│                          │  ● CVE-2023-xxxx MED   PIL               │
├──────────────────────────┴──────────────────────────────────────────┤
│  [↑↓] Navigate  [Enter] Inspect  [S] Sort  [F] Filter  [E] Export  │  ← Footer
└─────────────────────────────────────────────────────────────────────┘
```

Tree node icons:
- `▼` expanded branch
- `▷` collapsed branch  
- `◆` leaf (no children)
- `✓` healthy (green)
- `⚠` warning: stale or minor vuln (amber)
- `☠` critical: CVE found (red)
- `★` direct dependency (accent color star)
- `↑` outdated, newer version available (cyan arrow)

### screens/detail_screen.py (press Enter on any package)

```
┌─────────────────────────────────────────────────────────────────────┐
│  ← BACK  │  PACKAGE DETAIL: requests 2.28.2                        │
├───────────────────────────┬─────────────────────────────────────────┤
│  METADATA                 │  DEPENDENCY CHAIN                       │
│  Version:   2.28.2        │                                         │
│  Latest:    2.31.0 ↑      │  your-project                           │
│  Released:  2022-12-01    │    └── requests  ← YOU ARE HERE         │
│  Size:      142 KB        │         ├── urllib3                      │
│  PyPI:      [link]        │         ├── certifi                      │
│  License:   Apache 2.0    │         └── charset-normalizer           │
│                           │                                          │
│  ACTIVITY TIMELINE        │  WHO DEPENDS ON THIS?                   │
│  2024 ████████            │  ● requests (direct)                    │
│  2023 ████                │  No other packages depend on this.      │
│  2022 ██████████          │                                          │
│  2021 ███                 │  UPGRADE COMMAND                        │
│  (last update: 547 days)  │  pip install requests==2.31.0           │
│                           │  [Copy to clipboard]                    │
│  VULNERABILITIES (0)      │                                          │
│  ✓ No known CVEs          │  BLOAT CONTRIBUTION                     │
│                           │  Size score:     ░░░░░░░░░░  LOW        │
│                           │  Staleness:      ███░░░░░░░  MED        │
│                           │  Vuln score:     ░░░░░░░░░░  NONE       │
└───────────────────────────┴─────────────────────────────────────────┘
```

### widgets/bloat_gauge.py
```python
"""
Animated gauge widget that renders as a Rich progress-bar-style display.
On mount, animates from 0 to final score over 1.5 seconds.
Changes color dynamically as the number rises (green → cyan → yellow → red).
Shows: label "BLOAT SCORE", numeric value, rating string, animated bar.
Use Textual's reactive + watch pattern to drive the animation.
"""
```

### widgets/dep_tree.py
```python
"""
Custom Textual widget wrapping Rich's Tree.
- Lazy-loads children on expand (don't render 500 nodes at once)
- Keyboard navigation: arrow keys move selection, Enter expands/opens detail
- Search/filter: type any letter to jump to that package name
- Each node rendered with icon, name, version, badge (✓/⚠/☠), size chip
- Mouse click on node → select; double-click → open detail screen
- Scrollable, handles very large trees (200+ nodes) without lag
"""
```

### widgets/staleness_bar.py
```python
"""
Horizontal sparkline/timeline widget.
Shows a sorted list of packages on Y axis, colored bar on X axis
representing how many days since last update. 
Color gradient: green (< 180 days) → yellow (180–730) → red (730+)
Shows: package name, version, "last updated N days ago" 
Sorted by staleness descending by default.
"""
```

---

## PHASE 4 — LOADING EXPERIENCE

The loading screen is critical — it's the first impression:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│                                                                     │
│              ██████╗ ███████╗██████╗ ███████╗██████╗ ██╗   ██╗     │
│              ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝     │
│              ██║  ██║█████╗  ██████╔╝███████╗██████╔╝ ╚████╔╝      │
│              ██║  ██║██╔══╝  ██╔═══╝ ╚════██║██╔═══╝   ╚██╔╝       │
│              ██████╔╝███████╗██║     ███████║██║        ██║         │
│              ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝        ╚═╝         │
│                                                                     │
│                    D E P E N D E N C Y  D E T E C T I V E          │
│                                                                     │
│         ████████████████████░░░░░░░░░░░░░░░░░  64%                 │
│                                                                     │
│              ◈  Scanning vulnerabilities via OSV.dev...             │
│                                                                     │
│                  Found 42 packages  ·  3 warnings so far            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

Loading messages (cycle through):
- "Reading your requirements..."
- "Walking the dependency graph..."  
- "Pinging PyPI for latest versions..."
- "Interrogating OSV.dev for CVEs..."
- "Calculating disk footprint..."
- "Computing bloat score..."
- "Building the tree..."
- "Polishing the terminal..."

---

## PHASE 5 — PACKAGING (`pyproject.toml`)

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "depspy"
version = "0.1.0"
description = "Dependency Detective — visualize, audit, and score your Python dependencies"
readme = "README.md"
license = { text = "MIT" }
authors = [{ name = "Your Name", email = "you@example.com" }]
requires-python = ">=3.10"
keywords = ["dependencies", "security", "tui", "audit", "cli", "devtools"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Libraries",
    "Topic :: Utilities",
]
dependencies = [
    "textual>=0.47.0",
    "rich>=13.0.0",
    "httpx>=0.25.0",
    "typer>=0.9.0",
    "packaging>=23.0",
    "diskcache>=5.6.0",
]

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio", "pytest-textual-snapshot", "mypy", "ruff"]

[project.scripts]
depspy = "depspy.cli:app"

[project.urls]
Homepage = "https://github.com/yourname/depspy"
Documentation = "https://github.com/yourname/depspy#readme"
Repository = "https://github.com/yourname/depspy"
"Bug Tracker" = "https://github.com/yourname/depspy/issues"

[tool.hatch.build.targets.wheel]
packages = ["src/depspy"]
```

---

## PHASE 6 — CROSS-PLATFORM REQUIREMENTS

Ensure every piece of code is compatible with:

| Platform | Terminal | Special notes |
|---|---|---|
| macOS | Terminal.app, iTerm2, Warp | Fully supported, best experience |
| Linux | gnome-terminal, kitty, alacritty | Fully supported |
| Windows | Windows Terminal (WT) | Use `colorama` as optional dep, test with WT |
| Windows | CMD/PowerShell (legacy) | Graceful degradation: less color, same data |
| SSH | Any remote session | Must work in headless terminals |

```python
# In app.py:
import sys
import os

def get_color_support() -> str:
    """Returns 'truecolor', '256', 'basic', or 'none'"""
    if "COLORTERM" in os.environ and os.environ["COLORTERM"] in ("truecolor", "24bit"):
        return "truecolor"
    term = os.environ.get("TERM", "")
    if "256color" in term:
        return "256"
    if sys.platform == "win32":
        # Windows Terminal supports truecolor
        if "WT_SESSION" in os.environ:
            return "truecolor"
        return "basic"
    return "basic"
```

On Windows without Windows Terminal: fall back to a simplified Rich-only output
(no Textual TUI, just a pretty Rich table + tree layout). Detect and switch automatically.

---

## PHASE 7 — EXPORT (`depspy export`)

```python
"""
Export functionality — no TUI, pure data output.

JSON export schema:
{
  "project": "my-project",
  "analyzed_at": "2024-01-15T10:30:00Z",
  "python_version": "3.11.5",
  "summary": {
    "total_packages": 42,
    "direct_deps": 8,
    "total_size_bytes": 133169152,
    "vulnerability_count": 3,
    "stale_count": 7,
    "bloat_score": 67,
    "bloat_rating": "BLOATED"
  },
  "packages": [
    {
      "name": "requests",
      "version": "2.28.2",
      "latest_version": "2.31.0",
      "is_direct": true,
      "size_bytes": 145408,
      "days_since_update": 547,
      "vulnerabilities": [],
      "dependencies": ["urllib3", "certifi", "charset-normalizer"],
      "depth": 1
    }
  ],
  "vulnerabilities": [
    {
      "package": "Pillow",
      "version": "9.0.0",
      "id": "GHSA-xxxx-yyyy-zzzz",
      "severity": "HIGH",
      "description": "...",
      "fixed_in": "9.3.0"
    }
  ]
}

CSV export: flat table with one row per package, all columns above.
"""
```

---

## PHASE 8 — TESTING

```python
"""
tests/test_resolver.py:
  - test_reads_requirements_txt()
  - test_reads_pyproject_toml()
  - test_detects_cycles()
  - test_tree_depth()
  - test_size_calculation()

tests/test_scorer.py:
  - test_pristine_score_is_low()
  - test_many_vulns_raises_score()
  - test_stale_packages_raise_score()
  - test_score_bounded_0_100()

tests/test_scanner.py (use httpx mock):
  - test_pypi_fetch_returns_latest_version()
  - test_osv_fetch_returns_vulns()
  - test_cache_prevents_double_fetch()
  - test_handles_network_timeout_gracefully()
"""
```

---

## PHASE 9 — README.md (for PyPI)

Include:
1. Animated terminal demo GIF (use `vhs` or `asciinema` to record)
2. `pip install depspy` badge + Python version badge + PyPI version badge
3. Feature list with emoji icons
4. Usage section: basic commands + flag descriptions
5. Screenshot of the main TUI
6. "How bloat score is calculated" section — builds trust
7. Contributing guide
8. "Why depspy?" section comparing to `pip-audit`, `pipdeptree`, `safety`

---

## IMPLEMENTATION ORDER

Follow this sequence for a working product at each checkpoint:

1. **[ ] Core engine first** — resolver.py with no TUI. Verify tree building works.
2. **[ ] Scanner** — hit PyPI and OSV.dev, verify data enrichment.
3. **[ ] Scorer** — verify bloat score math, tune weights against real projects.
4. **[ ] CLI skeleton** — `depspy scan` that prints a Rich tree (no Textual yet).
5. **[ ] Textual loading screen** — just the animated loader, fake data.
6. **[ ] Main TUI screen** — wire real data into the layout.
7. **[ ] Detail screen** — press Enter, see package deep-dive.
8. **[ ] Polish** — animations, keybindings, themes, edge cases.
9. **[ ] Windows fallback** — test on Windows Terminal + CMD.
10. **[ ] Export** — JSON + CSV output.
11. **[ ] Tests** — cover core logic.
12. **[ ] Build + publish** — `python -m build` → `twine upload`.

---

## QUALITY GATES (before shipping)

- [ ] Works on Python 3.10, 3.11, 3.12
- [ ] Works on macOS + Ubuntu + Windows Terminal
- [ ] `pip install depspy` from a clean venv succeeds
- [ ] Handles a project with 0 dependencies gracefully
- [ ] Handles a project with 200+ dependencies without crash or lag
- [ ] Network timeout → graceful error message, not traceback
- [ ] Ctrl+C during loading → clean exit (no broken terminal state)
- [ ] `depspy --help` shows all commands and flags clearly
- [ ] Terminal state is ALWAYS restored on exit (Textual handles this, verify)
- [ ] Cache prevents redundant API calls on re-run within 1 hour

---

## VIRAL HOOKS TO IMPLEMENT

1. **Shareable bloat score** — `depspy export --share` generates a short summary card
   (Rich renderables) designed to be screenshot-shared on Twitter/X.

2. **"Hall of shame" output** — After scan, print 3 most-bloated packages with snarky
   commentary: *"boto3 brought 47 friends to the party and 3 of them have warrants."*

3. **`--compare` flag** — `depspy scan --compare requirements.txt requirements-slim.txt`
   Shows a diff of bloat scores between two dependency sets.

4. **Badge generator** — `depspy badge` outputs a markdown badge snippet showing the
   project's current bloat score: `![Bloat Score](https://img.shields.io/badge/bloat-67-orange)`

---

*Build this in the order above. Each phase is independently testable. The goal is a tool
so useful and beautiful that developers screenshot it and share it. Make the terminal sing.*
