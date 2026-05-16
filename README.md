# depspy

Dependency Detective — a terminal tool that visualizes Python dependency trees, staleness, vulnerabilities (OSV), and a bloat score.

## Install (from source)

```bash
pip install -e ".[dev]"
depspy --help
```

## Usage

```bash
depspy              # analyze current directory / environment
depspy scan .       # explicit path
depspy scan --env   # entire active environment
depspy clear-cache
depspy export --format json
```

See `depspy-master-prompt.md` for the full product specification.

## Requirements

- Python 3.10+
# depspy
