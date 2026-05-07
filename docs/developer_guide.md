# Developer Guide

## Module Structure

The codebase is split into the following main areas:

- `src/core/` for paths, bootstrap, platform selection, and command execution
- `src/collectors/` for sensor orchestration and fallback discovery
- `src/parsers/` for JSON, CSV, and log loading plus validation
- `src/analysis/` for correlation, anomaly detection, scoring, and orchestration
- `src/reporting/` for text, JSON, and alert output
- `src/utils/` for console, logging, and safe-exit helpers

## Code Standard

The project uses a straightforward Python style:

- snake_case for functions and variables
- docstrings on public functions
- pathlib for path handling
- read-only behavior only
- no shell-based command execution unless explicitly intended and controlled

## Risk Rules

Risk rules are centralized in `src/analysis/risk_rules.py`. The module defines
the four risk levels and the approved finding logic so risk classification
stays consistent across the analysis pipeline.

## Testing

Run the full Python test suite with:

```bash
python -m pytest
```

Run syntax checks with:

```bash
python -m compileall app.py src tests
```

## Definition of Done

A change is ready when:

- the code compiles
- tests pass
- documentation matches the implemented behavior
- no runtime artifacts are committed by mistake
- the read-only design remains intact
