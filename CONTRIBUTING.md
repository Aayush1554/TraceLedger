# Contributing to TraceLedger

Issues and pull requests are welcome.

## Getting started

```bash
# From the TraceLedger repository root:
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check traceledger tests
```

## Pull requests

- Keep each pull request to one change, with a short explanation of what it does and why.
- Add or update tests for any change in behaviour.
- Run `python -m pytest` and `python -m ruff check traceledger tests` before opening the pull request; CI runs both.
- Use clear names and docstrings. Readability matters more than brevity here.

## Reporting issues

Please include the version, a minimal example that reproduces the problem, and what you expected to happen. Do not attach real personal or confidential data; use the built-in synthetic data generator to build examples.
