# CI/CD

This project uses a small set of GitHub Actions workflows to keep the
application predictable and safe to maintain.

## Workflows

### `verify-scripts.yml`

This workflow checks that the repository layout matches the expected project
structure and that the main scripts still parse cleanly.

It verifies:
- key project files and directories exist
- Python sources compile with `py_compile`
- the Bash sensor parses with `bash -n`
- the PowerShell sensor can be parsed when `pwsh` is available

### `python-tests.yml`

This workflow installs the project dependencies, runs the full Python test
suite, and exercises the application in test mode.

It verifies:
- dependencies can be installed from `requirements.txt`
- `pytest` still passes
- `python app.py --test --no-bootstrap` completes successfully
- the expected report and alert files are generated in test mode

### `security-checks.yml`

This workflow performs lightweight guardrail checks that are easy to maintain.

It verifies:
- obvious secret-like strings are not introduced into source code
- runtime output is not tracked in git
- the PowerShell sensor uses `Export-Csv -NoTypeInformation`
- the Python command runner does not use `shell=True`

## Why these checks exist

The workflows are intentionally simple so they can be understood and updated
without special tooling. Together they cover repository structure, syntax,
tests, and a few high-value security checks before changes are merged.
