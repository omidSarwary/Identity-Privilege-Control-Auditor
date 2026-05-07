# CI/CD

This project uses GitHub Actions to validate structure, syntax, tests, and a
small set of security guardrails.

## `verify-scripts.yml`

This workflow checks the repository layout and script syntax.

It verifies:
- required project files and folders exist
- Python files compile with `py_compile`
- the Bash sensor parses with `bash -n`
- the PowerShell sensor can be parsed when `pwsh` is available

## `python-tests.yml`

This workflow installs the project dependencies, runs the Python test suite,
and executes the application in test mode.

It verifies:
- dependencies install from `requirements.txt`
- `pytest` passes
- `python app.py --test --no-bootstrap` completes successfully
- the expected report and alert outputs are created

## `security-checks.yml`

This workflow performs lightweight security checks.

It verifies:
- obvious secret-like strings are not introduced into source code
- runtime output is not tracked in git
- the PowerShell sensor uses `Export-Csv` together with `-NoTypeInformation`
- the Python command runner does not use `shell=True`

## Why the Workflows Are Small

The workflows are intentionally simple so they remain easy to maintain and easy
to explain in a review or examination setting.
