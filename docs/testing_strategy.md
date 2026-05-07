# Testing Strategy

## Unit Tests

Unit tests validate small pieces of logic such as:

- parsers
- validators
- risk rules
- scoring
- command execution wrappers
- console and safe-exit helpers

## Integration Tests

Integration tests check how the modules work together. They verify:

- the fallback flow
- the test-mode pipeline
- the production-mode pipeline
- report generation

## Mock Data

Mock data is used to keep test mode safe and deterministic. It allows the
pipeline to run end-to-end without touching live logs or real system exports.

## Test Mode

Test mode is the preferred way to verify the full pipeline locally. It should
produce reports and alerts from controlled evidence.

`python app.py --test` and `python app.py --mode test` run the full Python
pipeline with mock data. They do not invoke the Linux or Windows collectors
directly.

The Bash and PowerShell sensors can also be tested on their own:

- `bash bash/linux_identity_audit.sh --mode test`
- `powershell -NoProfile -ExecutionPolicy Bypass -File powershell/windows_identity_audit.ps1 -Mode Test`

In production-style manual checks, the sensors can be bounded explicitly to
avoid scanning large logs in one run:

- `bash bash/linux_identity_audit.sh --mode production --log-hours 12 --max-events 500`
- `powershell -NoProfile -ExecutionPolicy Bypass -File powershell/windows_identity_audit.ps1 -Mode Production -LogHours 12 -MaxEvents 500`

These sensor runs may write most of their evidence to `data/collected/` and
`logs/`, so the terminal output can be short. Successful runs should be
confirmed by exit code `0` and by validating the generated output files.

Suggested file checks:

- `python -m json.tool data/collected/linux_identity.json`
- `python -m json.tool data/collected/linux_policy.json`
- `Import-Csv data/collected/windows_identity.csv`
- `Import-Csv data/collected/windows_events.csv`
- `Import-Csv data/collected/windows_policy.csv`

## Manual Test Cases

Useful manual checks include:

- `python app.py --test`
- `python app.py --mode test`
- `python app.py --mode linux`
- `python app.py --mode windows`

These checks help confirm that the orchestrator, collectors, fallback logic,
and reporting flow still behave as expected.

## QA Summary

Current release-candidate verification confirms:

- the Python test suite passes
- the project compiles with `python -m compileall app.py src tests`
- the Bash sensor parses with `bash -n`
- the test pipeline generates reports and alerts in test mode
- the system remains read-only and safe-exit behavior is preserved

Known limitations remain the same as documented elsewhere in the project:

- missing evidence can still trigger fallback or safe exit
- report quality depends on the source data and baselines provided
- sensor scripts write evidence to files rather than producing verbose terminal
  output
