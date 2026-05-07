# Usage Guide

## Application Entry Point

Run the orchestrator with:

```bash
python app.py
```

The application shows a splashscreen, asks for the platform when needed, runs
bootstrap checks, starts collection or fallback handling, and then writes the
reports.

## Test Mode

Test mode is the safest way to validate the pipeline end-to-end:

```bash
python app.py --test
python app.py --mode test
```

In test mode the tool uses mock data and simulated logs only. These commands
run the full Python pipeline, not the Linux or Windows collectors directly.

If you want to test the sensors separately, run them directly:

```bash
bash bash/linux_identity_audit.sh --mode test
powershell -NoProfile -ExecutionPolicy Bypass -File powershell/windows_identity_audit.ps1 -Mode Test
```

The sensor scripts may produce little or no terminal output because they write
results to `data/collected/` and `logs/`. Confirm success by checking exit code
`0` and validating the generated files.

The application-level `--test` flow exercises the full Python pipeline with
mockdata and does not run the Linux or Windows collectors directly. The
component sensors can still be tested separately with their own commands when
you want to validate the Bash or PowerShell layer in isolation.

Validation examples:

```bash
python -m json.tool data/collected/linux_identity.json
python -m json.tool data/collected/linux_policy.json
Import-Csv data/collected/windows_identity.csv
Import-Csv data/collected/windows_events.csv
Import-Csv data/collected/windows_policy.csv
```

## Production Mode

Production mode is selected with:

```bash
python app.py --mode linux
python app.py --mode windows
```

The chosen platform determines which sensor runs:

- Linux mode uses the Bash sensor
- Windows mode uses the PowerShell sensor

Production runs can also be bounded with CLI options so very large logs do not
need to be scanned in one pass:

```bash
python app.py --mode linux --linux-log-hours 12 --linux-max-events 500
python app.py --mode windows --windows-log-hours 12 --windows-max-events 500
```

Interactive production mode prompts for the same values and falls back to the
safe defaults of 24 hours and 1000 events or lines when Enter is pressed.

## Platform Choice

When no explicit mode is passed, the application prompts for Linux, Windows, or
test mode. This keeps the runtime explicit and makes it clear which evidence
source is expected.

When Linux or Windows is selected interactively, the app also asks how many
hours of logs to analyze and how many events or lines to include. If older
logs are needed, export them manually and place them in:

- `data/incoming/`
- `logdata/linux/`
- `logdata/windows/`

## Fallback and Manual Evidence

If the primary collector does not produce usable output, the fallback collector
searches approved locations such as:

- `data/incoming/`
- `logdata/linux/`
- `logdata/windows/`

The fallback flow is read-only and only uses existing files.

## Safe Exit

If no usable data exists, the application exits safely instead of crashing.
This is intentional so the tool can report that evidence is missing without
producing a misleading analysis result.
