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

In test mode the tool uses mock data and simulated logs only.

## Production Mode

Production mode is selected with:

```bash
python app.py --mode linux
python app.py --mode windows
```

The chosen platform determines which sensor runs:

- Linux mode uses the Bash sensor
- Windows mode uses the PowerShell sensor

## Platform Choice

When no explicit mode is passed, the application prompts for Linux, Windows, or
test mode. This keeps the runtime explicit and makes it clear which evidence
source is expected.

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
