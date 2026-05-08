# NordSec Identity & Privilege Control Auditor

NordSec Identity & Privilege Control Auditor is a read-only security auditing
tool for identity, privilege, and policy review across Linux and Windows
environments. It is designed to help security teams and students collect
evidence, correlate identity risk, and produce clear audit outputs without
changing the target system.

## Purpose

The tool complements a SIEM by focusing on structured identity and privilege
review. A SIEM is strong at collecting and correlating security telemetry, but
this project adds a focused audit workflow for:

- approved and unapproved privileged access
- disabled or inactive accounts with activity
- login patterns that suggest elevated risk
- policy deviations across Linux and Windows
- clear reports and alerts for follow-up

## What the Tool Does

The project follows a read-only pipeline:

1. collect or locate evidence
2. validate and normalize the input data
3. correlate identities, privileges, events, and policies
4. score findings by risk level
5. generate text, JSON, and alert outputs

The application can run in:

- production mode for Linux or Windows evidence flows
- test mode using mock data and simulated logs

## Read-Only First

The tool is intentionally non-remediating. It does not disable accounts, change
policies, modify services, or write back to the inspected system. All actions
are limited to reading, validating, correlating, and reporting.

## Installation

### Requirements

- Python 3.11 or newer
- Bash for the Linux sensor
- PowerShell 7+ or Windows PowerShell for the Windows sensor

### Recommended Setup

1. Clone the repository.
2. Create and activate a Python virtual environment manually.
3. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

The application checks environment and bootstrap state at startup, but it does
not create a virtual environment or install packages automatically.

## Quick Start

Run the application in test mode:

```bash
python app.py --test
```

Run the application in production mode and choose a platform:

```bash
python app.py --mode linux
python app.py --mode windows
```

You can also provide bounded log collection settings explicitly:

```bash
python app.py --mode linux --linux-log-hours 12 --linux-max-events 500
python app.py --mode windows --windows-log-hours 12 --windows-max-events 500
```

By default, production mode analyzes only the selected platform's collector
data. Evidence from the other operating system is optional and must be
explicitly included:

```bash
python app.py --mode windows --include-manual-linux
python app.py --mode linux --include-manual-windows
python app.py --mode windows --no-manual-cross-evidence
```

## Production Mode

Production mode uses the platform-specific sensor and the fallback search
logic:

- Linux mode runs the Bash sensor and expects Linux evidence
- Windows mode runs the PowerShell sensor and expects Windows evidence
- evidence from the other operating system is not included unless the user
  explicitly selects it interactively or passes the relevant CLI flag
- production collection may require Administrator access on Windows or sudo/root
  on Linux when protected logs or policy files must be read
- interactive production mode prompts for a log lookback window and a maximum
  event or line limit, with safe defaults of 24 hours and 1000 items
- log collection input is clamped at 720 hours and 10000 events or lines to
  prevent accidental unbounded collection
- manually exported evidence can be placed in `data/incoming/`
- raw logs can be placed in `logdata/linux/` or `logdata/windows/`
- optional cross-platform evidence must be placed in `data/incoming/`,
  `logdata/linux/`, or `logdata/windows/`
- if older logs are needed, export them manually and place them in
  `data/incoming/`, `logdata/linux/`, or `logdata/windows/`
- fallback is used when the primary collector does not produce usable output

If a previous Linux run used sudo and a later non-sudo run cannot write runtime
files, fix ownership before running again:

```bash
sudo chown -R $USER:$USER logs reports data/alerts data/collected
```

## Evidence Sources and States

Production runs are selected-platform only by default. Windows mode collects
Windows evidence, and Linux mode collects Linux evidence. Evidence from the
other operating system is included only when explicitly selected with the
interactive prompt or with `--include-manual-linux` / `--include-manual-windows`.

Reports use explicit source states:

- `loaded`: evidence was read and validated
- `not selected`: the source was outside the selected analysis scope
- `missing_required`: selected-platform evidence was expected but not available
- `missing_optional`: optional manual evidence was requested but not supplied
- `ignored`: a candidate was excluded, for example stale or out of scope
- `invalid` or `needs review`: a file was present but failed validation

Supported manual evidence filenames are:

- Linux: `linux_identity.json`, `linux_policy.json`, `auth.log`
- Windows: `windows_identity.csv`, `windows_events.csv`, `windows_policy.csv`
- Windows event aliases: `security_events.csv` and `eventviewer_export.csv`,
  only when they use the same schema as `windows_events.csv`

The minimal Linux policy JSON must contain a `policy.ssh_policy` mapping with
`permit_root_login`, `password_authentication`, and `pubkey_authentication`.
Windows event CSV files must contain:
`ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType`.

## Test Mode

Test mode is safe and isolated. It uses mock data and simulated logs instead of
real system files and does not require elevated privileges.

```bash
python app.py --test
python app.py --mode test
```

In test mode, the pipeline runs end-to-end:

- mockdata loading
- validation
- analysis
- reporting
- alerts
- log generation

`python app.py --test` and `python app.py --mode test` both exercise the full
Python pipeline with mock data. They do not run the Linux or Windows collectors
directly.

The Bash and PowerShell sensors can also be tested directly:

```bash
bash bash/linux_identity_audit.sh --mode test
powershell -NoProfile -ExecutionPolicy Bypass -File powershell/windows_identity_audit.ps1 -Mode Test
```

These sensor scripts may produce little terminal output because they write
results to `data/collected/` and `logs/`. Verify success by checking exit code
`0` and validating the generated files.

Validation examples:

```bash
python -m json.tool data/collected/linux_identity.json
python -m json.tool data/collected/linux_policy.json
Import-Csv data/collected/windows_identity.csv
Import-Csv data/collected/windows_events.csv
Import-Csv data/collected/windows_policy.csv
```

## Output Files

The main outputs are:

- `reports/final_identity_risk_report.txt`
- `reports/final_identity_risk_report.json`
- `reports/executive_summary.txt`
- `data/alerts/alerts.json`
- `logs/critical_alerts.log`
- `logs/python_engine.log`

## Risk Levels

The project uses four risk levels:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`

Findings are scored by severity so the report always highlights the highest
risk first.

## Known Limitations

- The tool is read-only and does not remediate findings automatically.
- If production runs are not elevated, fallback may be used and reports can be
  partial because some protected sources were not readable.
- Some evidence sources may be missing in real environments, which can trigger
  fallback behavior or a safe exit.
- The project depends on the quality of the provided logs, baselines, and
  exported identity data.

## Documentation

Additional project documentation is available in the `docs/` directory.
