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
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

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

## Production Mode

Production mode uses the platform-specific sensor and the fallback search
logic:

- Linux mode runs the Bash sensor and expects Linux evidence
- Windows mode runs the PowerShell sensor and expects Windows evidence
- manually exported evidence can be placed in `data/incoming/`
- raw logs can be placed in `logdata/linux/` or `logdata/windows/`
- fallback is used when the primary collector does not produce usable output

## Test Mode

Test mode is safe and isolated. It uses mock data and simulated logs instead of
real system files.

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
- Some evidence sources may be missing in real environments, which can trigger
  fallback behavior or a safe exit.
- The project depends on the quality of the provided logs, baselines, and
  exported identity data.

## Documentation

Additional project documentation is available in the `docs/` directory.
