# PowerShell Sensor

The Windows PowerShell sensor is the read-only collection entry point for the
NordSec Identity & Privilege Control Auditor. It gathers local identity data,
administrator membership, Event Viewer evidence, and policy state for the
analysis pipeline.

## Usage

Run the script from the repository root so the relative project paths resolve
correctly.

### Production

```powershell
powershell -ExecutionPolicy Bypass -File powershell/windows_identity_audit.ps1 -Mode Production
```

Production mode uses the local Windows data sources that are available on the
host and writes output to:

- `data/collected/windows_identity.csv`
- `data/collected/windows_events.csv`
- `data/collected/windows_policy.csv`
- `logs/windows_audit.log`
- `logs/anomalies.log`

### Test

```powershell
powershell -ExecutionPolicy Bypass -File powershell/windows_identity_audit.ps1 -Mode Test
```

Test mode uses the approved mock data in `tests/mockdata/` and does not touch
real Event Viewer logs.

## Permission Limits

The sensor is read-only. If the Security log, local administrator group, or a
policy source cannot be read, the script writes a warning to the logs and
continues where possible. This keeps the sensor safe to run in restricted
contexts while still producing usable evidence for later analysis.
