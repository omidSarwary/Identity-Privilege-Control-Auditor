# Bash Sensor

The Linux Bash sensor is the read-only collection entry point for the NordSec
Identity & Privilege Control Auditor. It gathers approved identity, sudo, auth,
and SSH policy evidence and writes structured output for the Python analysis
pipeline.

## Usage

Run from the repository root so the script can resolve the project directories
correctly.

### Production

```bash
bash/linux_identity_audit.sh --mode production
```

Production mode uses the host's available Linux sources and writes evidence to:

- `data/collected/linux_identity.json`
- `data/collected/linux_policy.json`
- `logs/linux_audit.log`
- `logs/anomalies.log`

You can bound the auth-log collection window when running production mode:

```bash
bash/linux_identity_audit.sh --mode production --log-hours 12 --max-events 500
```

The script uses safe defaults of 24 hours and 1000 lines or events when these
options are not provided.

### Test

```bash
bash/linux_identity_audit.sh --mode test
```

Test mode uses the approved mock data under `tests/mockdata/` and keeps the
real system logs untouched.

If older Linux logs are needed, export them manually and place them in
`data/incoming/` or `logdata/linux/`.

## Permission Limits

The sensor is intentionally read-only. If a source file, policy file, or log is
not readable, the script logs a warning and continues with the available data
where possible. When a required source is missing or unreadable, the script can
return a controlled non-zero exit code so the orchestrator can trigger fallback.
