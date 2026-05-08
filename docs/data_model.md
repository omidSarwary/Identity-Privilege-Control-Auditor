# Data Model

## Linux JSON

Linux identity data is stored as JSON with structured account and privilege
information. Linux policy data is also stored as JSON so policy checks can be
kept separate from identity records.

The minimal Linux policy shape expected by validation is:

```json
{
  "source": "linux",
  "host": "hostname",
  "collection_time": "2026-05-08T00:00:00Z",
  "mode": "production",
  "policy": {
    "ssh_policy": {
      "permit_root_login": "no",
      "password_authentication": "no",
      "pubkey_authentication": "yes"
    }
  }
}
```

## Windows CSV

Windows identity, event, and policy data are stored as CSV files. The CSV
format keeps the exported evidence simple and easy to inspect.

Canonical Windows event columns are:

```text
ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType
```

Manual `security_events.csv` and `eventviewer_export.csv` files are accepted
only when they follow that same event schema.

## Baseline CSV

Approved baseline lists are stored as CSV files for:

- Linux sudo users
- Windows administrators
- service accounts

These files define the expected allowlists used during correlation.

## Normalized Model

The analysis pipeline converts source data into a normalized internal model
with fields such as:

- identity
- platforms
- privileges
- status
- baseline match information
- events
- policy findings
- risk score
- risk level
- reasons

Source quality records use explicit states such as `loaded`, `not_selected`,
`missing_required`, `missing_optional`, `ignored`, `invalid`, and
`needs_review`. These states prevent optional or out-of-scope evidence from
being described as both missing and valid.

## Alerts JSON

Alert output is written as JSON so it can be consumed by other tooling or
reviewed later without parsing the text report.
