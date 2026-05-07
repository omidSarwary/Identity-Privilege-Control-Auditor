# Data Model

## Linux JSON

Linux identity data is stored as JSON with structured account and privilege
information. Linux policy data is also stored as JSON so policy checks can be
kept separate from identity records.

## Windows CSV

Windows identity, event, and policy data are stored as CSV files. The CSV
format keeps the exported evidence simple and easy to inspect.

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

## Alerts JSON

Alert output is written as JSON so it can be consumed by other tooling or
reviewed later without parsing the text report.
