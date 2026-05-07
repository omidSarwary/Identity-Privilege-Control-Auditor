# Risk Model

## Risk Levels

The project uses four risk levels:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`

Findings are prioritized by severity so the report can highlight the most
important issues first.

## Core Rules

The implemented rules cover the project’s defined identity and policy checks,
including:

- disabled account with activity
- unauthorized Windows administrators membership
- unauthorized Linux sudo usage
- privileged account with repeated failed logins
- SSH root login allowed with privileged activity
- corrupted critical input data
- inactive account with privileges
- repeated failed logins from the same IP
- missing audit policy
- Windows Firewall disabled when the control can be read
- weak SSH policy
- normal account with a small number of failed logins
- missing log source while other data exists

## Recommended Actions

Recommended actions are read-only follow-up steps such as:

- verify account ownership
- review approved baselines
- investigate login activity
- confirm policy configuration
- collect missing evidence safely

The tool does not automate remediation. It only reports the risk so an
operator can investigate further.
