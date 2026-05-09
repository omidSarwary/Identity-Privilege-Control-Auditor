# Manual Test Evidence Notes

This folder documents the manually supplied evidence files used during the manual QA scenarios.

The active runtime input folders data/incoming/ and logdata/ are not committed as normal project input state. Instead, selected outputs and notes are saved under qa-runs/ as reviewable QA evidence.

## Linux manual QA: L6

Scenario:

qa-runs/linux/20260509-022752/L6-linux-manual-windows-with-files/

Purpose:

This scenario tested Linux production collection together with manually supplied Windows evidence.

Manual Windows evidence was placed in:

- data/incoming/
- logdata/windows/

The application detected the supplied Windows evidence and included it in the analysis scope together with Linux collector data.

The scenario output is saved in the L6 folder and includes:

- console.txt
- input.txt
- report_head.txt
- json_summary.txt
- alerts_summary.txt
- file_status.txt
- python_engine_tail.txt
- linux_audit_tail.txt
- windows_audit_tail.txt
- notes.txt

## Windows manual QA: W6

Scenario:

qa-runs/windows/20260509-033804/W6-windows-manual-linux-with-files/

Purpose:

This scenario tested Windows production collection together with manually supplied Linux evidence.

Manual Linux evidence was placed in:

- data/incoming/
- logdata/linux/

The application detected the supplied Linux evidence and included it in the analysis scope together with Windows collector data.

The scenario output is saved in the W6 folder and includes:

- console.txt
- input.txt
- report_head.txt
- json_summary.txt
- alerts_summary.txt
- file_status.txt
- python_engine_tail.txt
- windows_audit_tail.txt
- linux_audit_tail.txt
- notes.txt

## Placeholder evidence note

Some early manual Windows event files only contained the CSV header:

ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType

Those files were useful for testing schema-valid but empty event evidence behavior. They should not be described as full realistic event logs.

## Full evidence snapshots

Full collected evidence snapshots are saved in the clean-run folders:

- qa-runs/manual/ubuntu-linux-production-clean/
- qa-runs/manual/windows-production-after-fix/

These folders include collected identity/policy/event files and baseline snapshots used during the production validation runs.
