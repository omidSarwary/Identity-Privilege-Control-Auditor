# Windows Manual QA Session

This folder contains the Windows manual QA scenario test suite for NordSec Identity & Privilege Control Auditor.

## Test environment

The tests were run on a clean Windows VM from a clean cloned copy of the repository.

The Windows manual QA harness used:

.\tools\manual_test_windows.ps1

The harness runs one scenario at a time and saves evidence for each scenario in a separate folder.

## Session folder

qa-runs/windows/20260509-033804

## Scenarios included

- W1-wrong-os-linux-on-windows
  Tests choosing Linux mode on a Windows host.

- W2-windows-huge-values
  Tests very large log lookback and max event values to verify safety clamping.

- W3-windows-normal-no-manual-linux
  Tests normal Windows production collection without manual Linux evidence.

- W4-windows-manual-linux-skip
  Tests selecting manual Linux evidence and then skipping it.

- W5-windows-manual-linux-enter-no-new-files
  Tests selecting manual Linux evidence and pressing Enter without adding Linux evidence files.

- W6-windows-manual-linux-with-files
  Tests Windows production collection together with manually supplied Linux evidence files.

## Evidence files in each scenario folder

Each scenario folder contains:

- console.txt
  Full terminal output from the scenario.

- input.txt
  The interactive input provided to the application.

- report_head.txt
  The beginning of the generated human-readable report.

- json_summary.txt
  Summary extracted from the generated JSON report.

- alerts_summary.txt
  Summary extracted from alerts.json.

- file_status.txt
  Status of important generated files after the run.

- python_engine_tail.txt
  Tail of the Python engine log.

- windows_audit_tail.txt
  Tail of the Windows collector log, when available.

- linux_audit_tail.txt
  Tail of the Linux collector log, when available.

- git_ignored_status.txt
  Git status showing generated runtime files and ignored files.

- notes.txt
  Scenario notes created by the test harness.

## Important note about the Windows collector fix

Before the final Windows manual QA session, the Windows collector was fixed so it could handle unresolved/orphaned SIDs in the local Administrators group.

The fix was verified before this session in:

qa-runs/manual/windows-production-after-fix/

That run confirmed that eviladmin was detected as an unapproved Windows administrator.

## Overall result

The Windows manual QA session completed all six scenarios and saved evidence for each run.

The session verifies:

- wrong-OS guidance
- input clamping
- Windows collector execution
- manual cross-platform evidence prompts
- skip behavior
- missing manual evidence warning
- Windows + manual Linux cross-platform analysis
- report generation
- alert generation
- safe program exit
