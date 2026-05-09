# Linux Manual QA Session

This folder contains the Linux manual QA scenario test suite for NordSec Identity & Privilege Control Auditor.

## Test environment

The tests were run on an Ubuntu VM from a clean cloned copy of the repository.

The Linux manual QA harness used:

./tools/manual_test_linux.sh

The harness runs one scenario at a time and saves evidence for each scenario in a separate folder.

## Session folder

qa-runs/linux/20260509-022752

## Scenarios included

- L1-wrong-os-windows-on-linux  
  Tests choosing Windows mode on a Linux host.

- L2-linux-huge-values  
  Tests very large log lookback and max event values to verify safety clamping.

- L3-linux-normal-no-manual-windows  
  Tests normal Linux production collection without manual Windows evidence.

- L4-linux-manual-windows-skip  
  Tests selecting manual Windows evidence and then skipping it.

- L5-linux-manual-windows-enter-no-new-files  
  Tests selecting manual Windows evidence and pressing Enter when only pre-existing Windows placeholder/event files are present.

- L6-linux-manual-windows-with-files  
  Tests Linux production collection together with manually supplied Windows evidence files.

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

- linux_audit_tail.txt  
  Tail of the Linux collector log, when available.

- windows_audit_tail.txt  
  Tail of the Windows collector log, when available.

- git_ignored_status.txt  
  Git status showing generated runtime files and ignored files.

- notes.txt  
  Scenario notes created by the test harness.

## Important note about Windows evidence

Some Windows evidence files used during Linux manual testing were manually supplied to data/incoming/ and logdata/windows/.

Earlier placeholder Windows event files only contained CSV headers and were used to test schema-valid but empty/manual evidence behavior.

The L6 scenario included manually supplied Windows evidence files and produced additional cross-platform findings.

## Overall result

The Linux manual QA session completed all six scenarios and saved evidence for each run.

The session verifies:

- wrong-OS guidance
- input clamping
- Linux collector execution
- manual cross-platform evidence prompts
- skip behavior
- stale/partial manual evidence warnings
- Linux + manual Windows cross-platform analysis
- report generation
- alert generation
- safe program exit
