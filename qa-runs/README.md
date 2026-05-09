# Manual QA Evidence

This folder contains manual QA evidence for NordSec Identity & Privilege Control Auditor.

The purpose of this QA evidence is to show that the project was tested on clean Ubuntu and Windows virtual machines, including normal runs, wrong-OS handling, input validation, manual evidence handling, cross-platform evidence, generated reports, alerts and collector logs.

## Folder overview

qa-runs/manual/ contains focused clean-run evidence.

qa-runs/linux/ contains the Linux manual QA scenario suite.

qa-runs/windows/ contains the Windows manual QA scenario suite.

## Clean manual runs

### ubuntu-test-mode-clean

Verifies that test mode works on a clean Ubuntu VM using mock data.

Main evidence:

- console.txt
- final_identity_risk_report.txt
- final_identity_risk_report.json
- executive_summary.txt
- alerts.json
- critical_alerts.log
- python_engine.log
- README.md

### ubuntu-linux-production-clean

Verifies Linux production collection on a clean Ubuntu VM.

This run used a realistic Linux sudo baseline and an intentionally added unapproved sudo user named hacker.

Main result:

- Linux collector result: success
- Fallback used: No
- Findings: 3
- Critical: 1
- High: 2
- hacker was detected as an unapproved Linux sudo user

Main evidence:

- console.txt
- final_identity_risk_report.txt
- final_identity_risk_report.json
- executive_summary.txt
- alerts.json
- critical_alerts.log
- python_engine.log
- linux_audit.log
- linux_identity.json
- linux_policy.json
- approved_linux_sudoers.csv
- approved_service_accounts.csv
- expected_policy_baseline.json
- README.md

### windows-test-mode-clean

Verifies that test mode works on a clean Windows VM using mock data.

Main evidence:

- console.txt
- final_identity_risk_report.txt
- final_identity_risk_report.json
- executive_summary.txt
- alerts.json
- critical_alerts.log
- python_engine.log
- README.md

### windows-production-clean

Documents an initial Windows production run before the final Windows collector fix was verified.

This run exposed a Windows collector limitation caused by an unresolved/orphaned SID in the local Administrators group. The application still exited safely and generated reports, but the collector did not fully detect local administrator membership.

This folder is kept as QA evidence because it shows the issue that was found during manual testing.

### windows-production-after-fix

Verifies the corrected Windows collector behavior after the fix for unresolved/orphaned SID handling.

Main result:

- Windows collector result: success
- Fallback used: No
- Findings: 2
- Critical: 1
- Medium: 1
- eviladmin was detected as an unapproved Windows administrator

Main evidence:

- console.txt
- final_identity_risk_report.txt
- final_identity_risk_report.json
- executive_summary.txt
- alerts.json
- critical_alerts.log
- python_engine.log
- windows_audit.log
- windows_identity.csv
- windows_events.csv
- windows_policy.csv
- approved_windows_admins.csv
- approved_service_accounts.csv
- expected_policy_baseline.json
- README.md

## Linux manual QA scenario suite

Path:

qa-runs/linux/20260509-022752/

This suite was run with:

./tools/manual_test_linux.sh

Scenarios:

- L1-wrong-os-windows-on-linux
- L2-linux-huge-values
- L3-linux-normal-no-manual-windows
- L4-linux-manual-windows-skip
- L5-linux-manual-windows-enter-no-new-files
- L6-linux-manual-windows-with-files

The suite verifies:

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

Each scenario folder contains:

- console.txt
- input.txt
- report_head.txt
- json_summary.txt
- alerts_summary.txt
- file_status.txt
- python_engine_tail.txt
- linux_audit_tail.txt
- windows_audit_tail.txt
- git_ignored_status.txt
- notes.txt

## Windows manual QA scenario suite

Path:

qa-runs/windows/20260509-033804/

This suite was run with:

.\tools\manual_test_windows.ps1

Scenarios:

- W1-wrong-os-linux-on-windows
- W2-windows-huge-values
- W3-windows-normal-no-manual-linux
- W4-windows-manual-linux-skip
- W5-windows-manual-linux-enter-no-new-files
- W6-windows-manual-linux-with-files

The suite verifies:

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

Each scenario folder contains:

- console.txt
- input.txt
- report_head.txt
- json_summary.txt
- alerts_summary.txt
- file_status.txt
- python_engine_tail.txt
- windows_audit_tail.txt
- linux_audit_tail.txt
- git_ignored_status.txt
- notes.txt

## Notes about QA evidence

The files in this folder are saved test evidence. They are not runtime files from the current working directory.

The normal runtime output folders reports/, logs/, data/alerts/ and data/collected/ are ignored by Git, but selected copies of important outputs were saved here under qa-runs/ so they can be reviewed later.

The evidence demonstrates both successful behavior and a discovered Windows collector issue that was fixed and re-tested.
