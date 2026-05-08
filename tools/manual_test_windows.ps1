<#
Manual QA harness for NordSec Identity & Privilege Control Auditor on Windows.

Purpose:
- Runs one interactive scenario at a time.
- Captures console output and generated artifacts.
- Cleans runtime files between scenarios.
- Pauses after each scenario for human review.
- Does not modify source code.
- Does not commit or push anything.

Run from project root:
  .\tools\manual_test_windows.ps1

Recommended:
- Run in Administrator PowerShell when testing successful Windows collection.
- Run in normal PowerShell when testing permission/fallback behavior.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path ".").Path
$Python = "python"
$RunRoot = Join-Path $ProjectRoot "qa-runs\windows"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$SessionRoot = Join-Path $RunRoot $Timestamp

New-Item -ItemType Directory -Force $SessionRoot | Out-Null

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $Message
    Write-Host "============================================================"
}

function Wait-User {
    param([string]$Message = "Review the output, then press Enter to continue.")
    Write-Host ""
    Read-Host $Message | Out-Null
}

function Remove-GeneratedRuntimeFiles {
    Write-Host "Cleaning generated runtime files..."

    $files = @(
        "data\alerts\alerts.json",
        "data\collected\linux_identity.json",
        "data\collected\linux_policy.json",
        "data\collected\windows_identity.csv",
        "data\collected\windows_events.csv",
        "data\collected\windows_policy.csv",
        "logs\anomalies.log",
        "logs\critical_alerts.log",
        "logs\linux_audit.log",
        "logs\python_engine.log",
        "logs\windows_audit.log",
        "reports\executive_summary.txt",
        "reports\final_identity_risk_report.json",
        "reports\final_identity_risk_report.txt"
    )

    foreach ($file in $files) {
        $path = Join-Path $ProjectRoot $file
        if (Test-Path $path) {
            Remove-Item -Force $path -ErrorAction SilentlyContinue
        }
    }

    Get-ChildItem -Path (Join-Path $ProjectRoot "logs\archive") -Filter "python_engine-*.log" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
}

function Ensure-RuntimeFolders {
    $dirs = @(
        "data\alerts",
        "data\collected",
        "data\incoming",
        "logs",
        "logs\archive",
        "reports",
        "logdata\linux",
        "logdata\windows"
    )

    foreach ($dir in $dirs) {
        New-Item -ItemType Directory -Force (Join-Path $ProjectRoot $dir) | Out-Null
    }
}

function Get-FileStatus {
    param(
        [string[]]$Paths,
        [string]$OutputFile
    )

    $rows = foreach ($relative in $Paths) {
        $path = Join-Path $ProjectRoot $relative
        if (Test-Path $path) {
            $item = Get-Item $path
            [PSCustomObject]@{
                Path          = $relative
                Exists        = $true
                Length        = $item.Length
                LastWriteTime = $item.LastWriteTime
            }
        }
        else {
            [PSCustomObject]@{
                Path          = $relative
                Exists        = $false
                Length        = ""
                LastWriteTime = ""
            }
        }
    }

    $rows | Format-Table -AutoSize | Out-String | Set-Content -Encoding UTF8 $OutputFile
}

function Save-JsonSummary {
    param([string]$OutputFile)

    $jsonPath = Join-Path $ProjectRoot "reports\final_identity_risk_report.json"

    if (-not (Test-Path $jsonPath)) {
        "JSON report not found." | Set-Content -Encoding UTF8 $OutputFile
        return
    }

    $script = @"
import json
from pathlib import Path

path = Path(r"$jsonPath")
data = json.load(open(path, encoding="utf-8"))

print("mode:", data.get("mode"))
print("selected_platform:", data.get("selected_platform"))
print("analysis_scope:", data.get("analysis_scope"))
print("manual_cross_evidence_included:", data.get("manual_cross_evidence_included"))
print("manual_cross_evidence_platform:", data.get("manual_cross_evidence_platform"))
print("fallback_used:", data.get("fallback_used"))
findings = data.get("findings", [])
print("finding_count:", len(findings))
summary = data.get("summary", {})
print("summary_counts:", summary.get("counts"))
print("")
print("findings:")
for f in findings:
    print("-", f.get("identity"), "|", f.get("risk_level"), "|", f.get("finding"), "| source=", f.get("source"))
"@

    $script | & $Python - | Out-File -Encoding UTF8 $OutputFile
}

function Save-AlertsSummary {
    param([string]$OutputFile)

    $alertsPath = Join-Path $ProjectRoot "data\alerts\alerts.json"

    if (-not (Test-Path $alertsPath)) {
        "alerts.json not found." | Set-Content -Encoding UTF8 $OutputFile
        return
    }

    $script = @"
import json
from pathlib import Path

path = Path(r"$alertsPath")
data = json.load(open(path, encoding="utf-8"))

if isinstance(data, dict):
    alerts = data.get("alerts", [])
else:
    alerts = data

print("alert_count:", len(alerts))
for a in alerts:
    print("-", a.get("identity"), "|", a.get("risk_level"), "|", a.get("finding"))
"@

    $script | & $Python - | Out-File -Encoding UTF8 $OutputFile
}

function Save-ReportHead {
    param([string]$OutputFile)

    $reportPath = Join-Path $ProjectRoot "reports\final_identity_risk_report.txt"

    if (Test-Path $reportPath) {
        Get-Content $reportPath -TotalCount 120 | Set-Content -Encoding UTF8 $OutputFile
    }
    else {
        "Text report not found." | Set-Content -Encoding UTF8 $OutputFile
    }
}

function Save-LogTail {
    param(
        [string]$RelativePath,
        [string]$OutputFile,
        [int]$Lines = 120
    )

    $path = Join-Path $ProjectRoot $RelativePath

    if (Test-Path $path) {
        Get-Content $path -Tail $Lines | Set-Content -Encoding UTF8 $OutputFile
    }
    else {
        "$RelativePath not found." | Set-Content -Encoding UTF8 $OutputFile
    }
}

function Save-GitStatus {
    param([string]$OutputFile)

    git status --ignored data/collected data/alerts logs reports 2>&1 |
    Out-File -Encoding UTF8 $OutputFile
}

function Save-ScenarioEvidence {
    param(
        [string]$ScenarioDir,
        [string]$ScenarioName
    )

    Write-Host "Collecting evidence for $ScenarioName..."

    Get-FileStatus -Paths @(
        "data\collected\windows_identity.csv",
        "data\collected\windows_events.csv",
        "data\collected\windows_policy.csv",
        "data\collected\linux_identity.json",
        "data\collected\linux_policy.json",
        "data\alerts\alerts.json",
        "reports\final_identity_risk_report.txt",
        "reports\final_identity_risk_report.json",
        "reports\executive_summary.txt",
        "logs\critical_alerts.log",
        "logs\python_engine.log",
        "logs\windows_audit.log",
        "logs\linux_audit.log"
    ) -OutputFile (Join-Path $ScenarioDir "file_status.txt")

    Save-ReportHead -OutputFile (Join-Path $ScenarioDir "report_head.txt")
    Save-JsonSummary -OutputFile (Join-Path $ScenarioDir "json_summary.txt")
    Save-AlertsSummary -OutputFile (Join-Path $ScenarioDir "alerts_summary.txt")
    Save-LogTail -RelativePath "logs\python_engine.log" -OutputFile (Join-Path $ScenarioDir "python_engine_tail.txt")
    Save-LogTail -RelativePath "logs\windows_audit.log" -OutputFile (Join-Path $ScenarioDir "windows_audit_tail.txt")
    Save-LogTail -RelativePath "logs\linux_audit.log" -OutputFile (Join-Path $ScenarioDir "linux_audit_tail.txt")
    Save-GitStatus -OutputFile (Join-Path $ScenarioDir "git_ignored_status.txt")

    @"
Scenario: $ScenarioName
Generated at: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Project root: $ProjectRoot

Review checklist:
- Did terminal output match expected scenario behavior?
- Did selected_platform and analysis_scope match the scenario?
- Was fallback used correctly?
- Were stale/ignored/manual evidence warnings clear?
- Were generated reports consistent with console output?
- Were wrong-OS or permission problems handled clearly?
- Did git status remain clean except ignored runtime files?
"@ | Set-Content -Encoding UTF8 (Join-Path $ScenarioDir "notes.txt")
}

function Run-AppScenario {
    param(
        [string]$ScenarioId,
        [string]$ScenarioName,
        [string[]]$InputLines,
        [bool]$CleanBefore = $true,
        [bool]$PauseForManualFiles = $false,
        [string]$ManualFileMessage = ""
    )

    Write-Section "$ScenarioId - $ScenarioName"

    if ($CleanBefore) {
        Remove-GeneratedRuntimeFiles
        Ensure-RuntimeFolders
    }

    if ($PauseForManualFiles) {
        Write-Host $ManualFileMessage
        Wait-User "Copy the manual evidence files now, then press Enter to run this scenario."
    }

    $ScenarioDir = Join-Path $SessionRoot $ScenarioId
    New-Item -ItemType Directory -Force $ScenarioDir | Out-Null

    $inputFile = Join-Path $ScenarioDir "input.txt"
    $consoleFile = Join-Path $ScenarioDir "console.txt"

    $InputLines | Set-Content -Encoding UTF8 $inputFile

    Write-Host "Running scenario..."
    Write-Host "Input saved to: $inputFile"
    Write-Host "Console output will be saved to: $consoleFile"
    Write-Host ""

    Get-Content $inputFile | & $Python app.py 2>&1 |
    Tee-Object -FilePath $consoleFile

    Save-ScenarioEvidence -ScenarioDir $ScenarioDir -ScenarioName $ScenarioName

    Write-Host ""
    Write-Host "Scenario output folder:"
    Write-Host $ScenarioDir
    Wait-User
}

function Show-SessionSummary {
    Write-Section "Session summary"
    Write-Host "QA session folder:"
    Write-Host $SessionRoot
    Write-Host ""
    Write-Host "Scenario folders:"
    Get-ChildItem $SessionRoot -Directory | ForEach-Object {
        Write-Host "- $($_.FullName)"
    }
}

Write-Section "NordSec Windows Manual QA Harness"
Write-Host "Project root: $ProjectRoot"
Write-Host "Session root: $SessionRoot"
Write-Host ""
Write-Host "This harness runs one scenario at a time and pauses after each run."
Write-Host "Run in Administrator PowerShell for successful Windows Security log collection."
Write-Host "Run in normal PowerShell if you want to verify non-admin fallback behavior."
Wait-User "Press Enter to start W1."

# W1: wrong OS choice on Windows.
Run-AppScenario `
    -ScenarioId "W1-wrong-os-linux-on-windows" `
    -ScenarioName "Wrong OS choice: choose linux on Windows" `
    -InputLines @(
    "linux",
    "1",
    "100",
    "n"
)

# W2: huge values, should clamp/fallback safely.
Run-AppScenario `
    -ScenarioId "W2-windows-huge-values" `
    -ScenarioName "Windows with very large hours/events" `
    -InputLines @(
    "windows",
    "999999",
    "999999",
    "n"
)

# W3: normal Windows-only, no manual Linux.
Run-AppScenario `
    -ScenarioId "W3-windows-normal-no-manual-linux" `
    -ScenarioName "Windows normal values, no manual Linux" `
    -InputLines @(
    "windows",
    "1",
    "100",
    "n"
)

# W4: manual Linux yes, then skip.
Run-AppScenario `
    -ScenarioId "W4-windows-manual-linux-skip" `
    -ScenarioName "Windows normal values, manual Linux yes, then skip" `
    -InputLines @(
    "windows",
    "1",
    "100",
    "y",
    "skip"
)

# W5: manual Linux yes, press Enter without adding files.
Run-AppScenario `
    -ScenarioId "W5-windows-manual-linux-enter-no-new-files" `
    -ScenarioName "Windows normal values, manual Linux yes, Enter without adding files" `
    -InputLines @(
    "windows",
    "1",
    "100",
    "y",
    ""
)

# W6: manual Linux yes, pause for you to copy files, then continue.
Run-AppScenario `
    -ScenarioId "W6-windows-manual-linux-with-files" `
    -ScenarioName "Windows normal values, manual Linux yes, user adds manual Linux files" `
    -InputLines @(
    "windows",
    "1",
    "100",
    "y",
    ""
) `
    -PauseForManualFiles $true `
    -ManualFileMessage @"
Before continuing:
Copy your generated Linux manual evidence into one of these folders:

  $ProjectRoot\data\incoming\
  $ProjectRoot\logdata\linux\

Recommended for this scenario:
- Copy auth.log, syslog, journalctl_sample.log into logdata\linux\
- Copy linux_identity.json and linux_policy.json into data\incoming\ if you want full manual Linux evidence

The harness will run python app.py after you press Enter.
"@

Show-SessionSummary