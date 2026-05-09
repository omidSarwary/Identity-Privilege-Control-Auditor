"""PowerShell-level tests for the Windows identity audit sensor."""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_SENSOR = PROJECT_ROOT / "powershell" / "windows_identity_audit.ps1"


def _powershell_executable() -> str | None:
    """Return an available PowerShell executable for sensor function tests."""
    return shutil.which("pwsh") or shutil.which("powershell")


def test_windows_admin_membership_falls_back_when_group_member_translation_fails(tmp_path) -> None:
    """Fallback admin discovery should survive unresolved SID translation errors."""
    executable = _powershell_executable()
    if executable is None:
        pytest.skip("PowerShell is not available")

    source_text = WINDOWS_SENSOR.read_text(encoding="utf-8")
    harness_sensor = tmp_path / "windows_identity_audit_functions.ps1"
    harness_sensor.write_text(source_text.replace("\nInvoke-WindowsAudit\n", "\n"), encoding="utf-8")
    audit_log = tmp_path / "windows_audit.log"
    anomalies_log = tmp_path / "anomalies.log"

    harness = tmp_path / "harness.ps1"
    harness.write_text(
        textwrap.dedent(
            f"""
            . '{harness_sensor}'
            $AuditLogPath = '{audit_log}'
            $AnomaliesLogPath = '{anomalies_log}'
            $Mode = 'Production'
            New-Item -ItemType File -Path $AuditLogPath -Force | Out-Null
            New-Item -ItemType File -Path $AnomaliesLogPath -Force | Out-Null

            function Get-LocalGroupMember {{
                throw 'An unspecified error occurred: error code = 1789'
            }}

            function net.exe {{
                @(
                    'Alias name     Administrators',
                    'Comment        Administrators have complete and unrestricted access',
                    '',
                    'Members',
                    '-------------------------------------------------------------------------------',
                    'Administrator',
                    'eviladmin',
                    'Omidlab',
                    'S-1-5-21-1362498765-3355764325-479558430-512',
                    'The command completed successfully.'
                )
            }}

            function Get-LocalUser {{
                @(
                    [pscustomobject]@{{ Name = 'Administrator'; Enabled = $true; LastLogon = $null }},
                    [pscustomobject]@{{ Name = 'eviladmin'; Enabled = $true; LastLogon = $null }},
                    [pscustomobject]@{{ Name = 'Omidlab'; Enabled = $true; LastLogon = $null }},
                    [pscustomobject]@{{ Name = 'normaluser'; Enabled = $true; LastLogon = $null }}
                )
            }}

            $script:LocalAdminMembers = @(Get-LocalAdminMembers)
            $records = @(Get-LocalIdentityData)
            [pscustomobject]@{{
                Members = $script:LocalAdminMembers
                Records = $records
                Log = [System.IO.File]::ReadAllText($AuditLogPath)
            }} | ConvertTo-Json -Depth 6
            """
        ).strip(),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [executable, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    members = set(payload["Members"])
    assert {"Administrator", "eviladmin", "Omidlab"}.issubset(members)
    assert not any(str(member).startswith("S-1-5-21-") for member in members)

    records = {row["Username"]: row for row in payload["Records"]}
    assert records["Administrator"]["IsLocalAdmin"] is True
    assert records["eviladmin"]["IsLocalAdmin"] is True
    assert records["Omidlab"]["IsLocalAdmin"] is True
    assert records["normaluser"]["IsLocalAdmin"] is False
    assert "Unresolved administrator SID skipped" in payload["Log"]
