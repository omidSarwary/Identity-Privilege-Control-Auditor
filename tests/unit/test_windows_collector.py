"""Tests for the Windows collector adapter."""

from __future__ import annotations

from src.collectors import windows_collector
from src.core.command_runner import CommandResult


def test_collect_windows_data_reports_success_when_outputs_exist(monkeypatch, tmp_path) -> None:
    """The Windows collector should report success only after the expected files exist."""
    identity_path = tmp_path / "windows_identity.csv"
    events_path = tmp_path / "windows_events.csv"
    policy_path = tmp_path / "windows_policy.csv"
    identity_path.write_text("ComputerName,CollectionTime,Username,Enabled,IsLocalAdmin,LastLogon,Source\n", encoding="utf-8")
    events_path.write_text("ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType\n", encoding="utf-8")
    policy_path.write_text("ComputerName,CheckName,Status,Value,RiskHint\n", encoding="utf-8")

    monkeypatch.setattr(
        windows_collector,
        "EXPECTED_OUTPUTS",
        {
            "windows_identity": identity_path,
            "windows_events": events_path,
            "windows_policy": policy_path,
        },
    )
    monkeypatch.setattr(windows_collector, "WINDOWS_SENSOR_SCRIPT", tmp_path / "windows_identity_audit.ps1")
    monkeypatch.setattr(windows_collector.shutil, "which", lambda _: "pwsh")
    monkeypatch.setattr(
        windows_collector,
        "run_command",
        lambda *args, **kwargs: CommandResult(
            command=("pwsh", "windows_identity_audit.ps1"),
            returncode=0,
            stdout="ok",
            stderr="",
            timed_out=False,
            started_at=0.0,
            finished_at=1.0,
        ),
    )

    result = windows_collector.collect_windows_data(mode="test")

    assert result["platform"] == "windows"
    assert result["mode"] == "Test"
    assert result["success"] is True
    assert result["missing_outputs"] == []
    assert result["executable"] == "pwsh"


def test_collect_windows_data_reports_missing_outputs(monkeypatch, tmp_path) -> None:
    """The Windows collector should flag missing output files as a failure."""
    identity_path = tmp_path / "windows_identity.csv"
    events_path = tmp_path / "windows_events.csv"
    policy_path = tmp_path / "windows_policy.csv"

    monkeypatch.setattr(
        windows_collector,
        "EXPECTED_OUTPUTS",
        {
            "windows_identity": identity_path,
            "windows_events": events_path,
            "windows_policy": policy_path,
        },
    )
    monkeypatch.setattr(windows_collector, "WINDOWS_SENSOR_SCRIPT", tmp_path / "windows_identity_audit.ps1")
    monkeypatch.setattr(windows_collector.shutil, "which", lambda _: "pwsh")
    monkeypatch.setattr(
        windows_collector,
        "run_command",
        lambda *args, **kwargs: CommandResult(
            command=("pwsh", "windows_identity_audit.ps1"),
            returncode=0,
            stdout="ok",
            stderr="",
            timed_out=False,
            started_at=0.0,
            finished_at=1.0,
        ),
    )

    result = windows_collector.collect_windows_data(mode="production")

    assert result["platform"] == "windows"
    assert result["success"] is False
    assert str(identity_path) in result["missing_outputs"]
    assert str(events_path) in result["missing_outputs"]
    assert str(policy_path) in result["missing_outputs"]
