"""Tests for the Windows collector adapter."""

from __future__ import annotations

import os

from src.collectors import windows_collector
from src.core.command_runner import CommandResult


def test_collect_windows_data_reports_success_when_outputs_exist(monkeypatch, tmp_path) -> None:
    """The Windows collector should report success only after the expected files exist."""
    captured: dict[str, list[str]] = {}
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
    def _run_command(command, **kwargs):
        captured["command"] = list(command)
        return CommandResult(
            command=tuple(command),
            returncode=0,
            stdout="ok",
            stderr="",
            timed_out=False,
            started_at=0.0,
            finished_at=1.0,
        )

    monkeypatch.setattr(windows_collector, "run_command", _run_command)

    result = windows_collector.collect_windows_data(mode="test", log_hours=12, max_events=500)

    assert result["platform"] == "windows"
    assert result["mode"] == "Test"
    assert result["success"] is True
    assert result["missing_outputs"] == []
    assert result["executable"] == "pwsh"
    assert "-LogHours" in captured["command"]
    assert "12" in captured["command"]
    assert "-MaxEvents" in captured["command"]
    assert "500" in captured["command"]


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
        lambda command, **kwargs: CommandResult(
            command=tuple(command),
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


def test_collect_windows_data_summarizes_access_denied(monkeypatch, tmp_path) -> None:
    """Access-denied Windows output should surface as an Administrator hint."""
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
        lambda command, **kwargs: CommandResult(
            command=tuple(command),
            returncode=1,
            stdout="",
            stderr="Access is denied.",
            timed_out=False,
            started_at=0.0,
            finished_at=1.0,
        ),
    )

    result = windows_collector.collect_windows_data(mode="production")

    assert result["success"] is False
    assert "Administrator" in result["reason"]
    assert result["output_statuses"]["windows_identity"]["status"] == "failed"


def test_collect_windows_data_rejects_stale_outputs_when_command_fails(monkeypatch, tmp_path) -> None:
    """A fatal PowerShell failure must not be masked by old output files."""
    old_timestamp = 1000.0
    collector_started_at = 2000.0
    identity_path = tmp_path / "windows_identity.csv"
    events_path = tmp_path / "windows_events.csv"
    policy_path = tmp_path / "windows_policy.csv"
    identity_path.write_text("ComputerName,CollectionTime,Username,Enabled,IsLocalAdmin,LastLogon,Source\n", encoding="utf-8")
    events_path.write_text("ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType\n", encoding="utf-8")
    policy_path.write_text("ComputerName,CheckName,Status,Value,RiskHint\n", encoding="utf-8")
    for path in [identity_path, events_path, policy_path]:
        os.utime(path, (old_timestamp, old_timestamp))

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
        lambda command, **kwargs: CommandResult(
            command=tuple(command),
            returncode=127,
            stdout="",
            stderr="powershell not found",
            timed_out=False,
            started_at=collector_started_at,
            finished_at=1.0,
        ),
    )

    result = windows_collector.collect_windows_data(mode="production")

    assert result["success"] is False
    assert result["command"]["returncode"] == 127
    assert result["missing_outputs"] == []
    assert sorted(result["stale_outputs"]) == sorted([str(identity_path), str(events_path), str(policy_path)])
    assert result["current_outputs"] == []
    assert "PowerShell was not found" in result["reason"]
    assert result["output_statuses"]["windows_events"]["status"] == "not collected in this run"


def test_collect_windows_data_reports_partial_current_run_outputs(monkeypatch, tmp_path) -> None:
    """Only files updated after collector start should be shown as collected."""
    old_timestamp = 1000.0
    current_timestamp = 3000.0
    collector_started_at = 2000.0
    identity_path = tmp_path / "windows_identity.csv"
    events_path = tmp_path / "windows_events.csv"
    policy_path = tmp_path / "windows_policy.csv"
    identity_path.write_text("ComputerName,CollectionTime,Username,Enabled,IsLocalAdmin,LastLogon,Source\n", encoding="utf-8")
    events_path.write_text("ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType\n", encoding="utf-8")
    policy_path.write_text("ComputerName,CheckName,Status,Value,RiskHint\n", encoding="utf-8")
    os.utime(identity_path, (current_timestamp, current_timestamp))
    os.utime(events_path, (old_timestamp, old_timestamp))
    os.utime(policy_path, (old_timestamp, old_timestamp))

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
        lambda command, **kwargs: CommandResult(
            command=tuple(command),
            returncode=1,
            stdout="",
            stderr="Access is denied.",
            timed_out=False,
            started_at=collector_started_at,
            finished_at=collector_started_at + 1,
        ),
    )

    result = windows_collector.collect_windows_data(mode="production")

    assert result["success"] is False
    assert result["current_outputs"] == [str(identity_path)]
    assert sorted(result["stale_outputs"]) == sorted([str(events_path), str(policy_path)])
    assert result["output_statuses"]["windows_identity"]["status"] == "collected"
    assert result["output_statuses"]["windows_events"]["status"] == "not collected in this run"
    assert result["output_statuses"]["windows_policy"]["status"] == "not collected in this run"
