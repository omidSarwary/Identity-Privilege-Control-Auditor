"""Tests for the Linux collector adapter."""

from __future__ import annotations

from pathlib import Path

from src.collectors import linux_collector
from src.core.command_runner import CommandResult


def test_collect_linux_data_reports_success_when_outputs_exist(monkeypatch, tmp_path) -> None:
    """The Linux collector should report success only after the expected files exist."""
    captured: dict[str, list[str]] = {}
    identity_path = tmp_path / "linux_identity.json"
    policy_path = tmp_path / "linux_policy.json"
    identity_path.write_text("{}", encoding="utf-8")
    policy_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        linux_collector,
        "EXPECTED_OUTPUTS",
        {
            "linux_identity": identity_path,
            "linux_policy": policy_path,
        },
    )
    monkeypatch.setattr(linux_collector, "LINUX_SENSOR_SCRIPT", tmp_path / "linux_identity_audit.sh")
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

    monkeypatch.setattr(linux_collector, "run_command", _run_command)

    result = linux_collector.collect_linux_data(mode="test", log_hours=12, max_events=500)

    assert result["platform"] == "linux"
    assert result["mode"] == "test"
    assert result["success"] is True
    assert result["missing_outputs"] == []
    assert "--log-hours" in captured["command"]
    assert "12" in captured["command"]
    assert "--max-events" in captured["command"]
    assert "500" in captured["command"]


def test_collect_linux_data_reports_missing_outputs(monkeypatch, tmp_path) -> None:
    """The Linux collector should flag missing output files as a failure."""
    identity_path = tmp_path / "linux_identity.json"
    policy_path = tmp_path / "linux_policy.json"

    monkeypatch.setattr(
        linux_collector,
        "EXPECTED_OUTPUTS",
        {
            "linux_identity": identity_path,
            "linux_policy": policy_path,
        },
    )
    monkeypatch.setattr(linux_collector, "LINUX_SENSOR_SCRIPT", tmp_path / "linux_identity_audit.sh")
    monkeypatch.setattr(
        linux_collector,
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

    result = linux_collector.collect_linux_data(mode="production")

    assert result["platform"] == "linux"
    assert result["success"] is False
    assert str(identity_path) in result["missing_outputs"]
    assert str(policy_path) in result["missing_outputs"]
