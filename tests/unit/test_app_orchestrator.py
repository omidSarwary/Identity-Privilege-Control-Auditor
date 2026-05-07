"""Tests for the interactive application orchestrator."""

from __future__ import annotations

from pathlib import Path

import app
from src.core.bootstrap import BootstrapStatus
from src.core.environment import EnvironmentStatus


def _bootstrap_status() -> BootstrapStatus:
    """Build a healthy bootstrap result for orchestrator tests."""
    return BootstrapStatus(
        bootstrap_skipped=False,
        environment=EnvironmentStatus(
            python_ok=True,
            python_version="3.11.9",
            required_directories_ok=True,
            missing_directories=(),
            messages=(),
        ),
        requirements_file_present=True,
        requirements_file_nonempty=True,
        venv_active=True,
        messages=(),
    )


def test_parse_args_supports_orchestrator_flags() -> None:
    """The CLI should expose the documented orchestration flags."""
    args = app.parse_args(["--test", "--no-bootstrap", "--mode", "test"])

    assert args.test is True
    assert args.no_bootstrap is True
    assert args.mode == "test"


def test_main_runs_full_orchestration_when_data_exists(monkeypatch) -> None:
    """The main entry point should complete the full pipeline when data exists."""
    calls: list[str] = []
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "test"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode: calls.append(f"linux:{mode}") or {
            "platform": "linux",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"linux_identity": "data/collected/linux_identity.json"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode: calls.append(f"windows:{mode}") or {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("fallback should not run when collectors succeed")),
    )
    monkeypatch.setattr(
        app,
        "run_identity_risk_engine",
        lambda mode, data_paths, run_id: {
            "run_id": run_id,
            "mode": mode,
            "data_sources": {},
            "data_quality": {"valid": True, "warnings": [], "errors": [], "sources": {}},
            "findings": [],
            "summary": {"counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "identities": []},
        },
    )
    monkeypatch.setattr(
        app,
        "write_reports",
        lambda analysis_result: {
            "text_report": Path("reports/final_identity_risk_report.txt"),
            "executive_summary": Path("reports/executive_summary.txt"),
            "json_report": Path("reports/final_identity_risk_report.json"),
            "alerts_json": Path("data/alerts/alerts.json"),
            "critical_alerts_log": Path("logs/critical_alerts.log"),
        },
    )
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--test", "--no-bootstrap"], input_func=lambda _: "test")

    assert exit_code == 0
    assert calls == ["linux:test", "windows:test"]


def test_main_runs_linux_collector_for_linux_selection(monkeypatch) -> None:
    """A Linux selection should route through the Linux collector only."""
    calls: list[str] = []
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "linux"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode: calls.append(f"linux:{mode}") or {
            "platform": "linux",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"linux_identity": "data/collected/linux_identity.json"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("windows collector should not run for linux selection")),
    )
    monkeypatch.setattr(
        app,
        "run_identity_risk_engine",
        lambda mode, data_paths, run_id: {
            "run_id": run_id,
            "mode": mode,
            "data_sources": {},
            "data_quality": {"valid": True, "warnings": [], "errors": [], "sources": {}},
            "findings": [],
            "summary": {"counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "identities": []},
        },
    )
    monkeypatch.setattr(
        app,
        "write_reports",
        lambda analysis_result: {
            "text_report": Path("reports/final_identity_risk_report.txt"),
            "executive_summary": Path("reports/executive_summary.txt"),
            "json_report": Path("reports/final_identity_risk_report.json"),
            "alerts_json": Path("data/alerts/alerts.json"),
            "critical_alerts_log": Path("logs/critical_alerts.log"),
        },
    )
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "linux", "--no-bootstrap"], input_func=lambda _: "linux")

    assert exit_code == 0
    assert calls == ["linux:production"]


def test_main_routes_windows_selection_to_windows_collector(monkeypatch) -> None:
    """A Windows selection should route through the Windows collector only."""
    calls: list[str] = []
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows selection")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode: calls.append(f"windows:{mode}") or {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(
        app,
        "run_identity_risk_engine",
        lambda mode, data_paths, run_id: {
            "run_id": run_id,
            "mode": mode,
            "data_sources": {},
            "data_quality": {"valid": True, "warnings": [], "errors": [], "sources": {}},
            "findings": [],
            "summary": {"counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "identities": []},
        },
    )
    monkeypatch.setattr(
        app,
        "write_reports",
        lambda analysis_result: {
            "text_report": Path("reports/final_identity_risk_report.txt"),
            "executive_summary": Path("reports/executive_summary.txt"),
            "json_report": Path("reports/final_identity_risk_report.json"),
            "alerts_json": Path("data/alerts/alerts.json"),
            "critical_alerts_log": Path("logs/critical_alerts.log"),
        },
    )
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "windows")

    assert exit_code == 0
    assert calls == ["windows:production"]
def test_main_safe_exits_when_no_data_exists(monkeypatch) -> None:
    """The application should exit safely when fallback data is unavailable."""
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "test"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode: {
            "platform": "linux",
            "mode": mode,
            "success": False,
            "missing_outputs": ["data/collected/linux_identity.json"],
            "expected_outputs": {"linux_identity": "data/collected/linux_identity.json"},
            "command": {"returncode": 1},
        },
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode: {
            "platform": "windows",
            "mode": mode,
            "success": False,
            "missing_outputs": ["data/collected/windows_identity.csv"],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 1},
        },
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode: {
            "fallback_activated": True,
            "fallback_reason": "no data",
            "no_data_found": True,
            "used_files": {},
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("engine should not run")))
    monkeypatch.setattr(app, "write_reports", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reports should not be written")))
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--test"], input_func=lambda _: "test")

    assert exit_code == 1
