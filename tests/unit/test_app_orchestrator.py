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


def _mock_analysis_result(run_id: str, mode: str) -> dict[str, object]:
    """Build a minimal analysis result used by the orchestrator tests."""
    return {
        "run_id": run_id,
        "mode": mode,
        "data_sources": {},
        "data_quality": {"valid": True, "warnings": [], "errors": [], "sources": {}},
        "findings": [],
        "summary": {"counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "identities": []},
    }


def _mock_report_paths() -> dict[str, Path]:
    """Build deterministic report paths for orchestrator tests."""
    return {
        "text_report": Path("reports/final_identity_risk_report.txt"),
        "executive_summary": Path("reports/executive_summary.txt"),
        "json_report": Path("reports/final_identity_risk_report.json"),
        "alerts_json": Path("data/alerts/alerts.json"),
        "critical_alerts_log": Path("logs/critical_alerts.log"),
    }


def test_parse_args_supports_orchestrator_flags() -> None:
    """The CLI should expose the documented orchestration flags."""
    args = app.parse_args(["--test", "--no-bootstrap", "--mode", "test"])

    assert args.test is True
    assert args.no_bootstrap is True
    assert args.mode == "test"


def test_main_skips_platform_collectors_in_test_mode(monkeypatch) -> None:
    """Test mode should rely on mock fallback data instead of platform collectors."""
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "test"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("linux collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("windows collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode: {
            "fallback_activated": True,
            "fallback_reason": "mockdata used",
            "no_data_found": False,
            "used_files": {"linux_identity": {"path": "tests/mockdata/linux_identity.json"}},
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--test", "--no-bootstrap"], input_func=lambda _: "test")

    assert exit_code == 0


def test_main_skips_platform_collectors_in_mode_test(monkeypatch) -> None:
    """Explicit test mode should behave the same as the ``--test`` shortcut."""
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "test"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("linux collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("windows collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode: {
            "fallback_activated": True,
            "fallback_reason": "mockdata used",
            "no_data_found": False,
            "used_files": {"windows_identity": {"path": "tests/mockdata/windows_identity.csv"}},
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "test", "--no-bootstrap"], input_func=lambda _: "test")

    assert exit_code == 0


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
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode: (_ for _ in ()).throw(AssertionError("fallback should not run when linux collector succeeds")))
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
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
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode: (_ for _ in ()).throw(AssertionError("fallback should not run when windows collector succeeds")))
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
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
        lambda mode: (_ for _ in ()).throw(AssertionError("linux collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("windows collector should not run in test mode")),
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
