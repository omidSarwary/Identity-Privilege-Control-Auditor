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
    args = app.parse_args([
        "--test",
        "--no-bootstrap",
        "--mode",
        "test",
        "--windows-log-hours",
        "12",
        "--windows-max-events",
        "500",
        "--linux-log-hours",
        "6",
        "--linux-max-events",
        "250",
    ])

    assert args.test is True
    assert args.no_bootstrap is True
    assert args.mode == "test"
    assert args.windows_log_hours == "12"
    assert args.windows_max_events == "500"
    assert args.linux_log_hours == "6"
    assert args.linux_max_events == "250"


def test_main_skips_platform_collectors_in_test_mode(monkeypatch) -> None:
    """Test mode should rely on mock fallback data instead of platform collectors."""
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "test"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run in test mode")),
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
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run in test mode")),
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
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "linux"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: calls.append((mode, dict(kwargs))) or {
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
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run for linux selection")),
    )
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode: (_ for _ in ()).throw(AssertionError("fallback should not run when linux collector succeeds")))
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "linux", "--no-bootstrap"], input_func=lambda _: "linux")

    assert exit_code == 0
    assert calls[0][0] == "production"
    assert calls[0][1]["log_hours"] == 24
    assert calls[0][1]["max_events"] == 1000


def test_main_passes_linux_collection_window_arguments(monkeypatch) -> None:
    """CLI collection-window values should be forwarded to the Linux collector."""
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "linux"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: calls.append((mode, dict(kwargs))) or {
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
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run for linux selection")),
    )
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode: (_ for _ in ()).throw(AssertionError("fallback should not run when linux collector succeeds")))
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main([
        "--mode",
        "linux",
        "--linux-log-hours",
        "12",
        "--linux-max-events",
        "500",
        "--no-bootstrap",
    ], input_func=lambda _: "linux")

    assert exit_code == 0
    assert calls[0][1]["log_hours"] == 12
    assert calls[0][1]["max_events"] == 500


def test_main_routes_windows_selection_to_windows_collector(monkeypatch) -> None:
    """A Windows selection should route through the Windows collector only."""
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows selection")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: calls.append((mode, dict(kwargs))) or {
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
    assert calls[0][0] == "production"
    assert calls[0][1]["log_hours"] == 24
    assert calls[0][1]["max_events"] == 1000


def test_main_passes_windows_collection_window_arguments(monkeypatch) -> None:
    """CLI collection-window values should be forwarded to the Windows collector."""
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows selection")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: calls.append((mode, dict(kwargs))) or {
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

    exit_code = app.main([
        "--mode",
        "windows",
        "--windows-log-hours",
        "12",
        "--windows-max-events",
        "500",
        "--no-bootstrap",
    ], input_func=lambda _: "windows")

    assert exit_code == 0
    assert calls[0][1]["log_hours"] == 12
    assert calls[0][1]["max_events"] == 500


def test_main_safe_exits_when_no_data_exists(monkeypatch) -> None:
    """The application should exit safely when fallback data is unavailable."""
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "test"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run in test mode")),
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


def test_main_passes_fallback_metadata_to_report_writer(monkeypatch) -> None:
    """The orchestrator should forward fallback status to the reporting layer."""
    captured: dict[str, object] = {}
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "test"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run in test mode")))
    monkeypatch.setattr(app, "collect_windows_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run in test mode")))
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
    def _write_reports(analysis_result):
        captured["analysis_result"] = analysis_result
        return _mock_report_paths()

    monkeypatch.setattr(app, "write_reports", _write_reports)
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--test", "--no-bootstrap"], input_func=lambda _: "test")

    assert exit_code == 0
    assert captured["analysis_result"]["fallback_used"] is True
    assert captured["analysis_result"]["fallback_reason"] == "mockdata used"


def test_main_reports_fallback_reason_for_incomplete_collection(monkeypatch) -> None:
    """Collector failures should explain why fallback was used in the console."""
    captured_messages: list[str] = []
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": False,
            "missing_outputs": ["windows_identity.csv"],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 1, "stderr_summary": "Access is denied."},
            "reason": "access denied; run PowerShell as Administrator",
            "output_statuses": {
                "windows_identity": {
                    "status": "failed",
                    "reason": "access denied; run PowerShell as Administrator",
                    "path": "data/collected/windows_identity.csv",
                }
            },
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows selection")))
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode: {
            "mode": mode,
            "fallback_activated": True,
            "fallback_reason": "Primary collector output was incomplete.",
            "used_files": {"windows_identity": {"path": "tests/mockdata/windows_identity.csv"}},
            "missing_files": [],
            "no_data_found": False,
            "searched_directories": ["data/collected", "data/incoming"],
            "sources": {},
            "payloads": {},
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "windows")

    assert exit_code == 0
    assert any("Fallback used: Yes." in message and "Primary collector output was incomplete." in message for message in captured_messages)
