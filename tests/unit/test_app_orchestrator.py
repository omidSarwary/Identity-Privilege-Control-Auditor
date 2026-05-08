"""Tests for the interactive application orchestrator."""

from __future__ import annotations

import os
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
        "--include-manual-linux",
        "--include-manual-windows",
        "--no-manual-cross-evidence",
    ])

    assert args.test is True
    assert args.no_bootstrap is True
    assert args.mode == "test"
    assert args.windows_log_hours == "12"
    assert args.windows_max_events == "500"
    assert args.linux_log_hours == "6"
    assert args.linux_max_events == "250"
    assert args.include_manual_linux is True
    assert args.include_manual_windows is True
    assert args.no_manual_cross_evidence is True


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
        lambda mode, **kwargs: {
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
        lambda mode, **kwargs: {
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
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when linux collector succeeds")))
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
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when linux collector succeeds")))
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
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when windows collector succeeds")))
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
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when windows collector succeeds")))
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
        lambda mode, **kwargs: {
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
        lambda mode, **kwargs: {
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
    assert captured["analysis_result"]["selected_platform"] == "test"


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
        lambda mode, **kwargs: {
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


def test_main_does_not_report_stale_windows_outputs_as_collected(monkeypatch) -> None:
    """The terminal summary should distinguish fresh outputs from stale files."""
    captured_messages: list[str] = []
    captured_ignored_files: list[str] = []
    stale_events = "data/collected/windows_events.csv"
    stale_policy = "data/collected/windows_policy.csv"

    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": False,
            "missing_outputs": [],
            "stale_outputs": [stale_events, stale_policy],
            "current_outputs": ["data/collected/windows_identity.csv"],
            "expected_outputs": {
                "windows_identity": "data/collected/windows_identity.csv",
                "windows_events": stale_events,
                "windows_policy": stale_policy,
            },
            "command": {"returncode": 1, "stderr_summary": "Access is denied."},
            "reason": "access denied; run PowerShell as Administrator",
            "output_statuses": {
                "windows_identity": {
                    "status": "collected",
                    "reason": "output file created",
                    "path": "data/collected/windows_identity.csv",
                },
                "windows_events": {
                    "status": "not collected in this run",
                    "reason": "stale existing file ignored",
                    "path": stale_events,
                },
                "windows_policy": {
                    "status": "not collected in this run",
                    "reason": "stale existing file ignored",
                    "path": stale_policy,
                },
            },
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows selection")))

    def _collect_fallback_data(mode, **kwargs):
        captured_ignored_files.extend(kwargs.get("ignored_collected_files", []))
        return {
            "mode": mode,
            "fallback_activated": True,
            "fallback_reason": "Primary collector output was incomplete.",
            "used_files": {"windows_identity": {"path": "data/incoming/windows_identity.csv"}},
            "missing_files": [],
            "no_data_found": False,
            "searched_directories": ["data/collected", "data/incoming"],
            "warnings": [
                f"Fallback ignored an existing collected file that was not produced by the current run: {stale_events}"
            ],
            "sources": {},
            "payloads": {},
        }

    monkeypatch.setattr(app, "collect_fallback_data", _collect_fallback_data)
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))
    monkeypatch.setattr(app, "print_lines", lambda lines: captured_messages.extend(lines))

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "windows")

    terminal_output = "\n".join(captured_messages)
    assert exit_code == 0
    assert stale_events in captured_ignored_files
    assert stale_policy in captured_ignored_files
    assert "Security events: not collected in this run" in terminal_output
    assert "Policy data: not collected in this run" in terminal_output
    assert "Security events: collected" not in terminal_output
    assert "Warning: Fallback ignored an existing collected file" in terminal_output


def test_main_adds_stale_fallback_warning_to_report_metadata(monkeypatch) -> None:
    """Stale fallback warnings should reach report data quality."""
    captured: dict[str, object] = {}
    warning = (
        "Fallback ignored an existing collected file that was not produced by the current run: "
        "data/collected/windows_events.csv"
    )

    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": False,
            "missing_outputs": [],
            "stale_outputs": ["data/collected/windows_events.csv"],
            "expected_outputs": {"windows_events": "data/collected/windows_events.csv"},
            "command": {"returncode": 1},
            "reason": "collector exited with code 1",
            "output_statuses": {
                "windows_events": {
                    "status": "not collected in this run",
                    "reason": "stale existing file ignored",
                    "path": "data/collected/windows_events.csv",
                }
            },
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows selection")))
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: {
            "mode": mode,
            "fallback_activated": True,
            "fallback_reason": "Primary collector output was incomplete.",
            "used_files": {"windows_identity": {"path": "data/incoming/windows_identity.csv"}},
            "missing_files": [],
            "no_data_found": False,
            "searched_directories": ["data/collected", "data/incoming"],
            "warnings": [warning],
            "sources": {},
            "payloads": {},
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _mock_analysis_result(run_id, mode))

    def _write_reports(analysis_result):
        captured["analysis_result"] = analysis_result
        return _mock_report_paths()

    monkeypatch.setattr(app, "write_reports", _write_reports)
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "windows")

    assert exit_code == 0
    data_quality = captured["analysis_result"]["data_quality"]
    assert warning in data_quality["warnings"]


def test_windows_success_ignores_existing_linux_collected_outputs(monkeypatch, tmp_path) -> None:
    """Successful Windows runs should exclude old automatic Linux outputs."""
    captured_data_paths: dict[str, object] = {}
    captured_report: dict[str, object] = {}
    captured_lines: list[str] = []
    collected_dir = tmp_path / "data" / "collected"
    collected_dir.mkdir(parents=True)
    linux_identity = collected_dir / "linux_identity.json"
    linux_policy = collected_dir / "linux_policy.json"
    linux_identity.write_text('{"mode": "test"}', encoding="utf-8")
    linux_policy.write_text('{"mode": "test"}', encoding="utf-8")

    monkeypatch.setattr(app, "DATA_COLLECTED_DIR", collected_dir)
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "stale_outputs": [],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 0},
            "output_statuses": {
                "windows_identity": {
                    "status": "collected",
                    "reason": "output file created",
                    "path": "data/collected/windows_identity.csv",
                }
            },
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows selection")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when Windows collector succeeds")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    def _write_reports(analysis_result):
        captured_report.update(analysis_result)
        return _mock_report_paths()

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", _write_reports)
    monkeypatch.setattr(app, "print_message", lambda message: captured_lines.append(message))
    monkeypatch.setattr(app, "print_lines", lambda lines: captured_lines.extend(lines))

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "windows")

    assert exit_code == 0
    assert str(linux_identity) in captured_data_paths["excluded_paths"]
    assert str(linux_policy) in captured_data_paths["excluded_paths"]
    report_warnings = "\n".join(captured_report["data_quality"]["warnings"])
    terminal_output = "\n".join(captured_lines)
    assert "Existing Linux collected data was ignored" in report_warnings
    assert "Existing Linux collected data was ignored" in terminal_output


def test_linux_success_ignores_existing_windows_collected_outputs(monkeypatch, tmp_path) -> None:
    """Successful Linux runs should exclude old automatic Windows outputs."""
    captured_data_paths: dict[str, object] = {}
    collected_dir = tmp_path / "data" / "collected"
    collected_dir.mkdir(parents=True)
    windows_identity = collected_dir / "windows_identity.csv"
    windows_events = collected_dir / "windows_events.csv"
    windows_policy = collected_dir / "windows_policy.csv"
    for path in [windows_identity, windows_events, windows_policy]:
        path.write_text("placeholder\n", encoding="utf-8")

    monkeypatch.setattr(app, "DATA_COLLECTED_DIR", collected_dir)
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "linux"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: {
            "platform": "linux",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "stale_outputs": [],
            "expected_outputs": {"linux_identity": "data/collected/linux_identity.json"},
            "command": {"returncode": 0},
            "output_statuses": {
                "linux_identity": {
                    "status": "collected",
                    "reason": "output file created",
                    "path": "data/collected/linux_identity.json",
                }
            },
        },
    )
    monkeypatch.setattr(app, "collect_windows_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run for linux selection")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when Linux collector succeeds")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "linux", "--no-bootstrap"], input_func=lambda _: "linux")

    assert exit_code == 0
    assert str(windows_identity) in captured_data_paths["excluded_paths"]
    assert str(windows_events) in captured_data_paths["excluded_paths"]
    assert str(windows_policy) in captured_data_paths["excluded_paths"]


def test_direct_windows_mode_defaults_to_no_manual_linux(monkeypatch) -> None:
    """Direct CLI Windows runs should not include manual Linux evidence by default."""
    captured_data_paths: dict[str, object] = {}
    captured_report: dict[str, object] = {}

    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    def _write_reports(analysis_result):
        captured_report.update(analysis_result)
        return _mock_report_paths()

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", _write_reports)
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "unused")

    assert exit_code == 0
    assert captured_data_paths["manual_cross_evidence_included"] is False
    assert captured_data_paths["manual_cross_evidence_platform"] == "none"
    assert captured_report["analysis_scope"] == "Windows collector data only"


def test_direct_linux_mode_defaults_to_no_manual_windows(monkeypatch) -> None:
    """Direct CLI Linux runs should not include manual Windows evidence by default."""
    captured_data_paths: dict[str, object] = {}

    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "linux"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: {
            "platform": "linux",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"linux_identity": "data/collected/linux_identity.json"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(app, "collect_windows_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "linux", "--no-bootstrap"], input_func=lambda _: "unused")

    assert exit_code == 0
    assert captured_data_paths["manual_cross_evidence_included"] is False
    assert captured_data_paths["manual_cross_evidence_platform"] == "none"
    assert captured_data_paths["analysis_scope"] == "Linux collector data only"


def test_direct_windows_mode_can_include_manual_linux(monkeypatch, tmp_path) -> None:
    """The manual Linux flag should include Linux evidence in Windows scope."""
    captured_data_paths: dict[str, object] = {}
    logdata_linux = tmp_path / "logdata" / "linux"
    logdata_linux.mkdir(parents=True)
    (logdata_linux / "auth.log").write_text(
        "May 08 10:00:00 host sshd[1]: Failed password for test from 192.0.2.10\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(app, "LOGDATA_DIR", tmp_path / "logdata")
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "windows", "--include-manual-linux", "--no-bootstrap"], input_func=lambda _: "unused")

    assert exit_code == 0
    assert captured_data_paths["manual_cross_evidence_included"] is True
    assert captured_data_paths["manual_cross_evidence_platform"] == "linux"
    assert captured_data_paths["analysis_scope"] == "Windows collector data + manual Linux evidence"


def test_direct_linux_mode_can_include_manual_windows(monkeypatch, tmp_path) -> None:
    """The manual Windows flag should include Windows evidence in Linux scope."""
    captured_data_paths: dict[str, object] = {}
    incoming = tmp_path / "data" / "incoming"
    incoming.mkdir(parents=True)
    (incoming / "windows_events.csv").write_text(
        "ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(app, "DATA_INCOMING_DIR", incoming)
    monkeypatch.setattr(app, "LOGDATA_DIR", tmp_path / "logdata")
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "linux"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: {
            "platform": "linux",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"linux_identity": "data/collected/linux_identity.json"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(app, "collect_windows_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "linux", "--include-manual-windows", "--no-bootstrap"], input_func=lambda _: "unused")

    assert exit_code == 0
    assert captured_data_paths["manual_cross_evidence_included"] is True
    assert captured_data_paths["manual_cross_evidence_platform"] == "windows"
    assert captured_data_paths["analysis_scope"] == "Linux collector data + manual Windows evidence"


def test_interactive_windows_no_manual_linux_keeps_windows_only_scope(monkeypatch) -> None:
    """Interactive Windows users can explicitly decline manual Linux evidence."""
    captured_data_paths: dict[str, object] = {}
    responses = iter(["windows", "1", "100", "n"])

    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--no-bootstrap"], input_func=lambda _: next(responses))

    assert exit_code == 0
    assert captured_data_paths["manual_cross_evidence_included"] is False
    assert captured_data_paths["analysis_scope"] == "Windows collector data only"


def test_interactive_linux_no_manual_windows_keeps_linux_only_scope(monkeypatch) -> None:
    """Interactive Linux users can explicitly decline manual Windows evidence."""
    captured_data_paths: dict[str, object] = {}
    responses = iter(["linux", "1", "100", "n"])

    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "linux"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: {
            "platform": "linux",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"linux_identity": "data/collected/linux_identity.json"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(app, "collect_windows_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--no-bootstrap"], input_func=lambda _: next(responses))

    assert exit_code == 0
    assert captured_data_paths["manual_cross_evidence_included"] is False
    assert captured_data_paths["analysis_scope"] == "Linux collector data only"


def test_windows_fallback_ignores_linux_when_manual_linux_not_included(monkeypatch) -> None:
    """Fallback should not keep Linux-only files for a Windows-only run."""
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": False,
            "missing_outputs": ["data/collected/windows_identity.csv"],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 1},
            "reason": "collector exited with code 1",
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run")))
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: {
            "mode": mode,
            "fallback_activated": True,
            "fallback_reason": "Primary collector output was incomplete.",
            "used_files": {"linux_identity": {"path": "data/incoming/linux_identity.json"}},
            "missing_files": [],
            "no_data_found": False,
            "searched_directories": ["data/incoming"],
            "warnings": [],
            "sources": {"linux_identity": {"selected": True, "warnings": []}},
            "payloads": {"linux_identity": {}},
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("analysis should not run without in-scope evidence")))
    monkeypatch.setattr(app, "write_reports", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reports should not be written")))
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "unused")

    assert exit_code == 1


def test_windows_manual_linux_fallback_ignores_automatic_collected_linux(monkeypatch, tmp_path) -> None:
    """Manual Linux inclusion should not treat old data/collected Linux files as manual evidence."""
    captured_ignored: list[str] = []
    captured_data_paths: dict[str, object] = {}
    collected_dir = tmp_path / "data" / "collected"
    collected_dir.mkdir(parents=True)
    linux_identity = collected_dir / "linux_identity.json"
    linux_policy = collected_dir / "linux_policy.json"
    linux_identity.write_text("{}", encoding="utf-8")
    linux_policy.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(app, "DATA_COLLECTED_DIR", collected_dir)
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": False,
            "missing_outputs": ["data/collected/windows_events.csv"],
            "expected_outputs": {"windows_events": "data/collected/windows_events.csv"},
            "command": {"returncode": 1},
            "reason": "collector exited with code 1",
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run")))

    def _fallback(mode, **kwargs):
        captured_ignored.extend(kwargs.get("ignored_collected_files", []))
        return {
            "mode": mode,
            "fallback_activated": True,
            "fallback_reason": "Primary collector output was incomplete.",
            "used_files": {"windows_identity": {"path": "data/incoming/windows_identity.csv"}},
            "missing_files": [],
            "no_data_found": False,
            "searched_directories": ["data/collected", "data/incoming"],
            "warnings": [],
            "sources": {},
            "payloads": {},
        }

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    monkeypatch.setattr(app, "collect_fallback_data", _fallback)
    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--mode", "windows", "--include-manual-linux", "--no-bootstrap"], input_func=lambda _: "unused")

    assert exit_code == 0
    assert str(linux_identity) in captured_ignored
    assert str(linux_policy) in captured_ignored
    assert str(linux_identity) in captured_data_paths["excluded_paths"]
    assert str(linux_policy) in captured_data_paths["excluded_paths"]


def test_interactive_manual_linux_requested_but_no_files_found_disables_manual_scope(monkeypatch, tmp_path) -> None:
    """If the user requests manual Linux evidence but supplies none, continue Windows-only."""
    captured_data_paths: dict[str, object] = {}
    captured_messages: list[str] = []
    responses = iter(["windows", "1", "100", "y", ""])
    incoming = tmp_path / "data" / "incoming"
    logdata = tmp_path / "logdata"
    (logdata / "linux").mkdir(parents=True)
    incoming.mkdir(parents=True)

    monkeypatch.setattr(app, "DATA_INCOMING_DIR", incoming)
    monkeypatch.setattr(app, "LOGDATA_DIR", logdata)
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))
    monkeypatch.setattr(app, "print_lines", lambda lines: captured_messages.extend(lines))

    exit_code = app.main(["--no-bootstrap"], input_func=lambda _: next(responses))

    terminal = "\n".join(captured_messages)
    assert exit_code == 0
    assert captured_data_paths["manual_cross_evidence_requested"] is True
    assert captured_data_paths["manual_cross_evidence_included"] is False
    assert captured_data_paths["analysis_scope"] == "Windows collector data only"
    assert "No manual Linux evidence files were found" in terminal


def test_manual_linux_auth_log_preexisting_is_reported(monkeypatch, tmp_path) -> None:
    """Existing manual auth.log should be listed and warned as potentially stale."""
    captured_data_paths: dict[str, object] = {}
    captured_report: dict[str, object] = {}
    captured_messages: list[str] = []
    incoming = tmp_path / "data" / "incoming"
    logdata_linux = tmp_path / "logdata" / "linux"
    incoming.mkdir(parents=True)
    logdata_linux.mkdir(parents=True)
    auth_log = logdata_linux / "auth.log"
    auth_log.write_text("May 08 10:00:00 host sshd[1]: Failed password for test from 192.0.2.10\n", encoding="utf-8")
    os.utime(auth_log, (1000.0, 1000.0))

    monkeypatch.setattr(app, "DATA_INCOMING_DIR", incoming)
    monkeypatch.setattr(app, "LOGDATA_DIR", tmp_path / "logdata")
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(app, "collect_linux_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run")))
    monkeypatch.setattr(app, "collect_fallback_data", lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run")))

    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _mock_analysis_result(run_id, mode)

    def _write_reports(analysis_result):
        captured_report.update(analysis_result)
        return _mock_report_paths()

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", _write_reports)
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))
    monkeypatch.setattr(app, "print_lines", lambda lines: captured_messages.extend(lines))

    exit_code = app.main(["--mode", "windows", "--include-manual-linux", "--no-bootstrap"], input_func=lambda _: "unused")

    terminal = "\n".join(captured_messages)
    assert exit_code == 0
    assert captured_data_paths["manual_cross_evidence_included"] is True
    assert str(auth_log) in terminal
    assert "file appears older than this run and may be stale" in terminal
    assert captured_report["manual_cross_evidence_files"][0]["path"] == str(auth_log)
    assert any("may be stale" in warning for warning in captured_report["manual_cross_evidence_warnings"])


def test_wrong_os_linux_mode_reports_clear_guidance_and_safe_exits(monkeypatch, capsys) -> None:
    """Linux mode on an unsupported host should explain the wrong-OS condition."""
    monkeypatch.setattr(app, "_host_supports_platform", lambda platform: (False, "Linux mode was selected, but this appears to be a Windows environment. The Linux Bash collector cannot run here. Run Linux mode from Linux/WSL, or choose Windows mode."))
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "linux"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: {
            "fallback_activated": True,
            "fallback_reason": "No fallback data was found in any configured directory.",
            "no_data_found": True,
            "used_files": {},
            "missing_files": ["linux_identity.json"],
            "searched_directories": ["data/collected"],
            "warnings": [],
        },
    )

    exit_code = app.main(["--mode", "linux", "--no-bootstrap"], input_func=lambda _: "unused")

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "Linux Bash collector cannot run here" in output
    assert output.count("No valid evidence files were found.") == 1


def test_wrong_os_windows_mode_with_manual_evidence_can_continue(monkeypatch, tmp_path) -> None:
    """Wrong-OS preflight may continue when explicit in-scope manual evidence exists."""
    captured_data_paths: dict[str, object] = {}
    incoming = tmp_path / "data" / "incoming"
    incoming.mkdir(parents=True)
    (incoming / "windows_events.csv").write_text(
        "ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "DATA_INCOMING_DIR", incoming)
    monkeypatch.setattr(app, "LOGDATA_DIR", tmp_path / "logdata")
    monkeypatch.setattr(app, "_host_supports_platform", lambda platform: (False, "Windows mode was selected, but this appears to be a Linux environment. The Windows PowerShell collector cannot run here. Choose Linux mode, or provide manually exported Windows evidence."))
    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec", "version": "0.2.0", "default_mode": "windows"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: {
            "fallback_activated": True,
            "fallback_reason": "Primary collector output was incomplete, so fallback sources were used.",
            "no_data_found": False,
            "used_files": {"windows_events": {"path": str(incoming / "windows_events.csv"), "source_directory": str(incoming), "valid": True}},
            "missing_files": [],
            "searched_directories": [str(incoming)],
            "warnings": [],
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: captured_data_paths.update(data_paths) or _mock_analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: _mock_report_paths())

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "unused")

    assert exit_code == 0
    assert captured_data_paths["windows_events"] == str(incoming / "windows_events.csv")
