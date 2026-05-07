"""Integration tests for the production-mode application flow."""

from __future__ import annotations

from pathlib import Path

import app
from src.core.bootstrap import BootstrapStatus
from src.core.environment import EnvironmentStatus
from src.reporting.report_writer import write_reports


def _bootstrap_status() -> BootstrapStatus:
    """Build a healthy bootstrap result so production flow tests stay focused."""
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


def _analysis_result(run_id: str, mode: str) -> dict[str, object]:
    """Build a minimal analysis result used by the production-mode tests."""
    return {
        "run_id": run_id,
        "mode": mode,
        "data_sources": {},
        "data_quality": {"valid": True, "warnings": [], "errors": [], "sources": {}},
        "findings": [],
        "summary": {"counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "identities": []},
    }


def _report_paths(output_root: Path) -> dict[str, Path]:
    """Return the report paths generated under the temporary output root."""
    return {
        "text_report": output_root / "reports" / "final_identity_risk_report.txt",
        "executive_summary": output_root / "reports" / "executive_summary.txt",
        "json_report": output_root / "reports" / "final_identity_risk_report.json",
        "alerts_json": output_root / "data" / "alerts" / "alerts.json",
        "critical_alerts_log": output_root / "logs" / "critical_alerts.log",
    }


def test_linux_production_mode_shows_manual_windows_guidance_and_generates_reports(monkeypatch, tmp_path) -> None:
    """Linux production mode should explain manual Windows evidence handling.

    The application should route to the Linux collector, keep the flow read
    only, and still generate reports when the collector succeeds.
    """
    fixed_run_id = "20260507-130000"
    captured_messages: list[str] = []

    monkeypatch.setattr(app, "create_run_id", lambda: fixed_run_id)
    monkeypatch.setattr(
        app,
        "load_app_config",
        lambda: {"project_name": "NordSec Identity & Privilege Control Auditor", "version": "0.2.0"},
    )
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
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run for linux production mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when Linux collector succeeds")),
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: write_reports(analysis_result, output_root=tmp_path))
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))

    exit_code = app.main(["--mode", "linux", "--no-bootstrap"], input_func=lambda _: "linux")

    assert exit_code == 0
    assert any("Linux logs will be collected automatically" in message for message in captured_messages)
    assert any("Environment checks started." in message for message in captured_messages)
    assert any("Collecting available evidence." in message for message in captured_messages)
    assert any("Reports generated." in message for message in captured_messages)
    assert _report_paths(tmp_path)["json_report"].exists()


def test_windows_production_mode_shows_manual_linux_guidance_and_safe_exits(monkeypatch) -> None:
    """Windows production mode should explain manual Linux evidence handling.

    When the collector fails and fallback cannot find usable evidence, the app
    must exit cleanly without a traceback in the user-facing flow.
    """
    captured_messages: list[str] = []

    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec Identity & Privilege Control Auditor", "version": "0.2.0"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows production mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": False,
            "missing_outputs": ["windows_identity.csv"],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 1},
        },
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: {
            "mode": mode,
            "fallback_activated": True,
            "fallback_reason": "no usable data",
            "used_files": {},
            "missing_files": ["windows_identity.csv"],
            "no_data_found": True,
            "searched_directories": [],
            "sources": {},
            "payloads": {},
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("engine should not run when no data exists")))
    monkeypatch.setattr(app, "write_reports", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reports should not be written when no data exists")))
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "windows")

    assert exit_code == 1
    assert any("Windows logs will be collected automatically" in message for message in captured_messages)
    assert any("No usable data was found. The application will exit safely." in message for message in captured_messages)
