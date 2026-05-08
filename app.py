"""Main entry point for the NordSec Identity & Privilege Control Auditor.

This phase turns the application into a lightweight interactive orchestrator.
It shows the splashscreen, collects a platform choice, performs safe bootstrap
checks, uses the fallback collector to confirm evidence is available, runs the
identity risk engine, and writes the final reports.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from src.analysis.identity_risk_engine import run_identity_risk_engine
from src.collectors.linux_collector import collect_linux_data
from src.collectors.fallback_collector import collect_fallback_data
from src.collectors.windows_collector import collect_windows_data
from src.core.bootstrap import bootstrap_project, load_app_config
from src.core.paths import (
    BASELINES_DIR,
    PRODUCTION_CONFIG_FILE,
    TEST_CONFIG_FILE,
)
from src.core.platform_manager import choose_platform
from src.parsers.json_loader import load_json_file
from src.reporting.report_writer import write_reports
from src.utils.console import (
    build_privilege_notice,
    format_banner,
    format_section_title,
    format_status_line,
    print_lines,
    print_message,
)
from src.utils.logging_config import get_component_logger, setup_logging
from src.utils.safe_exit import safe_exit


def create_run_id() -> str:
    """Create a stable UTC run identifier for logs and reports."""
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def build_run_id() -> str:
    """Backward-compatible alias for the run-id helper used in earlier phases."""
    return create_run_id()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the supported interactive CLI flags.

    Expects an optional sequence of argument strings and returns the parsed
    namespace. The parser stays intentionally small so the orchestrator remains
    easy to understand and test.
    """
    parser = argparse.ArgumentParser(
        description="NordSec Identity & Privilege Control Auditor",
    )
    parser.add_argument(
        "--mode",
        choices=("linux", "windows", "test"),
        help="Select the runtime platform or test mode explicitly.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Shortcut for test mode with mock data.",
    )
    parser.add_argument(
        "--no-bootstrap",
        action="store_true",
        help="Skip the extended bootstrap checks and continue with safe defaults.",
    )
    parser.add_argument(
        "--windows-log-hours",
        help="Windows Security log lookback window in hours.",
    )
    parser.add_argument(
        "--windows-max-events",
        help="Maximum Windows Security events to collect.",
    )
    parser.add_argument(
        "--linux-log-hours",
        help="Linux log lookback window in hours.",
    )
    parser.add_argument(
        "--linux-max-events",
        help="Maximum Linux log lines or events to collect.",
    )
    return parser.parse_args(argv)


def _mode_config_path(analysis_mode: str) -> Path:
    """Return the mode-specific configuration file without duplicating paths."""
    return TEST_CONFIG_FILE if analysis_mode == "test" else PRODUCTION_CONFIG_FILE


def _build_data_paths(mode_config: dict[str, object]) -> dict[str, object]:
    """Build the data-path mapping used by the analysis engine."""
    data_paths = dict(mode_config.get("paths", {}))
    data_paths["baselines"] = str(BASELINES_DIR)
    return data_paths


def _run_platform_collectors(platform_selection: object) -> list[dict[str, object]]:
    """Run the approved collector modules for the selected platform.

    The application uses the Linux Bash sensor for Linux runs and the
    PowerShell sensor for Windows runs. Test mode skips platform collectors
    entirely and relies on fallback/mock data so it stays safe on any host.
    """
    platform = str(getattr(platform_selection, "platform", "")).strip().lower()
    analysis_mode = str(getattr(platform_selection, "analysis_mode", "production")).strip().lower()

    if platform == "test":
        return []
    if platform == "linux":
        return [
            collect_linux_data(
                mode=analysis_mode,
                log_hours=getattr(platform_selection, "log_hours", 24),
                max_events=getattr(platform_selection, "max_events", 1000),
            )
        ]
    if platform == "windows":
        return [
            collect_windows_data(
                mode=analysis_mode,
                log_hours=getattr(platform_selection, "log_hours", 24),
                max_events=getattr(platform_selection, "max_events", 1000),
            )
        ]

    return []


def _collectors_succeeded(collector_results: list[dict[str, object]]) -> bool:
    """Return ``True`` when every collector completed and created its outputs."""
    return all(bool(result.get("success")) for result in collector_results)


def _collector_results_to_used_files(collector_results: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    """Translate collector output paths into the fallback-style summary format."""
    used_files: dict[str, dict[str, object]] = {}
    for result in collector_results:
        if not result.get("success"):
            continue
        expected_outputs = result.get("expected_outputs", {})
        if not isinstance(expected_outputs, dict):
            continue
        for name, path in expected_outputs.items():
            path_obj = Path(str(path))
            used_files[str(name)] = {
                "path": str(path_obj),
                "source_directory": str(path_obj.parent),
                "valid": True,
            }
    return used_files


def _apply_collector_output_paths(
    data_paths: dict[str, object],
    collector_results: list[dict[str, object]],
) -> dict[str, object]:
    """Prefer fresh collector outputs when a platform collector succeeded.

    The analysis engine resolves explicit source keys before generic
    directories. Adding the successful collector outputs here prevents older
    manual files in ``data/incoming`` from being analyzed while the console says
    fresh collector evidence was used.
    """
    updated_paths = dict(data_paths)
    for result in collector_results:
        if not result.get("success"):
            continue
        expected_outputs = result.get("expected_outputs", {})
        if not isinstance(expected_outputs, dict):
            continue
        for source_name, path in expected_outputs.items():
            updated_paths[str(source_name)] = str(path)
    return updated_paths


def _build_collector_fallback_result(
    *,
    collector_results: list[dict[str, object]],
    analysis_mode: str,
) -> dict[str, object]:
    """Build a fallback-style summary when platform collectors succeeded.

    This keeps the console summary and reporting flow consistent without
    invoking the fallback searcher unnecessarily.
    """
    used_files = _collector_results_to_used_files(collector_results)
    return {
        "mode": analysis_mode,
        "fallback_activated": False,
        "fallback_reason": "Platform collectors produced usable outputs.",
        "searched_directories": [],
        "used_files": used_files,
        "missing_files": [],
        "no_data_found": not bool(used_files),
        "sources": {},
        "payloads": {},
    }


def _collector_status_text(collector_result: dict[str, object]) -> str:
    """Build a clear collector status string for logging.

    The log line explains whether the collector command failed, whether output
    files were missing, or whether both conditions occurred. This avoids the
    misleading ``missing_outputs=none`` text when the command itself failed.
    """
    success = bool(collector_result.get("success"))
    command_info = collector_result.get("command", {})
    if isinstance(command_info, dict):
        returncode = command_info.get("returncode", "unknown")
    else:
        returncode = "unknown"

    missing_outputs = collector_result.get("missing_outputs", [])
    missing_text = ", ".join(str(item) for item in missing_outputs) if missing_outputs else "none"
    if success:
        return f"success=True returncode={returncode} missing_outputs={missing_text}"
    return f"success=False returncode={returncode} missing_outputs={missing_text}"


def _collector_name(platform: str) -> str:
    """Return a title-cased collector name for the console."""
    normalized = platform.strip().lower()
    if normalized == "windows":
        return "Windows"
    if normalized == "linux":
        return "Linux"
    if normalized == "test":
        return "Test"
    return platform.title() or "Collector"


def _collector_evidence_lines(collector_result: dict[str, object], platform: str) -> list[str]:
    """Build short user-facing evidence lines from one collector result."""
    output_statuses = collector_result.get("output_statuses", {})
    lines: list[str] = []
    if isinstance(output_statuses, dict) and output_statuses:
        for key, details in output_statuses.items():
            if not isinstance(details, dict):
                continue
            label = {
                "linux_identity": "Identity data",
                "linux_policy": "Policy data",
                "windows_identity": "Identity data",
                "windows_events": "Security events",
                "windows_policy": "Policy data",
            }.get(str(key), str(key))
            status = str(details.get("status", "unknown"))
            reason = str(details.get("reason") or "").strip() or None
            lines.append(format_status_line(label, status, reason))
        return lines

    expected_outputs = collector_result.get("expected_outputs", {})
    if isinstance(expected_outputs, dict) and expected_outputs:
        for key in expected_outputs:
            label = {
                "linux_identity": "Identity data",
                "linux_policy": "Policy data",
                "windows_identity": "Identity data",
                "windows_events": "Security events",
                "windows_policy": "Policy data",
            }.get(str(key), str(key))
            lines.append(format_status_line(label, "collected", None))
    else:
        lines.append(format_status_line(f"{_collector_name(platform)} evidence", "unknown", "no collector metadata available"))
    return lines


def _collector_summary_state(collector_result: dict[str, object]) -> str:
    """Translate a collector result into a short overall state."""
    if bool(collector_result.get("success")):
        return "success"
    if collector_result.get("reason"):
        return f"incomplete: {collector_result.get('reason')}"
    return "incomplete"


def _collector_has_warning(collector_result: dict[str, object]) -> bool:
    """Return ``True`` when a collector produced outputs but still warned."""
    command_info = collector_result.get("command", {})
    if not isinstance(command_info, dict):
        return False
    return bool(collector_result.get("success")) and command_info.get("returncode") not in (None, 0)


def _fallback_console_reason(
    *,
    platform: str,
    fallback_result: dict[str, object],
    collector_results: list[dict[str, object]],
) -> str:
    """Build the fallback explanation shown in the terminal."""
    if platform == "test":
        return "Fallback used because test mode uses mockdata."
    if fallback_result.get("fallback_activated"):
        return str(fallback_result.get("fallback_reason") or "Primary collector output was incomplete.")
    if _collectors_succeeded(collector_results):
        return "Fallback not used because the primary collector outputs were used."
    return "Fallback used because the primary collector output was incomplete."


def _fallback_file_lines(fallback_result: dict[str, object]) -> list[str]:
    """Build readable lines about fallback file selection."""
    if fallback_result.get("no_data_found"):
        missing_files = fallback_result.get("missing_files", [])
        missing_text = ", ".join(str(item) for item in missing_files) if missing_files else "none"
        searched = fallback_result.get("searched_directories", [])
        searched_text = ", ".join(str(item) for item in searched) if searched else "none"
        return [
            "Fallback found no usable evidence files.",
            f"Search order: {searched_text}",
            f"Missing files: {missing_text}",
            "No valid evidence files were found. Place exported logs in data/incoming/ or logdata/linux/ or logdata/windows/ and run again.",
        ]

    used_files = fallback_result.get("used_files", {})
    if isinstance(used_files, dict) and used_files:
        files = ", ".join(f"{name}={info.get('path')}" for name, info in used_files.items() if isinstance(info, dict))
        if fallback_result.get("fallback_activated"):
            return [f"Fallback found usable files: {files}"]
        return [f"Collected files in use: {files}"]
    return ["Fallback found partial files only."]


def _analysis_source_label(fallback_result: dict[str, object]) -> str:
    """Return the evidence source label used by analysis."""
    return "fallback data" if fallback_result.get("fallback_activated") else "collector data"


def _report_lines(report_paths: dict[str, Path]) -> list[str]:
    """Format report artifact paths for the console."""
    label_map = {
        "text_report": "text report",
        "executive_summary": "executive summary",
        "json_report": "JSON report",
        "alerts_json": "alerts",
        "critical_alerts_log": "critical alerts",
    }
    lines = []
    for name, path in report_paths.items():
        lines.append(format_status_line(label_map.get(name, name), "generated", str(path)))
    return lines


def _collector_reason(collector_result: dict[str, object]) -> str:
    """Return the best short reason available for a collector result."""
    reason = str(collector_result.get("reason") or "").strip()
    if reason:
        return reason
    command = collector_result.get("command", {})
    if isinstance(command, dict):
        stderr_summary = str(command.get("stderr_summary") or "").strip()
        if stderr_summary:
            return stderr_summary
        stdout_summary = str(command.get("stdout_summary") or "").strip()
        if stdout_summary:
            return stdout_summary
        if command.get("timed_out"):
            return "collector timed out"
        returncode = command.get("returncode")
        if returncode not in (None, 0):
            return f"collector exited with code {returncode}"
    return "unknown error, see log file"


def _format_final_summary(
    *,
    platform: str,
    analysis_result: dict[str, object],
    report_paths: dict[str, Path],
    fallback_result: dict[str, object],
) -> str:
    """Build a concise final summary for the console."""
    summary = analysis_result.get("summary", {}) if isinstance(analysis_result, dict) else {}
    counts = summary.get("counts", {}) if isinstance(summary, dict) else {}
    lines = [
        "Final summary",
        f"Platform: {platform}",
        f"Run ID: {analysis_result.get('run_id', 'unknown')}",
        f"Findings: {len(analysis_result.get('findings', []))}",
        f"Critical: {counts.get('CRITICAL', 0)}",
        f"High: {counts.get('HIGH', 0)}",
        f"Medium: {counts.get('MEDIUM', 0)}",
        f"Low: {counts.get('LOW', 0)}",
        f"Analysis source: {'fallback data' if fallback_result.get('fallback_activated') else 'collector data'}",
        f"Fallback used: {'Yes' if fallback_result.get('fallback_activated') else 'No'}",
        "Reports:",
    ]
    lines.extend(f"- {name}: {path}" for name, path in report_paths.items())
    return "\n".join(lines)


def _attach_report_metadata(
    analysis_result: dict[str, object],
    fallback_result: dict[str, object],
    *,
    selected_platform: str,
) -> dict[str, object]:
    """Attach report-only metadata to the analysis result.

    The analysis output stays unchanged, but the reporting layer needs a clear
    fallback marker so the console, text report, and JSON report describe the
    same execution path.
    """
    report_result = dict(analysis_result)
    report_result["fallback_used"] = bool(fallback_result.get("fallback_activated"))
    report_result["fallback_reason"] = fallback_result.get("fallback_reason")
    report_result["selected_platform"] = selected_platform
    return report_result


def main(argv: Sequence[str] | None = None, input_func: Callable[[str], str] = input) -> int:
    """Run the application orchestrator and return a controlled exit code.

    Expects optional CLI arguments and an input function so the interactive
    platform prompt can be tested. The function only orchestrates existing
    modules: it does not collect system data directly or implement analysis
    logic itself.
    """
    args = parse_args(argv)
    run_id = create_run_id()
    setup_logging(run_id=run_id, debug=False)
    logger = get_component_logger("app", run_id)

    try:
        app_config = load_app_config()
        project_name = str(app_config.get("project_name", "NordSec Identity & Privilege Control Auditor"))
        project_version = str(app_config.get("version", "0.0.0"))
        banner_mode = "test" if (args.test or args.mode == "test") else ("production" if args.mode in {"linux", "windows"} else "interactive")

        logger.info("Program start")
        print_message(format_banner(project_name, project_version, banner_mode))

        requested_platform = "test" if args.test else args.mode
        platform_selection = choose_platform(
            requested_platform=requested_platform,
            test_flag=args.test,
            input_func=input_func,
            windows_log_hours=args.windows_log_hours,
            windows_max_events=args.windows_max_events,
            linux_log_hours=args.linux_log_hours,
            linux_max_events=args.linux_max_events,
        )
        print_message(platform_selection.instructions)
        print_message(build_privilege_notice(platform_selection.platform, test_mode=platform_selection.use_mockdata))
        print_message(f"Selected platform: {platform_selection.platform}")
        logger.info("Selected platform: %s", platform_selection.platform)
        if platform_selection.platform != "test":
            print_message(
                f"Collection window: {platform_selection.log_hours} hours, max {platform_selection.max_events} events/lines"
            )
        else:
            print_message("Collection window: mockdata only")
        logger.info(
            "Collection window resolved: platform=%s mode=%s log_hours=%s max_events=%s",
            platform_selection.platform,
            platform_selection.analysis_mode,
            platform_selection.log_hours,
            platform_selection.max_events,
        )

        logger.info("Environment checks starting")
        print_message(format_section_title(1, 6, "Environment checks started."))
        bootstrap_status = bootstrap_project(perform_full_checks=not args.no_bootstrap)
        if not bootstrap_status.environment.python_ok:
            for message in bootstrap_status.environment.messages:
                logger.error(message)
            return safe_exit(logger, 1, "Python version check failed")

        if not bootstrap_status.environment.required_directories_ok:
            for missing_directory in bootstrap_status.environment.missing_directories:
                logger.error("Missing directory: %s", missing_directory)
            return safe_exit(logger, 1, "Required directory check failed")

        logger.info("Environment checks completed")
        print_message(format_section_title(1, 6, "Environment checks completed."))

        mode_config_path = _mode_config_path(platform_selection.analysis_mode)
        mode_config = load_json_file(mode_config_path)
        data_paths = _build_data_paths(mode_config)
        logger.info("Analysis configuration loaded from %s", mode_config_path)

        logger.info("Evidence collection starting for platform=%s mode=%s", platform_selection.platform, platform_selection.analysis_mode)
        print_message(format_section_title(2, 6, f"Collecting {_collector_name(platform_selection.platform)} evidence."))
        collector_results = _run_platform_collectors(platform_selection)
        if platform_selection.platform == "test":
            print_message("Test mode uses mockdata; platform collectors are skipped.")
        for collector_result in collector_results:
            collector_platform = str(collector_result.get("platform", platform_selection.platform))
            logger.info(
                "Collector result: platform=%s mode=%s %s",
                collector_platform,
                collector_result.get("mode", platform_selection.analysis_mode),
                _collector_status_text(collector_result),
            )
            print_lines(_collector_evidence_lines(collector_result, collector_platform))
            print_message(f"{_collector_name(collector_platform)} collector result: {_collector_summary_state(collector_result)}")
            if not bool(collector_result.get("success")):
                print_message(f"Reason: {_collector_reason(collector_result)}")
            elif _collector_has_warning(collector_result):
                print_message(
                    f"Collector warning: {_collector_reason(collector_result)}. Collected files will be used."
                )
        logger.info("Collector phase completed with %s result(s)", len(collector_results))

        if not collector_results:
            fallback_result = collect_fallback_data(mode=platform_selection.analysis_mode)
        elif _collectors_succeeded(collector_results):
            fallback_result = _build_collector_fallback_result(
                collector_results=collector_results,
                analysis_mode=platform_selection.analysis_mode,
            )
            data_paths = _apply_collector_output_paths(data_paths, collector_results)
        else:
            fallback_result = collect_fallback_data(mode=platform_selection.analysis_mode)

        print_message(format_section_title(3, 6, "Fallback check."))
        print_message(
            f"Fallback used: {'Yes' if fallback_result.get('fallback_activated') else 'No'}. "
            f"Reason: {_fallback_console_reason(platform=platform_selection.platform, fallback_result=fallback_result, collector_results=collector_results)}"
        )
        print_lines(_fallback_file_lines(fallback_result))
        logger.info(
            "Fallback summary: activated=%s used_files=%s reason=%s",
            fallback_result.get("fallback_activated"),
            len(fallback_result.get("used_files", {})),
            fallback_result.get("fallback_reason", "n/a"),
        )

        if fallback_result.get("no_data_found"):
            return safe_exit(
                logger,
                1,
                "No valid evidence files were found. Place exported logs in data/incoming/ or logdata/linux/ or logdata/windows/ and run again.",
            )

        print_message(format_section_title(4, 6, "Analysis started."))
        print_message(f"Analysis data source: {_analysis_source_label(fallback_result)}.")
        try:
            analysis_result = run_identity_risk_engine(
                mode=platform_selection.analysis_mode,
                data_paths=data_paths,
                run_id=run_id,
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Analysis failed: %s", exc)
            return safe_exit(logger, 1, f"Analysis failed: {str(exc).splitlines()[0] or 'unknown error, see log file'}")
        print_message(format_section_title(4, 6, "Analysis completed."))
        report_analysis_result = _attach_report_metadata(
            analysis_result,
            fallback_result,
            selected_platform=platform_selection.platform,
        )
        print_message(format_section_title(5, 6, "Report generation started."))
        try:
            report_paths = write_reports(report_analysis_result)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Report generation failed: %s", exc)
            return safe_exit(logger, 1, f"Report generation failed: {str(exc).splitlines()[0] or 'unknown error, see log file'}")
        print_message("Reports generated.")
        print_lines(_report_lines(report_paths))
        print_message(
            _format_final_summary(
                platform=platform_selection.platform,
                analysis_result=analysis_result,
                report_paths=report_paths,
                fallback_result=fallback_result,
            )
        )
        logger.info(
            "Analysis completed with %s findings across %s identities",
            len(analysis_result.get("findings", [])),
            len(analysis_result.get("summary", {}).get("identities", [])),
        )
        logger.info("Report artifacts created: %s", ", ".join(f"{name}={path}" for name, path in report_paths.items()))
        return safe_exit(logger, 0, format_section_title(6, 6, "Safe exit."))
    except Exception as exc:  # pragma: no cover - defensive bootstrap guard
        logger.exception("Unhandled bootstrap error: %s", exc)
        return safe_exit(logger, 1, "Unhandled bootstrap error")


if __name__ == "__main__":
    raise SystemExit(main())
