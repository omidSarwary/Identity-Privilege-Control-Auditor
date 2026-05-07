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
from src.utils.console import format_banner, print_message
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
        return [collect_linux_data(mode=analysis_mode)]
    if platform == "windows":
        return [collect_windows_data(mode=analysis_mode)]

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
        "fallback_reason": "Platform collectors completed successfully.",
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
        f"Fallback used: {'Yes' if fallback_result.get('fallback_activated') else 'No'}",
        "Reports:",
    ]
    lines.extend(f"- {name}: {path}" for name, path in report_paths.items())
    return "\n".join(lines)


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
        )
        print_message(platform_selection.instructions)
        logger.info("Selected platform: %s", platform_selection.platform)

        bootstrap_status = bootstrap_project(perform_full_checks=not args.no_bootstrap)
        if not bootstrap_status.environment.python_ok:
            for message in bootstrap_status.environment.messages:
                logger.error(message)
            return safe_exit(logger, 1, "Python version check failed")

        if not bootstrap_status.environment.required_directories_ok:
            for missing_directory in bootstrap_status.environment.missing_directories:
                logger.error("Missing directory: %s", missing_directory)
            return safe_exit(logger, 1, "Required directory check failed")

        mode_config_path = _mode_config_path(platform_selection.analysis_mode)
        mode_config = load_json_file(mode_config_path)
        data_paths = _build_data_paths(mode_config)

        collector_results = _run_platform_collectors(platform_selection)
        for collector_result in collector_results:
            logger.info(
                "Collector result: platform=%s mode=%s %s",
                collector_result.get("platform", "unknown"),
                collector_result.get("mode", platform_selection.analysis_mode),
                _collector_status_text(collector_result),
            )

        if not collector_results:
            fallback_result = collect_fallback_data(mode=platform_selection.analysis_mode)
        elif _collectors_succeeded(collector_results):
            fallback_result = _build_collector_fallback_result(
                collector_results=collector_results,
                analysis_mode=platform_selection.analysis_mode,
            )
        else:
            fallback_result = collect_fallback_data(mode=platform_selection.analysis_mode)

        if fallback_result.get("no_data_found"):
            print_message("No usable data was found. The application will exit safely.")
            return safe_exit(logger, 1, "No data found for analysis")

        analysis_result = run_identity_risk_engine(
            mode=platform_selection.analysis_mode,
            data_paths=data_paths,
            run_id=run_id,
        )
        report_paths = write_reports(analysis_result)

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
        return safe_exit(logger, 0, "Safe exit")
    except Exception as exc:  # pragma: no cover - defensive bootstrap guard
        logger.exception("Unhandled bootstrap error: %s", exc)
        return safe_exit(logger, 1, "Unhandled bootstrap error")


if __name__ == "__main__":
    raise SystemExit(main())
