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
import platform as host_platform
import time
from typing import Callable, Sequence

from src.analysis.identity_risk_engine import run_identity_risk_engine
from src.collectors.linux_collector import collect_linux_data
from src.collectors.fallback_collector import collect_fallback_data
from src.collectors.windows_collector import collect_windows_data
from src.core.bootstrap import bootstrap_project, load_app_config
from src.core.paths import (
    BASELINES_DIR,
    DATA_COLLECTED_DIR,
    DATA_INCOMING_DIR,
    LOGDATA_DIR,
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
from src.utils.logging_config import RuntimeLoggingError, get_component_logger, setup_logging, verify_logging_path_writable
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
    parser.add_argument(
        "--include-manual-linux",
        action="store_true",
        help="Include manually exported Linux evidence during a Windows production run.",
    )
    parser.add_argument(
        "--include-manual-windows",
        action="store_true",
        help="Include manually exported Windows evidence during a Linux production run.",
    )
    parser.add_argument(
        "--no-manual-cross-evidence",
        action="store_true",
        help="Do not include evidence from the non-selected operating system.",
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


def _analysis_scope(
    selected_platform: str,
    *,
    manual_cross_evidence_included: bool,
    manual_cross_evidence_platform: str,
) -> str:
    """Describe which evidence families are intentionally in scope."""
    platform = selected_platform.strip().lower()
    if platform == "test":
        return "Test mockdata pipeline"
    if manual_cross_evidence_included and manual_cross_evidence_platform == "linux":
        return "Windows collector data + manual Linux evidence"
    if manual_cross_evidence_included and manual_cross_evidence_platform == "windows":
        return "Linux collector data + manual Windows evidence"
    if platform == "windows":
        return "Windows collector data only"
    if platform == "linux":
        return "Linux collector data only"
    return "Selected platform collector data only"


def _manual_evidence_candidates(platform: str) -> dict[str, Path]:
    """Return approved manual evidence candidates for the opposite OS.

    The list is deliberately limited to documented manual locations so old
    automatic collector files in ``data/collected`` cannot be mistaken for
    user-supplied cross-platform evidence.
    """
    normalized = platform.strip().lower()
    if normalized == "linux":
        return {
            "linux_identity": DATA_INCOMING_DIR / "linux_identity.json",
            "linux_policy": DATA_INCOMING_DIR / "linux_policy.json",
            "auth_log_incoming": DATA_INCOMING_DIR / "auth.log",
            "auth_log": LOGDATA_DIR / "linux" / "auth.log",
        }
    if normalized == "windows":
        return {
            "windows_identity": DATA_INCOMING_DIR / "windows_identity.csv",
            "windows_events": DATA_INCOMING_DIR / "windows_events.csv",
            "windows_security_events": DATA_INCOMING_DIR / "security_events.csv",
            "windows_eventviewer_export": DATA_INCOMING_DIR / "eventviewer_export.csv",
            "windows_policy": DATA_INCOMING_DIR / "windows_policy.csv",
            "windows_identity_logdata": LOGDATA_DIR / "windows" / "windows_identity.csv",
            "windows_events_logdata": LOGDATA_DIR / "windows" / "windows_events.csv",
            "windows_security_events_logdata": LOGDATA_DIR / "windows" / "security_events.csv",
            "windows_eventviewer_export_logdata": LOGDATA_DIR / "windows" / "eventviewer_export.csv",
            "windows_policy_logdata": LOGDATA_DIR / "windows" / "windows_policy.csv",
        }
    return {}


def _manual_evidence_expected_labels(platform: str) -> list[str]:
    """Return the high-value manual evidence files expected for one platform."""
    if platform == "linux":
        return ["linux_identity.json", "linux_policy.json", "auth.log"]
    if platform == "windows":
        return ["windows_identity.csv", "windows_events.csv", "windows_policy.csv"]
    return []


def _scan_manual_evidence(platform: str, reference_time: float) -> dict[str, object]:
    """Scan approved manual folders and describe discovered files.

    ``reference_time`` is the moment before the user was asked to place files,
    or the application start time for direct CLI runs. Files older than that
    time are still allowed, but only older files are reported as potentially
    stale. Recently modified files are shown as already present so users can
    verify they are the intended exports without overstating the risk.
    """
    recent_threshold_seconds = 600
    found_files: list[dict[str, object]] = []
    warnings: list[str] = []
    candidates = _manual_evidence_candidates(platform)
    for source_name, path in candidates.items():
        if not path.exists() or not path.is_file():
            continue
        modified_time = path.stat().st_mtime
        existed_before_prompt = modified_time < reference_time
        recently_modified = modified_time >= reference_time - recent_threshold_seconds
        file_info = {
            "source_name": source_name,
            "path": str(path),
            "modified_time": modified_time,
            "existed_before_prompt": existed_before_prompt,
            "recently_modified": recently_modified,
        }
        found_files.append(file_info)
        if existed_before_prompt:
            if recently_modified:
                warnings.append(
                    f"Manual {platform.title()} evidence file was already present when scanned. Verify it is the intended file: {path}"
                )
            else:
                warnings.append(
                    f"Manual {platform.title()} evidence file appears older than this run and may be stale: {path}"
                )

    found_names = {Path(str(item["path"])).name for item in found_files}
    missing_expected = [name for name in _manual_evidence_expected_labels(platform) if name not in found_names]
    if found_files and missing_expected:
        found_text = ", ".join(sorted(found_names))
        missing_text = ", ".join(missing_expected)
        warnings.append(
            f"Manual {platform.title()} evidence is partial: {found_text} was found, but {missing_text} were not supplied."
        )

    return {
        "platform": platform,
        "found_files": found_files,
        "missing_expected_files": missing_expected,
        "warnings": warnings,
    }


def _manual_evidence_scan_lines(scan_result: dict[str, object]) -> list[str]:
    """Build readable terminal lines for a manual evidence scan."""
    platform = str(scan_result.get("platform") or "manual").title()
    lines = [f"Manual {platform} evidence scan:"]
    found_files = list(scan_result.get("found_files", []) or [])
    if not found_files:
        lines.append(f"- No manual {platform} evidence files were found.")
        return lines

    for item in found_files:
        if not isinstance(item, dict):
            continue
        lines.append(f"- Found: {item.get('path')}")
        if item.get("existed_before_prompt"):
            if item.get("recently_modified"):
                lines.append("- Note: file was already present when scanned. Verify it is the intended file.")
            else:
                lines.append("- Note: file appears older than this run and may be stale.")
    return lines


def _resolve_manual_cross_evidence(
    *,
    selected_platform: str,
    args: argparse.Namespace,
    interactive: bool,
    input_func: Callable[[str], str],
    reference_time: float,
) -> dict[str, object]:
    """Resolve whether opposite-OS manual evidence should be included.

    Direct ``--mode`` runs stay non-interactive and default to a single-platform
    scope. Fully interactive production runs ask once so the user explicitly
    chooses whether manual cross-platform evidence should be part of analysis.
    """
    platform = selected_platform.strip().lower()
    if platform == "test" or args.no_manual_cross_evidence:
        return {
            "manual_cross_evidence_included": False,
            "manual_cross_evidence_platform": "none",
            "manual_cross_evidence_requested": False,
            "manual_cross_evidence_files": [],
            "manual_cross_evidence_warnings": [],
            "analysis_scope": _analysis_scope(
                platform,
                manual_cross_evidence_included=False,
                manual_cross_evidence_platform="none",
            ),
        }

    requested_platform = "linux" if platform == "windows" else "windows" if platform == "linux" else "none"
    cli_included = (
        (platform == "windows" and bool(args.include_manual_linux))
        or (platform == "linux" and bool(args.include_manual_windows))
    )
    include_manual = cli_included
    manual_requested = cli_included
    scan_result: dict[str, object] = {"platform": requested_platform, "found_files": [], "warnings": []}

    if interactive and platform == "windows" and not cli_included:
        response = input_func("Do you want to include manually exported Linux evidence as well? [y/N]: ").strip().lower()
        include_manual = response in {"y", "yes"}
        manual_requested = include_manual
        if include_manual:
            reference_time = time.time()
            print_lines(
                [
                    "Place Linux evidence in one of these locations before continuing:",
                    "- data/incoming/",
                    "- logdata/linux/",
                    "Examples: auth.log, syslog, journalctl exports, linux_identity.json, linux_policy.json",
                ]
            )
            ready = input_func("Press Enter when the Linux evidence files are ready, or type skip to continue without them: ")
            include_manual = ready.strip().lower() != "skip"
            manual_requested = include_manual
    elif interactive and platform == "linux" and not cli_included:
        response = input_func("Do you want to include manually exported Windows evidence as well? [y/N]: ").strip().lower()
        include_manual = response in {"y", "yes"}
        manual_requested = include_manual
        if include_manual:
            reference_time = time.time()
            print_lines(
                [
                    "Place Windows evidence in one of these locations before continuing:",
                    "- data/incoming/",
                    "- logdata/windows/",
                    "Examples: windows_identity.csv, windows_events.csv, windows_policy.csv, Event Viewer CSV exports",
                ]
            )
            ready = input_func("Press Enter when the Windows evidence files are ready, or type skip to continue without them: ")
            include_manual = ready.strip().lower() != "skip"
            manual_requested = include_manual

    if include_manual:
        scan_result = _scan_manual_evidence(requested_platform, reference_time)
        print_lines(_manual_evidence_scan_lines(scan_result))
        if not scan_result.get("found_files"):
            scan_result.setdefault("warnings", [])
            scan_result["warnings"].append(
                f"No manual {requested_platform.title()} evidence files were found after the user requested it."
            )
            print_message(
                f"No manual {requested_platform.title()} evidence files were found. "
                f"Continuing with {platform.title()} collector data only."
            )
            include_manual = False

    manual_platform = requested_platform if include_manual else "none"
    return {
        "manual_cross_evidence_included": include_manual,
        "manual_cross_evidence_requested": manual_requested,
        "manual_cross_evidence_platform": manual_platform,
        "manual_cross_evidence_files": list(scan_result.get("found_files", []) or []) if include_manual else [],
        "manual_cross_evidence_warnings": list(scan_result.get("warnings", []) or []),
        "analysis_scope": _analysis_scope(
            platform,
            manual_cross_evidence_included=include_manual,
            manual_cross_evidence_platform=manual_platform,
        ),
    }


def _attach_scope_to_data_paths(data_paths: dict[str, object], scope: dict[str, object], selected_platform: str) -> dict[str, object]:
    """Attach source-scope metadata consumed by the analysis engine."""
    updated_paths = dict(data_paths)
    updated_paths["selected_platform"] = selected_platform
    updated_paths["manual_cross_evidence_included"] = bool(scope["manual_cross_evidence_included"])
    updated_paths["manual_cross_evidence_requested"] = bool(scope.get("manual_cross_evidence_requested", False))
    updated_paths["manual_cross_evidence_platform"] = str(scope["manual_cross_evidence_platform"])
    updated_paths["manual_cross_evidence_files"] = list(scope.get("manual_cross_evidence_files", []) or [])
    updated_paths["manual_cross_evidence_warnings"] = list(scope.get("manual_cross_evidence_warnings", []) or [])
    updated_paths["analysis_scope"] = str(scope["analysis_scope"])
    source_labels = dict(updated_paths.get("source_labels", {}) or {})
    if scope.get("manual_cross_evidence_included"):
        for item in scope.get("manual_cross_evidence_files", []) or []:
            if not isinstance(item, dict):
                continue
            source_name = str(item.get("source_name") or "")
            if source_name in {"auth_log", "auth_log_incoming"}:
                source_labels["linux_auth_log"] = "manual"
                updated_paths["auth.log"] = str(item.get("path"))
            elif source_name:
                canonical = source_name
                if (
                    source_name.startswith("windows_events")
                    or "security_events" in source_name
                    or "eventviewer_export" in source_name
                ):
                    canonical = "windows_events"
                source_labels[canonical] = "manual"
    updated_paths["source_labels"] = source_labels
    return updated_paths


def _source_platform(source_name: str) -> str | None:
    """Return the platform family for one logical evidence source."""
    if source_name.startswith("linux_") or source_name == "auth_log":
        return "linux"
    if source_name.startswith("windows_"):
        return "windows"
    return None


def _source_in_scope(source_name: str, selected_platform: str, scope: dict[str, object]) -> bool:
    """Return whether a fallback source is intentionally in scope."""
    if selected_platform == "test":
        return True
    platform = _source_platform(source_name)
    if platform is None or platform == selected_platform:
        return True
    return bool(scope.get("manual_cross_evidence_included")) and platform == scope.get("manual_cross_evidence_platform")


def _filter_fallback_result_for_scope(
    fallback_result: dict[str, object],
    *,
    selected_platform: str,
    scope: dict[str, object],
) -> dict[str, object]:
    """Remove fallback files from operating systems the user did not select."""
    if selected_platform == "test":
        return fallback_result

    filtered = dict(fallback_result)
    warnings = list(filtered.get("warnings", []) or [])
    used_files = dict(filtered.get("used_files", {}) or {})
    payloads = dict(filtered.get("payloads", {}) or {})
    sources = dict(filtered.get("sources", {}) or {})

    for source_name in list(used_files):
        if _source_in_scope(source_name, selected_platform, scope):
            continue
        platform = _source_platform(source_name) or "cross-platform"
        warning = (
            f"Existing {platform.title()} fallback evidence was ignored. To include it, choose manual "
            f"{platform.title()} evidence or use --include-manual-{platform}: {used_files[source_name].get('path')}"
        )
        warnings.append(warning)
        used_files.pop(source_name, None)
        payloads.pop(source_name, None)
        if isinstance(sources.get(source_name), dict):
            sources[source_name] = {
                **sources[source_name],
                "selected": False,
                "not_selected": True,
                "source_label": "ignored_out_of_scope",
                "warnings": [*list(sources[source_name].get("warnings", []) or []), warning],
            }

    filtered["used_files"] = used_files
    filtered["payloads"] = payloads
    filtered["sources"] = sources
    filtered["warnings"] = warnings
    filtered["no_data_found"] = not bool(used_files)
    if filtered["no_data_found"]:
        filtered["fallback_reason"] = "No in-scope fallback data was found in any configured directory."
    return filtered


def _host_supports_platform(platform: str) -> tuple[bool, str]:
    """Return whether the selected platform collector can run on this host."""
    normalized = platform.strip().lower()
    host_name = host_platform.system().strip().lower()
    if normalized == "linux":
        if host_name == "linux":
            return True, ""
        return (
            False,
            "Linux mode was selected, but this appears to be a Windows environment. "
            "The Linux Bash collector cannot run here. Run Linux mode from Linux/WSL, or choose Windows mode.",
        )
    if normalized == "windows":
        if host_name == "windows":
            return True, ""
        return (
            False,
            "Windows mode was selected, but this appears to be a Linux environment. "
            "The Windows PowerShell collector cannot run here. Choose Linux mode, or provide manually exported Windows evidence.",
        )
    return True, ""


def _preflight_failure_result(platform: str, reason: str) -> dict[str, object]:
    """Build a collector-shaped result for a preflight stop condition."""
    if platform == "windows":
        expected = {
            "windows_identity": "data/collected/windows_identity.csv",
            "windows_events": "data/collected/windows_events.csv",
            "windows_policy": "data/collected/windows_policy.csv",
        }
    else:
        expected = {
            "linux_identity": "data/collected/linux_identity.json",
            "linux_policy": "data/collected/linux_policy.json",
        }
    return {
        "platform": platform,
        "mode": "production",
        "command": None,
        "expected_outputs": expected,
        "missing_outputs": list(expected.values()),
        "stale_outputs": [],
        "current_outputs": [],
        "success": False,
        "reason": reason,
        "preflight_failed": True,
        "output_statuses": {
            name: {"status": "not collected", "reason": reason, "path": path}
            for name, path in expected.items()
        },
    }


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
    supported, reason = _host_supports_platform(platform)
    if not supported:
        return [_preflight_failure_result(platform, reason)]
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
                "source_label": "collector",
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
    source_labels = dict(updated_paths.get("source_labels", {}) or {})
    for result in collector_results:
        if not result.get("success"):
            continue
        expected_outputs = result.get("expected_outputs", {})
        if not isinstance(expected_outputs, dict):
            continue
        for source_name, path in expected_outputs.items():
            updated_paths[str(source_name)] = str(path)
            source_labels[str(source_name)] = "collector"
            if str(source_name) == "linux_identity":
                source_labels["linux_auth_events"] = "collector"
    updated_paths["source_labels"] = source_labels
    return updated_paths


def _stale_collector_outputs(collector_results: list[dict[str, object]]) -> list[str]:
    """Return collector outputs that existed but were not written by this run.

    These paths must be treated carefully because they may contain evidence
    from a previous execution. Keeping the list explicit lets fallback and
    analysis avoid silently using stale files after a failed collector run.
    """
    stale_outputs: list[str] = []
    for result in collector_results:
        for path in result.get("stale_outputs", []) or []:
            stale_outputs.append(str(path))
    return stale_outputs


def _apply_fallback_output_paths(
    data_paths: dict[str, object],
    fallback_result: dict[str, object],
    *,
    excluded_paths: Sequence[str] = (),
) -> dict[str, object]:
    """Pin analysis to the exact fallback files selected for this run.

    The risk engine normally resolves files from configured directories. When
    fallback has already chosen validated files, explicit paths prevent the
    engine from accidentally re-selecting an older file from ``data/collected``.
    """
    updated_paths = dict(data_paths)
    used_files = fallback_result.get("used_files", {})
    source_labels = dict(updated_paths.get("source_labels", {}) or {})
    if isinstance(used_files, dict):
        for source_name, info in used_files.items():
            if isinstance(info, dict) and info.get("path"):
                canonical_name = "linux_auth_log" if str(source_name) == "auth_log" else str(source_name)
                updated_paths[canonical_name] = str(info["path"])
                if str(source_name) == "auth_log":
                    updated_paths["auth.log"] = str(info["path"])
                source_labels[canonical_name] = "fallback" if fallback_result.get("fallback_activated") else "collector"
    updated_paths["source_labels"] = source_labels

    if excluded_paths:
        existing = updated_paths.get("excluded_paths", [])
        if isinstance(existing, (str, bytes)):
            normalized_existing = [str(existing)]
        else:
            normalized_existing = [str(path) for path in (existing or [])]
        updated_paths["excluded_paths"] = [*normalized_existing, *[str(path) for path in excluded_paths]]
    return updated_paths


def _non_selected_collected_outputs(selected_platform: str) -> tuple[list[str], list[str]]:
    """Return automatic collector files that must not bleed across platforms.

    ``data/collected`` is reserved for automatic collector output. When a
    Windows collector succeeds, older Linux files in that directory are not
    evidence for the current run, and the inverse is true for Linux runs.
    Manual cross-platform evidence remains supported through ``data/incoming``
    and the documented ``logdata`` folders.
    """
    platform = selected_platform.strip().lower()
    if platform == "windows":
        paths = [
            DATA_COLLECTED_DIR / "linux_identity.json",
            DATA_COLLECTED_DIR / "linux_policy.json",
        ]
        warnings = [
            "Existing Linux collected data was ignored because Linux was not collected in this Windows run. "
            "Place manual Linux evidence in data/incoming/ or logdata/linux/ if cross-platform analysis is intended."
        ]
    elif platform == "linux":
        paths = [
            DATA_COLLECTED_DIR / "windows_identity.csv",
            DATA_COLLECTED_DIR / "windows_events.csv",
            DATA_COLLECTED_DIR / "windows_policy.csv",
        ]
        warnings = [
            "Existing Windows collected data was ignored because Windows was not collected in this Linux run. "
            "Place manual Windows evidence in data/incoming/ or logdata/windows/ if cross-platform analysis is intended."
        ]
    else:
        return [], []

    existing_paths = [str(path) for path in paths if path.exists()]
    return existing_paths, warnings if existing_paths else []


def _build_collector_fallback_result(
    *,
    collector_results: list[dict[str, object]],
    analysis_mode: str,
    warnings: Sequence[str] = (),
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
        "warnings": list(warnings),
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
    stale_outputs = collector_result.get("stale_outputs", [])
    stale_text = ", ".join(str(item) for item in stale_outputs) if stale_outputs else "none"
    if success:
        return f"success=True returncode={returncode} missing_outputs={missing_text} stale_outputs={stale_text}"
    return f"success=False returncode={returncode} missing_outputs={missing_text} stale_outputs={stale_text}"


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
    warning_lines = [f"Warning: {warning}" for warning in fallback_result.get("warnings", []) or []]
    if fallback_result.get("no_data_found"):
        missing_files = fallback_result.get("missing_files", [])
        missing_text = ", ".join(str(item) for item in missing_files) if missing_files else "none"
        searched = fallback_result.get("searched_directories", [])
        searched_text = ", ".join(str(item) for item in searched) if searched else "none"
        return warning_lines + [
            "Fallback found no usable evidence files.",
            f"Search order: {searched_text}",
            f"Missing files: {missing_text}",
        ]

    used_files = fallback_result.get("used_files", {})
    if isinstance(used_files, dict) and used_files:
        files = ", ".join(f"{name}={info.get('path')}" for name, info in used_files.items() if isinstance(info, dict))
        if fallback_result.get("fallback_activated"):
            return warning_lines + [f"Fallback found usable files: {files}"]
        return warning_lines + [f"Collected files in use: {files}"]
    return warning_lines + ["Fallback found partial files only."]


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


def _data_quality_warning_lines(analysis_result: dict[str, object]) -> list[str]:
    """Return important evidence-boundary warnings for terminal display."""
    data_quality = analysis_result.get("data_quality", {})
    if not isinstance(data_quality, dict):
        return []
    warnings = [str(warning) for warning in data_quality.get("warnings", []) or []]
    return [f"Warning: {warning}" for warning in dict.fromkeys(warnings) if "ignored" in warning.lower()]


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
    scope: dict[str, object] | None = None,
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
    if scope:
        report_result["analysis_scope"] = scope.get("analysis_scope")
        report_result["manual_cross_evidence_included"] = bool(scope.get("manual_cross_evidence_included"))
        report_result["manual_cross_evidence_requested"] = bool(scope.get("manual_cross_evidence_requested", False))
        report_result["manual_cross_evidence_platform"] = scope.get("manual_cross_evidence_platform", "none")
        report_result["manual_cross_evidence_files"] = list(scope.get("manual_cross_evidence_files", []) or [])
        report_result["manual_cross_evidence_warnings"] = list(scope.get("manual_cross_evidence_warnings", []) or [])
    fallback_warnings = [str(warning) for warning in fallback_result.get("warnings", []) or []]
    manual_warnings = [str(warning) for warning in (scope or {}).get("manual_cross_evidence_warnings", []) or []]
    if fallback_warnings or manual_warnings:
        data_quality = dict(report_result.get("data_quality", {}) or {})
        existing_warnings = list(data_quality.get("warnings", []) or [])
        data_quality["warnings"] = list(dict.fromkeys([*existing_warnings, *fallback_warnings, *manual_warnings]))
        report_result["data_quality"] = data_quality
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
    run_started_at = time.time()
    try:
        verify_logging_path_writable()
        setup_logging(run_id=run_id, debug=False)
    except RuntimeLoggingError as exc:
        print(str(exc))
        return 1
    logger = get_component_logger("app", run_id)

    try:
        app_config = load_app_config()
        project_name = str(app_config.get("project_name", "NordSec Identity & Privilege Control Auditor"))
        project_version = str(app_config.get("version", "0.0.0"))
        banner_mode = "test" if (args.test or args.mode == "test") else ("production" if args.mode in {"linux", "windows"} else "interactive")

        logger.info("Program start")
        print_message(format_banner(project_name, project_version, banner_mode))

        requested_platform = "test" if args.test else args.mode
        interactive_run = requested_platform is None
        platform_selection = choose_platform(
            requested_platform=requested_platform,
            test_flag=args.test,
            input_func=input_func,
            windows_log_hours=args.windows_log_hours,
            windows_max_events=args.windows_max_events,
            linux_log_hours=args.linux_log_hours,
            linux_max_events=args.linux_max_events,
        )
        if getattr(platform_selection, "messages", ()):
            print_lines(list(platform_selection.messages))
        print_message(platform_selection.instructions)
        print_message(build_privilege_notice(platform_selection.platform, test_mode=platform_selection.use_mockdata))
        print_message(f"Selected platform: {platform_selection.platform}")
        logger.info("Selected platform: %s", platform_selection.platform)
        scope = _resolve_manual_cross_evidence(
            selected_platform=platform_selection.platform,
            args=args,
            interactive=interactive_run and platform_selection.platform != "test",
            input_func=input_func,
            reference_time=run_started_at,
        )
        print_message(
            "Cross-platform manual evidence: "
            + (
                f"{scope['manual_cross_evidence_platform'].title()} manual evidence included."
                if scope["manual_cross_evidence_included"]
                else "not included."
            )
        )
        print_message(f"Analysis scope: {scope['analysis_scope']}")
        if scope.get("manual_cross_evidence_warnings"):
            print_lines([f"Warning: {warning}" for warning in scope["manual_cross_evidence_warnings"]])
        logger.info(
            "Analysis scope resolved: %s manual_cross_evidence_included=%s manual_cross_evidence_platform=%s",
            scope["analysis_scope"],
            scope["manual_cross_evidence_included"],
            scope["manual_cross_evidence_platform"],
        )
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
        data_paths = _attach_scope_to_data_paths(data_paths, scope, platform_selection.platform)
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
            fallback_result = _filter_fallback_result_for_scope(
                fallback_result,
                selected_platform=platform_selection.platform,
                scope=scope,
            )
            data_paths = _apply_fallback_output_paths(data_paths, fallback_result)
        elif _collectors_succeeded(collector_results):
            non_selected_paths, non_selected_warnings = _non_selected_collected_outputs(platform_selection.platform)
            fallback_result = _build_collector_fallback_result(
                collector_results=collector_results,
                analysis_mode=platform_selection.analysis_mode,
                warnings=non_selected_warnings,
            )
            data_paths = _apply_collector_output_paths(data_paths, collector_results)
            data_paths = _apply_fallback_output_paths(
                data_paths,
                fallback_result,
                excluded_paths=non_selected_paths,
            )
        else:
            stale_outputs = _stale_collector_outputs(collector_results)
            opposite_collected_outputs, opposite_collected_warnings = _non_selected_collected_outputs(
                platform_selection.platform
            )
            fallback_result = collect_fallback_data(
                mode=platform_selection.analysis_mode,
                ignored_collected_files=[*stale_outputs, *opposite_collected_outputs],
            )
            if opposite_collected_warnings:
                fallback_result = {
                    **fallback_result,
                    "warnings": [*list(fallback_result.get("warnings", []) or []), *opposite_collected_warnings],
                }
            fallback_result = _filter_fallback_result_for_scope(
                fallback_result,
                selected_platform=platform_selection.platform,
                scope=scope,
            )
            data_paths = _apply_fallback_output_paths(
                data_paths,
                fallback_result,
                excluded_paths=[*stale_outputs, *opposite_collected_outputs],
            )

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
        print_lines(_data_quality_warning_lines(analysis_result))
        report_analysis_result = _attach_report_metadata(
            analysis_result,
            fallback_result,
            selected_platform=platform_selection.platform,
            scope=scope,
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
