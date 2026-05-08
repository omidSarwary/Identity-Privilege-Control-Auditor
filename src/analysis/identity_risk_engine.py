"""Central orchestration layer for identity risk analysis.

This module glues together the existing parsers, validators, correlation
helpers, anomaly detection, and scoring logic. The goal is to keep the
analysis pipeline read-only while giving the rest of the application one clean
entry point for loading data and producing a structured analysis result.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.analysis.anomaly_detection import detect_anomalies
from src.analysis.correlation import (
    correlate_events_to_identities,
    correlate_identity_privileges,
    correlate_policy_findings,
    normalize_identities,
)
from src.analysis.scoring import summarize_findings
from src.core.paths import (
    BASELINES_DIR,
    DATA_COLLECTED_DIR,
    DATA_INCOMING_DIR,
    LOGDATA_DIR,
    PROJECT_ROOT,
    TEST_MOCKDATA_DIR,
)
from src.parsers._common import EmptyFileError, FileMissingError, InvalidFormatError, ParserError
from src.parsers.csv_loader import load_csv_file
from src.parsers.json_loader import load_json_file
from src.parsers.log_loader import load_text_log
from src.parsers.validators import (
    ValidationStatus,
    validate_baseline_csv,
    validate_linux_identity,
    validate_linux_policy,
    validate_windows_events,
    validate_windows_identity,
    validate_windows_policy,
)


LOGGER = logging.getLogger("nordsec.ipca.analysis.identity_risk_engine")
NON_PATH_DATA_KEYS = {
    "selected_platform",
    "manual_cross_evidence_included",
    "manual_cross_evidence_requested",
    "manual_cross_evidence_platform",
    "manual_cross_evidence_files",
    "manual_cross_evidence_warnings",
    "analysis_scope",
    "excluded_paths",
}

WINDOWS_IDENTITY_COLUMNS = [
    "ComputerName",
    "CollectionTime",
    "Username",
    "Enabled",
    "IsLocalAdmin",
    "LastLogon",
    "Source",
]
WINDOWS_EVENTS_COLUMNS = [
    "ComputerName",
    "TimeCreated",
    "EventId",
    "TargetUserName",
    "IpAddress",
    "EventType",
]
WINDOWS_POLICY_COLUMNS = [
    "ComputerName",
    "CheckName",
    "Status",
    "Value",
    "RiskHint",
]
APPROVED_LINUX_SUDOERS_COLUMNS = ["username", "reason", "owner", "approved_until"]
APPROVED_WINDOWS_ADMINS_COLUMNS = ["username", "reason", "owner", "approved_until"]
APPROVED_SERVICE_ACCOUNTS_COLUMNS = ["username", "platform", "interactive_login_allowed", "owner"]
PLATFORM_SOURCE_MAP = {
    "linux_identity": "linux",
    "linux_policy": "linux",
    "linux_auth_log": "linux",
    "windows_identity": "windows",
    "windows_events": "windows",
    "windows_policy": "windows",
}


def _as_path(value: Any) -> Path | None:
    """Convert a loosely formatted path value into a ``Path`` instance.

    The engine accepts paths from configuration files, test fixtures, and
    direct calls from ``app.py``. This helper keeps that input flexible while
    still normalizing everything into pathlib objects before filesystem access.
    """
    if value is None:
        return None
    if isinstance(value, Path):
        return value if value.is_absolute() else PROJECT_ROOT / value
    path = Path(str(value))
    return path if path.is_absolute() else PROJECT_ROOT / path


def _base_directories(mode: str, data_paths: Mapping[str, Any]) -> list[Path]:
    """Build the ordered search paths for source files.

    Test mode is intentionally isolated and only reads mock data plus the
    approved baseline directory. Production mode reads the documented data and
    log locations first so live evidence can still be analyzed later.
    """
    normalized_mode = str(mode).strip().lower()
    if normalized_mode == "test":
        ordered_keys = (
            ("mockdata", TEST_MOCKDATA_DIR),
            ("baselines", BASELINES_DIR),
        )
    else:
        ordered_keys = (
            ("incoming", DATA_INCOMING_DIR),
            ("collected", DATA_COLLECTED_DIR),
            ("logdata", LOGDATA_DIR),
            ("baselines", BASELINES_DIR),
        )

    base_directories: list[Path] = []
    for key, default_path in ordered_keys:
        configured = _as_path(data_paths.get(key))
        candidate = configured if configured is not None else default_path
        if candidate not in base_directories:
            base_directories.append(candidate)
    return base_directories


def _resolve_source_path(
    mode: str,
    data_paths: Mapping[str, Any],
    filename: str,
    *,
    extra_candidates: Sequence[str] = (),
) -> Path | None:
    """Resolve a source file from the configured paths without hardcoding one path.

    The helper first checks for an explicit file path in ``data_paths`` and then
    falls back to the ordered base directories. This keeps test data, mock data,
    and later production paths interchangeable.
    """
    excluded_paths = {
        str((_as_path(path) or Path(str(path))).resolve())
        for path in data_paths.get("excluded_paths", []) or []
    }
    explicit_keys = (filename, Path(filename).stem)
    for key in explicit_keys:
        explicit = _as_path(data_paths.get(key))
        if explicit is None:
            continue
        if str(explicit.resolve()) in excluded_paths:
            continue
        if explicit.exists() and explicit.is_file():
            return explicit
        if explicit.exists() and explicit.is_dir():
            candidate = explicit / filename
            if candidate.exists() and str(candidate.resolve()) not in excluded_paths:
                return candidate

    for base_dir in _base_directories(mode, data_paths):
        if base_dir.exists() and base_dir.is_file() and base_dir.name == filename:
            if str(base_dir.resolve()) not in excluded_paths:
                return base_dir
            continue
        if not base_dir.exists() or not base_dir.is_dir():
            continue

        for relative_name in (filename, *extra_candidates):
            candidate = base_dir / relative_name
            if candidate.exists() and str(candidate.resolve()) not in excluded_paths:
                return candidate
    return None


def _record_count(data: Any) -> int:
    """Return a simple record count for any loaded source."""
    if isinstance(data, Mapping):
        return len(data)
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return len(data)
    if data:
        return 1
    return 0


def _serialize_data_paths(data_paths: Mapping[str, Any]) -> dict[str, Any]:
    """Serialize configured paths while preserving non-path metadata values."""
    serialized: dict[str, Any] = {}
    for key, value in data_paths.items():
        if key in NON_PATH_DATA_KEYS:
            serialized[key] = value
        else:
            serialized[key] = str(_as_path(value) or value)
    return serialized


def _quality_entry(
    *,
    path: Path | None,
    loaded: bool,
    valid: bool,
    record_count: int,
    warnings: Sequence[str] | None = None,
    errors: Sequence[str] | None = None,
    required: bool = True,
) -> dict[str, Any]:
    """Create a serializable quality record for one source.

    The engine stores validation results as plain dictionaries so the final
    analysis result can be handed to reporting code or serialized later without
    extra conversion.
    """
    return {
        "path": str(path) if path is not None else None,
        "loaded": loaded,
        "valid": valid,
        "record_count": record_count,
        "warnings": list(warnings or []),
        "errors": list(errors or []),
        "required": required,
    }


def _source_platform(source_name: str) -> str | None:
    """Return the platform family for a source, if it is platform-specific."""
    return PLATFORM_SOURCE_MAP.get(source_name)


def _source_selected(mode: str, data_paths: Mapping[str, Any], source_name: str) -> bool:
    """Return whether a source is intentionally part of this analysis scope.

    Production runs default to the selected platform only. The opposite
    platform is included only when the user explicitly opted into manual
    cross-platform evidence. Test mode keeps the existing mockdata behavior and
    loads both platform families.
    """
    if str(mode).strip().lower() == "test":
        return True

    platform = _source_platform(source_name)
    if platform is None:
        return True

    selected_platform = str(data_paths.get("selected_platform") or "").strip().lower()
    manual_included = bool(data_paths.get("manual_cross_evidence_included", False))
    manual_platform = str(data_paths.get("manual_cross_evidence_platform") or "none").strip().lower()

    if not selected_platform:
        return True
    if selected_platform and platform == selected_platform:
        return True
    return manual_included and platform == manual_platform


def _not_selected_quality(source_name: str, filename: str) -> dict[str, Any]:
    """Build a non-error source record for evidence outside the chosen scope."""
    return _quality_entry(
        path=None,
        loaded=False,
        valid=True,
        record_count=0,
        warnings=[],
        errors=[],
        required=False,
    ) | {"not_selected": True, "selection_reason": f"{filename}: source not selected for this run"}


def _json_mode_warning(
    *,
    analysis_mode: str,
    source_name: str,
    path: Path,
    payload: Mapping[str, Any],
) -> str | None:
    """Return a warning when JSON evidence belongs to a different run mode.

    Production analysis must not treat mock/test collector output as real
    evidence. The check is intentionally limited to explicit JSON ``mode``
    metadata so normal production files without that optional field continue to
    load as before.
    """
    evidence_mode = str(payload.get("mode") or "").strip().lower()
    normalized_mode = str(analysis_mode).strip().lower()
    if normalized_mode == "production" and evidence_mode == "test":
        platform_label = "Linux" if source_name.startswith("linux_") else source_name.replace("_", " ").title()
        return (
            f"{platform_label} evidence file ignored because it was collected in test mode "
            f"during a production run: {path}"
        )
    if normalized_mode == "test" and evidence_mode == "production":
        platform_label = "Linux" if source_name.startswith("linux_") else source_name.replace("_", " ").title()
        return (
            f"{platform_label} evidence file ignored because it was collected in production mode "
            f"during a test run: {path}"
        )
    return None


def _load_json_source(
    mode: str,
    data_paths: Mapping[str, Any],
    source_name: str,
    filename: str,
    validator,
    *,
    extra_candidates: Sequence[str] = (),
    required: bool = True,
) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """Load and validate one JSON source.

    The helper centralizes parser error handling so callers can keep the
    high-level pipeline readable and consistent.
    """
    data: Any = {}
    warnings: list[str] = []
    errors: list[str] = []
    loaded = False
    ignored_for_mode = False

    if not _source_selected(mode, data_paths, source_name):
        entry = _not_selected_quality(source_name, filename)
        LOGGER.info("%s not selected for this analysis scope", source_name)
        return {}, entry, {"warnings": [], "errors": [], "valid": True}

    path = _resolve_source_path(mode, data_paths, filename, extra_candidates=extra_candidates)

    if path is None:
        errors.append(f"{source_name}: file not found")
        LOGGER.warning("%s missing", source_name)
    else:
        try:
            data = load_json_file(path)
            loaded = True
            if isinstance(data, Mapping):
                mode_warning = _json_mode_warning(
                    analysis_mode=mode,
                    source_name=source_name,
                    path=path,
                    payload=data,
                )
                if mode_warning:
                    warnings.append(mode_warning)
                    LOGGER.warning(mode_warning)
                    ignored_for_mode = True
                    data = {}
        except (FileMissingError, EmptyFileError, InvalidFormatError) as exc:
            errors.append(f"{source_name}: {exc}")
            LOGGER.error("%s could not be loaded: %s", source_name, exc)
        except ParserError as exc:  # pragma: no cover - defensive fallback
            errors.append(f"{source_name}: {exc}")
            LOGGER.error("%s failed with a parser error: %s", source_name, exc)

    if loaded and not ignored_for_mode:
        validation = validator(data)
        warnings.extend(validation.warnings)
        errors.extend(validation.errors)
        valid = validation.valid
    else:
        valid = False

    entry = _quality_entry(
        path=path,
        loaded=loaded,
        valid=valid,
        record_count=_record_count(data),
        warnings=warnings,
        errors=errors,
        required=required,
    )
    return data if loaded and not ignored_for_mode else {}, entry, {"warnings": warnings, "errors": errors, "valid": valid}


def _load_csv_source(
    mode: str,
    data_paths: Mapping[str, Any],
    source_name: str,
    filename: str,
    required_columns: Sequence[str],
    validator,
    *,
    extra_candidates: Sequence[str] = (),
    required: bool = True,
    allow_empty_rows: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Load and validate one CSV source.

    CSV sources are used for Windows identity, Windows events, Windows policy,
    and approved baseline lists. Keeping the logic in one helper ensures that
    headers, row counts, and parser failures are handled the same way for each
    file.
    """
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    loaded = False

    if not _source_selected(mode, data_paths, source_name):
        entry = _not_selected_quality(source_name, filename)
        LOGGER.info("%s not selected for this analysis scope", source_name)
        return [], entry, {"warnings": [], "errors": [], "valid": True}

    path = _resolve_source_path(mode, data_paths, filename, extra_candidates=extra_candidates)

    if path is None:
        errors.append(f"{source_name}: file not found")
        LOGGER.warning("%s missing", source_name)
    else:
        try:
            rows = load_csv_file(path, list(required_columns), allow_empty_rows=allow_empty_rows)
            loaded = True
        except (FileMissingError, EmptyFileError, InvalidFormatError) as exc:
            errors.append(f"{source_name}: {exc}")
            LOGGER.error("%s could not be loaded: %s", source_name, exc)
        except ParserError as exc:  # pragma: no cover - defensive fallback
            errors.append(f"{source_name}: {exc}")
            LOGGER.error("%s failed with a parser error: %s", source_name, exc)

    if loaded:
        validation = validator(rows)
        warnings.extend(validation.warnings)
        errors.extend(validation.errors)
        valid = validation.valid
    else:
        valid = False

    entry = _quality_entry(
        path=path,
        loaded=loaded,
        valid=valid,
        record_count=_record_count(rows),
        warnings=warnings,
        errors=errors,
        required=required,
    )
    return rows, entry, {"warnings": warnings, "errors": errors, "valid": valid}


def _load_text_log_source(
    mode: str,
    data_paths: Mapping[str, Any],
    source_name: str,
    filename: str,
    *,
    extra_candidates: Sequence[str] = (),
    required: bool = False,
) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
    """Load a text log source and capture quality metadata.

    Log files are optional in this phase, but the engine still records whether
    they were found so later reporting can explain the evidence coverage.
    """
    lines: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []
    loaded = False

    if not _source_selected(mode, data_paths, source_name):
        entry = _not_selected_quality(source_name, filename)
        LOGGER.info("%s not selected for this analysis scope", source_name)
        return [], entry, {"warnings": [], "errors": [], "valid": True}

    path = _resolve_source_path(mode, data_paths, filename, extra_candidates=extra_candidates)

    if path is None:
        warnings.append(f"{source_name}: log source not available")
        LOGGER.info("%s not available", source_name)
    else:
        try:
            lines = load_text_log(path)
            loaded = True
        except (FileMissingError, EmptyFileError, InvalidFormatError) as exc:
            errors.append(f"{source_name}: {exc}")
            LOGGER.error("%s could not be loaded: %s", source_name, exc)
        except ParserError as exc:  # pragma: no cover - defensive fallback
            errors.append(f"{source_name}: {exc}")
            LOGGER.error("%s failed with a parser error: %s", source_name, exc)

    entry = _quality_entry(
        path=path,
        loaded=loaded,
        valid=loaded and not errors,
        record_count=_record_count(lines),
        warnings=warnings,
        errors=errors,
        required=required,
    )
    return lines, entry, {"warnings": warnings, "errors": errors, "valid": loaded and not errors}


def _validate_expected_policy_baseline(data: Mapping[str, Any]) -> ValidationStatus:
    """Validate the policy baseline shape used by correlation and anomaly checks.

    The project compares against a small approved baseline, so the engine only
    checks for the keys that later stages actually reference.
    """
    status = ValidationStatus(valid=True)
    for key in ["ssh_policy", "windows_policy_checks", "audit_policy", "firewall_policy", "execution_policy"]:
        if key not in data:
            status.add_error(f"expected_policy_baseline: missing required key '{key}'")
    return status


def _aggregate_data_quality(sources: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate source-level quality into one serializable summary."""
    warnings: list[str] = []
    errors: list[str] = []
    valid = True

    for source_name, entry in sources.items():
        warnings.extend(f"{source_name}: {warning}" for warning in entry.get("warnings", []))
        errors.extend(f"{source_name}: {error}" for error in entry.get("errors", []))
        if entry.get("required", True) and not entry.get("valid", False):
            valid = False

    return {
        "valid": valid,
        "warnings": warnings,
        "errors": errors,
        "sources": sources,
    }


def load_analysis_inputs(mode: str, data_paths: dict) -> dict:
    """Load all analysis inputs for the selected mode.

    Expects a mode string and a dictionary of configured paths. The function
    loads Linux JSON, Windows CSV, approved baselines, and optional log data,
    then returns a serializable bundle that later stages can validate and
    correlate without re-reading the files.

    Security / robustness
    ---------------------
    The loader is read-only and intentionally tolerant of missing optional log
    data so the pipeline can still report partial evidence instead of failing
    outright on one absent source.
    """
    LOGGER.info("Loading analysis inputs for mode=%s", mode)

    normalized_paths = {key: value for key, value in (data_paths or {}).items()}

    linux_identity, linux_identity_quality, _ = _load_json_source(
        mode,
        normalized_paths,
        "linux_identity",
        "linux_identity.json",
        validate_linux_identity,
        extra_candidates=("linux/linux_identity.json",),
        required=True,
    )
    linux_policy, linux_policy_quality, _ = _load_json_source(
        mode,
        normalized_paths,
        "linux_policy",
        "linux_policy.json",
        validate_linux_policy,
        extra_candidates=("linux/linux_policy.json",),
        required=True,
    )
    windows_identity_rows, windows_identity_quality, _ = _load_csv_source(
        mode,
        normalized_paths,
        "windows_identity",
        "windows_identity.csv",
        WINDOWS_IDENTITY_COLUMNS,
        validate_windows_identity,
        extra_candidates=("windows/windows_identity.csv",),
        required=True,
    )
    windows_events_rows, windows_events_quality, _ = _load_csv_source(
        mode,
        normalized_paths,
        "windows_events",
        "windows_events.csv",
        WINDOWS_EVENTS_COLUMNS,
        validate_windows_events,
        extra_candidates=("windows/windows_events.csv",),
        required=True,
        allow_empty_rows=True,
    )
    windows_policy_rows, windows_policy_quality, _ = _load_csv_source(
        mode,
        normalized_paths,
        "windows_policy",
        "windows_policy.csv",
        WINDOWS_POLICY_COLUMNS,
        validate_windows_policy,
        extra_candidates=("windows/windows_policy.csv",),
        required=True,
    )
    approved_linux_sudoers, approved_linux_quality, _ = _load_csv_source(
        mode,
        normalized_paths,
        "approved_linux_sudoers",
        "approved_linux_sudoers.csv",
        APPROVED_LINUX_SUDOERS_COLUMNS,
        lambda rows: validate_baseline_csv(rows, APPROVED_LINUX_SUDOERS_COLUMNS),
        required=True,
    )
    approved_windows_admins, approved_windows_quality, _ = _load_csv_source(
        mode,
        normalized_paths,
        "approved_windows_admins",
        "approved_windows_admins.csv",
        APPROVED_WINDOWS_ADMINS_COLUMNS,
        lambda rows: validate_baseline_csv(rows, APPROVED_WINDOWS_ADMINS_COLUMNS),
        required=True,
    )
    approved_service_accounts, approved_service_quality, _ = _load_csv_source(
        mode,
        normalized_paths,
        "approved_service_accounts",
        "approved_service_accounts.csv",
        APPROVED_SERVICE_ACCOUNTS_COLUMNS,
        lambda rows: validate_baseline_csv(rows, APPROVED_SERVICE_ACCOUNTS_COLUMNS),
        required=True,
    )
    expected_policy_baseline_path = _resolve_source_path(
        mode,
        normalized_paths,
        "expected_policy_baseline.json",
        extra_candidates=("expected_policy_baseline.json", "policy/expected_policy_baseline.json"),
    )
    expected_policy_baseline: dict[str, Any] = {}
    expected_policy_warnings: list[str] = []
    expected_policy_errors: list[str] = []
    expected_policy_loaded = False
    if expected_policy_baseline_path is None:
        expected_policy_errors.append("expected_policy_baseline: file not found")
        LOGGER.warning("expected_policy_baseline missing")
    else:
        try:
            expected_policy_baseline = load_json_file(expected_policy_baseline_path)
            expected_policy_loaded = True
            validation = _validate_expected_policy_baseline(expected_policy_baseline)
            expected_policy_warnings.extend(validation.warnings)
            expected_policy_errors.extend(validation.errors)
        except (FileMissingError, EmptyFileError, InvalidFormatError) as exc:
            expected_policy_errors.append(f"expected_policy_baseline: {exc}")
            LOGGER.error("expected_policy_baseline could not be loaded: %s", exc)
        except ParserError as exc:  # pragma: no cover - defensive fallback
            expected_policy_errors.append(f"expected_policy_baseline: {exc}")
            LOGGER.error("expected_policy_baseline failed with a parser error: %s", exc)

    linux_auth_log_lines, linux_auth_log_quality, _ = _load_text_log_source(
        mode,
        normalized_paths,
        "linux_auth_log",
        "auth.log",
        extra_candidates=("linux/auth.log",),
        required=False,
    )

    data_sources = {
        "linux_identity": linux_identity_quality,
        "linux_policy": linux_policy_quality,
        "windows_identity": windows_identity_quality,
        "windows_events": windows_events_quality,
        "windows_policy": windows_policy_quality,
        "approved_linux_sudoers": approved_linux_quality,
        "approved_windows_admins": approved_windows_quality,
        "approved_service_accounts": approved_service_quality,
        "expected_policy_baseline": _quality_entry(
            path=expected_policy_baseline_path,
            loaded=expected_policy_loaded,
            valid=expected_policy_loaded and not expected_policy_errors,
            record_count=_record_count(expected_policy_baseline),
            warnings=expected_policy_warnings,
            errors=expected_policy_errors,
            required=True,
        ),
        "linux_auth_log": linux_auth_log_quality,
    }

    data_quality = _aggregate_data_quality(data_sources)
    manual_warnings = [str(warning) for warning in normalized_paths.get("manual_cross_evidence_warnings", []) or []]
    if manual_warnings:
        data_quality["warnings"] = [*list(data_quality.get("warnings", []) or []), *manual_warnings]

    inputs = {
        "mode": mode,
        "data_paths": _serialize_data_paths(normalized_paths),
        "data_sources": data_sources,
        "data_quality": data_quality,
        "linux_identity": linux_identity,
        "linux_policy": linux_policy,
        "windows_identity_rows": windows_identity_rows,
        "windows_events_rows": windows_events_rows,
        "windows_policy_rows": windows_policy_rows,
        "approved_linux_sudoers": approved_linux_sudoers,
        "approved_windows_admins": approved_windows_admins,
        "approved_service_accounts": approved_service_accounts,
        "expected_policy_baseline": expected_policy_baseline,
        "linux_auth_log_lines": linux_auth_log_lines,
    }

    LOGGER.info("Completed loading analysis inputs")
    return inputs


def analyze_inputs(inputs: dict) -> dict:
    """Validate, correlate, detect anomalies, and score one analysis bundle.

    Expects the dictionary returned by ``load_analysis_inputs`` plus a run id.
    The function returns a complete analysis result that can be handed to later
    reporting code without any additional file I/O.

    Security / robustness
    ---------------------
    The function keeps partial analysis alive when some sources are missing, but
    it preserves the source-quality details so the report can explain the gap
    clearly instead of silently hiding it.
    """
    run_id = str(inputs.get("run_id") or "unknown")
    mode = str(inputs.get("mode") or "test")
    LOGGER.info("Starting analysis for run_id=%s mode=%s", run_id, mode)

    data_quality = _aggregate_data_quality(inputs.get("data_sources", {}))
    data_sources = inputs.get("data_sources", {})
    data_paths = inputs.get("data_paths", {})
    manual_warnings = [str(warning) for warning in data_paths.get("manual_cross_evidence_warnings", []) or []]
    if manual_warnings:
        data_quality["warnings"] = [*list(data_quality.get("warnings", []) or []), *manual_warnings]
    linux_policy_selected = not bool((data_sources.get("linux_policy", {}) or {}).get("not_selected", False))
    windows_policy_selected = not bool((data_sources.get("windows_policy", {}) or {}).get("not_selected", False))
    manual_platform = str(data_paths.get("manual_cross_evidence_platform") or "none").strip().lower()
    if manual_platform == "linux" and not bool((data_sources.get("linux_policy", {}) or {}).get("loaded", False)):
        linux_policy_selected = False
    if manual_platform == "windows" and not bool((data_sources.get("windows_policy", {}) or {}).get("loaded", False)):
        windows_policy_selected = False
    expected_policy_baseline = dict(inputs.get("expected_policy_baseline") or {})
    if not linux_policy_selected:
        expected_policy_baseline.pop("ssh_policy", None)
    if not windows_policy_selected:
        for key in ("windows_policy_checks", "audit_policy", "firewall_policy", "execution_policy"):
            expected_policy_baseline.pop(key, None)

    normalized_identities = normalize_identities(
        inputs.get("linux_identity"),
        inputs.get("windows_identity_rows"),
    )
    correlated_privileges = correlate_identity_privileges(
        normalized_identities,
        inputs.get("approved_linux_sudoers"),
        inputs.get("approved_windows_admins"),
        inputs.get("approved_service_accounts"),
    )
    correlated_events = correlate_events_to_identities(
        correlated_privileges,
        linux_auth_events=(inputs.get("linux_identity") or {}).get("auth_events", []),
        windows_events=inputs.get("windows_events_rows"),
    )
    correlated_policy = correlate_policy_findings(
        correlated_events,
        linux_policy=inputs.get("linux_policy"),
        windows_policy_rows=inputs.get("windows_policy_rows"),
        expected_policy_baseline=expected_policy_baseline,
    )

    findings = detect_anomalies(
        correlated_policy,
        linux_policy=inputs.get("linux_policy"),
        windows_policy_rows=inputs.get("windows_policy_rows"),
        expected_policy_baseline=expected_policy_baseline,
        approved_linux_sudoers=inputs.get("approved_linux_sudoers"),
        approved_windows_admins=inputs.get("approved_windows_admins"),
        approved_service_accounts=inputs.get("approved_service_accounts"),
    )
    summary = summarize_findings(findings)

    analysis_result = {
        "run_id": run_id,
        "mode": mode,
        "data_sources": inputs.get("data_sources", {}),
        "data_quality": data_quality,
        "findings": findings,
        "summary": summary,
    }
    LOGGER.info("Completed analysis for run_id=%s with %s findings", run_id, len(findings))
    return analysis_result


def _build_run_id() -> str:
    """Create a UTC run identifier for direct engine execution.

    The helper mirrors the application entry point so tests can exercise the
    engine without having to construct a separate bootstrap layer.
    """
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def run_identity_risk_engine(
    mode: str,
    data_paths: Mapping[str, Any] | None = None,
    run_id: str | None = None,
) -> dict:
    """Run the full identity risk engine and return a structured result.

    Expects a mode, an optional mapping of configured data paths, and an
    optional run identifier. The function loads the analysis inputs, runs the
    read-only analysis pipeline, and returns the result for reporting layers.

    Security / robustness
    ---------------------
    The engine never edits system state. Its only output is a dictionary that
    can be logged, tested, or handed to reporting modules.
    """
    effective_run_id = run_id or _build_run_id()
    LOGGER.info("Initializing identity risk engine for run_id=%s", effective_run_id)
    inputs = load_analysis_inputs(mode, dict(data_paths or {}))
    inputs["run_id"] = effective_run_id
    result = analyze_inputs(inputs)
    LOGGER.info("Identity risk engine finished for run_id=%s", effective_run_id)
    return result
