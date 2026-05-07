"""Fallback collection helpers for read-only data discovery.

This module searches the project's known data directories when the primary
collector has not produced usable output. It only locates and validates files;
it does not transform the evidence into findings or perform any analysis.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from src.core.paths import DATA_COLLECTED_DIR, DATA_INCOMING_DIR, LOGDATA_DIR, TEST_MOCKDATA_DIR
from src.parsers._common import EmptyFileError, FileMissingError, InvalidFormatError, ParserError
from src.parsers.csv_loader import load_csv_file
from src.parsers.json_loader import load_json_file
from src.parsers.log_loader import load_text_log
from src.parsers.validators import (
    ValidationStatus,
    validate_linux_identity,
    validate_linux_policy,
    validate_windows_events,
    validate_windows_identity,
    validate_windows_policy,
)


LOGGER = logging.getLogger("nordsec.ipca.collectors.fallback")

KNOWN_SOURCE_SPECS: dict[str, dict[str, Any]] = {
    "linux_identity": {
        "filename": "linux_identity.json",
        "kind": "json",
        "validator": validate_linux_identity,
    },
    "linux_policy": {
        "filename": "linux_policy.json",
        "kind": "json",
        "validator": validate_linux_policy,
    },
    "windows_identity": {
        "filename": "windows_identity.csv",
        "kind": "csv",
        "validator": validate_windows_identity,
        "required_columns": ["ComputerName", "CollectionTime", "Username", "Enabled", "IsLocalAdmin", "LastLogon", "Source"],
    },
    "windows_events": {
        "filename": "windows_events.csv",
        "kind": "csv",
        "validator": validate_windows_events,
        "required_columns": ["ComputerName", "TimeCreated", "EventId", "TargetUserName", "IpAddress", "EventType"],
    },
    "windows_policy": {
        "filename": "windows_policy.csv",
        "kind": "csv",
        "validator": validate_windows_policy,
        "required_columns": ["ComputerName", "CheckName", "Status", "Value", "RiskHint"],
    },
    "auth_log": {
        "filename": "auth.log",
        "kind": "log",
    },
}


def _search_directories(mode: str) -> list[Path]:
    """Build the exact fallback search order for one run.

    The collector always checks collected output first, then incoming output,
    then platform log folders. Test mode adds mock data last so unit and
    integration tests can run without touching live sources.
    """
    directories = [
        DATA_COLLECTED_DIR,
        DATA_INCOMING_DIR,
        LOGDATA_DIR / "linux",
        LOGDATA_DIR / "windows",
    ]
    if str(mode).strip().lower() == "test":
        directories.append(TEST_MOCKDATA_DIR)
    return directories


def _status_dict(
    *,
    path: Path | None,
    source_directory: Path | None,
    loaded: bool,
    valid: bool,
    selected: bool = False,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    attempts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the per-source metadata returned by the fallback collector."""
    return {
        "path": str(path) if path is not None else None,
        "source_directory": str(source_directory) if source_directory is not None else None,
        "loaded": loaded,
        "valid": valid,
        "selected": selected,
        "warnings": list(warnings or []),
        "errors": list(errors or []),
        "attempts": list(attempts or []),
    }


def _load_json_source(path: Path, validator: Callable[[dict[str, Any]], ValidationStatus]) -> tuple[dict[str, Any], ValidationStatus]:
    """Load and validate a JSON source using the central parser helpers."""
    data = load_json_file(path)
    validation = validator(data)
    return data, validation


def _load_csv_source(
    path: Path,
    required_columns: Sequence[str],
    validator: Callable[[list[dict[str, Any]]], ValidationStatus],
) -> tuple[list[dict[str, Any]], ValidationStatus]:
    """Load and validate a CSV source using the central parser helpers."""
    rows = load_csv_file(path, list(required_columns))
    validation = validator(rows)
    return rows, validation


def _load_log_source(path: Path) -> list[str]:
    """Load a text log source using the central parser helpers."""
    return load_text_log(path)


def _attempt_source_load(
    spec: Mapping[str, Any],
    candidate: Path,
) -> tuple[Any, ValidationStatus | None, str | None]:
    """Try to load one candidate path and return the outcome.

    The collector intentionally evaluates one candidate at a time so invalid
    files can be skipped and the search can continue to the next approved
    directory for the same logical source.
    """
    try:
        if spec["kind"] == "json":
            payload, validation = _load_json_source(candidate, spec["validator"])
        elif spec["kind"] == "csv":
            payload, validation = _load_csv_source(candidate, spec["required_columns"], spec["validator"])
        else:
            payload = _load_log_source(candidate)
            validation = ValidationStatus(valid=True)
    except (FileMissingError, EmptyFileError, InvalidFormatError) as exc:
        return None, None, str(exc)
    except ParserError as exc:  # pragma: no cover - defensive fallback
        return None, None, str(exc)

    if validation.valid:
        return payload, validation, None
    return payload, validation, validation.errors[-1] if validation.errors else "validation failed"


def collect_fallback_data(mode: str = "production") -> dict[str, Any]:
    """Locate and validate fallback data for one run.

    Expects a mode string so test mode can include the mock data directory last
    in the search order. Returns a structured dictionary containing the loaded
    payloads, per-source status, the search order, and a no-data flag for safe
    downstream handling. The function never performs analysis or remediation.
    """
    search_directories = _search_directories(mode)
    searched_directory_names = [str(directory) for directory in search_directories]
    LOGGER.warning(
        "Fallback collector activated because primary collector output was unavailable or incomplete."
    )
    LOGGER.info("Fallback search order: %s", ", ".join(searched_directory_names))

    sources: dict[str, dict[str, Any]] = {}
    payloads: dict[str, Any] = {}
    used_files: dict[str, dict[str, Any]] = {}
    missing_files: list[str] = []

    for source_name, spec in KNOWN_SOURCE_SPECS.items():
        attempts: list[dict[str, Any]] = []
        selected_payload: Any = None
        selected_path: Path | None = None
        selected_directory: Path | None = None
        selected_validation: ValidationStatus | None = None
        selected = False

        for directory in search_directories:
            candidate = directory / spec["filename"]
            if not candidate.exists() or not candidate.is_file():
                attempts.append(
                    {
                        "path": str(candidate),
                        "source_directory": str(directory),
                        "loaded": False,
                        "valid": False,
                        "selected": False,
                        "errors": [f"{spec['filename']}: file not found"],
                    }
                )
                continue

            LOGGER.info("Fallback source candidate found: %s", candidate)
            payload, validation, error_message = _attempt_source_load(spec, candidate)
            if validation is None:
                LOGGER.warning("Fallback source skipped: %s (%s)", candidate, error_message)
                attempts.append(
                    {
                        "path": str(candidate),
                        "source_directory": str(directory),
                        "loaded": False,
                        "valid": False,
                        "selected": False,
                        "errors": [error_message],
                    }
                )
                continue

            if validation.valid:
                LOGGER.info("Fallback source selected: %s", candidate)
                selected = True
                selected_payload = payload
                selected_path = candidate
                selected_directory = directory
                selected_validation = validation
                attempts.append(
                    {
                        "path": str(candidate),
                        "source_directory": str(directory),
                        "loaded": True,
                        "valid": True,
                        "selected": True,
                        "warnings": list(validation.warnings),
                        "errors": list(validation.errors),
                    }
                )
                break

            invalid_reason = validation.errors[-1] if validation.errors else "validation failed"
            LOGGER.warning("Fallback source invalid and skipped: %s (%s)", candidate, invalid_reason)
            attempts.append(
                {
                    "path": str(candidate),
                    "source_directory": str(directory),
                    "loaded": True,
                    "valid": False,
                    "selected": False,
                    "warnings": list(validation.warnings),
                    "errors": list(validation.errors),
                }
            )

        if selected and selected_path is not None and selected_directory is not None and selected_validation is not None:
            source_status = _status_dict(
                path=selected_path,
                source_directory=selected_directory,
                loaded=True,
                valid=True,
                selected=True,
                warnings=selected_validation.warnings,
                errors=selected_validation.errors,
                attempts=attempts,
            )
            sources[source_name] = source_status
            payloads[source_name] = selected_payload
            used_files[source_name] = {
                "path": str(selected_path),
                "source_directory": str(selected_directory),
                "valid": True,
            }
        else:
            LOGGER.warning("Fallback source missing after search: %s", spec["filename"])
            sources[source_name] = _status_dict(
                path=None,
                source_directory=None,
                loaded=False,
                valid=False,
                selected=False,
                warnings=[],
                errors=[f"{spec['filename']}: file not found"],
                attempts=attempts,
            )
            missing_files.append(spec["filename"])

    no_data_found = not used_files
    fallback_activated = any(
        details.get("selected") and details.get("source_directory") != str(DATA_COLLECTED_DIR)
        for details in sources.values()
    ) or bool(missing_files) or no_data_found

    if no_data_found:
        fallback_reason = "No fallback data was found in any configured directory."
    elif fallback_activated:
        fallback_reason = "Primary collector output was incomplete, so fallback sources were used."
    else:
        fallback_reason = "Collected output satisfied all required sources."

    LOGGER.info("Fallback files used: %s", ", ".join(f"{name}={info['path']}" for name, info in used_files.items()) or "none")
    LOGGER.info("Fallback files missing: %s", ", ".join(missing_files) or "none")
    LOGGER.info("Fallback result: %s", fallback_reason)

    return {
        "mode": str(mode),
        "fallback_activated": fallback_activated,
        "fallback_reason": fallback_reason,
        "searched_directories": searched_directory_names,
        "used_files": used_files,
        "missing_files": missing_files,
        "no_data_found": no_data_found,
        "sources": sources,
        "payloads": payloads,
    }
