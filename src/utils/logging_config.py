"""Central logging configuration for the audit tool."""

from __future__ import annotations

import logging
from pathlib import Path
import sys
from datetime import datetime, timezone

from src.core.paths import DATA_ALERTS_DIR, DATA_COLLECTED_DIR, LOGS_ARCHIVE_DIR, LOGS_DIR, REPORTS_DIR


LOG_FILE_NAME = "python_engine.log"
LOG_FILE_PATH = LOGS_DIR / LOG_FILE_NAME
MAX_LOG_BYTES = 1_048_576
RUNTIME_PERMISSION_HINT = (
    "Fix ownership with: sudo chown -R $USER:$USER logs reports data/alerts data/collected"
)


class RuntimeLoggingError(RuntimeError):
    """Raised when the application cannot write its runtime log file."""


class RunContextFilter(logging.Filter):
    """Inject the current run identifier and component into log records.

    The filter keeps every log line traceable to one execution, which matters
    for audit logs and forensic review after a security scan or report run.
    """

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self.run_id = run_id

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "run_id"):
            record.run_id = self.run_id
        if not hasattr(record, "component"):
            record.component = "app"
        return True


class CompactLogFormatter(logging.Formatter):
    """Format logs in the compact audit format used by the project.

    The formatter preserves a predictable timestamp, severity, component, and
    run identifier so logs are easy to compare across test and production runs.
    """

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        return super().formatTime(record, datefmt or "%Y-%m-%d %H:%M:%S")


class ConsoleVisibilityFilter(logging.Filter):
    """Keep the console focused on user-facing app messages.

    The detailed audit trail still goes to the file handler, but the terminal
    only shows app-level warnings/errors plus any critical stop condition.
    This keeps normal runs readable without hiding important failures.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.CRITICAL:
            return True
        return record.name == "nordsec.ipca" and record.levelno >= logging.WARNING


def _rotate_existing_log_if_needed(log_file_path: Path) -> None:
    """Archive an oversized log file before a new run writes to it.

    This keeps the active log small while preserving historical evidence in
    ``logs/archive/``. The rotation is intentionally simple and read-only.
    """
    if not log_file_path.exists() or log_file_path.stat().st_size < MAX_LOG_BYTES:
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archived_path = LOGS_ARCHIVE_DIR / f"{log_file_path.stem}-{timestamp}{log_file_path.suffix}"
    log_file_path.replace(archived_path)


def verify_runtime_paths_writable(log_file_path: Path = LOG_FILE_PATH) -> None:
    """Verify that runtime output paths are writable before full logging starts.

    This function is intentionally small and dependency-free because it may run
    before the logging system is configured. It catches the common Linux case
    where a previous sudo run left root-owned runtime files behind.
    """
    try:
        for directory in (LOGS_DIR, REPORTS_DIR, DATA_ALERTS_DIR, DATA_COLLECTED_DIR):
            directory.mkdir(parents=True, exist_ok=True)
            probe = directory / ".write_test"
            with probe.open("w", encoding="utf-8"):
                pass
            probe.unlink(missing_ok=True)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        with log_file_path.open("a", encoding="utf-8"):
            pass
    except PermissionError as exc:
        raise RuntimeLoggingError(
            f"Cannot write to {log_file_path} because it is not writable by the current user. "
            "This can happen after running the app with sudo. "
            f"{RUNTIME_PERMISSION_HINT}. Or run the app with sudo if collection requires elevated privileges."
        ) from exc
    except OSError as exc:
        raise RuntimeLoggingError(f"Cannot prepare runtime log file {log_file_path}: {exc}") from exc


def verify_logging_path_writable(log_file_path: Path = LOG_FILE_PATH) -> None:
    """Backward-compatible wrapper for runtime path permission checks."""
    verify_runtime_paths_writable(log_file_path)


def _prepare_handlers(run_id: str, debug: bool) -> list[logging.Handler]:
    """Build the file and console handlers used by the application.

    Expects a run identifier and debug flag, then returns the configured
    handlers that write to the engine log and console. The handlers are kept in
    one place so the format stays consistent across the project.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    _rotate_existing_log_if_needed(LOG_FILE_PATH)

    file_handler = logging.FileHandler(LOG_FILE_PATH, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    # Keep the terminal focused on actionable messages while the file log
    # preserves the full audit trail for later review.
    console_handler.setLevel(logging.DEBUG if debug else logging.ERROR)

    formatter = CompactLogFormatter(
        "%(asctime)s %(levelname)s %(component)s %(run_id)s %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(ConsoleVisibilityFilter())

    context_filter = RunContextFilter(run_id=run_id)
    file_handler.addFilter(context_filter)
    console_handler.addFilter(context_filter)

    return [file_handler, console_handler]


def setup_logging(run_id: str, debug: bool = False) -> logging.Logger:
    """Configure application logging for the current run.

    Parameters
    ----------
    run_id:
        Unique identifier for the current execution.
    debug:
        When ``True``, console output includes debug-level messages.

    Returns
    -------
    logging.Logger
        The shared project logger used by the application and analysis layers.

    Security / robustness
    ---------------------
    The function resets root handlers so the project does not accidentally
    duplicate messages or inherit unrelated logging configuration from the
    environment.
    """
    verify_runtime_paths_writable()

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG)

    for handler in _prepare_handlers(run_id=run_id, debug=debug):
        root_logger.addHandler(handler)

    return logging.getLogger("nordsec.ipca")


def get_component_logger(component: str, run_id: str) -> logging.LoggerAdapter:
    """Return a component-aware logger adapter for structured output.

    Expects a component name and the current run identifier, then returns a
    logger adapter that stamps both values into each record. This keeps logs
    easy to trace when several pipeline steps run in the same session.
    """
    return logging.LoggerAdapter(
        logging.getLogger("nordsec.ipca"),
        {"component": component, "run_id": run_id},
    )
