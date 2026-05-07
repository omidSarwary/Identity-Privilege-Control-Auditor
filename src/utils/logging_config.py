"""Central logging configuration for the audit tool."""

from __future__ import annotations

import logging
from pathlib import Path
import sys
from datetime import datetime, timezone

from src.core.paths import LOGS_ARCHIVE_DIR, LOGS_DIR


LOG_FILE_NAME = "python_engine.log"
LOG_FILE_PATH = LOGS_DIR / LOG_FILE_NAME
MAX_LOG_BYTES = 1_048_576


class RunContextFilter(logging.Filter):
    """Inject run metadata into every log record."""

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
    """Format log lines with a compact audit-friendly structure."""

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        return super().formatTime(record, datefmt or "%Y-%m-%d %H:%M:%S")


def _rotate_existing_log_if_needed(log_file_path: Path) -> None:
    """Move an oversized log file into the archive directory."""
    if not log_file_path.exists() or log_file_path.stat().st_size < MAX_LOG_BYTES:
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archived_path = LOGS_ARCHIVE_DIR / f"{log_file_path.stem}-{timestamp}{log_file_path.suffix}"
    log_file_path.replace(archived_path)


def _prepare_handlers(run_id: str, debug: bool) -> list[logging.Handler]:
    """Build the file and console handlers used by the application."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    _rotate_existing_log_if_needed(LOG_FILE_PATH)

    file_handler = logging.FileHandler(LOG_FILE_PATH, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)

    formatter = CompactLogFormatter(
        "%(asctime)s %(levelname)s %(component)s %(run_id)s %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

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
    """
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG)

    for handler in _prepare_handlers(run_id=run_id, debug=debug):
        root_logger.addHandler(handler)

    return logging.getLogger("nordsec.ipca")


def get_component_logger(component: str, run_id: str) -> logging.LoggerAdapter:
    """Return a logger adapter that injects component and run metadata."""
    return logging.LoggerAdapter(
        logging.getLogger("nordsec.ipca"),
        {"component": component, "run_id": run_id},
    )
