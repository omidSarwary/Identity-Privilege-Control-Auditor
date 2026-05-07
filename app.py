"""Main entry point for the NordSec Identity & Privilege Control Auditor.

This phase initializes the shared project paths, environment checks, and
central logging foundation. Collection and analysis logic are intentionally
not activated yet.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.core.bootstrap import load_app_config
from src.core.environment import check_environment
from src.core.paths import ensure_required_directories
from src.utils.console import format_banner, print_message
from src.utils.logging_config import get_component_logger, setup_logging


def build_run_id() -> str:
    """Create a stable run identifier for logs and future reports."""
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def main() -> int:
    """Run the bootstrap-only application entry point."""
    run_id = build_run_id()
    setup_logging(run_id=run_id, debug=False)
    logger = get_component_logger("app", run_id)

    try:
        ensure_required_directories()
        app_config = load_app_config()
        app_name = app_config["project_name"]
        app_version = app_config["version"]
        default_mode = app_config["default_mode"]

        logger.info("Program start")
        print_message(format_banner(app_name, app_version, default_mode))

        environment_status = check_environment()
        if not environment_status.python_ok:
            logger.critical("Python version check failed")
            for message in environment_status.messages:
                logger.error(message)
            logger.info("Safe exit")
            return 1

        if not environment_status.required_directories_ok:
            logger.error("Required directory check failed")
            for missing_directory in environment_status.missing_directories:
                logger.error("Missing directory: %s", missing_directory)
            logger.info("Safe exit")
            return 1

        logger.info("Environment checks passed")
        logger.info("Safe exit")
        return 0
    except Exception as exc:  # pragma: no cover - defensive bootstrap guard
        logger.exception("Unhandled bootstrap error: %s", exc)
        logger.info("Safe exit")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
