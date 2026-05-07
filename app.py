"""Main entry point for the NordSec Identity & Privilege Control Auditor.

This phase initializes the shared project paths, environment checks, central
logging, and the read-only identity risk engine. Collection logic is still
deferred to later phases, but analysis can now run against prepared inputs.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.core.bootstrap import load_app_config
from src.core.environment import check_environment
from src.core.paths import (
    BASELINES_DIR,
    PRODUCTION_CONFIG_FILE,
    TEST_CONFIG_FILE,
    ensure_required_directories,
)
from src.analysis.identity_risk_engine import run_identity_risk_engine
from src.parsers.json_loader import load_json_file
from src.utils.console import format_banner, print_message
from src.utils.logging_config import get_component_logger, setup_logging


def build_run_id() -> str:
    """Create a stable run identifier for logs and future reports.

    Returns a UTC timestamp string that tags the current execution. The run id
    keeps logs and future reports easy to correlate without exposing secrets or
    machine-specific details.
    """
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def main() -> int:
    """Run the application bootstrap and analysis entry point.

    Initializes paths, logging, environment checks, and the read-only analysis
    engine. The function expects the project configuration files to be present
    and returns a process exit code so the caller can tell whether the run was
    safe and complete.
    """
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
        mode_config_file = TEST_CONFIG_FILE if default_mode == "test" else PRODUCTION_CONFIG_FILE
        mode_config = load_json_file(mode_config_file)
        data_paths = dict(mode_config.get("paths", {}))
        data_paths["baselines"] = str(BASELINES_DIR)

        analysis_result = run_identity_risk_engine(
            mode=default_mode,
            data_paths=data_paths,
            run_id=run_id,
        )

        logger.info(
            "Analysis completed with %s findings across %s identities",
            len(analysis_result.get("findings", [])),
            len(analysis_result.get("summary", {}).get("identities", [])),
        )
        logger.info("Safe exit")
        return 0
    except Exception as exc:  # pragma: no cover - defensive bootstrap guard
        logger.exception("Unhandled bootstrap error: %s", exc)
        logger.info("Safe exit")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
