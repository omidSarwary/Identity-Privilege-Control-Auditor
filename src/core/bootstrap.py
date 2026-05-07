"""Bootstrap helpers for application start-up checks."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import logging
import sys
from typing import Any

from src.core.environment import EnvironmentStatus, check_environment
from src.core.paths import APP_CONFIG_FILE, REQUIREMENTS_FILE, ensure_required_directories


LOGGER = logging.getLogger("nordsec.ipca.core.bootstrap")


@dataclass(frozen=True)
class BootstrapStatus:
    """Structured bootstrap summary used by the application orchestrator.

    The status keeps environment, requirements, and virtual-environment checks
    together so the app can decide whether to continue without making any
    system changes.
    """

    bootstrap_skipped: bool
    environment: EnvironmentStatus
    requirements_file_present: bool
    requirements_file_nonempty: bool
    venv_active: bool
    messages: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable representation of the bootstrap result."""
        return asdict(self)

    @property
    def can_continue(self) -> bool:
        """Return ``True`` when the project environment is ready for analysis."""
        return self.environment.python_ok and self.environment.required_directories_ok


def load_app_config() -> dict[str, Any]:
    """Load the central application configuration.

    Expects the project configuration file at ``config/app_config.json`` and
    returns the parsed JSON object as a dictionary. The function exists so the
    application can read runtime metadata from one central place instead of
    hardcoding values in multiple modules.
    """
    import json

    with APP_CONFIG_FILE.open(encoding="utf-8") as config_file:
        return json.load(config_file)


def _check_requirements_file() -> tuple[bool, bool, tuple[str, ...]]:
    """Inspect ``requirements.txt`` without installing anything.

    The project only needs a light-weight readiness check here. The function
    verifies that the file exists and contains at least one non-comment entry,
    which is enough to confirm that the repo captured its runtime intent.
    """
    if not REQUIREMENTS_FILE.exists():
        return False, False, ("requirements.txt was not found.",)

    lines = [
        line.strip()
        for line in REQUIREMENTS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        return True, False, ("requirements.txt does not list any dependencies.",)
    return True, True, (f"requirements.txt lists {len(lines)} dependencies.",)


def _check_venv_state() -> tuple[bool, str]:
    """Check whether the process is running inside a virtual environment."""
    venv_active = sys.prefix != sys.base_prefix
    if venv_active:
        return True, "Virtual environment detected."
    return False, "Virtual environment not detected; analysis can continue, but a venv is recommended."


def bootstrap_project(*, perform_full_checks: bool = True) -> BootstrapStatus:
    """Prepare the project runtime in a safe, read-only manner.

    Expects no input and returns a structured bootstrap summary. The function
    creates required directories, checks the Python/runtime environment, and
    optionally performs light requirements and virtual-environment checks. It
    never installs packages or modifies the host system.
    """
    ensure_required_directories()
    environment_status = check_environment()
    messages = list(environment_status.messages)

    requirements_file_present = False
    requirements_file_nonempty = False
    venv_active = False

    if perform_full_checks:
        requirements_file_present, requirements_file_nonempty, requirements_messages = _check_requirements_file()
        venv_active, venv_message = _check_venv_state()
        messages.extend(requirements_messages)
        messages.append(venv_message)
    else:
        messages.append("Bootstrap checks were reduced because --no-bootstrap was selected.")

    for message in messages:
        LOGGER.info(message)

    return BootstrapStatus(
        bootstrap_skipped=not perform_full_checks,
        environment=environment_status,
        requirements_file_present=requirements_file_present,
        requirements_file_nonempty=requirements_file_nonempty,
        venv_active=venv_active,
        messages=tuple(messages),
    )
