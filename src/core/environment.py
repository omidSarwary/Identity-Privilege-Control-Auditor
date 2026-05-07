"""Environment validation helpers for the audit tool."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import sys
from typing import Any

from src.core.paths import REQUIRED_DIRECTORIES


MIN_PYTHON_VERSION = (3, 11)


@dataclass(frozen=True)
class EnvironmentStatus:
    """Structured environment status for bootstrap decisions."""

    python_ok: bool
    python_version: str
    required_directories_ok: bool
    missing_directories: tuple[str, ...]
    messages: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable representation of the environment status."""
        return asdict(self)


def check_python_version(min_version: tuple[int, int] = MIN_PYTHON_VERSION) -> bool:
    """Check whether the active interpreter meets the minimum supported version.

    Expects a ``(major, minor)`` tuple and returns ``True`` when the running
    Python version is new enough for the project. This protects the pipeline
    from running under an unsupported interpreter.
    """
    return sys.version_info >= min_version


def check_required_directories() -> tuple[bool, tuple[str, ...]]:
    """Verify that the required project directories exist.

    Returns a ``(status, missing_paths)`` tuple so bootstrap code can report
    missing folders without crashing. This helps the audit tool fail safely when
    its working directories are incomplete.
    """
    missing = tuple(str(directory) for directory in REQUIRED_DIRECTORIES if not directory.exists())
    return not missing, missing


def check_environment() -> EnvironmentStatus:
    """Collect the current bootstrap status for Python and project folders.

    Returns an :class:`EnvironmentStatus` object that the application can log or
    inspect before starting work. The structured result keeps error handling
    explicit and avoids relying on print statements or hidden side effects.
    """
    python_ok = check_python_version()
    directories_ok, missing_directories = check_required_directories()
    messages = []

    if not python_ok:
        messages.append(
            f"Python {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]} or newer is required."
        )

    if not directories_ok:
        messages.append("One or more required directories are missing.")

    return EnvironmentStatus(
        python_ok=python_ok,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        required_directories_ok=directories_ok,
        missing_directories=missing_directories,
        messages=tuple(messages),
    )
