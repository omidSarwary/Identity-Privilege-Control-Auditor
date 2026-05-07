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
    """Return ``True`` when the current interpreter meets the minimum version."""
    return sys.version_info >= min_version


def check_required_directories() -> tuple[bool, tuple[str, ...]]:
    """Verify that the required directories are present on disk."""
    missing = tuple(str(directory) for directory in REQUIRED_DIRECTORIES if not directory.exists())
    return not missing, missing


def check_environment() -> EnvironmentStatus:
    """Collect structured status for the core runtime environment."""
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
