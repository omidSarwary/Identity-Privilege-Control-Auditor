"""Safe command execution helpers for platform collectors."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import logging
import subprocess
import time
from typing import Mapping, Sequence


LOGGER = logging.getLogger("nordsec.ipca.core.command_runner")


@dataclass(frozen=True)
class CommandResult:
    """Structured result for one executed command.

    The result keeps the original command arguments, captured stdout and
    stderr, the exit code, and timeout state so collectors can make a safe
    decision without parsing console output.
    """

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    started_at: float
    finished_at: float

    @property
    def duration_seconds(self) -> float:
        """Return the elapsed runtime for the command."""
        return max(0.0, self.finished_at - self.started_at)

    @property
    def succeeded(self) -> bool:
        """Return ``True`` when the command completed cleanly."""
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> dict[str, object]:
        """Return a serializable representation of the command result."""
        payload = asdict(self)
        payload["duration_seconds"] = self.duration_seconds
        payload["succeeded"] = self.succeeded
        return payload


def run_command(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Execute a command safely and return structured output.

    Expects a list-style command, optional working directory, optional timeout,
    and optional environment mapping. The helper never uses ``shell=True`` so
    collectors do not inherit shell parsing risks.
    """
    command_list = [str(part) for part in command]
    start_time = time.time()
    LOGGER.info("Starting command: %s", command_list)

    try:
        completed = subprocess.run(
            command_list,
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env) if env is not None else None,
            timeout=timeout,
            check=False,
            capture_output=True,
            text=True,
            shell=False,
        )
        end_time = time.time()
        LOGGER.info("Completed command: %s (rc=%s)", command_list, completed.returncode)
        return CommandResult(
            command=tuple(command_list),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            started_at=start_time,
            finished_at=end_time,
        )
    except subprocess.TimeoutExpired as exc:
        end_time = time.time()
        LOGGER.error("Command timed out after %s seconds: %s", timeout, command_list)
        return CommandResult(
            command=tuple(command_list),
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or f"Command timed out after {timeout} seconds.",
            timed_out=True,
            started_at=start_time,
            finished_at=end_time,
        )
    except FileNotFoundError as exc:
        end_time = time.time()
        LOGGER.error("Command not found: %s", command_list)
        return CommandResult(
            command=tuple(command_list),
            returncode=127,
            stdout="",
            stderr=str(exc),
            timed_out=False,
            started_at=start_time,
            finished_at=end_time,
        )
    except Exception as exc:  # pragma: no cover - defensive guard
        end_time = time.time()
        LOGGER.exception("Unexpected command failure: %s", command_list)
        return CommandResult(
            command=tuple(command_list),
            returncode=1,
            stdout="",
            stderr=str(exc),
            timed_out=False,
            started_at=start_time,
            finished_at=end_time,
        )
