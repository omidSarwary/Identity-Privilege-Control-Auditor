"""Tests for the safe command execution helper."""

from __future__ import annotations

import sys

from src.core.command_runner import run_command


def test_run_command_captures_stdout_without_shell() -> None:
    """The command runner should capture output while avoiding shell parsing."""
    result = run_command([sys.executable, "-c", "print('hello')"], timeout=10)

    assert result.succeeded is True
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"
    assert result.stderr == ""
    assert result.timed_out is False
