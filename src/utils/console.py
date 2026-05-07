"""Console formatting helpers for user-facing output."""

from __future__ import annotations


def format_banner(title: str, version: str, mode: str) -> str:
    """Build the console banner shown at program start.

    Expects the project title, version, and mode, and returns a single string
    that can be printed to the console. The banner reminds the user that the
    tool is read-only and does not modify system state.
    """
    lines = [
        "=" * 60,
        f" {title}",
        f" Version: {version}",
        f" Mode: {mode}",
        "",
        " This tool performs read-only security validation.",
        " It does not modify accounts, privileges, or policy state.",
        "=" * 60,
    ]
    return "\n".join(lines)


def print_message(message: str) -> None:
    """Print a concise user-facing console message.

    Expects a single line of text and writes it to standard output. The helper
    keeps user-facing messaging centralized so the console style stays
    consistent.
    """
    print(message)
