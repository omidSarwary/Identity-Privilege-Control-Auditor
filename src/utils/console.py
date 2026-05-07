"""Console formatting helpers for user-facing output."""

from __future__ import annotations


def format_banner(title: str, version: str, mode: str) -> str:
    """Return a professional splashscreen banner."""
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
    """Print a concise console message for important events."""
    print(message)
