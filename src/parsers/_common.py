"""Shared parser utilities and controlled exceptions."""

from __future__ import annotations

from pathlib import Path


class ParserError(Exception):
    """Base class for controlled parser failures in the parser pipeline."""


class FileMissingError(ParserError):
    """Raised when an expected input file is not present."""


class EmptyFileError(ParserError):
    """Raised when an expected input file is empty."""


class InvalidFormatError(ParserError):
    """Raised when parser input does not match the expected format."""


def read_text_file(path: Path, *, encoding: str = "utf-8", errors: str = "strict") -> str:
    """Read a text file with controlled error handling.

    Expects a filesystem path and returns the file contents as a string. The
    helper raises dedicated exceptions for missing or empty input so callers
    can decide whether to fail fast or fall back to another data source.
    """
    if not path.exists():
        raise FileMissingError(f"File not found: {path}")

    content = path.read_text(encoding=encoding, errors=errors)
    if not content.strip():
        raise EmptyFileError(f"File is empty: {path}")
    return content
