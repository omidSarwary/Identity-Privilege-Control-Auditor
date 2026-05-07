"""Log loading helpers for collected audit data."""

from __future__ import annotations

import logging
from pathlib import Path

from src.parsers._common import EmptyFileError, FileMissingError, read_text_file


LOGGER = logging.getLogger("nordsec.ipca.parsers.log_loader")


def load_text_log(path: Path) -> list[str]:
    """Load a text log file and return its lines.

    Expects a path to a text log and returns a list of lines. The loader uses
    replacement decoding so unusual characters do not break the pipeline, which
    is useful when log exports come from mixed operating systems.
    """
    try:
        content = read_text_file(path, errors="replace")
    except (FileMissingError, EmptyFileError):
        LOGGER.error("Unable to load text log: %s", path)
        raise

    lines = content.splitlines()
    if not lines:
        LOGGER.error("Text log contains no readable lines: %s", path)
        raise EmptyFileError(f"Text log contains no readable lines: {path}")
    return lines
