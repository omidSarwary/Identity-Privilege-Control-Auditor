"""JSON loading helpers for collected audit data."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.parsers._common import EmptyFileError, FileMissingError, InvalidFormatError, read_text_file


LOGGER = logging.getLogger("nordsec.ipca.parsers.json_loader")


def load_json_file(path: Path) -> dict:
    """Load a JSON file and return a dictionary.

    Missing, empty, and invalid JSON inputs are reported through controlled
    exceptions so fallback logic can handle them later.
    """
    try:
        content = read_text_file(path)
        payload = json.loads(content)
    except (FileMissingError, EmptyFileError):
        LOGGER.error("Unable to load JSON file: %s", path)
        raise
    except json.JSONDecodeError as exc:
        LOGGER.error("Invalid JSON in file: %s", path)
        raise InvalidFormatError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(payload, dict):
        LOGGER.error("JSON root must be an object: %s", path)
        raise InvalidFormatError(f"JSON root must be an object: {path}")

    return payload
