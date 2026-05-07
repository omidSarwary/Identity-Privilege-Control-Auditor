"""CSV loading helpers for collected audit data."""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path

from src.parsers._common import EmptyFileError, FileMissingError, InvalidFormatError, read_text_file


LOGGER = logging.getLogger("nordsec.ipca.parsers.csv_loader")


def load_csv_file(path: Path, required_columns: list[str]) -> list[dict]:
    """Load a CSV file and return its rows as dictionaries.

    The parser validates required headers and surfaces controlled exceptions so
    later fallback logic can decide how to proceed.
    """
    try:
        content = read_text_file(path)
    except (FileMissingError, EmptyFileError):
        LOGGER.error("Unable to load CSV file: %s", path)
        raise

    reader = csv.DictReader(io.StringIO(content))
    fieldnames = reader.fieldnames or []
    missing_columns = [column for column in required_columns if column not in fieldnames]
    if missing_columns:
        LOGGER.error("CSV file missing required columns %s: %s", missing_columns, path)
        raise InvalidFormatError(
            f"CSV file missing required columns {missing_columns}: {path}"
        )

    rows = [row for row in reader if any(value is not None and str(value).strip() for value in row.values())]
    if not rows:
        LOGGER.error("CSV file contains no data rows: %s", path)
        raise EmptyFileError(f"CSV file contains no data rows: {path}")

    return rows
