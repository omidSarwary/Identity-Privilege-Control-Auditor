"""CSV loading helpers for collected audit data."""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path

from src.parsers._common import EmptyFileError, FileMissingError, InvalidFormatError, read_text_file


LOGGER = logging.getLogger("nordsec.ipca.parsers.csv_loader")


def _normalize_header_name(value: str) -> str:
    """Return a clean CSV header name for validation and row keys.

    The loader accepts UTF-8 BOM-prefixed headers and harmless surrounding
    double quotes so Windows-authored exports can be consumed safely without
    changing the underlying schema.
    """
    cleaned = value.replace("\ufeff", "").strip()
    if len(cleaned) >= 2 and cleaned.startswith('"') and cleaned.endswith('"'):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def load_csv_file(path: Path, required_columns: list[str], *, allow_empty_rows: bool = False) -> list[dict]:
    """Load a CSV file and return its rows as dictionaries.

    Expects a path to a CSV file and a list of required header names. The
    function validates the headers before returning data so the rest of the
    pipeline only sees well-formed rows, which is important for risk
    correlation and baseline matching. Event sources may explicitly allow a
    header-only file to represent an empty but valid collection window.
    """
    try:
        content = read_text_file(path, encoding="utf-8-sig")
    except (FileMissingError, EmptyFileError):
        LOGGER.error("Unable to load CSV file: %s", path)
        raise

    reader = csv.reader(io.StringIO(content))
    try:
        raw_fieldnames = next(reader)
    except StopIteration as exc:
        LOGGER.error("CSV file contains no header row: %s", path)
        raise EmptyFileError(f"CSV file contains no header row: {path}") from exc

    fieldnames = [_normalize_header_name(fieldname) for fieldname in raw_fieldnames]
    missing_columns = [column for column in required_columns if column not in fieldnames]
    if missing_columns:
        LOGGER.error("CSV file missing required columns %s: %s", missing_columns, path)
        raise InvalidFormatError(
            f"CSV file missing required columns {missing_columns}: {path}"
        )

    rows = []
    for raw_row in reader:
        if not raw_row or not any(str(value).strip() for value in raw_row):
            continue

        normalized_row = {
            fieldname: (raw_row[index] if index < len(raw_row) else "")
            for index, fieldname in enumerate(fieldnames)
        }
        rows.append(normalized_row)

    if not rows and not allow_empty_rows:
        LOGGER.error("CSV file contains no data rows: %s", path)
        raise EmptyFileError(f"CSV file contains no data rows: {path}")

    return rows
