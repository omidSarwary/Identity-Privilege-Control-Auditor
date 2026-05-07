"""Tests for CSV loading helpers."""

from __future__ import annotations

import pytest

from src.parsers._common import EmptyFileError, FileMissingError, InvalidFormatError
from src.parsers.csv_loader import load_csv_file


def test_load_csv_file_valid(tmp_path) -> None:
    """Valid CSV should become a list of row dictionaries.

    The parser contract matters because baseline and Windows event data are
    consumed row-by-row by the correlation and anomaly layers.
    """
    path = tmp_path / "valid.csv"
    path.write_text(
        "username,reason,owner,approved_until\n"
        "ops_backup,Backup access,NordSec,2026-12-31\n",
        encoding="utf-8",
    )

    result = load_csv_file(path, ["username", "reason", "owner", "approved_until"])

    assert result == [
        {
            "username": "ops_backup",
            "reason": "Backup access",
            "owner": "NordSec",
            "approved_until": "2026-12-31",
        }
    ]


def test_load_csv_file_missing_required_column(tmp_path) -> None:
    """Missing headers should raise a controlled format exception.

    The pipeline needs a stable schema, so absent headers must stop the parser
    before malformed rows reach the security rules.
    """
    path = tmp_path / "missing_column.csv"
    path.write_text("username,owner,approved_until\nops_backup,NordSec,2026-12-31\n", encoding="utf-8")

    with pytest.raises(InvalidFormatError):
        load_csv_file(path, ["username", "reason", "owner", "approved_until"])


def test_load_csv_file_missing(tmp_path) -> None:
    """A missing CSV file should raise a controlled missing-file exception.

    This protects fallback behavior by making the failure explicit and easy to
    handle in later orchestration.
    """
    path = tmp_path / "missing.csv"

    with pytest.raises(FileMissingError):
        load_csv_file(path, ["username"])


def test_load_csv_file_empty(tmp_path) -> None:
    """An empty CSV should raise a controlled empty-file exception.

    Empty data would otherwise look like a successful collection run, which is
    dangerous in a security audit pipeline.
    """
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")

    with pytest.raises(EmptyFileError):
        load_csv_file(path, ["username"])
