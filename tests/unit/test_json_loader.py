"""Tests for JSON loading helpers."""

from __future__ import annotations

import json

import pytest

from src.parsers._common import EmptyFileError, FileMissingError, InvalidFormatError
from src.parsers.json_loader import load_json_file


def test_load_json_file_valid(tmp_path) -> None:
    """Valid JSON should load into a dictionary without altering the data.

    This protects the parser contract used by later correlation code, which
    expects structured Linux identity and policy payloads.
    """
    path = tmp_path / "valid.json"
    path.write_text(json.dumps({"name": "nordsec"}), encoding="utf-8")

    result = load_json_file(path)

    assert result == {"name": "nordsec"}


def test_load_json_file_invalid(tmp_path) -> None:
    """Invalid JSON should raise a controlled format exception.

    The parser must fail safely so fallback logic can choose another source
    instead of feeding corrupt data into the analysis layer.
    """
    path = tmp_path / "invalid.json"
    path.write_text("{not-json}", encoding="utf-8")

    with pytest.raises(InvalidFormatError):
        load_json_file(path)


def test_load_json_file_missing(tmp_path) -> None:
    """A missing JSON file should raise a controlled missing-file exception.

    Missing inputs are expected in fallback scenarios, so the parser should
    signal the problem cleanly rather than crash.
    """
    path = tmp_path / "missing.json"

    with pytest.raises(FileMissingError):
        load_json_file(path)


def test_load_json_file_empty(tmp_path) -> None:
    """An empty JSON file should raise a controlled empty-file exception.

    Empty exports should not be treated as valid evidence because they would
    produce misleading downstream findings.
    """
    path = tmp_path / "empty.json"
    path.write_text("   ", encoding="utf-8")

    with pytest.raises(EmptyFileError):
        load_json_file(path)
