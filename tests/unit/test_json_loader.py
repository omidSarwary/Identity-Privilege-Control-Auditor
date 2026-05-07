"""Tests for JSON loading helpers."""

from __future__ import annotations

import json

import pytest

from src.parsers._common import EmptyFileError, FileMissingError, InvalidFormatError
from src.parsers.json_loader import load_json_file


def test_load_json_file_valid(tmp_path) -> None:
    """A valid JSON object should be returned as a dictionary."""
    path = tmp_path / "valid.json"
    path.write_text(json.dumps({"name": "nordsec"}), encoding="utf-8")

    result = load_json_file(path)

    assert result == {"name": "nordsec"}


def test_load_json_file_invalid(tmp_path) -> None:
    """Invalid JSON should raise a controlled format exception."""
    path = tmp_path / "invalid.json"
    path.write_text("{not-json}", encoding="utf-8")

    with pytest.raises(InvalidFormatError):
        load_json_file(path)


def test_load_json_file_missing(tmp_path) -> None:
    """A missing JSON file should raise a controlled missing-file exception."""
    path = tmp_path / "missing.json"

    with pytest.raises(FileMissingError):
        load_json_file(path)


def test_load_json_file_empty(tmp_path) -> None:
    """An empty JSON file should raise a controlled empty-file exception."""
    path = tmp_path / "empty.json"
    path.write_text("   ", encoding="utf-8")

    with pytest.raises(EmptyFileError):
        load_json_file(path)
