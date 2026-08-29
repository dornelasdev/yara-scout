from pathlib import Path

import pytest

from yara_scout.filetypes import detect_file_type
from yara_scout.models import FileType


@pytest.mark.parametrize(
    ("header", "expected_mime_type"),
    [
        (
            b"MZ" + b"\0" * 58 + b"\x40\0\0\0" + b"PE\0\0",
            "application/vnd.microsoft.portable-executable",
        ),
        (b"\x7fELF\x02\x01", "application/x-elf"),
        (b"%PDF-1.7", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff\xe0", "image/jpeg"),
        (b"\x1f\x8b\x08", "application/gzip"),
    ],
)
def test_detect_file_type_prefers_known_signatures(
    tmp_path: Path,
    header: bytes,
    expected_mime_type: str,
) -> None:
    file_path = tmp_path / "misleading.txt"
    file_path.write_bytes(header + b"test data")

    result = detect_file_type(file_path)

    assert result == FileType(mime_type=expected_mime_type, source="signature")


def test_detect_file_type_falls_back_to_the_extension(tmp_path: Path) -> None:
    file_path = tmp_path / "example.json"
    file_path.write_text('{"safe": true}')

    result = detect_file_type(file_path)

    assert result == FileType(mime_type="application/json", source="extension")


def test_detect_file_type_uses_binary_fallback_for_an_unknown_file(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "unknown"
    file_path.write_bytes(b"unrecognized content")

    result = detect_file_type(file_path)

    assert result == FileType(
        mime_type="application/octet-stream",
        source="fallback",
    )
