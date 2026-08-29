import mimetypes
from pathlib import Path
from typing import BinaryIO

from yara_scout.models import FileType


HEADER_SIZE = 64
PE_HEADER_POINTER_OFFSET = 0x3C
PE_MIME_TYPE = "application/vnd.microsoft.portable-executable"
SIGNATURES: tuple[tuple[tuple[bytes, ...], str], ...] = (
    ((b"\x7fELF",), "application/x-elf"),
    ((b"%PDF-",), "application/pdf"),
    ((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"), "application/zip"),
    ((b"\x89PNG\r\n\x1a\n",), "image/png"),
    ((b"\xff\xd8\xff",), "image/jpeg"),
    ((b"\x1f\x8b",), "application/gzip"),
)


def detect_file_type(file_path: Path) -> FileType:
    """Identify a file by signature, extension, or a binary fallback."""
    with file_path.open("rb") as file:
        header = file.read(HEADER_SIZE)
        if _has_pe_signature(file, header):
            return FileType(mime_type=PE_MIME_TYPE, source="signature")

    for prefixes, mime_type in SIGNATURES:
        if any(header.startswith(prefix) for prefix in prefixes):
            return FileType(mime_type=mime_type, source="signature")

    mime_type, _encoding = mimetypes.guess_type(file_path.name)
    if mime_type is not None:
        return FileType(mime_type=mime_type, source="extension")

    return FileType(mime_type="application/octet-stream", source="fallback")


def _has_pe_signature(file: BinaryIO, header: bytes) -> bool:
    if not header.startswith(b"MZ") or len(header) < HEADER_SIZE:
        return False

    pe_header_offset = int.from_bytes(
        header[PE_HEADER_POINTER_OFFSET:HEADER_SIZE],
        byteorder="little",
    )
    file.seek(pe_header_offset)
    return file.read(4) == b"PE\0\0"
