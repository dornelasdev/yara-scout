"""Structured records shared by YARA Scout components."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypeAlias


MetadataValue: TypeAlias = str | int | bool
FileTypeSource: TypeAlias = Literal["signature", "extension", "fallback"]


@dataclass(frozen=True, slots=True)
class FileType:
    """The detected MIME type and the method used to identify it."""

    mime_type: str
    source: FileTypeSource


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A normalized YARA rule match."""

    rule: str
    namespace: str
    tags: tuple[str, ...] = ()
    metadata: dict[str, MetadataValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The triage information collected for one file."""

    path: Path
    size: int | None
    sha256: str | None
    file_type: FileType | None = None
    matches: tuple[RuleMatch, ...] = ()
    error: str | None = None
    skipped_reason: str | None = None

    @property
    def matched(self) -> bool:
        """Return whether at least one YARA rule matched the file."""
        return bool(self.matches)

    @property
    def skipped(self) -> bool:
        """Return whether a scanner policy prevented scanning the file."""
        return self.skipped_reason is not None
