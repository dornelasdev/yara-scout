import os
from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path

import yara

from yara_scout.filetypes import detect_file_type
from yara_scout.models import FileType, MetadataValue, RuleMatch, ScanResult


RULE_EXTENSIONS = frozenset({".yar", ".yara"})
HASH_CHUNK_SIZE = 1024 * 1024
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024


class Scanner:
    """Compile YARA rules once and stream triage results for target files."""

    def __init__(
        self,
        rule_path: Path,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        follow_symlinks: bool = False,
    ) -> None:
        if timeout <= 0:
            raise ValueError("YARA timeout must be greater than zero")
        if max_file_size <= 0:
            raise ValueError("Maximum file size must be greater than zero")

        self.rule_path = rule_path.expanduser().resolve()
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.follow_symlinks = follow_symlinks
        self._rules = self._compile_rules(self.rule_path)

    def scan(self, target: Path) -> Iterator[ScanResult]:
        """Yield one scan result for each file under the target path."""
        resolved_target = target.expanduser().absolute()

        if not resolved_target.exists():
            raise FileNotFoundError(f"Scan target does not exist: {resolved_target}")
        if not resolved_target.is_file() and not resolved_target.is_dir():
            raise ValueError(f"Scan target is not a file or directory: {resolved_target}")

        for file_path in self._discover_files(resolved_target):
            yield self._scan_file(file_path)

    def _discover_files(self, target: Path) -> Iterator[Path]:
        if target.is_symlink() and not self.follow_symlinks:
            yield target
            return

        if target.is_file():
            yield target
            return

        visited_directories: set[tuple[int, int]] = set()

        for root, directories, filenames in os.walk(
            target,
            followlinks=self.follow_symlinks,
            onerror=self._raise_discovery_error,
        ):
            root_path = Path(root)

            if self.follow_symlinks:
                stat = root_path.stat()
                identity = (stat.st_dev, stat.st_ino)
                if identity in visited_directories:
                    directories.clear()
                    continue
                visited_directories.add(identity)

            directories.sort()
            filenames.sort()
            for filename in filenames:
                yield root_path / filename

    @staticmethod
    def _raise_discovery_error(error: OSError) -> None:
        raise error

    @staticmethod
    def _compile_rules(rule_path: Path) -> yara.Rules:
        if not rule_path.exists():
            raise FileNotFoundError(f"Rule path does not exist: {rule_path}")

        if rule_path.is_file():
            if rule_path.suffix.lower() not in RULE_EXTENSIONS:
                raise ValueError(f"Unsupported rule file extension: {rule_path}")
            return yara.compile(filepath=str(rule_path))

        if not rule_path.is_dir():
            raise ValueError(f"Rule path is not a file or directory: {rule_path}")

        rule_files = sorted(
            (
                path
                for path in rule_path.rglob("*")
                if path.is_file() and path.suffix.lower() in RULE_EXTENSIONS
            ),
            key=lambda path: path.as_posix(),
        )
        if not rule_files:
            raise ValueError(f"No YARA rule files found in: {rule_path}")

        namespaced_files = {
            f"rule_file_{index}": str(path)
            for index, path in enumerate(rule_files)
        }
        return yara.compile(filepaths=namespaced_files)

    def _scan_file(self, file_path: Path) -> ScanResult:
        size: int | None = None
        digest: str | None = None
        file_type: FileType | None = None

        if file_path.is_symlink() and not self.follow_symlinks:
            return ScanResult(
                path=file_path,
                size=None,
                sha256=None,
                skipped_reason="Symbolic link scanning is disabled",
            )

        try:
            size = file_path.stat().st_size
            if size > self.max_file_size:
                return ScanResult(
                    path=file_path,
                    size=size,
                    sha256=None,
                    skipped_reason=(
                        f"File exceeds maximum size of {self.max_file_size} bytes"
                    ),
                )

            file_type = detect_file_type(file_path)
            digest = self._hash_file(file_path)
            raw_matches = self._rules.match(
                filepath=str(file_path),
                timeout=self.timeout,
            )
            matches = tuple(self._normalize_match(match) for match in raw_matches)
            return ScanResult(
                path=file_path,
                size=size,
                sha256=digest,
                file_type=file_type,
                matches=matches,
            )
        except (OSError, yara.Error) as error:
            return ScanResult(
                path=file_path,
                size=size,
                sha256=digest,
                file_type=file_type,
                error=str(error),
            )

    @staticmethod
    def _hash_file(file_path: Path) -> str:
        digest = sha256()

        with file_path.open("rb") as file:
            while chunk := file.read(HASH_CHUNK_SIZE):
                digest.update(chunk)

        return digest.hexdigest()

    @staticmethod
    def _normalize_match(match: yara.Match) -> RuleMatch:
        metadata: dict[str, MetadataValue] = {
            key: value
            for key, value in match.meta.items()
            if isinstance(value, (str, int, bool))
        }
        return RuleMatch(
            rule=match.rule,
            namespace=match.namespace,
            tags=tuple(match.tags),
            metadata=metadata,
        )
