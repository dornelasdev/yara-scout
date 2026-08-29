from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

from rich.console import Console
from rich.text import Text

from yara_scout.models import RuleMatch, ScanResult


JSON_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Aggregate counts produced while rendering scan results."""

    files_scanned: int = 0
    matched_files: int = 0
    clean_files: int = 0
    errors: int = 0
    skipped_files: int = 0
    rule_matches: int = 0


class TerminalReporter:
    """Render streamed scan results and a final summary to a terminal."""

    def __init__(self, console: Console) -> None:
        self.console = console

    def report(
        self,
        results: Iterable[ScanResult],
        *,
        matches_only: bool = False,
    ) -> ReportSummary:
        """Consume scan results, render them, and return aggregate counts."""
        files_scanned = 0
        matched_files = 0
        clean_files = 0
        errors = 0
        skipped_files = 0
        rule_matches = 0

        for result in results:
            files_scanned += 1

            if result.skipped:
                skipped_files += 1
                self._render_skipped(result)
                continue

            if result.error is not None:
                errors += 1
                self._render_error(result)
                continue

            if result.matched:
                matched_files += 1
                rule_matches += len(result.matches)
                self._render_result(result, status="MATCH", style="bold red")
                continue

            clean_files += 1
            if not matches_only:
                self._render_result(result, status="CLEAN", style="green")

        summary = ReportSummary(
            files_scanned=files_scanned,
            matched_files=matched_files,
            clean_files=clean_files,
            errors=errors,
            skipped_files=skipped_files,
            rule_matches=rule_matches,
        )
        self._render_summary(summary)
        return summary

    def _render_result(self, result: ScanResult, *, status: str, style: str) -> None:
        self._render_status(status, style, str(result.path))

        if result.size is not None:
            self.console.print(Text(f"  Size: {result.size} bytes"))
        if result.sha256 is not None:
            self.console.print(Text(f"  SHA-256: {result.sha256}"))
        if result.file_type is not None:
            self.console.print(
                Text(
                    "  File type: "
                    f"{result.file_type.mime_type} "
                    f"({result.file_type.source})"
                )
            )

        for match in result.matches:
            self._render_match(match)

    def _render_error(self, result: ScanResult) -> None:
        self._render_status("ERROR", "bold yellow", str(result.path))
        self.console.print(Text(f"  {result.error}"))

    def _render_skipped(self, result: ScanResult) -> None:
        self._render_status("SKIPPED", "bold cyan", str(result.path))
        self.console.print(Text(f"  {result.skipped_reason}"))

    def _render_match(self, match: RuleMatch) -> None:
        self.console.print(Text(f"  Rule: {match.rule}"))
        self.console.print(Text(f"    Namespace: {match.namespace}"))

        if match.tags:
            self.console.print(Text(f"    Tags: {', '.join(match.tags)}"))
        for key, value in match.metadata.items():
            self.console.print(Text(f"    {key}: {value}"))

    def _render_status(self, status: str, style: str, path: str) -> None:
        line = Text(f"[{status}]", style=style)
        line.append(f" {path}")
        self.console.print(line)

    def _render_summary(self, summary: ReportSummary) -> None:
        self.console.rule("Summary")
        self.console.print(Text(f"Files scanned: {summary.files_scanned}"))
        self.console.print(Text(f"Matched files: {summary.matched_files}"))
        self.console.print(Text(f"Clean files: {summary.clean_files}"))
        self.console.print(Text(f"Errors: {summary.errors}"))
        self.console.print(Text(f"Skipped files: {summary.skipped_files}"))
        self.console.print(Text(f"Rule matches: {summary.rule_matches}"))


class JsonReporter:
    """Write a shareable JSON report without exposing local root paths."""

    def write(
        self,
        output_path: Path,
        *,
        target: Path,
        results: Iterable[ScanResult],
        summary: ReportSummary,
        timeout: int,
        max_file_size: int,
        follow_symlinks: bool,
    ) -> None:
        """Serialize a complete scan report to the requested path."""
        target = target.expanduser().absolute()
        target_root = target.parent if target.is_file() else target
        report = {
            "schema_version": JSON_SCHEMA_VERSION,
            "generated_at": self._timestamp(),
            "scan": {
                "target": "$TARGET",
                "rules": "$RULES",
                "path_mode": "relative",
                "options": {
                    "timeout_seconds": timeout,
                    "max_file_size_bytes": max_file_size,
                    "follow_symlinks": follow_symlinks,
                },
            },
            "summary": asdict(summary),
            "results": [
                self._serialize_result(result, target_root) for result in results
            ],
        }

        output_path = output_path.expanduser().absolute()
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @classmethod
    def _serialize_result(cls, result: ScanResult, target_root: Path) -> dict:
        return {
            "path": cls._relative_path(result.path, target_root),
            "status": cls._status(result),
            "size": result.size,
            "sha256": result.sha256,
            "file_type": (
                asdict(result.file_type) if result.file_type is not None else None
            ),
            "matches": [asdict(match) for match in result.matches],
            "error": cls._redact_text(result.error, target_root),
            "skipped_reason": cls._redact_text(
                result.skipped_reason,
                target_root,
            ),
        }

    @staticmethod
    def _relative_path(file_path: Path, target_root: Path) -> str:
        try:
            return file_path.absolute().relative_to(target_root).as_posix()
        except ValueError:
            return file_path.name

    @staticmethod
    def _status(result: ScanResult) -> str:
        if result.skipped:
            return "skipped"
        if result.error is not None:
            return "error"
        if result.matched:
            return "matched"
        return "clean"

    @staticmethod
    def _redact_text(value: str | None, target_root: Path) -> str | None:
        if value is None:
            return None

        redacted = value
        roots = {str(target_root.absolute()), str(target_root.resolve())}
        for root in sorted(roots, key=len, reverse=True):
            redacted = redacted.replace(root, "$TARGET")
        return redacted
