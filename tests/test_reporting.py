import json
from io import StringIO
from pathlib import Path

from rich.console import Console

from yara_scout.models import FileType, RuleMatch, ScanResult
from yara_scout.reporting import JsonReporter, ReportSummary, TerminalReporter


def create_reporter() -> tuple[TerminalReporter, StringIO]:
    output = StringIO()
    console = Console(file=output, color_system=None, width=120)
    return TerminalReporter(console), output


def test_report_renders_results_and_returns_a_summary() -> None:
    reporter, output = create_reporter()
    results = [
        ScanResult(
            path=Path("matched.txt"),
            size=12,
            sha256="abc123",
            file_type=FileType(mime_type="text/plain", source="extension"),
            matches=(
                RuleMatch(
                    rule="Example_Rule",
                    namespace="default",
                    tags=("example",),
                    metadata={"severity": 2},
                ),
            ),
        ),
        ScanResult(
            path=Path("clean.txt"),
            size=5,
            sha256="def456",
        ),
        ScanResult(
            path=Path("unreadable.txt"),
            size=None,
            sha256=None,
            error="Permission denied",
        ),
        ScanResult(
            path=Path("large.bin"),
            size=200,
            sha256=None,
            skipped_reason="File exceeds maximum size",
        ),
    ]

    summary = reporter.report(iter(results))
    rendered = output.getvalue()

    assert summary == ReportSummary(
        files_scanned=4,
        matched_files=1,
        clean_files=1,
        errors=1,
        skipped_files=1,
        rule_matches=1,
    )
    assert "[MATCH] matched.txt" in rendered
    assert "Rule: Example_Rule" in rendered
    assert "File type: text/plain (extension)" in rendered
    assert "Tags: example" in rendered
    assert "severity: 2" in rendered
    assert "[CLEAN] clean.txt" in rendered
    assert "[ERROR] unreadable.txt" in rendered
    assert "Permission denied" in rendered
    assert "[SKIPPED] large.bin" in rendered
    assert "File exceeds maximum size" in rendered
    assert "Files scanned: 4" in rendered
    assert "Skipped files: 1" in rendered


def test_matches_only_hides_clean_details_but_keeps_the_count() -> None:
    reporter, output = create_reporter()
    results = [
        ScanResult(
            path=Path("matched.txt"),
            size=12,
            sha256="abc123",
            matches=(RuleMatch(rule="Example_Rule", namespace="default"),),
        ),
        ScanResult(
            path=Path("clean.txt"),
            size=5,
            sha256="def456",
        ),
    ]

    summary = reporter.report(iter(results), matches_only=True)
    rendered = output.getvalue()

    assert summary.clean_files == 1
    assert "[MATCH] matched.txt" in rendered
    assert "[CLEAN] clean.txt" not in rendered
    assert "Clean files: 1" in rendered


def test_json_report_uses_an_envelope_and_redacted_relative_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "fixtures"
    target.mkdir()
    positive = target / "positive"
    positive.mkdir()
    sample = positive / "sample.txt"
    sample.write_text("safe")
    output_path = tmp_path / "report.json"
    result = ScanResult(
        path=sample,
        size=4,
        sha256="abc123",
        file_type=FileType(mime_type="text/plain", source="extension"),
        matches=(
            RuleMatch(
                rule="Example_Rule",
                namespace="default",
                metadata={"severity": "medium"},
            ),
        ),
    )
    error_result = ScanResult(
        path=positive / "unreadable.txt",
        size=None,
        sha256=None,
        error=f"Unable to read {positive / 'unreadable.txt'}",
    )
    summary = ReportSummary(
        files_scanned=2,
        matched_files=1,
        errors=1,
        rule_matches=1,
    )
    monkeypatch.setattr(
        JsonReporter,
        "_timestamp",
        staticmethod(lambda: "2026-08-29T12:00:00Z"),
    )

    JsonReporter().write(
        output_path,
        target=target,
        results=[result, error_result],
        summary=summary,
        timeout=10,
        max_file_size=104857600,
        follow_symlinks=False,
    )

    report_text = output_path.read_text()
    report = json.loads(report_text)

    assert str(tmp_path) not in report_text
    assert report["schema_version"] == "1.0"
    assert report["generated_at"] == "2026-08-29T12:00:00Z"
    assert report["scan"] == {
        "target": "$TARGET",
        "rules": "$RULES",
        "path_mode": "relative",
        "options": {
            "timeout_seconds": 10,
            "max_file_size_bytes": 104857600,
            "follow_symlinks": False,
        },
    }
    assert report["summary"]["matched_files"] == 1
    assert report["results"][0]["path"] == "positive/sample.txt"
    assert report["results"][0]["status"] == "matched"
    assert report["results"][0]["file_type"] == {
        "mime_type": "text/plain",
        "source": "extension",
    }
    assert report["results"][0]["matches"][0]["rule"] == "Example_Rule"
    assert report["results"][1]["status"] == "error"
    assert report["results"][1]["error"] == (
        "Unable to read $TARGET/positive/unreadable.txt"
    )
