import json
from pathlib import Path

from typer.testing import CliRunner

from yara_scout.cli import app
from yara_scout.models import ScanResult


runner = CliRunner()
PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES = PROJECT_ROOT / "rules"
FIXTURES = PROJECT_ROOT / "fixtures"


def test_help_describes_the_application() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Inspect files with YARA rules" in result.output
    assert "scan" in result.output


def test_version_displays_the_project_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == "0.1.0"


def test_scan_help_describes_its_inputs() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "target" in result.output
    assert "--rules" in result.output
    assert "--matches-only" in result.output
    assert "-m" in result.output
    assert "--timeout" in result.output
    assert "-t" in result.output
    assert "--max-file-size-mb" in result.output
    assert "-s" in result.output
    assert "--follow-symlinks" in result.output
    assert "-L" in result.output
    assert "--json" in result.output
    assert "-j" in result.output
    assert "File or directory to scan" in result.output


def test_scan_connects_scanner_and_terminal_reporter() -> None:
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES), "--rules", str(RULES)],
    )

    assert result.exit_code == 0
    assert "[MATCH]" in result.output
    assert "Suspicious_PowerShell_Patterns" in result.output
    assert "[CLEAN]" in result.output
    assert "Files scanned: 2" in result.output
    assert "Matched files: 1" in result.output
    assert "Clean files: 1" in result.output


def test_scan_matches_only_hides_the_clean_fixture() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES),
            "--rules",
            str(RULES),
            "--matches-only",
        ],
    )

    assert result.exit_code == 0
    assert "Suspicious_PowerShell_Patterns" in result.output
    assert "ordinary_note.txt" not in result.output
    assert "Clean files: 1" in result.output


def test_scan_exits_one_when_a_file_cannot_be_scanned(tmp_path, monkeypatch) -> None:
    target = tmp_path / "target.txt"
    target.write_text("test")
    rule_file = tmp_path / "rule.yar"
    rule_file.write_text("test")

    class ScannerWithFileError:
        def __init__(self, rule_path: Path, **options) -> None:
            pass

        def scan(self, scan_target: Path):
            yield ScanResult(
                path=scan_target,
                size=None,
                sha256=None,
                error="Permission denied",
            )

    monkeypatch.setattr("yara_scout.cli.Scanner", ScannerWithFileError)

    result = runner.invoke(
        app,
        ["scan", str(target), "--rules", str(rule_file)],
    )

    assert result.exit_code == 1
    assert "[ERROR]" in result.output
    assert "Errors: 1" in result.output


def test_scan_exits_two_when_rules_cannot_be_compiled(tmp_path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("test")
    invalid_rule = tmp_path / "invalid.yar"
    invalid_rule.write_text("this is not a YARA rule")

    result = runner.invoke(
        app,
        ["scan", str(target), "--rules", str(invalid_rule)],
    )

    assert result.exit_code == 2
    assert "Unable to start scan" in result.output


def test_scan_writes_a_complete_json_report(tmp_path) -> None:
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES),
            "--rules",
            str(RULES),
            "--matches-only",
            "--json",
            str(report_path),
        ],
    )

    assert result.exit_code == 0

    report = json.loads(report_path.read_text())
    assert report["scan"]["target"] == "$TARGET"
    assert report["scan"]["path_mode"] == "relative"
    assert report["summary"]["files_scanned"] == 2
    assert {item["status"] for item in report["results"]} == {
        "clean",
        "matched",
    }
    assert {item["path"] for item in report["results"]} == {
        "negative/ordinary_note.txt",
        "positive/suspicious_powershell.txt",
    }
