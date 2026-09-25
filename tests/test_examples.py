from pathlib import Path

from yara_scout.models import ScanResult
from yara_scout.scanner import Scanner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES = PROJECT_ROOT / "rules"
FIXTURES = PROJECT_ROOT / "fixtures"


def scan_fixture(rule_filename: str, fixture_path: str) -> ScanResult:
    results = list(
        Scanner(RULES / rule_filename).scan(FIXTURES / fixture_path)
    )

    assert len(results) == 1
    assert results[0].error is None
    return results[0]


def test_powershell_rule_matches_only_the_combined_indicators() -> None:
    positive = scan_fixture(
        "suspicious_powershell.yar",
        "positive/suspicious_powershell.txt",
    )
    negative = scan_fixture(
        "suspicious_powershell.yar",
        "negative/benign_powershell.txt",
    )

    assert positive.matched is True
    assert [match.rule for match in positive.matches] == [
        "Suspicious_PowerShell_Patterns"
    ]
    assert negative.matched is False
    assert negative.matches == ()


def test_pdf_rule_matches_only_active_content_indicators() -> None:
    positive = scan_fixture(
        "pdf_embedded_actions.yar",
        "positive/pdf_embedded_actions.pdf",
    )
    negative = scan_fixture(
        "pdf_embedded_actions.yar",
        "negative/benign_document.pdf",
    )

    assert positive.matched is True
    assert [match.rule for match in positive.matches] == ["PDF_Embedded_Actions"]
    assert negative.matched is False
    assert negative.matches == ()


def test_eicar_rule_matches_only_the_canonical_payload(tmp_path: Path) -> None:
    eicar_bytes = bytes.fromhex(
        "58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 "
        "34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 "
        "52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 "
        "49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 "
        "48 2B 48 2A"
    )
    canonical = tmp_path / "eicar.com"
    altered = tmp_path / "altered_eicar.com"
    canonical.write_bytes(eicar_bytes)
    altered.write_bytes(eicar_bytes[:-1] + b"?")

    results = {
        result.path.name: result
        for result in Scanner(RULES / "eicar_test_file.yar").scan(tmp_path)
    }

    assert results[canonical.name].error is None
    assert results[canonical.name].matched is True
    assert [match.rule for match in results[canonical.name].matches] == [
        "EICAR_Antivirus_Test_File"
    ]
    assert results[altered.name].error is None
    assert results[altered.name].matched is False
    assert results[altered.name].matches == ()


def test_complete_rule_pack_matches_only_expected_fixtures() -> None:
    results = {
        result.path.relative_to(FIXTURES): result
        for result in Scanner(RULES).scan(FIXTURES)
    }

    expected_matches = {
        Path("positive/pdf_embedded_actions.pdf"): ["PDF_Embedded_Actions"],
        Path("positive/suspicious_powershell.txt"): [
            "Suspicious_PowerShell_Patterns"
        ],
    }

    assert set(results) == {
        Path("negative/benign_document.pdf"),
        Path("negative/benign_powershell.txt"),
        Path("negative/ordinary_note.txt"),
        *expected_matches,
    }

    for path, result in results.items():
        assert result.error is None
        assert [match.rule for match in result.matches] == expected_matches.get(
            path,
            [],
        )
