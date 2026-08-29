from pathlib import Path

from yara_scout.scanner import Scanner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES = PROJECT_ROOT / "rules"
FIXTURES = PROJECT_ROOT / "fixtures"


def test_example_rule_matches_only_the_positive_fixture() -> None:
    results = {
        result.path.relative_to(FIXTURES): result
        for result in Scanner(RULES).scan(FIXTURES)
    }

    positive = results[Path("positive/suspicious_powershell.txt")]
    negative = results[Path("negative/ordinary_note.txt")]

    assert positive.error is None
    assert positive.matched is True
    assert [match.rule for match in positive.matches] == [
        "Suspicious_PowerShell_Patterns"
    ]

    assert negative.error is None
    assert negative.matched is False
    assert negative.matches == ()
