from pathlib import Path

import pytest

from yara_scout.validation import RuleValidator, ValidationReport


def valid_rule(
    *,
    name: str = "Valid_Test_Rule",
    rule_id: str = "YS-1000",
    tag: str = "test",
    metadata: str = "",
) -> str:
    return f'''rule {name} : {tag}
{{
    meta:
        id = "{rule_id}"
        description = "Detects a harmless validation marker"
        author = "YARA Scout"
        created = "2026-09-25"
        license = "MIT"
        category = "test"
        severity = "informational"
        confidence = "high"
        scope = "file"
        false_positives = "None known"
{metadata}
    condition:
        true
}}
'''


def finding_messages(report: ValidationReport) -> list[str]:
    return [finding.message for finding in report.findings]


def test_validator_accepts_a_compiling_conventional_rule(tmp_path: Path) -> None:
    rule_file = tmp_path / "valid_test_rule.yar"
    rule_file.write_text(valid_rule())

    report = RuleValidator().validate(rule_file)

    assert report.valid is True
    assert report.files_checked == 1
    assert report.rules_checked == 1
    assert report.findings == ()


def test_validator_reports_yara_compilation_errors(tmp_path: Path) -> None:
    rule_file = tmp_path / "invalid_rule.yar"
    rule_file.write_text("this is not a YARA rule")

    report = RuleValidator().validate(rule_file)

    assert report.valid is False
    assert report.rules_checked == 0
    assert any(
        message.startswith("YARA compilation failed:")
        for message in finding_messages(report)
    )


def test_validator_reports_missing_required_metadata(tmp_path: Path) -> None:
    rule_file = tmp_path / "missing_metadata.yar"
    rule_file.write_text("rule Missing_Metadata { condition: true }")

    report = RuleValidator().validate(rule_file)

    messages = finding_messages(report)
    assert report.valid is False
    assert "Missing required metadata field: id" in messages
    assert "Missing required metadata field: description" in messages
    assert "Missing required metadata field: false_positives" in messages


def test_validator_checks_controlled_values_and_dates(tmp_path: Path) -> None:
    source = valid_rule(
        metadata='''        modified = "2026-09-24"
''',
    )
    source = source.replace('category = "test"', 'category = "unknown"')
    source = source.replace(
        'severity = "informational"',
        'severity = "urgent"',
    )
    source = source.replace('confidence = "high"', 'confidence = "certain"')
    source = source.replace('scope = "file"', 'scope = "process"')
    rule_file = tmp_path / "invalid_metadata.yar"
    rule_file.write_text(source)

    report = RuleValidator().validate(rule_file)

    messages = finding_messages(report)
    assert any(
        "Metadata 'category' must be one of:" in message
        for message in messages
    )
    assert any(
        "Metadata 'severity' must be one of:" in message
        for message in messages
    )
    assert any(
        "Metadata 'confidence' must be one of:" in message
        for message in messages
    )
    assert any("Metadata 'scope' must be one of:" in message for message in messages)
    assert "Metadata 'modified' cannot be earlier than 'created'" in messages


def test_validator_checks_rule_ids_and_date_formats(tmp_path: Path) -> None:
    source = valid_rule(rule_id="TEST-1").replace(
        'created = "2026-09-25"',
        'created = "25/09/2026"',
    )
    rule_file = tmp_path / "invalid_identity.yar"
    rule_file.write_text(source)

    report = RuleValidator().validate(rule_file)

    messages = finding_messages(report)
    assert "Metadata 'id' must match YS-NNNN" in messages
    assert "Metadata 'created' must use YYYY-MM-DD" in messages


def test_validator_checks_names_and_tags(tmp_path: Path) -> None:
    rule_file = tmp_path / "Bad-Name.yar"
    rule_file.write_text(valid_rule(name="lowercase_rule", tag="Windows"))

    report = RuleValidator().validate(rule_file)

    messages = finding_messages(report)
    assert any(message.startswith("Filename must use") for message in messages)
    assert any(
        message.startswith("Rule identifier must use") for message in messages
    )
    assert any(message.startswith("Tag 'Windows' must") for message in messages)


def test_validator_reports_duplicate_rule_names_and_ids(tmp_path: Path) -> None:
    (tmp_path / "first_rule.yar").write_text(valid_rule())
    (tmp_path / "second_rule.yar").write_text(valid_rule())

    report = RuleValidator().validate(tmp_path)

    messages = finding_messages(report)
    assert any(message.startswith("Duplicate rule identifier") for message in messages)
    assert any(message.startswith("Duplicate rule id") for message in messages)


def test_validator_rejects_a_directory_without_rules(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="No YARA rule files found"):
        RuleValidator().validate(tmp_path)
