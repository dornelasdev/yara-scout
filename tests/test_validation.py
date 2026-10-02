from pathlib import Path

import pytest
from plyara import Plyara
from plyara.exceptions import ParseTypeError, ParseValueError

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


def test_validator_continues_after_compilation_failure(tmp_path: Path) -> None:
    broken = tmp_path / "a_broken.yar"
    incomplete = tmp_path / "b_incomplete.yar"
    valid = tmp_path / "c_valid.yar"
    broken.write_text("this is not a YARA rule", encoding="utf-8")
    incomplete.write_text(
        valid_rule(name="Incomplete_Rule").replace(
            '        id = "YS-1000"\n', ""
        ),
        encoding="utf-8",
    )
    valid.write_text(valid_rule(), encoding="utf-8")

    report = RuleValidator().validate(tmp_path)

    assert report.valid is False
    assert report.files_checked == 3
    assert report.rules_checked == 2
    assert len(report.findings) == 2
    compilation, convention = report.findings
    assert compilation.path == broken.resolve()
    assert compilation.message.startswith("YARA compilation failed:")
    assert convention.path == incomplete.resolve()
    assert convention.rule == "Incomplete_Rule"
    assert convention.message == "Missing required metadata field: id"


@pytest.mark.parametrize("error_type", [ParseTypeError, ParseValueError])
def test_validator_continues_after_parser_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[ParseTypeError] | type[ParseValueError],
) -> None:
    incompatible = tmp_path / "a_parser_failure.yar"
    incomplete = tmp_path / "b_incomplete.yar"
    valid = tmp_path / "c_valid.yar"
    incompatible_source = valid_rule(
        name="Parser_Compatibility_Rule", rule_id="YS-1001"
    )
    incompatible.write_text(incompatible_source, encoding="utf-8")
    incomplete.write_text(
        valid_rule(name="Incomplete_Rule").replace(
            '        id = "YS-1000"\n', ""
        ),
        encoding="utf-8",
    )
    valid.write_text(valid_rule(), encoding="utf-8")

    # Simulate a compatibility gap without depending on a particular parser bug.
    # Compilation remains real, and all other files use the real parser.
    original_parse = Plyara.parse_string

    def parse_with_failure(parser: Plyara, source: str):
        if source == incompatible_source:
            raise error_type("Simulated parser compatibility failure", 1, 0)
        return original_parse(parser, source)

    monkeypatch.setattr(Plyara, "parse_string", parse_with_failure)

    report = RuleValidator().validate(tmp_path)

    assert report.valid is False
    assert report.files_checked == 3
    assert report.rules_checked == 2
    assert len(report.findings) == 2
    parser_finding, convention = report.findings
    assert parser_finding.path == incompatible.resolve()
    assert parser_finding.message == (
        "Plyara could not parse rule structure: "
        "Simulated parser compatibility failure"
    )
    assert convention.path == incomplete.resolve()
    assert convention.rule == "Incomplete_Rule"
    assert convention.message == "Missing required metadata field: id"


def test_validator_reports_missing_required_metadata(tmp_path: Path) -> None:
    rule_file = tmp_path / "missing_metadata.yar"
    rule_file.write_text("rule Missing_Metadata { condition: true }")

    report = RuleValidator().validate(rule_file)

    messages = finding_messages(report)
    assert report.valid is False
    assert "Missing required metadata field: id" in messages
    assert "Missing required metadata field: description" in messages
    assert "Missing required metadata field: false_positives" in messages


@pytest.mark.parametrize(
    "field",
    [
        "id", "description", "author", "created", "license",
        "category", "severity", "confidence", "scope", "false_positives",
    ],
)
@pytest.mark.parametrize(
    "literal", ["42", "false", '""', '"   "'],
    ids=["integer", "boolean", "empty", "whitespace"],
)
def test_validator_rejects_invalid_required_metadata_values(
    tmp_path: Path, field: str, literal: str,
) -> None:
    source = valid_rule()
    declaration = next(
        line for line in source.splitlines()
        if line.strip().startswith(f"{field} =")
    )
    rule_file = tmp_path / "invalid_metadata.yar"
    rule_file.write_text(
        source.replace(declaration, f"        {field} = {literal}"),
        encoding="utf-8",
    )

    report = RuleValidator().validate(rule_file)

    assert report.valid is False
    assert report.rules_checked == 1
    assert f"Metadata '{field}' must be a non-empty string" in finding_messages(
        report
    )
    assert all(finding.rule == "Valid_Test_Rule" for finding in report.findings)


@pytest.mark.parametrize("field", ["created", "modified"])
@pytest.mark.parametrize(
    "value",
    ["2026-02-29", "2026-04-31", "2026-13-01", "20260925", "2026-9-25"],
)
def test_validator_rejects_invalid_calendar_dates_and_formats(
    tmp_path: Path, field: str, value: str,
) -> None:
    if field == "created":
        source = valid_rule().replace(
            'created = "2026-09-25"', f'created = "{value}"'
        )
    else:
        source = valid_rule(metadata=f'        modified = "{value}"')
    rule_file = tmp_path / "invalid_date.yar"
    rule_file.write_text(source, encoding="utf-8")

    report = RuleValidator().validate(rule_file)

    assert report.valid is False
    assert report.rules_checked == 1
    assert finding_messages(report) == [
        f"Metadata '{field}' must use YYYY-MM-DD"
    ]


@pytest.mark.parametrize("field", ["modified", "reference", "reference_2"])
@pytest.mark.parametrize(
    "literal", ["42", "false", '""', '"   "'],
    ids=["integer", "boolean", "empty", "whitespace"],
)
def test_validator_rejects_invalid_optional_metadata_values(
    tmp_path: Path, field: str, literal: str,
) -> None:
    rule_file = tmp_path / "invalid_optional_metadata.yar"
    rule_file.write_text(
        valid_rule(metadata=f"        {field} = {literal}"),
        encoding="utf-8",
    )

    report = RuleValidator().validate(rule_file)

    assert report.valid is False
    assert report.rules_checked == 1
    expected = (
        "Metadata 'modified' must use YYYY-MM-DD"
        if field == "modified"
        else f"Metadata '{field}' must be a non-empty string"
    )
    assert finding_messages(report) == [expected]


@pytest.mark.parametrize(
    ("created", "metadata"),
    [
        ("2026-09-25", ""),
        ("2026-09-25", '        modified = "2026-09-25"'),
        ("2026-09-25", '        modified = "2026-09-26"'),
        ("2024-02-29", '        modified = "2024-03-01"'),
        (
            "2026-09-25",
            '        reference = "https://example.org/research"\n'
            '        reference_2 = "T1059.001"',
        ),
    ],
    ids=["omitted", "same-day", "later-date", "leap-day", "references"],
)
def test_validator_accepts_valid_dates_and_optional_metadata(
    tmp_path: Path, created: str, metadata: str,
) -> None:
    rule_file = tmp_path / "valid_metadata.yar"
    rule_file.write_text(
        valid_rule(metadata=metadata).replace(
            'created = "2026-09-25"', f'created = "{created}"'
        ),
        encoding="utf-8",
    )

    report = RuleValidator().validate(rule_file)

    assert report.valid is True
    assert report.rules_checked == 1
    assert report.findings == ()


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


def test_validator_accepts_multiple_rules_in_one_file(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule_family.yar"
    rule_file.write_text(
        valid_rule(name="First_Rule", rule_id="YS-1000")
        + "\n"
        + valid_rule(name="Second_Rule", rule_id="YS-1001"),
        encoding="utf-8",
    )

    report = RuleValidator().validate(rule_file)

    assert report.valid is True
    assert report.files_checked == 1
    assert report.rules_checked == 2
    assert report.findings == ()


def test_validator_reports_duplicate_ids_within_one_file(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule_family.yar"
    rule_file.write_text(
        valid_rule(name="First_Rule", rule_id="YS-1000")
        + "\n"
        + valid_rule(name="Second_Rule", rule_id="YS-1000"),
        encoding="utf-8",
    )

    report = RuleValidator().validate(rule_file)

    assert report.valid is False
    assert report.files_checked == 1
    assert report.rules_checked == 2
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.path == rule_file.resolve()
    assert finding.rule == "Second_Rule"
    assert finding.message == (
        "Duplicate rule id 'YS-1000'; first used by First_Rule in rule_family.yar"
    )


def test_validator_attributes_findings_to_each_rule_in_one_file(
    tmp_path: Path,
) -> None:
    first = valid_rule(name="Missing_Author_Rule", rule_id="YS-1000").replace(
        '        author = "YARA Scout"\n', ""
    )
    second = valid_rule(name="Empty_Description_Rule", rule_id="YS-1001").replace(
        'description = "Detects a harmless validation marker"',
        'description = ""',
    )
    third = valid_rule(name="Valid_Final_Rule", rule_id="YS-1002")
    source = "\n".join([first, second, third])
    rule_file = tmp_path / "rule_family.yar"
    rule_file.write_text(source, encoding="utf-8")

    report = RuleValidator().validate(rule_file)

    assert report.valid is False
    assert report.files_checked == 1
    assert report.rules_checked == 3
    assert len(report.findings) == 2
    assert {
        (finding.rule, finding.message) for finding in report.findings
    } == {
        ("Missing_Author_Rule", "Missing required metadata field: author"),
        (
            "Empty_Description_Rule",
            "Metadata 'description' must be a non-empty string",
        ),
    }
    for finding in report.findings:
        assert finding.path == rule_file.resolve()
        assert finding.line is not None
        assert source.splitlines()[finding.line - 1] == (
            f"rule {finding.rule} : test"
        )


def test_validator_rejects_a_directory_without_rules(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="No YARA rule files found"):
        RuleValidator().validate(tmp_path)


def test_validator_follows_nested_include_only_wrappers(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    entry = tmp_path / "entry.yar"
    entry.write_text('include "nested/wrapper.yar"\n', encoding="utf-8")
    (nested / "wrapper.yar").write_text(
        'include "leaf.yar"\n', encoding="utf-8"
    )
    (nested / "leaf.yar").write_text(valid_rule(), encoding="utf-8")

    report = RuleValidator().validate(entry)

    assert report.valid is True
    assert report.files_checked == 3
    assert report.rules_checked == 1
    assert report.findings == ()


def test_validator_reports_metadata_in_included_source(tmp_path: Path) -> None:
    helper = tmp_path / "helper.yar"
    helper.write_text(
        valid_rule(name="Helper_Rule").replace(
            '        author = "YARA Scout"\n', ""
        ),
        encoding="utf-8",
    )
    entry = tmp_path / "entry.yar"
    entry.write_text(
        'include "helper.yar"\n'
        + valid_rule(name="Entry_Rule", rule_id="YS-1001"),
        encoding="utf-8",
    )

    report = RuleValidator().validate(entry)

    assert report.valid is False
    assert report.files_checked == 2
    assert report.rules_checked == 2
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.path == helper.resolve()
    assert finding.rule == "Helper_Rule"
    assert finding.line == 1
    assert finding.message == "Missing required metadata field: author"


def test_validator_inspects_shared_dependency_once(tmp_path: Path) -> None:
    helper = tmp_path / "helper.yar"
    helper.write_text(valid_rule(), encoding="utf-8")
    for filename in ("first.yar", "second.yar"):
        (tmp_path / filename).write_text(
            'include "helper.yar"\n', encoding="utf-8"
        )

    report = RuleValidator().validate(tmp_path)

    # The helper is reached through two includes and directory discovery.
    assert report.valid is True
    assert report.files_checked == 3
    assert report.rules_checked == 1
    assert report.findings == ()


@pytest.mark.parametrize("validate_directory", [False, True])
def test_validator_keeps_selected_entry_compilation_context(
    tmp_path: Path, validate_directory: bool,
) -> None:
    helper = tmp_path / "helper.yar"
    helper.write_text(
        valid_rule(name="Helper_Rule", rule_id="YS-1001").replace(
            "        true", "        Entry_Rule"
        ),
        encoding="utf-8",
    )
    entry = tmp_path / "entry.yar"
    entry.write_text(
        valid_rule(name="Entry_Rule") + '\ninclude "helper.yar"\n',
        encoding="utf-8",
    )

    report = RuleValidator().validate(tmp_path if validate_directory else entry)

    assert report.files_checked == 2
    assert report.rules_checked == 2
    if validate_directory:
        # Like Scanner, directory validation selects helper.yar as an entry too.
        assert report.valid is False
        assert len(report.findings) == 1
        assert report.findings[0].path == helper.resolve()
        assert report.findings[0].message.startswith("YARA compilation failed:")
    else:
        assert report.valid is True
        assert report.findings == ()


def test_validator_detects_ids_shared_with_included_rules(tmp_path: Path) -> None:
    helper = tmp_path / "helper.yar"
    helper.write_text(valid_rule(name="Helper_Rule"), encoding="utf-8")
    entry = tmp_path / "entry.yar"
    entry.write_text(
        'include "helper.yar"\n' + valid_rule(name="Entry_Rule"),
        encoding="utf-8",
    )

    report = RuleValidator().validate(entry)

    assert report.valid is False
    assert report.rules_checked == 2
    assert len(report.findings) == 1
    assert report.findings[0].message.startswith("Duplicate rule id 'YS-1000'")


@pytest.mark.parametrize("include_kind", ["missing", "cycle", "syntax"])
def test_validator_reports_include_compilation_failures_and_continues(
    tmp_path: Path, include_kind: str,
) -> None:
    entry = tmp_path / "a_entry.yar"
    if include_kind == "cycle":
        entry.write_text('include "a_entry.yar"\n', encoding="utf-8")
    else:
        entry.write_text('include "broken.inc"\n', encoding="utf-8")
        if include_kind == "syntax":
            (tmp_path / "broken.inc").write_text(
                "not a valid YARA rule", encoding="utf-8"
            )
    (tmp_path / "z_valid.yar").write_text(valid_rule(), encoding="utf-8")

    report = RuleValidator().validate(tmp_path)

    assert report.valid is False
    assert report.rules_checked == 1
    assert len(report.findings) == 1
    assert report.findings[0].path == entry.resolve()
    assert report.findings[0].message.startswith("YARA compilation failed:")


def test_validator_inspects_includes_outside_discovery_and_other_extensions(
    tmp_path: Path,
) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    helper = tmp_path / "helper.inc"
    helper.write_text(
        valid_rule().replace('        author = "YARA Scout"\n', ""),
        encoding="utf-8",
    )
    (rules / "entry.yar").write_text(
        'include "../helper.inc"\n', encoding="utf-8"
    )

    report = RuleValidator().validate(rules)

    assert report.valid is False
    assert report.files_checked == 2
    assert report.rules_checked == 1
    assert len(report.findings) == 2
    assert all(finding.path == helper.resolve() for finding in report.findings)
    assert any(
        message.startswith("Filename must use") for message in finding_messages(report)
    )
    assert "Missing required metadata field: author" in finding_messages(report)


def test_validator_does_not_accept_wrappers_with_no_rules(tmp_path: Path) -> None:
    (tmp_path / "empty.yar").write_text("// No declarations\n", encoding="utf-8")
    entry = tmp_path / "entry.yar"
    entry.write_text('include "empty.yar"\n', encoding="utf-8")

    report = RuleValidator().validate(entry)

    assert report.valid is False
    assert report.rules_checked == 0
    assert len(report.findings) == 1
    assert report.findings[0].path == (tmp_path / "empty.yar").resolve()
    assert report.findings[0].message == "No rule declarations were found"


def test_validator_reports_parser_failure_in_included_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = tmp_path / "helper.yar"
    helper_source = valid_rule(name="Helper_Rule", rule_id="YS-1001")
    helper.write_text(helper_source, encoding="utf-8")
    entry = tmp_path / "entry.yar"
    entry.write_text(
        'include "helper.yar"\n' + valid_rule(name="Entry_Rule"),
        encoding="utf-8",
    )
    original_parse = Plyara.parse_string

    def parse_with_failure(parser: Plyara, source: str):
        if source == helper_source:
            raise ParseTypeError("Simulated include parser failure", 1, 0)
        return original_parse(parser, source)

    monkeypatch.setattr(Plyara, "parse_string", parse_with_failure)

    report = RuleValidator().validate(entry)

    assert report.valid is False
    assert report.files_checked == 2
    assert report.rules_checked == 1
    assert len(report.findings) == 1
    assert report.findings[0].path == helper.resolve()
    assert report.findings[0].message.startswith("Plyara could not parse rule structure:")
