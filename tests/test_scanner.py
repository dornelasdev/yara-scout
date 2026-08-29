from collections.abc import Iterator
from hashlib import sha256

import pytest

from yara_scout.models import FileType
from yara_scout.scanner import Scanner


RULE_SOURCE = """
rule Contains_Yara_Lab_Marker
{
    meta:
        description = "Detects the harmless YARA Scout test marker"
        severity = 2
    strings:
        $marker = "YARA_SCOUT_MARKER"
    condition:
        $marker
}
"""


def test_scan_streams_a_normalized_match(tmp_path) -> None:
    rule_file = tmp_path / "marker.yar"
    rule_file.write_text(RULE_SOURCE)
    target = tmp_path / "sample.txt"
    content = b"This contains a YARA_SCOUT_MARKER for testing."
    target.write_bytes(content)

    scanner = Scanner(rule_file)
    results = scanner.scan(target)

    assert isinstance(results, Iterator)

    result = next(results)
    assert result.path == target.resolve()
    assert result.size == len(content)
    assert result.sha256 == sha256(content).hexdigest()
    assert result.file_type == FileType(mime_type="text/plain", source="extension")
    assert result.error is None
    assert result.matched is True
    assert len(result.matches) == 1
    assert result.matches[0].rule == "Contains_Yara_Lab_Marker"
    assert result.matches[0].metadata == {
        "description": "Detects the harmless YARA Scout test marker",
        "severity": 2,
    }


def test_scan_returns_a_result_when_no_rule_matches(tmp_path) -> None:
    rule_file = tmp_path / "marker.yar"
    rule_file.write_text(RULE_SOURCE)
    target = tmp_path / "clean.txt"
    target.write_text("A harmless file without the marker.")

    result = next(Scanner(rule_file).scan(target))

    assert result.error is None
    assert result.matched is False
    assert result.matches == ()


def test_scan_discovers_directory_files_in_stable_order(tmp_path) -> None:
    rule_file = tmp_path / "marker.yar"
    rule_file.write_text(RULE_SOURCE)
    targets = tmp_path / "targets"
    targets.mkdir()
    (targets / "second.txt").write_text("Second")
    (targets / "first.txt").write_text("First")

    results = list(Scanner(rule_file).scan(targets))

    assert [result.path.name for result in results] == ["first.txt", "second.txt"]


def test_scanner_rejects_a_directory_without_rules(tmp_path) -> None:
    empty_rules = tmp_path / "rules"
    empty_rules.mkdir()

    with pytest.raises(ValueError, match="No YARA rule files found"):
        Scanner(empty_rules)


def test_scanner_skips_files_over_the_size_limit(tmp_path) -> None:
    rule_file = tmp_path / "marker.yar"
    rule_file.write_text(RULE_SOURCE)
    target = tmp_path / "large.txt"
    target.write_bytes(b"YARA_SCOUT_MARKER")

    result = next(Scanner(rule_file, max_file_size=4).scan(target))

    assert result.skipped is True
    assert result.skipped_reason == "File exceeds maximum size of 4 bytes"
    assert result.sha256 is None
    assert result.matches == ()
    assert result.error is None


def test_scanner_passes_the_timeout_to_yara(tmp_path, monkeypatch) -> None:
    rule_file = tmp_path / "marker.yar"
    rule_file.write_text(RULE_SOURCE)
    target = tmp_path / "sample.txt"
    target.write_text("safe")
    received_timeout = None

    class Rules:
        def match(self, *, filepath: str, timeout: int):
            nonlocal received_timeout
            received_timeout = timeout
            return []

    monkeypatch.setattr(Scanner, "_compile_rules", lambda self, path: Rules())

    result = next(Scanner(rule_file, timeout=7).scan(target))

    assert result.error is None
    assert received_timeout == 7


def test_scanner_skips_symbolic_links_by_default(tmp_path) -> None:
    rule_file = tmp_path / "marker.yar"
    rule_file.write_text(RULE_SOURCE)
    original = tmp_path / "original.txt"
    original.write_text("YARA_SCOUT_MARKER")
    link = tmp_path / "link.txt"
    link.symlink_to(original)

    result = next(Scanner(rule_file).scan(link))

    assert result.path == link.absolute()
    assert result.skipped is True
    assert result.skipped_reason == "Symbolic link scanning is disabled"


def test_scanner_can_follow_symbolic_links(tmp_path) -> None:
    rule_file = tmp_path / "marker.yar"
    rule_file.write_text(RULE_SOURCE)
    original = tmp_path / "original.txt"
    original.write_text("YARA_SCOUT_MARKER")
    link = tmp_path / "link.txt"
    link.symlink_to(original)

    result = next(Scanner(rule_file, follow_symlinks=True).scan(link))

    assert result.path == link.absolute()
    assert result.skipped is False
    assert result.matched is True
    assert result.error is None


@pytest.mark.parametrize(
    ("parameter", "value", "message"),
    [
        ("timeout", 0, "YARA timeout must be greater than zero"),
        ("max_file_size", 0, "Maximum file size must be greater than zero"),
    ],
)
def test_scanner_rejects_invalid_safety_values(
    tmp_path,
    parameter: str,
    value: int,
    message: str,
) -> None:
    rule_file = tmp_path / "marker.yar"
    rule_file.write_text(RULE_SOURCE)

    with pytest.raises(ValueError, match=message):
        Scanner(rule_file, **{parameter: value})
