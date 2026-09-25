"""Compilation and convention validation for YARA rule collections."""

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Callable

import plyara
from plyara.exceptions import ParseTypeError, ParseValueError
import yara


RULE_EXTENSIONS = frozenset({".yar", ".yara"})
REQUIRED_METADATA = (
    "id",
    "description",
    "author",
    "created",
    "license",
    "category",
    "severity",
    "confidence",
    "scope",
    "false_positives",
)
CONTROLLED_METADATA = {
    "category": frozenset(
        {"malware", "behavior", "document", "network", "test", "other"}
    ),
    "severity": frozenset(
        {"informational", "low", "medium", "high", "critical"}
    ),
    "confidence": frozenset({"low", "medium", "high"}),
    "scope": frozenset({"file", "memory", "network"}),
}
FILE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*\.yara?$")
RULE_NAME_PATTERN = re.compile(
    r"^[A-Z][A-Za-z0-9]*(?:_[A-Z][A-Za-z0-9]*)*$"
)
RULE_ID_PATTERN = re.compile(r"^YS-\d{4}$")
TAG_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
REFERENCE_PATTERN = re.compile(r"^reference(?:_\d+)?$")


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    """One actionable problem found in a rule file."""

    path: Path
    message: str
    rule: str | None = None
    line: int | None = None


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Aggregate validation results for one rule file or directory."""

    rule_path: Path
    files_checked: int
    rules_checked: int
    findings: tuple[ValidationFinding, ...]

    @property
    def valid(self) -> bool:
        """Return whether compilation and convention checks all passed."""
        return not self.findings


@dataclass(frozen=True, slots=True)
class _RuleIdentity:
    path: Path
    name: str
    line: int | None


class RuleValidator:
    """Validate that YARA rules compile and follow the project convention."""

    def validate(self, rule_path: Path) -> ValidationReport:
        """Validate every supported rule file beneath ``rule_path``."""
        resolved_path = rule_path.expanduser().resolve()
        rule_files = self._discover_rule_files(resolved_path)
        findings: list[ValidationFinding] = []
        identities_by_id: dict[str, _RuleIdentity] = {}
        identities_by_name: dict[str, _RuleIdentity] = {}
        rules_checked = 0
        compiled_files = 0

        for path in rule_files:
            if not FILE_NAME_PATTERN.fullmatch(path.name):
                findings.append(
                    ValidationFinding(
                        path=path,
                        message=(
                            "Filename must use lowercase words separated by "
                            "underscores"
                        ),
                    )
                )

            try:
                yara.compile(filepath=str(path))
            except yara.Error as error:
                findings.append(
                    ValidationFinding(
                        path=path,
                        message=f"YARA compilation failed: {error}",
                    )
                )
                continue

            compiled_files += 1
            parsed_rules, parse_finding = self._parse_file(path)
            if parse_finding is not None:
                findings.append(parse_finding)
                continue

            if not parsed_rules:
                findings.append(
                    ValidationFinding(
                        path=path,
                        message="No rule declarations were found",
                    )
                )
                continue

            for parsed_rule in parsed_rules:
                rules_checked += 1
                rule_findings, rule_id, identity = self._validate_rule(
                    path,
                    parsed_rule,
                )
                findings.extend(rule_findings)

                previous_name = identities_by_name.get(identity.name)
                if previous_name is None:
                    identities_by_name[identity.name] = identity
                else:
                    findings.append(
                        ValidationFinding(
                            path=path,
                            rule=identity.name,
                            line=identity.line,
                            message=(
                                f"Duplicate rule identifier '{identity.name}'; "
                                f"first declared in {previous_name.path.name}"
                            ),
                        )
                    )

                if rule_id is not None:
                    previous_id = identities_by_id.get(rule_id)
                    if previous_id is None:
                        identities_by_id[rule_id] = identity
                    else:
                        findings.append(
                            ValidationFinding(
                                path=path,
                                rule=identity.name,
                                line=identity.line,
                                message=(
                                    f"Duplicate rule id '{rule_id}'; first used "
                                    f"by {previous_id.name} in "
                                    f"{previous_id.path.name}"
                                ),
                            )
                        )

        if compiled_files == len(rule_files) and len(rule_files) > 1:
            collection_files = {
                f"rule_file_{index}": str(path)
                for index, path in enumerate(rule_files)
            }
            try:
                yara.compile(filepaths=collection_files)
            except yara.Error as error:
                findings.append(
                    ValidationFinding(
                        path=resolved_path,
                        message=f"YARA collection compilation failed: {error}",
                    )
                )

        return ValidationReport(
            rule_path=resolved_path,
            files_checked=len(rule_files),
            rules_checked=rules_checked,
            findings=tuple(findings),
        )

    @staticmethod
    def _discover_rule_files(rule_path: Path) -> list[Path]:
        if not rule_path.exists():
            raise FileNotFoundError(f"Rule path does not exist: {rule_path}")

        if rule_path.is_file():
            if rule_path.suffix.lower() not in RULE_EXTENSIONS:
                raise ValueError(
                    f"Unsupported rule file extension: {rule_path}"
                )
            return [rule_path]

        if not rule_path.is_dir():
            raise ValueError(
                f"Rule path is not a file or directory: {rule_path}"
            )

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
        return rule_files

    @staticmethod
    def _parse_file(
        path: Path,
    ) -> tuple[list[dict[str, Any]], ValidationFinding | None]:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            return [], ValidationFinding(
                path=path,
                message=f"Unable to read rule source as UTF-8: {error}",
            )

        try:
            parsed_rules = plyara.Plyara().parse_string(source)
        except (ParseTypeError, ParseValueError) as error:
            return [], ValidationFinding(
                path=path,
                message=f"Plyara could not parse rule structure: {error}",
            )

        return parsed_rules, None

    def _validate_rule(
        self,
        path: Path,
        parsed_rule: dict[str, Any],
    ) -> tuple[list[ValidationFinding], str | None, _RuleIdentity]:
        findings: list[ValidationFinding] = []
        rule_name = str(parsed_rule.get("rule_name", "<unknown>"))
        raw_line = parsed_rule.get("start_line")
        line = raw_line if isinstance(raw_line, int) else None
        identity = _RuleIdentity(path=path, name=rule_name, line=line)

        def add(message: str) -> None:
            findings.append(
                ValidationFinding(
                    path=path,
                    message=message,
                    rule=rule_name,
                    line=line,
                )
            )

        if not RULE_NAME_PATTERN.fullmatch(rule_name):
            add(
                "Rule identifier must use capitalized, underscore-separated "
                "words"
            )

        tags = parsed_rule.get("tags", [])
        for tag in tags if isinstance(tags, list) else []:
            if not isinstance(tag, str) or not TAG_PATTERN.fullmatch(tag):
                add(
                    f"Tag '{tag}' must contain lowercase letters, digits, "
                    "or underscores"
                )

        metadata, duplicate_keys = self._metadata_values(parsed_rule)
        for key in duplicate_keys:
            add(f"Metadata field '{key}' is declared more than once")

        for key in REQUIRED_METADATA:
            if key not in metadata:
                add(f"Missing required metadata field: {key}")
            elif not isinstance(metadata[key], str) or not metadata[key].strip():
                add(f"Metadata '{key}' must be a non-empty string")

        rule_id = metadata.get("id")
        valid_rule_id = rule_id if isinstance(rule_id, str) else None
        if valid_rule_id is not None and not RULE_ID_PATTERN.fullmatch(valid_rule_id):
            add("Metadata 'id' must match YS-NNNN")

        for key, allowed_values in CONTROLLED_METADATA.items():
            value = metadata.get(key)
            if isinstance(value, str) and value not in allowed_values:
                allowed = ", ".join(sorted(allowed_values))
                add(f"Metadata '{key}' must be one of: {allowed}")

        created = self._validate_date(metadata, "created", add)
        modified = self._validate_date(metadata, "modified", add, optional=True)
        if created is not None and modified is not None and modified < created:
            add("Metadata 'modified' cannot be earlier than 'created'")

        for key, value in metadata.items():
            if REFERENCE_PATTERN.fullmatch(key) and (
                not isinstance(value, str) or not value.strip()
            ):
                add(f"Metadata '{key}' must be a non-empty string")

        return findings, valid_rule_id, identity

    @staticmethod
    def _metadata_values(
        parsed_rule: dict[str, Any],
    ) -> tuple[dict[str, Any], tuple[str, ...]]:
        values: dict[str, Any] = {}
        duplicate_keys: list[str] = []
        metadata = parsed_rule.get("metadata", [])
        if not isinstance(metadata, list):
            return values, ()

        for entry in metadata:
            if not isinstance(entry, dict):
                continue
            for key, value in entry.items():
                if key in values:
                    duplicate_keys.append(str(key))
                else:
                    values[str(key)] = value
        return values, tuple(duplicate_keys)

    @staticmethod
    def _validate_date(
        metadata: dict[str, Any],
        key: str,
        add_finding: Callable[[str], None],
        *,
        optional: bool = False,
    ) -> date | None:
        value = metadata.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            if optional:
                add_finding(f"Metadata '{key}' must use YYYY-MM-DD")
            return None

        try:
            parsed = date.fromisoformat(value)
        except ValueError:
            add_finding(f"Metadata '{key}' must use YYYY-MM-DD")
            return None

        if parsed.isoformat() != value:
            add_finding(f"Metadata '{key}' must use YYYY-MM-DD")
            return None
        return parsed
