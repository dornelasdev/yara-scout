# YARA Scout

YARA Scout is a lightweight command-line triage scanner that applies YARA rules
to files, records useful metadata, and produces terminal or JSON findings. It is
intended for analysts, students, and rule authors who want a small, transparent
file-triage workflow.

The current `v0.1.0` release provides the core scanning and reporting workflow.

## Features

- Scan one file or recursively scan a directory.
- Compile one rule file or a directory of `.yar` and `.yara` files.
- Calculate SHA-256 and collect file size information.
- Detect common file signatures with MIME extension fallback.
- Report YARA rule names, namespaces, tags, and metadata.
- Stream readable terminal findings and aggregate counts.
- Export a versioned JSON report with redacted local roots.
- Limit per-file YARA time, file size, and symbolic-link traversal.
- Continue after individual file errors.

## Requirements

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/)

## Installation

Install the project and its development dependencies:

```console
uv sync
```

Activate the generated environment to use `pytest` and `yara-scout` directly:

```console
source .venv/bin/activate
```

Run `deactivate` when you want to leave the environment.

## Quick start

Run the included safe demonstration:

```console
yara-scout scan fixtures -r rules
```

Write the same complete scan to JSON while retaining terminal output:

```console
yara-scout scan fixtures -r rules -j report.json
```

The demonstration data is inert text. It does not contain executable content or
live malware.

## Command reference

```console
yara-scout scan TARGET --rules PATH [OPTIONS]
```

| Input | Short form | Meaning | Default |
| --- | --- | --- | --- |
| `TARGET` | — | File or directory to scan | Required |
| `--rules PATH` | `-r` | YARA rule file or directory | Required |
| `--matches-only` | `-m` | Hide clean-file details in the terminal | Disabled |
| `--timeout SECONDS` | `-t` | Maximum YARA matching time per file | `10` |
| `--max-file-size-mb SIZE` | `-s` | Skip files larger than this many MiB | `100` |
| `--follow-symlinks` | `-L` | Scan files reached through symbolic links | Disabled |
| `--json PATH` | `-j` | Write a complete JSON report | Disabled |

Use `yara-scout scan --help` for generated CLI help and `yara-scout --version` for
the installed project version.

Examples:

```console
# Scan one file
yara-scout scan suspicious-file -r rules

# Display matches, errors, and skipped files without clean-file detail
yara-scout scan samples -r rules -m

# Use tighter safety limits
yara-scout scan samples -r rules -t 5 -s 50

# Intentionally follow symbolic links
yara-scout scan samples -r rules -L
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The scan completed without file errors. Matches and policy skips are valid results. |
| `1` | The scan completed, but one or more files produced an error. |
| `2` | Arguments, rule compilation, discovery, or JSON output prevented complete operation. |

## Safety behavior

The scanner applies these defaults:

- YARA matching is limited to 10 seconds per file.
- Files larger than 100 MiB are reported as `SKIPPED`.
- Symbolic links are not followed unless `--follow-symlinks` is set. Discovered
  symlinked files are reported as `SKIPPED`; linked directories are not entered.
- Directory-link cycles are not traversed repeatedly.
- File read and YARA match failures become `ERROR` results.

An inaccessible file does not stop other discovered files from being processed.
An error while traversing a directory prevents the scanner from completing and
returns exit code `2`.

## JSON reports

JSON reports contain a schema version, UTC generation time, scanner options,
summary counts, and complete file results. Local roots are represented as
`$TARGET` and `$RULES`, while result paths remain relative to `$TARGET`.

`--matches-only` changes terminal presentation only; clean results remain in the
JSON report. An existing file passed to `--json` is replaced.

See [JSON report format](docs/json-report.md) for the schema and privacy model.

## Safe example data

```text
rules/
├── eicar_test_file.yar
├── pdf_embedded_actions.yar
└── suspicious_powershell.yar
fixtures/
├── positive/
│   └── suspicious_powershell.txt
└── negative/
    └── ordinary_note.txt
```

The starter rule pack covers suspicious PowerShell behavior, PDF active-content
indicators, and the canonical EICAR antivirus test file. The current positive
fixture contains inert command-like text intended to match the PowerShell rule;
the negative fixture provides a known clean result. A YARA match indicates that
a rule condition was satisfied; it does not by itself prove maliciousness.

## Rule development

First-party rules follow the project [rule-authoring convention](docs/rule-authoring.md),
which defines naming, metadata, attribution, detection, and review expectations.
The existing demonstration rule will be aligned with this convention as the
curated starter rule pack is developed.

## Project structure

```text
src/yara_scout/
├── cli.py          # Command parsing, orchestration, and exit codes
├── filetypes.py    # Hybrid file-signature and extension detection
├── models.py       # Structured findings and match records
├── reporting.py    # Terminal and JSON report generation
└── scanner.py      # Rule compilation, discovery, hashing, and matching
```

See [architecture](docs/architecture.md) for component boundaries and data flow.

## Development

Run the test suite from the activated project environment:

```console
pytest
```

Tests create harmless temporary rules and files. Repository fixtures provide an
additional end-to-end contract for the example rule.

## Limitations

- Scans regular files on disk; process and memory scanning are not supported.
- Does not unpack archives, execute files, or provide malware sandboxing.
- MIME detection is best-effort and supports a limited built-in signature set.
- YARA matches can include false positives and false negatives.
- JSON export retains scan results in memory until the report is written.
- Automatic rule downloads, threat-intelligence integrations, web interfaces,
  and persistent storage are outside the `v0.1.0` scope.

## License

YARA Scout is available under the [MIT License](LICENSE).
