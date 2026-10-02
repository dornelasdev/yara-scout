# Architecture

YARA Scout separates command handling, scanning, result representation, and
presentation. The YARA engine compiles and evaluates rules; YARA Scout coordinates
the surrounding triage workflow.

## Data flow

```mermaid
flowchart LR
    CLI[CLI input] --> Scan[scan command]
    CLI --> Validate[validate command]
    Scan --> Scanner
    Scanner --> Discovery[File discovery and safety policy]
    Discovery --> Type[File-type detection]
    Discovery --> Hash[SHA-256 hashing]
    Discovery --> YARA[YARA matching]
    Type --> Result[ScanResult]
    Hash --> Result
    YARA --> Result
    Result --> Terminal[TerminalReporter]
    Result --> JSON[JsonReporter]
    Validate --> Validator[RuleValidator]
    Validator --> Compile[YARA compilation]
    Validator --> Parse[Plyara structure parsing]
    Compile --> Findings[ValidationReport]
    Parse --> Findings
    Findings --> ValidationTerminal[Terminal output]
```

The scanner compiles the selected rule collection once. Its `scan()` method then
yields one `ScanResult` for each discovered file. Terminal reporting consumes
those results as they arrive. When JSON output is requested, the CLI retains the
same streamed results and writes the complete report afterward.

The validator checks each rule with the same YARA engine used for scanning, then
uses Plyara to inspect rule names, tags, and metadata. It returns all objective
convention findings together rather than stopping after the first invalid file.

## Components

### CLI

`cli.py` owns Typer arguments, scanner construction, reporter coordination, and
process exit codes. It does not perform hashing, file-type detection, or YARA
matching.

### Scanner

`scanner.py` owns:

- rule-file discovery and compilation;
- target-file discovery;
- timeout, size, and symbolic-link policy;
- SHA-256 hashing;
- calls into `yara-python`; and
- normalization of raw YARA matches.

The `Scanner` instance retains compiled rules and safety settings. Scan results
are yielded rather than accumulated inside the scanner.

### Validator

`validation.py` owns rule discovery, authoritative compilation through
`yara-python`, structural parsing through Plyara, and objective convention
checks. `ValidationReport` and `ValidationFinding` keep that logic independent
from terminal formatting.

Compilation and parsing are intentionally separate. A rule must compile before
its convention is inspected, and parser compatibility failures are reported
separately from YARA syntax failures.

Each selected entry compiles with its includes in context. After successful
compilation, an iterative traversal follows Plyara's include paths and checks
metadata in every reachable source. Resolved paths deduplicate shared sources;
findings retain each declaration's source path and line number. Include-only
wrappers are allowed. YARA compilation detects missing dependencies and cycles.
File counts include selected entries and additional inspected dependencies;
rule counts include declarations actually inspected.

Directory input retains the scanner's entry selection: all discovered `.yar`
and `.yara` files compile independently and then together in separate namespaces.
Single-file input compiles just that entry and inspects dependencies without
requiring independent compilation. A failed entry does not prevent other entries
from being checked, but its dependencies may remain uninspected.

### File-type detector

`filetypes.py` checks known signatures for PE, ELF, PDF, ZIP, PNG, JPEG, and
GZIP. When no signature matches, it consults Python's MIME extension mapping and
finally falls back to `application/octet-stream`.

This classification is triage metadata, not a file-validity guarantee.

### Models

`models.py` defines the data exchanged between components:

- `FileType` records a MIME value and detection source.
- `RuleMatch` normalizes a YARA rule, namespace, tags, and metadata.
- `ScanResult` represents the outcome for one discovered path.

### Reporters

`TerminalReporter` streams human-readable findings through a Rich console and
returns aggregate counts. `JsonReporter` serializes the same models into a
versioned envelope and applies path redaction.

## Result states

Each result is interpreted as exactly one of four states:

| State | Meaning |
| --- | --- |
| `matched` | The file was scanned and one or more rules matched. |
| `clean` | The file was scanned and no rules matched. |
| `error` | Reading, hashing, or YARA evaluation failed for the file. |
| `skipped` | Scanner policy excluded the file before YARA evaluation. |

Reporters apply the precedence `skipped → error → matched → clean` when mapping
a result to a status.

## Failure boundaries

Invalid configuration, unavailable rule paths, compilation failures, and target
discovery failures prevent the operation from completing. Individual file
failures are recorded and scanning continues with the next discovered file.
Policy skips are expected outcomes rather than failures.

Validation startup failures return immediately. Once validation begins,
compilation and convention findings are collected across the discovered rule
files and produce validation exit code `1`.

The resulting process codes are documented in the
[README command reference](../README.md#command-reference).
