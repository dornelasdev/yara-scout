# JSON report format

`yara-scout scan --json PATH` writes a complete scan report using schema version
`1.0`. The JSON file is written after terminal reporting finishes.

## Envelope

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-08-29T12:00:00Z",
  "scan": {
    "target": "$TARGET",
    "rules": "$RULES",
    "path_mode": "relative",
    "options": {
      "timeout_seconds": 10,
      "max_file_size_bytes": 104857600,
      "follow_symlinks": false
    }
  },
  "summary": {
    "files_scanned": 1,
    "matched_files": 1,
    "clean_files": 0,
    "errors": 0,
    "skipped_files": 0,
    "rule_matches": 1
  },
  "results": [
    {
      "path": "positive/suspicious_powershell.txt",
      "status": "matched",
      "size": 242,
      "sha256": "example-sha256-value",
      "file_type": {
        "mime_type": "text/plain",
        "source": "extension"
      },
      "matches": [
        {
          "rule": "Suspicious_PowerShell_Patterns",
          "namespace": "rule_file_0",
          "tags": ["demo", "powershell"],
          "metadata": {
            "severity": "medium"
          }
        }
      ],
      "error": null,
      "skipped_reason": null
    }
  ]
}
```

The SHA-256 value above is illustrative rather than a valid fixture digest.

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Version of this JSON contract, independent of the application version. |
| `generated_at` | UTC timestamp in ISO 8601 format. |
| `scan` | Redacted roots and effective scanner options. |
| `summary` | Counts produced while consuming all scan results. |
| `results` | One object for each discovered file or reported policy skip. |

## Summary fields

| Field | Meaning |
| --- | --- |
| `files_scanned` | Total result records, including matched, clean, errored, and skipped paths. |
| `matched_files` | Files with at least one YARA rule match. |
| `clean_files` | Successfully scanned files without a match. |
| `errors` | Files that could not be processed completely. |
| `skipped_files` | Paths excluded by scanner policy. |
| `rule_matches` | Total number of YARA rule matches across all files. |

## Result fields

| Field | Meaning |
| --- | --- |
| `path` | POSIX-style path relative to `$TARGET`. |
| `status` | `matched`, `clean`, `error`, or `skipped`. |
| `size` | File size in bytes, or `null` when unavailable. |
| `sha256` | Lowercase SHA-256 hex digest, or `null` when unavailable. |
| `file_type` | MIME value and `signature`, `extension`, or `fallback` source. |
| `matches` | Normalized YARA matches; empty when no rule matched. |
| `error` | File-processing failure text, otherwise `null`. |
| `skipped_reason` | Policy explanation for a skipped result, otherwise `null`. |

### Status semantics

| Status | Expected accompanying values |
| --- | --- |
| `matched` | One or more entries in `matches`; `error` is `null`. |
| `clean` | Empty `matches`; `error` and `skipped_reason` are `null`. |
| `error` | `error` contains a message; other metadata may be partial. |
| `skipped` | `skipped_reason` contains a message; no YARA match was attempted. |

## Path privacy

Reports do not serialize the supplied absolute target or rule roots:

- `scan.target` is `$TARGET`.
- `scan.rules` is `$RULES`.
- result paths are relative to `$TARGET`;
- target-root occurrences in scanner error and skip messages are replaced with
  `$TARGET`.

File contents are never placed in the JSON report. SHA-256 values, relative
directory names, filenames, and YARA metadata remain present. Rule metadata is
user-controlled and is serialized unchanged, so rule authors should avoid
placing sensitive local information in metadata fields.

## Output behavior

- JSON always contains complete results, even with `--matches-only`.
- Results are retained in memory only when JSON export is requested.
- An existing output file is replaced.
- Failure to write the requested report returns exit code `2`.

Consumers should check `schema_version` before parsing. A backward-incompatible
schema change increments its major component; additive compatible changes
increment its minor component.
