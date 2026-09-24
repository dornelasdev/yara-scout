# Rule-authoring convention

This convention applies to first-party rules maintained by YARA Scout. It keeps
rules understandable, attributable, and suitable for structured reports without
turning metadata into a rigid detection schema. Imported third-party rules should
retain their upstream authorship, metadata, and licensing terms.

YARA metadata describes a rule but does not affect whether the rule matches.
Detection behavior belongs in the `strings` and `condition` sections.

## Files, identifiers, and tags

- Store one related rule or a small related rule family in each `.yar` file.
- Name files with lowercase words separated by underscores, such as
  `suspicious_powershell.yar`.
- Give rules descriptive identifiers with words separated by underscores, such
  as `Suspicious_PowerShell_Encoded_Command`.
- Preserve familiar capitalization in product and technology names.
- Use lowercase tags for broad, searchable context such as platform, technology,
  or technique: `windows powershell execution`.
- Keep rule IDs stable after publication, even if the rule name later improves.

## Metadata

Every first-party rule should contain these fields:

| Field | Format | Purpose |
| --- | --- | --- |
| `id` | `YS-NNNN` | Stable project identifier, for example `YS-0001`. |
| `description` | Short string | Explains what combination of evidence the rule detects. |
| `author` | Name or handle | Identifies the rule owner or original author. |
| `created` | `YYYY-MM-DD` | Records the initial creation date. |
| `license` | SPDX identifier when available | States how the rule may be reused. |
| `category` | Controlled value | Groups the rule by detection purpose. |
| `severity` | Controlled value | Estimates the impact if the finding is accurate. |
| `confidence` | Controlled value | Estimates how strongly a match supports the description. |
| `scope` | Controlled value | Identifies the kind of data the rule expects. |
| `false_positives` | Short string | Describes plausible legitimate matches; use `None known` only when justified. |

Add these fields when applicable:

| Field | Format | Purpose |
| --- | --- | --- |
| `modified` | `YYYY-MM-DD` | Records the most recent meaningful detection change. |
| `reference` | URL or public identifier | Connects the rule to supporting research. |
| `reference_2`, `reference_3` | URL or public identifier | Records additional sources because YARA metadata has no list type. |

Do not place local paths, credentials, internal hostnames, case identifiers, or
other sensitive data in metadata. YARA Scout includes rule metadata unchanged in
JSON reports.

### Controlled values

- `category`: `malware`, `behavior`, `document`, `network`, `test`, or `other`
- `severity`: `informational`, `low`, `medium`, `high`, or `critical`
- `confidence`: `low`, `medium`, or `high`
- `scope`: `file`, `memory`, or `network`

Severity and confidence describe different things. Severity expresses potential
impact; confidence expresses the expected reliability of the detection. A rule
can therefore be high severity and low confidence.

## Detection guidelines

- Combine contextual indicators instead of matching a common string alone.
- State modifiers such as `ascii`, `wide`, and `nocase` deliberately.
- Use descriptive string identifiers that communicate their role in the
  condition.
- Keep the condition readable; split unrelated behavior into separate rules.
- Use size, format, or structural checks when they meaningfully narrow the rule.
- Default-pack rules must compile without external variables or optional module
  data because YARA Scout does not currently provide them.
- Document realistic benign matches in `false_positives`.
- Treat every match as a triage finding, not proof that a file is malicious.

## Example

```yara
rule Suspicious_PowerShell_Encoded_Command : windows powershell execution
{
    meta:
        id = "YS-0001"
        description = "Detects PowerShell combined with encoded command execution"
        author = "dornelasdev"
        created = "2026-09-24"
        license = "MIT"
        category = "behavior"
        severity = "medium"
        confidence = "medium"
        scope = "file"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        false_positives = "Administrative scripts that use encoded PowerShell commands"

    strings:
        $powershell = "powershell" ascii wide nocase
        $encoded_command = "-EncodedCommand" ascii wide nocase

    condition:
        filesize < 5MB and all of them
}
```

## Review checklist

Before adding or changing a rule, verify that:

- its identifier and `id` are unique;
- required metadata is present and uses the documented values;
- references and third-party attribution are accurate;
- the condition represents the behavior described by the metadata;
- safe positive and negative fixtures cover the intended boundary;
- expected false positives are documented; and
- the complete rule collection still compiles together.
