# Rule Authoring Guide

## YAML Rule Schema

Each rule file in `rules/` contains a top-level `rules:` list. Every item in
that list is a rule dict with the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Unique rule identifier. Convention: `CATEGORY-NNN` (e.g. `PROC-001`, `NET-003`). Must be unique across all rule files. |
| `name` | string | yes | Human-readable display name shown in alerts and the dashboard. |
| `description` | string | yes | One or two sentences describing what behavior the rule detects and why it is suspicious. |
| `severity` | string | yes | One of `low`, `medium`, `high`, `critical`. Controls alert priority and dashboard color coding. |
| `mitre_technique` | string | yes | MITRE ATT&CK technique ID (e.g. `T1059.001`). Used for tactic grouping in stats. |
| `mitre_tactic` | string | yes | MITRE ATT&CK tactic name (e.g. `Execution`, `Persistence`). |
| `event_id` | integer | yes | Sysmon Event ID this rule targets. Events with a different ID are skipped without condition evaluation. |
| `conditions` | list | yes | One or more condition objects (see below). |
| `logic` | string | yes | `AND` — all conditions must match. `OR` — any condition must match. |
| `false_positive_notes` | string | recommended | Describes known benign scenarios that can trigger this rule. Helps analysts triage quickly. |
| `tuning_tag` | string | recommended | Short snake_case label for grouping related rules in suppression lists or dashboards. |

### Condition Object Schema

Each item in `conditions:` has these fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `field` | string | yes | The event field name to evaluate (e.g. `Image`, `CommandLine`, `TargetObject`). |
| `operator` | string | yes | Comparison operator. See supported operators below. |
| `value` | string | yes | The comparison value. Empty string `""` is valid (used with `equals` to detect absent hostnames). |
| `case_insensitive` | boolean | yes | When `true`, both the event value and rule value are lowercased before comparison. |

---

## Supported Operators

### `contains`
Returns true if `value` appears anywhere in the event field.

```yaml
- field: "CommandLine"
  operator: contains
  value: "-EncodedCommand"
  case_insensitive: true
```

Matches: `powershell.exe -EncodedCommand dABl...`, `cmd /c powershell -encodedcommand ...`

---

### `not_contains`
Returns true if `value` does NOT appear in the event field. Useful for
excluding known-safe values.

```yaml
- field: "DestinationPort"
  operator: not_contains
  value: "443"
  case_insensitive: false
```

Matches any event where the destination port is not `443`.

---

### `equals`
Returns true only on an exact string match (after case folding if
`case_insensitive: true`). Primarily used to detect empty fields.

```yaml
- field: "DestinationHostname"
  operator: equals
  value: ""
  case_insensitive: false
```

Matches events where `DestinationHostname` is absent or an empty string.

---

### `startswith`
Returns true if the event field begins with `value`.

```yaml
- field: "TargetObject"
  operator: startswith
  value: "HKLM\\SOFTWARE\\Microsoft"
  case_insensitive: true
```

---

### `endswith`
Returns true if the event field ends with `value`. Preferred over `contains`
for matching binary names to avoid false matches on path components.

```yaml
- field: "Image"
  operator: endswith
  value: "whoami.exe"
  case_insensitive: true
```

Matches `C:\Windows\System32\whoami.exe` but not `fake-whoami.exe.bak`.

---

### `regex`
Returns true if the event field matches the regular expression in `value`.
Use sparingly — regex is the slowest operator and can be error-prone.

```yaml
- field: "CommandLine"
  operator: regex
  value: "-(enc|encodedcommand)"
  case_insensitive: true
```

When `case_insensitive: true`, the `re.IGNORECASE` flag is applied automatically.

---

## Testing a New Rule Against Sample Data

**Step 1 — Write the rule** in the appropriate YAML file under `rules/` or
create a new `rules/my_new_rules.yaml`.

**Step 2 — Add a matching event** to `sample_data/sysmon_events_sample.xml` that
should trigger the rule, and optionally a benign event that should not.

**Step 3 — Run the pipeline** against the sample data in headless mode:

```bash
python -m cli.main \
  --input sample_data/sysmon_events_sample.xml \
  --config config/config.yaml \
  --no-dashboard \
  --benchmark
```

**Step 4 — Verify the output.** Your new rule ID should appear in the JSON
stream printed to stdout. The benchmark summary shows alert counts by severity.

**Step 5 — Run the test suite** to confirm existing rules are unaffected:

```bash
pytest tests/ -v
```

**Step 6 — Add a unit test** in `tests/test_rule_engine.py` following the
`test_proc001_fires_on_match` pattern: define a minimal event dict, pass it
through `evaluate_event()` with only your rule in the rules list, and assert
the correct `rule_id` appears in alerts.

---

## Common False Positive Pitfalls

### Overly broad `contains` on short strings
Matching `value: "net"` on the `CommandLine` field will fire on `netstat`,
`network`, `.NET`, and many other benign strings. Use `endswith` for
binary names and combine with a second condition on a more specific field.

### Case sensitivity mismatches
Sysmon field values for paths are mixed-case on Windows. Always set
`case_insensitive: true` for path and filename fields unless you have a
specific reason to be case-sensitive (e.g. Base64 regex patterns).

### Missing event_id scoping
A rule without the correct `event_id` will never fire — but it will also
silently evaluate zero events. Verify the Sysmon event type for the fields
you are matching (e.g. `TargetObject` only appears in Event ID 13).

### Single-condition rules on common processes
A rule that only checks `Image endswith svchost.exe` will produce enormous
alert volume. Always combine process name conditions with a second
behavioral condition (CommandLine, ParentImage, destination port, etc.).

### Using `tuning_tag` for suppression
The `tuning_tag` field is stored in rule metadata and surfaced in exports.
Build suppression logic in your SIEM or analyst workflow around these tags
rather than deleting rules — this preserves audit history and makes it easy
to re-enable rules when the suppression context changes.
