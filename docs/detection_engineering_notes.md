# Detection Engineering Notes

This document outlines the design decisions, tradeoffs, and rationale behind the pipeline’s detection logic, correlation algorithm, and risk scoring model. It’s intended to give contributors context on how the system works and why certain choices were made.

---

## Detection philosophy

The goal of the rule set is not to detect every possible technique — 15 rules cannot do that. The goal is to cover the most common post-exploitation behaviors seen in real-world Sysmon telemetry, implement each detection correctly and tightly, and document every known false positive source so analysts can tune without guesswork.

Each rule was written with three requirements:

1. **The condition must match the described behavior, not just the general area.** REG-002 and REG-003, for example, check both `TargetObject` (the key path) and `Details` (the value written). A rule that fires on any write to `DisableRealtimeMonitoring`, including a write that re-enables protection, is not a detection — it is a noise generator.

2. **The ATT&CK mapping must reflect the analytic intent.** NET-002 detects a C2 communication pattern (direct IP connection without hostname resolution) and maps to T1071 (Application Layer Protocol, generic) rather than T1071.004 (DNS), which it has nothing to do with. PA-003 maps to T1055 (Process Injection) because the behavior of a non-system binary accessing sensitive processes is a strong injection indicator, while noting in `false_positive_notes` that it requires environmental tuning before use as a high-confidence alert.

3. **The false positive surface must be explicitly documented in the rule.** Every rule has a `false_positive_notes` field. The engine does not suppress anything automatically — that judgment belongs to the analyst.

---

## Scoring model

The incident risk score (0–100) is computed in `engine/scorer.py` from four independent components, each capped so no single dimension dominates:

| Component | How it works | Cap |
|-----------|-------------|-----|
| **Severity** | Sum of per-alert severity weights: critical=25, high=15, medium=8, low=3 | 40 |
| **Tactic diversity** | 5 points per unique MITRE tactic covered | 30 |
| **Kill chain match** | 20 points per matched kill chain pattern | 20 |
| **Alert volume** | 1 point per alert beyond the first two | 10 |

**Why these weights:**

Severity is the largest component because it directly reflects the analyst's own judgment about individual rule confidence — a critical-severity rule was written to fire on high-confidence events. Tactic diversity rewards incidents that span the kill chain: a single-tactic incident is more likely to be a noisy rule than a real intrusion. Kill chain bonus is awarded only when specific tactic combinations are present, not just any combination. Volume is deliberately small — alert count is easy to inflate through noisy rules and should not be the deciding factor.

**Why it is a heuristic and not a model:**

The weights are chosen to produce a score that a human analyst would agree with directionally — incidents with critical-severity alerts spanning multiple tactics should score higher than incidents with a single low-confidence detection. The score is not derived from empirical base rates or threat intelligence, and it should be treated as a prioritization aid, not a confidence threshold. Analysts are expected to review the incident timeline and matched fields before making escalation decisions.

**Weights are intentionally hardcoded rather than config-driven** in the current version to keep the scoring logic transparent and auditable. Moving them to config would allow per-environment tuning but introduces the risk of weights being changed without understanding their effect on score distribution.

---

## Correlation algorithm

The correlator (`engine/correlator.py`) groups alerts into incidents using adjacency chaining:

1. Alerts are sorted by `(computer, timestamp)`.
2. A new group starts when the host changes or the gap to the immediately previous alert exceeds `time_window_seconds`.
3. Groups with fewer than `min_alerts_for_incident` members are discarded.

**Why adjacency chaining rather than bounded windows:**

Bounded windows (comparing each alert to the group's start timestamp rather than the previous alert) are more resistant to over-grouping in low-alert-rate environments. Adjacency chaining is more appropriate when alert sequences represent continuous activity with pauses — a sequence of LOLBin executions with 90-second gaps between them is more naturally represented as one incident than as several disconnected ones.

The tradeoff is that a persistently noisy host can chain many alerts over a long period into one high-scoring incident, inflating the score through volume. The volume component's 10-point cap partially controls this.

**Timestamp handling:** If a timestamp cannot be parsed, the two alerts are conservatively kept together rather than split. This avoids dropping correlation context when Sysmon logs contain malformed timestamps, but can result in imprecise duration calculations. A stricter implementation would isolate unparseable-timestamp alerts into their own group.

---

## Kill chain definitions

The five kill chain patterns in `KNOWN_CHAINS` were chosen to represent common real-world attack sequences rather than arbitrary tactic combinations:

| Chain | Tactics required | What it represents |
|-------|-----------------|-------------------|
| `macro_to_c2` | Execution, Command and Control | Office macro dropper making C2 contact |
| `execution_to_persistence` | Execution, Persistence | Post-exploitation persistence installation |
| `execution_to_credential_access` | Execution, Credential Access | Execution followed by credential dumping |
| `defense_evasion_and_privilege_escalation` | Defense Evasion, Privilege Escalation | UAC bypass or Defender tampering with privilege escalation |
| `full_compromise_chain` | Execution, Persistence, Defense Evasion, Credential Access | Complete post-access kill chain |

Kill chains are matched by tactic presence only, not by the order tactics appear in the timeline. A production implementation could enforce ordering (Execution must precede Credential Access) by comparing alert timestamps within the incident.

---

## Process access rules

PA-001 and PA-002 both detect LSASS access but at different confidence levels:

- **PA-001** fires on any handle open to `lsass.exe`. It will fire on AV, EDR, backup software, and identity management agents. It is useful as a hunting rule to inventory all processes touching LSASS, but should not be used as an automated escalation trigger without an allowlist.

- **PA-002** fires only when the `GrantedAccess` mask matches one of six values known to appear in credential dumping tools: `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1f0fff`, `0x1fffff`. The regex is anchored (`^0x(...)$`) to prevent partial matches. This is the high-confidence credential dumping detection — PA-001 is the broad sweep that catches anything else.

- **PA-003** is a hunting heuristic for injection or dumping from unexpected binary locations. It will fire on any third-party application installed outside `C:\Windows\System32` that opens a handle to `lsass`, `winlogon`, or `csrss`. In most environments this requires an explicit allowlist before it produces actionable alerts.

---

## Rule engine edge cases

**Empty conditions:** A rule with an empty `conditions:` list returns `(False, {})` immediately rather than evaluating `all([])`, which Python resolves to `True`. An empty-condition rule matching every event would be a silent mass-fire event. The guard in `_evaluate_conditions` logs a warning and skips the rule.

**Missing fields:** If an event does not contain a field referenced in a condition, the field value is treated as an empty string `""`. This means negative operators (`not_contains`, `not_equals`) will return `True` for missing fields — a field that does not exist does not contain the exclusion value. This is defensible for process event fields that are always present in well-formed Sysmon output, but callers should be aware of the behavior when writing rules for event types with optional fields.

---

## What is not implemented

- **Allowlists in rules:** The `tuning_tag` field on each rule is reserved for future allowlist lookup (e.g., suppress PA-001 alerts where `SourceImage` matches a known EDR binary). The field is stored but not currently evaluated.
- **`correlation.enabled` config key:** Present in config but not wired. Correlation currently runs whenever `--correlate` is passed on the CLI.
- **`output_format` config key:** Present but not wired. Export format is controlled exclusively by `--export` on the CLI.
- **Sigma `selection and not filter` patterns:** The converter emits a warning and does not generate exclusion conditions. These require manual addition as `not_contains` conditions after conversion.
