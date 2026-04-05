# Detection Rules

This directory contains YAML-format detection rules evaluated by the pipeline engine against Sysmon event logs. Each file groups rules by Sysmon event type:

| File | Event ID | Coverage |
|---|---|---|
| `process_creation.yaml` | 1 | Process launches, LOLBin abuse, encoded commands |
| `network_connection.yaml` | 3 | Suspicious outbound connections, C2 patterns |
| `registry_modification.yaml` | 13 | Persistence, defense evasion, privilege escalation |
| `process_access.yaml` | 10 | LSASS credential access, suspicious process handle access |

## Adding a Rule

1. Open the appropriate YAML file (or create a new one — the engine auto-discovers all `*.yaml` files in this directory).
2. Append a new entry to the `rules:` list following the existing schema.
3. Every rule requires: `id`, `name`, `description`, `severity`, `mitre_technique`, `mitre_tactic`, `event_id`, `conditions`, and `logic`.
4. Test the rule: `python -m cli.main --input sample_data/sysmon_events_sample.xml --no-dashboard`

For full field documentation, operator reference, and testing workflow, see [docs/rule_authoring_guide.md](../docs/rule_authoring_guide.md).
