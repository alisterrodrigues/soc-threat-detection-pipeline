# Architecture

## System Overview

The SOC Threat Detection Pipeline is a Python-native behavioral detection engine built around the Sysmon XML event format. It ingests raw endpoint telemetry, normalizes events into Python dicts, evaluates each event against a library of YAML-defined detection rules, stores matched alerts in a local SQLite database, and renders a Rich-powered terminal dashboard for analyst review. The engine runs entirely offline — there are no external API calls or cloud dependencies. All tunable parameters (log level, rule directory, database path, severity threshold, enrichment depth) are centralized in `config/config.yaml`, keeping the executable code free of hardcoded values.

## Module Dependency Diagram

```
cli/main.py
    │
    ├── engine/parser.py          (XML → list[dict])
    │
    ├── engine/rule_engine.py     (load YAML rules, evaluate events)
    │       └── rules/*.yaml      (detection rule definitions)
    │
    ├── engine/enricher.py        (process tree ancestry annotation)
    │
    ├── engine/alert_store.py     (SQLite persistence, stats, disposition)
    │
    └── dashboard/terminal_ui.py  (Rich layout rendering)

config/config.yaml  ←  consumed by cli/main.py (all paths and thresholds)
```

No module imports from `cli/` or `dashboard/` — the dependency graph is acyclic.
`engine/` modules are independently importable for testing and scripting.

## Data Flow

```
Sysmon XML log file
        │
        ▼
engine/parser.py — parse_sysmon_xml()
  • ET.parse() → root element
  • Iterates <Event> elements
  • Extracts System fields (EventID, Timestamp, Computer)
  • Extracts all EventData <Data Name="..."> pairs
  • Returns list[dict], one dict per event
        │
        ▼
engine/enricher.py — enrich_event()  [optional, controlled by config]
  • Builds ProcessId → event dict lookup from all_events
  • Walks ParentProcessId chain up to max_parent_depth levels
  • Attaches 'ancestors' list to the event dict
        │
        ▼
engine/rule_engine.py — evaluate_event()
  • Filters rules by matching event_id
  • For each applicable rule, evaluates all conditions
  • Applies AND / OR logic across condition results
  • On match: calls _build_alert() → alert dict
  • Returns list[dict] of alerts for this event
        │
        ▼
engine/alert_store.py — AlertStore.store_alert()
  • Inserts alert row into SQLite alerts table
  • Tracks: timestamp, rule metadata, MITRE fields,
    computer, matched_fields (JSON), raw_event (JSON)
  • Supports analyst disposition (true_positive / false_positive)
        │
        ▼
dashboard/terminal_ui.py — run_dashboard()
  • Reads alerts + stats from AlertStore
  • Builds Rich Layout: header / alert table / stats panel / footer
  • Renders to terminal via Console.print()
```

## Extensibility Notes

### Adding new detection rules

Create or edit any `*.yaml` file in the `rules/` directory. The engine discovers
rule files at startup via `Path.glob("*.yaml")` — no code change is needed.
Each rule file must have a top-level `rules:` list. New rules take effect on
the next pipeline invocation.

### Adding new operators

Extend `_apply_operator()` in `engine/rule_engine.py` with a new `elif` branch.
The operator string in the branch must match the `operator:` value used in YAML
rules. Existing rules are unaffected. Add a corresponding test case in
`tests/test_rule_engine.py` to document expected behavior.

### Adding new event types

Event type coverage is controlled entirely by the `event_id:` field in rules.
To support a new Sysmon event type (e.g., Event ID 7 — Image Load), write
rules targeting that event_id. The parser already extracts all EventData fields
generically, so no parser changes are required unless the new event type uses
a non-standard XML structure.

### Switching to a remote alert store

`engine/alert_store.py` encapsulates all storage logic behind the `AlertStore`
class interface. A drop-in replacement targeting Elasticsearch, PostgreSQL, or
a SIEM API only needs to implement `store_alert()`, `get_alerts()`,
`mark_disposition()`, and `get_stats()` with the same signatures.
