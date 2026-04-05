# Architecture

## System overview

The SOC Threat Detection Pipeline is a Python-native behavioral detection engine built around the Sysmon event format. It ingests raw endpoint telemetry from Sysmon XML exports or `.evtx` files, normalizes events into Python dicts, evaluates each event against a library of YAML-defined detection rules, persists matched alerts to SQLite, correlates alerts into incidents, scores each incident, and surfaces results through a terminal dashboard, HTML report, and interactive analyst triage CLI.

All tunable parameters — log level, rule directory, database path, severity threshold, enrichment depth, correlation window, and triage thresholds — are centralized in `config/config.yaml`. Executable code contains no hardcoded values.

---

## Module dependency diagram

```
cli/main.py  ←─── config/config.yaml
    │
    ├── engine/parser.py          XML → list[dict]
    ├── engine/evtx_parser.py     .evtx → list[dict]
    │
    ├── engine/enricher.py        Process tree ancestry + suspicious parent flag
    │
    ├── engine/rule_engine.py     Rule loader + condition evaluator
    │       └── rules/*.yaml      Detection rule definitions (15 rules)
    │
    ├── engine/alert_store.py     SQLite persistence, stats, disposition
    │
    ├── engine/correlator.py      Alert grouping by host + time window
    ├── engine/scorer.py          0–100 incident risk scoring
    ├── engine/reporter.py        Self-contained HTML incident report
    │
    └── dashboard/terminal_ui.py  Rich terminal dashboard (one-shot and live)

cli/triage.py                     Analyst review CLI (reads alert_store directly)
tools/sigma_converter.py          Standalone Sigma → native YAML translator
```

No module imports from `cli/` or `dashboard/`. The dependency graph is acyclic. All `engine/` modules are independently importable for testing and scripting.

---

## Data flow

```
Sysmon XML / EVTX file
        │
        ▼
engine/parser.py or engine/evtx_parser.py
  • Parses XML via ET.parse() or python-evtx record iterator
  • Extracts System fields: EventID, Timestamp, Computer
  • Extracts all EventData <Data Name="..."> pairs
  • Returns list[dict], one dict per event, malformed events skipped
        │
        ▼
engine/enricher.py  [optional — controlled by config.enrichment.enable_process_tree]
  • Builds ProcessId → event dict lookup from the full event corpus
  • Walks ParentProcessId chain up to max_parent_depth levels
  • Attaches 'ancestors' list to the event dict (ordered from immediate parent outward)
  • Checks ParentImage/Image against known-suspicious pairs (e.g. Word → PowerShell)
  • Attaches 'suspicious_parent': bool to the event dict
        │
        ▼
engine/rule_engine.py — evaluate_event()
  • Filters rules by event_id match (O(n) per event, n = applicable rules)
  • For each applicable rule, evaluates all conditions
  • Guards against empty condition lists (returns False immediately)
  • Applies AND / OR logic across condition results
  • On match: _build_alert() → alert dict matching AlertStore schema
  • Returns list[dict] of alerts for this event
        │
        ▼
engine/alert_store.py — AlertStore.store_alert()
  • Inserts alert row into SQLite alerts table
  • Tracked fields: timestamp, rule metadata, MITRE fields, computer,
    matched_fields (JSON blob), raw_event (JSON blob)
  • Supports analyst disposition: true_positive | false_positive | NULL
        │
        ├── [--correlate or --report flag]
        │        │
        │        ▼
        │   engine/correlator.py — correlate_alerts()
        │     • Sorts alerts by (computer, timestamp)
        │     • Groups by adjacency: same host, gap ≤ time_window_seconds
        │     • Discards groups below min_alerts_for_incident
        │     • Annotates: tactics, techniques, kill chains, duration
        │     • Assigns sequential INC-NNN IDs to emitted incidents only
        │        │
        │        ▼
        │   engine/scorer.py — score_incidents()
        │     • Severity component (capped at 40)
        │     • Tactic diversity component (capped at 30)
        │     • Kill chain bonus (capped at 20)
        │     • Volume bonus (capped at 10)
        │     • Returns incidents sorted by risk_score descending
        │        │
        │        ├── [--report] engine/reporter.py
        │        │     • Generates self-contained HTML with inline CSS
        │        │     • All user-controlled values are HTML-escaped
        │        │     • Incident cards, alert timelines, ATT&CK coverage
        │        │     • Writes to output/incident_report.html
        │        │
        │        └── [--correlate] prints incident summary to stdout
        │
        └── dashboard/terminal_ui.py — run_dashboard()
              • One-shot mode: renders once from provided alert list
              • Live mode: polls AlertStore on refresh_rate interval
              • Header + alert table + stats panel + footer
              • Content-sized layout (footer always visible)
```

---

## Extensibility

### Adding detection rules

Drop a new `*.yaml` file into `rules/`. The engine discovers rule files at startup via `Path.glob("*.yaml")` — no code change is required. Each file must have a top-level `rules:` list. See `docs/rule_authoring_guide.md` for the full rule schema.

### Adding condition operators

Add a new `elif` branch to `_apply_operator()` in `engine/rule_engine.py`. The branch name must match the `operator:` string used in YAML rules. Add a test in `tests/test_rule_engine.py`. Existing rules are unaffected.

### Supporting new Sysmon event types

Coverage is controlled entirely by `event_id:` in rules. The parser extracts all `EventData` fields generically — no parser changes are needed to support new event IDs. Write rules targeting the desired `event_id` and the engine will evaluate them.

### Replacing the alert store

`AlertStore` in `engine/alert_store.py` exposes four methods: `store_alert()`, `get_alerts()`, `mark_disposition()`, and `get_stats()`. A drop-in replacement targeting Elasticsearch, PostgreSQL, or a SIEM API only needs to implement those four methods with the same signatures. The rest of the pipeline does not care how alerts are stored.

### Replacing the dashboard

`run_dashboard()` in `dashboard/terminal_ui.py` takes a list of alert dicts and a stats dict as plain Python. Any rendering layer — a web UI, a Slack notifier, a Kafka producer — can replace it by implementing the same interface.

---

## Configuration reference

All keys in `config/config.yaml`:

```yaml
pipeline:
  log_level: INFO             # Python logging level
  output_format: json         # Reserved — not currently wired
  alert_db_path: output/alerts.db
  benchmark_mode: false       # Enable throughput logging without --benchmark flag

rules:
  rules_dir: rules/
  severity_threshold: low     # Minimum severity to store; lower-severity alerts discarded

enrichment:
  enable_process_tree: true
  max_parent_depth: 3         # How many parent levels to walk per event

dashboard:
  refresh_rate_seconds: 2     # Live mode polling interval
  max_alerts_displayed: 50

correlation:
  enabled: true               # Reserved — correlation runs via --correlate flag
  time_window_seconds: 120    # Max gap between consecutive alerts to group as one incident
  min_alerts_for_incident: 2
  risk_score_threshold: 60    # Incidents below this score are not printed in --correlate output

triage:
  auto_suppress_after_fp: 3   # FP count above which a rule is flagged NOISY in --stats
```
