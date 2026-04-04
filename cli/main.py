import argparse
import csv
import json
import logging
import os
import sys
import time
from pathlib import Path

import yaml

# Ensure project root is on sys.path when running as `python -m cli.main`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.alert_store import AlertStore
from engine.enricher import enrich_event, flag_suspicious_parent
from engine.parser import parse_sysmon_xml
from engine.rule_engine import evaluate_event, load_rules


def load_config(config_path: str) -> dict:
    """
    Load and return the YAML configuration file as a dict.

    Exits the process with a non-zero status if the file is missing
    or unparseable, since the pipeline cannot run without valid config.

    Args:
        config_path: Path to the config.yaml file.

    Returns:
        Parsed configuration dict.
    """
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load config: {e}")
        sys.exit(1)


def setup_logging(level_str: str):
    """
    Configure the root logger with the canonical pipeline log format.

    Args:
        level_str: Log level string such as 'INFO', 'DEBUG', or 'WARNING'.
                   Falls back to INFO for unrecognized values.
    """
    level = getattr(logging, level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def print_benchmark(stats: dict, events_processed: int, elapsed: float, rules: list):
    """
    Print a formatted run-summary table to stdout after pipeline completion.

    Displays throughput, rule count, alert totals broken down by severity,
    the highest-firing rule, and the overall alert rate as a percentage.

    Args:
        stats: Aggregate stats dict from AlertStore.get_stats().
        events_processed: Total number of events that were evaluated.
        elapsed: Wall-clock seconds taken for the full run.
        rules: Full list of loaded rule dicts (used for count display).
    """
    throughput = int(events_processed / elapsed) if elapsed > 0 else 0
    total_alerts = stats.get("total", 0)
    alert_rate = (total_alerts / events_processed * 100) if events_processed > 0 else 0

    by_sev = stats.get("by_severity", {})
    by_rule = stats.get("by_rule", {})
    top_rule = max(
        by_rule.items(), key=lambda x: x[1]["count"], default=(None, {"name": "N/A", "count": 0})
    )

    print("\n" + "━" * 50)
    print("  Detection Pipeline — Run Summary")
    print("━" * 50)
    print(f"  Events processed:     {events_processed:,}")
    print(f"  Processing time:      {elapsed:.2f}s")
    print(f"  Throughput:           {throughput:,} events/sec")
    print(f"  Rules evaluated:      {len(rules)}")
    print(f"  Alerts fired:         {total_alerts}")
    print(f"    Critical:           {by_sev.get('critical', 0)}")
    print(f"    High:               {by_sev.get('high', 0)}")
    print(f"    Medium:             {by_sev.get('medium', 0)}")
    print(f"    Low:                {by_sev.get('low', 0)}")
    if top_rule[0]:
        print(
            f"  Top rule triggered:   {top_rule[0]} ({top_rule[1]['name']}) — {top_rule[1]['count']} hits"
        )
    print(f"  Alert rate:           {alert_rate:.2f}%")
    print("━" * 50 + "\n")


def export_alerts(alerts: list[dict], output_dir: str, fmt: str):
    """
    Write alerts to disk in JSON, CSV, or both formats.

    Creates output_dir if it does not already exist. JSON is pretty-printed
    with 2-space indentation. CSV uses DictWriter with headers from the first
    alert's keys. An empty alerts list produces no CSV output.

    Args:
        alerts: List of alert dicts to export.
        output_dir: Directory path where output files are written.
        fmt: One of 'json', 'csv', or 'both'.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    export_logger = logging.getLogger(__name__)

    if fmt in ("json", "both"):
        out_path = os.path.join(output_dir, "alerts.json")
        try:
            with open(out_path, "w") as f:
                json.dump(alerts, f, indent=2, default=str)
            export_logger.info(f"Alerts exported to {out_path}")
        except OSError as e:
            export_logger.warning(f"Failed to write JSON export: {e}")

    if fmt in ("csv", "both"):
        out_path = os.path.join(output_dir, "alerts.csv")
        if alerts:
            try:
                with open(out_path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
                    writer.writeheader()
                    writer.writerows(alerts)
                export_logger.info(f"Alerts exported to {out_path}")
            except OSError as e:
                export_logger.warning(f"Failed to write CSV export: {e}")


def main():
    """
    CLI entry point for the SOC Threat Detection Pipeline.

    Parses arguments, loads config, reads rules, parses the Sysmon XML log,
    evaluates every event against all rules, stores matching alerts in SQLite,
    then either renders the terminal dashboard or streams JSON to stdout.
    """
    parser = argparse.ArgumentParser(
        description="SOC Threat Detection Pipeline — Sysmon behavioral detection engine"
    )
    parser.add_argument("--input", required=True, help="Path to Sysmon XML log file")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config.yaml")
    parser.add_argument("--output-dir", default="output/", help="Directory for output files")
    parser.add_argument(
        "--severity",
        default=None,
        help="Minimum severity to alert on (low|medium|high|critical)",
    )
    parser.add_argument(
        "--benchmark", action="store_true", help="Print processing speed metrics at completion"
    )
    parser.add_argument(
        "--export",
        default=None,
        choices=["json", "csv", "both"],
        help="Export alerts after processing",
    )
    parser.add_argument(
        "--no-dashboard", action="store_true", help="Run headless — print alerts to stdout only"
    )

    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config.get("pipeline", {}).get("log_level", "INFO"))
    logger = logging.getLogger("main")

    benchmark_mode = args.benchmark or config.get("pipeline", {}).get("benchmark_mode", False)
    rules_dir = config.get("rules", {}).get("rules_dir", "rules/")
    db_path = config.get("pipeline", {}).get("alert_db_path", "output/alerts.db")
    severity_threshold = args.severity or config.get("rules", {}).get("severity_threshold", "low")
    output_dir = args.output_dir
    refresh_rate = config.get("dashboard", {}).get("refresh_rate_seconds", 2)
    max_alerts = config.get("dashboard", {}).get("max_alerts_displayed", 50)
    enable_enrichment = config.get("enrichment", {}).get("enable_process_tree", True)
    max_depth = config.get("enrichment", {}).get("max_parent_depth", 3)

    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_rank = severity_rank.get(severity_threshold.lower(), 0)

    logger.info(f"Loading rules from {rules_dir}")
    rules = load_rules(rules_dir)
    if not rules:
        logger.error("No rules loaded. Exiting.")
        sys.exit(1)

    logger.info(f"Parsing events from {args.input}")
    start_time = time.perf_counter()
    events = parse_sysmon_xml(args.input)
    if not events:
        logger.error("No events parsed. Check file path and format.")
        sys.exit(1)

    store = AlertStore(db_path)
    all_alerts = []

    for event in events:
        if enable_enrichment:
            event = enrich_event(event, events, max_depth)

        matched_alerts = evaluate_event(event, rules, benchmark_mode)

        for alert in matched_alerts:
            sev = alert.get("severity", "low").lower()
            if severity_rank.get(sev, 0) >= min_rank:
                store.store_alert(alert)
                all_alerts.append(alert)

    elapsed = time.perf_counter() - start_time
    stats = store.get_stats()

    if args.export:
        export_alerts(all_alerts, output_dir, args.export)

    if benchmark_mode:
        print_benchmark(stats, len(events), elapsed, rules)

    if args.no_dashboard:
        for alert in all_alerts:
            print(json.dumps(alert, default=str))
    else:
        from dashboard.terminal_ui import run_dashboard

        run_dashboard(
            alerts=all_alerts,
            stats=stats,
            events_processed=len(events),
            events_per_sec=len(events) / elapsed if elapsed > 0 else 0,
            db_path=db_path,
            rule_count=len(rules),
            refresh_rate=refresh_rate,
            max_alerts=max_alerts,
        )


if __name__ == "__main__":
    main()
