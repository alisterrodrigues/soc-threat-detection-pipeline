"""
Analyst triage CLI — interactive tool for reviewing and dispositioning alerts
stored in the SQLite alert database.

Usage:
    python -m cli.triage [OPTIONS]

Options:
    --db PATH           Path to alerts.db  [default: output/alerts.db]
    --config PATH       Path to config.yaml [default: config/config.yaml]
    --rule RULE_ID      Filter to a specific rule ID
    --severity LEVEL    Exact severity filter (low|medium|high|critical)
    --undispositioned   Show only alerts not yet reviewed
    --stats             Print rule-level FP/TP summary and exit
"""

import argparse
import json
import logging
import sqlite3
import sys
from pathlib import Path

import yaml
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.alert_store import AlertStore

console = Console()
logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "cyan",
}


def load_config(path: str) -> dict:
    """
    Load the YAML configuration file and return it as a dict.

    Exits the process if the file is missing or unparseable, since the
    triage tool cannot determine thresholds without valid config.

    Args:
        path: File system path to config.yaml.

    Returns:
        Parsed configuration dict.
    """
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        sys.exit(1)


def print_alert_detail(alert: dict):
    """
    Print a single alert's full detail as a Rich Panel to the console.

    Renders rule metadata, matched fields parsed from JSON, and any
    existing analyst notes. Truncation is not applied here — the full
    field values are shown so analysts can make informed decisions.

    Args:
        alert: Alert dict retrieved from AlertStore.get_alerts().
    """
    sev = alert.get("severity", "low").lower()
    color = SEVERITY_COLORS.get(sev, "white")

    lines = [
        f"[bold]Alert ID:[/bold]      {alert.get('id')}",
        f"[bold]Rule:[/bold]          [{color}]{alert.get('rule_id')}[/{color}] — {alert.get('rule_name')}",
        f"[bold]Severity:[/bold]      [{color}]{sev.upper()}[/{color}]",
        f"[bold]Technique:[/bold]     {alert.get('mitre_technique')}  ({alert.get('mitre_tactic')})",
        f"[bold]Computer:[/bold]      {alert.get('computer')}",
        f"[bold]Timestamp:[/bold]     {alert.get('timestamp', '')[:19]}",
        f"[bold]Disposition:[/bold]   {alert.get('analyst_disposition') or '[dim]None[/dim]'}",
        "",
        "[bold]Matched Fields:[/bold]",
    ]

    try:
        matched = json.loads(alert.get("matched_fields", "{}"))
        for field, value in matched.items():
            lines.append(f"  [cyan]{field}[/cyan] = {value}")
    except Exception:
        lines.append(f"  {alert.get('matched_fields', '')}")

    if alert.get("notes"):
        lines.append("")
        lines.append(f"[bold]Analyst Notes:[/bold] {alert.get('notes')}")

    console.print(Panel("\n".join(lines), title="Alert Detail", border_style="blue"))


def print_stats(store: AlertStore, auto_suppress_threshold: int):
    """
    Print a per-rule false positive summary table to the console.

    Queries the database directly for per-rule TP/FP breakdown, then
    renders a Rich Table with a NOISY flag on rules that exceed the
    auto-suppress threshold. Rules with no dispositions are shown as
    'unreviewed' so analysts know where coverage gaps exist.

    Args:
        store: Initialized AlertStore connected to the alerts database.
        auto_suppress_threshold: Number of FP dispositions above which
                                 a rule is flagged as NOISY.
    """
    try:
        with sqlite3.connect(store.db_path) as conn:
            rows = conn.execute(
                """
                SELECT rule_id, rule_name,
                       COUNT(*) as total,
                       SUM(CASE WHEN analyst_disposition = 'false_positive' THEN 1 ELSE 0 END) as fp_count,
                       SUM(CASE WHEN analyst_disposition = 'true_positive' THEN 1 ELSE 0 END) as tp_count
                FROM alerts
                GROUP BY rule_id
                ORDER BY fp_count DESC
                """
            ).fetchall()
    except Exception as e:
        console.print(f"[red]Failed to query stats: {e}[/red]")
        return

    table = Table(
        title="Rule Disposition Summary",
        box=box.SIMPLE_HEAD,
        header_style="bold magenta",
    )
    table.add_column("Rule ID", width=10)
    table.add_column("Rule Name", min_width=30)
    table.add_column("Total", width=7)
    table.add_column("TP", width=6, style="green")
    table.add_column("FP", width=6, style="red")
    table.add_column("FP Rate", width=9)
    table.add_column("Status", width=12)

    for rule_id, rule_name, total, fp_count, tp_count in rows:
        fp_rate = (fp_count / total * 100) if total > 0 else 0
        dispositioned = fp_count + tp_count

        if dispositioned == 0:
            status = "[dim]unreviewed[/dim]"
        elif fp_count >= auto_suppress_threshold:
            status = "[bold red]NOISY[/bold red]"
        elif fp_rate > 50:
            status = "[yellow]review[/yellow]"
        else:
            status = "[green]ok[/green]"

        table.add_row(
            rule_id,
            rule_name[:40],
            str(total),
            str(tp_count),
            str(fp_count),
            f"{fp_rate:.0f}%",
            status,
        )

    console.print(table)
    if auto_suppress_threshold:
        console.print(
            f"\n[dim]Rules with {auto_suppress_threshold}+ false positives are flagged as NOISY.[/dim]"
        )


def interactive_triage(store: AlertStore, alerts: list[dict]):
    """
    Walk through alerts one at a time, prompting the analyst to disposition each.

    For each alert the analyst can:
      t — mark as true_positive (with optional free-text notes)
      f — mark as false_positive (with optional free-text notes)
      s — skip (no disposition recorded)
      q — quit the session immediately

    Keyboard interrupts (Ctrl-C) at any prompt exit gracefully without
    crashing and without losing dispositions already saved.

    Args:
        store: Initialized AlertStore used to persist dispositions.
        alerts: Ordered list of alert dicts to review.
    """
    if not alerts:
        console.print("[dim]No alerts to review.[/dim]")
        return

    console.print(f"\n[bold]Starting triage — {len(alerts)} alert(s) to review.[/bold]")
    console.print(
        "[dim]Commands: t = true positive  |  f = false positive  |  s = skip  |  q = quit[/dim]\n"
    )

    reviewed = 0
    for alert in alerts:
        print_alert_detail(alert)

        while True:
            try:
                choice = console.input("[bold]Disposition [t/f/s/q]:[/bold] ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Triage interrupted.[/dim]")
                return

            if choice == "q":
                console.print(f"\n[dim]Triage exited. {reviewed} alert(s) reviewed.[/dim]")
                return
            elif choice == "s":
                console.print("[dim]Skipped.[/dim]\n")
                break
            elif choice in ("t", "f"):
                disposition = "true_positive" if choice == "t" else "false_positive"
                try:
                    notes = console.input(
                        "[dim]Notes (optional, press Enter to skip):[/dim] "
                    ).strip()
                except (KeyboardInterrupt, EOFError):
                    notes = ""
                success = store.mark_disposition(alert["id"], disposition, notes)
                if success:
                    label = (
                        "[green]TRUE POSITIVE[/green]"
                        if choice == "t"
                        else "[red]FALSE POSITIVE[/red]"
                    )
                    console.print(f"Marked as {label}\n")
                    reviewed += 1
                else:
                    console.print("[red]Failed to save disposition.[/red]\n")
                break
            else:
                console.print("[dim]Invalid input. Use t, f, s, or q.[/dim]")

    console.print(f"\n[bold]Triage complete. {reviewed} alert(s) dispositioned.[/bold]")


def main():
    """
    Entry point for the analyst triage CLI.

    Loads the alert database, applies any requested filters, then either
    prints the rule-level FP/TP stats table (--stats) or starts an
    interactive review session for matching alerts.
    """
    parser = argparse.ArgumentParser(
        description="Analyst triage CLI — review and disposition alerts from the detection pipeline"
    )
    parser.add_argument("--db", default="output/alerts.db", help="Path to alerts.db")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config.yaml")
    parser.add_argument("--rule", default=None, help="Filter to a specific rule ID")
    parser.add_argument(
        "--severity",
        default=None,
        help="Exact severity filter (low|medium|high|critical) — shows only alerts at this severity level",
    )
    parser.add_argument(
        "--undispositioned",
        action="store_true",
        help="Show only alerts not yet reviewed",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print per-rule FP/TP summary and exit",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING,
        format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    )

    config = load_config(args.config)
    auto_suppress_threshold = config.get("triage", {}).get("auto_suppress_after_fp", 3)

    if not Path(args.db).exists():
        console.print(f"[red]Database not found: {args.db}[/red]")
        console.print("[dim]Run the pipeline first to generate alerts.[/dim]")
        sys.exit(1)

    store = AlertStore(args.db)

    if args.stats:
        print_stats(store, auto_suppress_threshold)
        return

    alerts = store.get_alerts(severity=args.severity, rule_id=args.rule)

    if args.undispositioned:
        alerts = [a for a in alerts if a.get("analyst_disposition") is None]

    # Reverse so oldest alerts come first — chronological review order
    alerts = list(reversed(alerts))

    if not alerts:
        console.print("[dim]No alerts match the specified filters.[/dim]")
        return

    interactive_triage(store, alerts)


if __name__ == "__main__":
    main()
