"""
Terminal dashboard — Rich-based live tailing display for the detection pipeline.

Two rendering modes:
  - One-shot mode (default): renders the current alert set once and exits.
    Used when the pipeline has finished processing a static log file.
  - Live mode (--live flag): polls AlertStore every N seconds for new alerts,
    updating the display until the user presses Ctrl+C.

The layout is content-sized — header, body, and footer are stacked with no
terminal-height dependency, so the footer always appears immediately after
the last alert row regardless of terminal window size.
"""

import logging
import time

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "yellow",
    "low":      "cyan",
}

console = Console()


def build_header(stats: dict, events_processed: int, events_per_sec: float) -> Panel:
    """
    Build the top-bar Panel showing pipeline-level throughput metrics.

    Args:
        stats: Aggregate stats dict from AlertStore.get_stats().
        events_processed: Total number of events evaluated in this run.
        events_per_sec: Computed throughput value for display.

    Returns:
        A Rich Panel for the header row.
    """
    header_text = (
        f"[bold]SOC Threat Detection Pipeline[/bold]  |  "
        f"Events: [green]{events_processed:,}[/green]  |  "
        f"Alerts: [red]{stats.get('total', 0)}[/red]  |  "
        f"Throughput: [cyan]{events_per_sec:.0f} evt/s[/cyan]"
    )
    return Panel(header_text, style="bold white on dark_blue")


def build_alert_table(alerts: list, max_alerts: int = 50) -> Table:
    """
    Build a Rich Table showing alerts in the order they fired.

    Args:
        alerts: List of alert dicts from the pipeline run or AlertStore.
        max_alerts: Maximum number of rows to render.

    Returns:
        A configured Rich Table.
    """
    table = Table(
        title="Alert Feed",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Time", style="dim", width=20)
    table.add_column("Rule", min_width=25)
    table.add_column("Severity", width=10)
    table.add_column("Computer", width=16)
    table.add_column("Technique", width=12)

    for alert in alerts[:max_alerts]:
        sev = alert.get("severity", "low").lower()
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            alert.get("timestamp", "")[:19],
            alert.get("rule_name", ""),
            f"[{color}]{sev.upper()}[/{color}]",
            alert.get("computer", ""),
            alert.get("mitre_technique", ""),
        )
    return table


def build_stats_panel(stats: dict) -> Panel:
    """
    Build the right-side statistics Panel with severity bars and top-rule counts.

    Args:
        stats: Aggregate stats dict from AlertStore.get_stats().

    Returns:
        A Rich Panel for the stats column.
    """
    severity_order = ["critical", "high", "medium", "low"]
    lines = []

    lines.append("[bold]Severity Breakdown[/bold]")
    lines.append("")

    total = stats.get("total", 1) or 1
    for sev in severity_order:
        count = stats.get("by_severity", {}).get(sev, 0)
        bar_len = int((count / total) * 20)
        bar = "█" * bar_len
        color = SEVERITY_COLORS.get(sev, "white")
        lines.append(f"[{color}]{sev.upper():8}[/{color}] [{color}]{bar:<20}[/{color}] {count}")

    lines.append("")
    lines.append("[bold]Top Rules[/bold]")
    lines.append("")

    by_rule = stats.get("by_rule", {})
    sorted_rules = sorted(by_rule.items(), key=lambda x: x[1]["count"], reverse=True)[:5]
    for rule_id, rule_data in sorted_rules:
        lines.append(
            f"[cyan]{rule_id}[/cyan]  {rule_data['name'][:28]}  [yellow]{rule_data['count']}[/yellow]"
        )

    return Panel("\n".join(lines), title="Detection Stats", border_style="blue")


def build_footer(db_path: str, last_event_time: str, rule_count: int) -> Panel:
    """
    Build the bottom-bar Panel showing database path, last event time, and rule count.

    Args:
        db_path: Path to the SQLite alert database file.
        last_event_time: ISO timestamp string from the most recent alert.
        rule_count: Number of detection rules currently loaded.

    Returns:
        A Rich Panel for the footer row.
    """
    footer_text = (
        f"DB: [dim]{db_path}[/dim]  |  "
        f"Last event: [dim]{last_event_time[:19]}[/dim]  |  "
        f"Rules loaded: [cyan]{rule_count}[/cyan]"
    )
    return Panel(footer_text, style="dim")


def _render_frame(
    alerts: list,
    stats: dict,
    events_processed: int,
    events_per_sec: float,
    db_path: str,
    rule_count: int,
    max_alerts: int,
):
    """
    Assemble a complete dashboard frame as a Rich renderable Group.

    Stacks header, side-by-side body (alert table + stats panel), and footer
    with no empty space between sections — content-driven height.

    Args:
        alerts: Current list of alert dicts to display.
        stats: Current aggregate stats dict.
        events_processed: Total events processed so far.
        events_per_sec: Current throughput metric.
        db_path: SQLite database path for the footer.
        rule_count: Number of loaded rules for the footer.
        max_alerts: Maximum alert rows to render.

    Returns:
        A Rich Group renderable.
    """
    from rich.console import Group

    last_event_time = alerts[0]["timestamp"] if alerts else ""

    header = build_header(stats, events_processed, events_per_sec)
    alert_table = build_alert_table(alerts, max_alerts)
    stats_panel = build_stats_panel(stats)
    body = Columns(
        [
            Panel(alert_table, border_style="dim", padding=(0, 1)),
            Panel(stats_panel, border_style="dim", padding=(0, 1), width=48),
        ],
        expand=True,
    )
    footer = build_footer(db_path, last_event_time, rule_count)

    return Group(header, body, footer)


def run_dashboard(
    alerts: list,
    stats: dict,
    events_processed: int,
    events_per_sec: float,
    db_path: str,
    rule_count: int,
    refresh_rate: float = 2.0,
    max_alerts: int = 50,
    live: bool = False,
    store=None,
):
    """
    Render the terminal dashboard in one-shot or live tailing mode.

    One-shot mode (live=False, default):
        Renders the provided alert list once and returns immediately.
        Used after a completed batch pipeline run on a static log file.

    Live mode (live=True):
        Enters a Rich Live context and polls AlertStore every refresh_rate
        seconds for new alerts. Runs until the user interrupts with Ctrl+C.
        Requires store to be a valid AlertStore instance.

    Args:
        alerts: Initial alert list (used in one-shot mode).
        stats: Initial stats dict (used in one-shot mode).
        events_processed: Total events evaluated during this run.
        events_per_sec: Pipeline throughput for the header display.
        db_path: SQLite database path shown in the footer.
        rule_count: Number of loaded rules shown in the footer.
        refresh_rate: Seconds between live refreshes (live mode only).
        max_alerts: Maximum alert rows to render in the table.
        live: When True, run in continuous tailing mode.
        store: AlertStore instance required for live mode polling.
    """
    if not live:
        frame = _render_frame(
            alerts, stats, events_processed, events_per_sec,
            db_path, rule_count, max_alerts,
        )
        console.print(frame)
        return

    if store is None:
        logger.warning("Live mode requires an AlertStore instance. Falling back to one-shot.")
        frame = _render_frame(
            alerts, stats, events_processed, events_per_sec,
            db_path, rule_count, max_alerts,
        )
        console.print(frame)
        return

    console.print("[dim]Live dashboard active — press Ctrl+C to exit[/dim]")

    try:
        with Live(console=console, refresh_per_second=1, screen=False) as live_ctx:
            while True:
                current_alerts = store.get_alerts()
                current_stats = store.get_stats()
                frame = _render_frame(
                    current_alerts, current_stats, events_processed, events_per_sec,
                    db_path, rule_count, max_alerts,
                )
                live_ctx.update(frame)
                time.sleep(refresh_rate)
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard closed.[/dim]")
