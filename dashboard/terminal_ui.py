import logging

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "cyan",
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
        A Rich Panel suitable for placement in the 'header' Layout region.
    """
    header_text = (
        f"[bold]SOC Threat Detection Pipeline[/bold]  |  "
        f"Events: [green]{events_processed:,}[/green]  |  "
        f"Alerts: [red]{stats.get('total', 0)}[/red]  |  "
        f"Throughput: [cyan]{events_per_sec:.0f} evt/s[/cyan]"
    )
    return Panel(header_text, style="bold white on dark_blue")


def build_alert_table(alerts: list[dict], max_alerts: int = 50) -> Table:
    """
    Build a Rich Table showing the most recent alerts in reverse-chronological order.

    Columns: Time, Rule, Severity (color-coded), Computer, MITRE Technique.
    Truncated to max_alerts rows so the terminal doesn't overflow.

    Args:
        alerts: List of alert dicts from AlertStore.get_alerts().
        max_alerts: Maximum number of rows to render.

    Returns:
        A configured Rich Table ready to be inserted into a Layout.
    """
    table = Table(
        title="Live Alert Feed",
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

    Renders a simple ASCII bar chart for severity breakdown and a ranked list
    of the five most frequently firing rules.

    Args:
        stats: Aggregate stats dict from AlertStore.get_stats().

    Returns:
        A Rich Panel suitable for the 'stats' Layout region.
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
            f"[cyan]{rule_id}[/cyan]  {rule_data['name'][:30]}  [yellow]{rule_data['count']}[/yellow]"
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
        A Rich Panel suitable for the 'footer' Layout region.
    """
    footer_text = (
        f"DB: [dim]{db_path}[/dim]  |  "
        f"Last event: [dim]{last_event_time[:19]}[/dim]  |  "
        f"Rules loaded: [cyan]{rule_count}[/cyan]"
    )
    return Panel(footer_text, style="dim")


def run_dashboard(
    alerts: list[dict],
    stats: dict,
    events_processed: int,
    events_per_sec: float,
    db_path: str,
    rule_count: int,
    refresh_rate: float = 2.0,
    max_alerts: int = 50,
):
    """
    Render a complete terminal dashboard layout and print it to stdout.

    Constructs a three-region Layout (header / body / footer) where the body
    is split into an alert table (2/3 width) and a stats panel (1/3 width).
    This is a one-shot render — for continuous live updates, wrap repeated
    calls in a Rich Live context outside this function.

    Args:
        alerts: List of alert dicts to display in the table.
        stats: Aggregate stats dict from AlertStore.get_stats().
        events_processed: Total events evaluated in this pipeline run.
        events_per_sec: Pipeline throughput for the header metric.
        db_path: SQLite database path shown in the footer.
        rule_count: Number of loaded rules shown in the footer.
        refresh_rate: Retained for API compatibility; unused in one-shot mode.
        max_alerts: Maximum number of alert rows to render in the table.
    """
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="alerts", ratio=2),
        Layout(name="stats", ratio=1),
    )

    last_event_time = alerts[0]["timestamp"] if alerts else ""

    layout["header"].update(build_header(stats, events_processed, events_per_sec))
    layout["body"]["alerts"].update(build_alert_table(alerts, max_alerts))
    layout["body"]["stats"].update(build_stats_panel(stats))
    layout["footer"].update(build_footer(db_path, last_event_time, rule_count))

    console.print(layout)
