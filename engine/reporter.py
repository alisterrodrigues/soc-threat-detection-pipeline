"""
HTML incident report generator.

Produces a self-contained single-file HTML report from correlated incidents
and their constituent alerts. All CSS and JavaScript are inlined — the output
file has no external dependencies and can be opened directly in any browser.

Typical usage:
    from engine.reporter import generate_html_report
    generate_html_report(incidents, alerts, stats, output_path)
"""

import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#06b6d4",
}

TACTIC_COLORS = {
    "Execution":              "#8b5cf6",
    "Persistence":            "#ec4899",
    "Privilege Escalation":   "#f43f5e",
    "Defense Evasion":        "#f97316",
    "Credential Access":      "#ef4444",
    "Discovery":              "#06b6d4",
    "Lateral Movement":       "#10b981",
    "Command and Control":    "#3b82f6",
    "Exfiltration":           "#a855f7",
    "Impact":                 "#64748b",
}


def _e(value) -> str:
    """HTML-escape a value for safe inline insertion into HTML attributes and text."""
    return html.escape(str(value), quote=True)


def _short_ts(ts: str) -> str:
    """
    Return only the time portion of an ISO timestamp for compact table display.

    Input:  '2026-04-03T14:22:10'
    Output: '14:22:10'

    Keeps table timestamp columns narrow while preserving enough precision
    for analysts to read event sequencing within a single-day incident.
    """
    clean = ts[:19].replace("T", " ")
    parts = clean.split(" ")
    return parts[1] if len(parts) == 2 else clean


def _sev_color(severity: str) -> str:
    """Return the hex color for a given severity string."""
    return SEVERITY_COLORS.get(severity.lower(), "#64748b")


def _tactic_color(tactic: str) -> str:
    """Return the hex color for a given MITRE tactic string."""
    return TACTIC_COLORS.get(tactic, "#64748b")


def _now_utc() -> str:
    """Return the current UTC time as a human-readable string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _render_incident_card(incident: dict) -> str:
    """
    Render a single incident as a self-contained HTML card section.

    Includes the incident header, metadata grid, ATT&CK tactic pills,
    kill chain badges, and a full alert timeline table. All user-controlled
    values are HTML-escaped before insertion.

    Args:
        incident: Incident dict from score_incidents().

    Returns:
        HTML string for the incident card.
    """
    inc_id = _e(incident.get("incident_id", "INC-???"))
    score = incident.get("risk_score", 0)
    computer = _e(incident.get("computer", "Unknown"))
    duration = incident.get("duration_seconds", 0)
    alert_count = incident.get("alert_count", 0)
    tactics = incident.get("tactics", [])
    kill_chains = incident.get("kill_chains", [])
    first_seen = _e(_short_ts(incident.get("first_seen", "")))
    last_seen = _e(_short_ts(incident.get("last_seen", "")))

    if score >= 80:
        score_color = "#ef4444"
    elif score >= 60:
        score_color = "#f97316"
    elif score >= 40:
        score_color = "#eab308"
    else:
        score_color = "#06b6d4"

    tactic_pills = "".join(
        f'<span class="pill" style="background:{_tactic_color(t)}">{_e(t)}</span>'
        for t in tactics
    )

    chain_badges = "".join(
        f'<span class="chain-badge">{_e(c.replace("_", " "))}</span>'
        for c in kill_chains
    ) or '<span style="color:#64748b;font-size:0.85em">none detected</span>'

    alert_rows = ""
    for a in incident.get("alerts", []):
        sev = a.get("severity", "low")
        color = _sev_color(sev)
        ts = _e(_short_ts(a.get("timestamp", "")))
        rule_id = _e(a.get("rule_id", ""))
        rule_name = _e(a.get("rule_name", ""))
        technique = _e(a.get("mitre_technique", ""))
        try:
            matched = json.loads(a.get("matched_fields", "{}"))
            fields_text = _e(" | ".join(f"{k}: {str(v)[:60]}" for k, v in matched.items()))
        except Exception:
            fields_text = ""
        alert_rows += f"""
        <tr>
          <td class="mono ts-col">{ts}</td>
          <td class="ruleid-col"><code>{rule_id}</code></td>
          <td>{rule_name}</td>
          <td><span class="sev-badge" style="background:{color}">{_e(sev.upper())}</span></td>
          <td class="mono" style="font-size:0.8em;color:#94a3b8">{technique}</td>
          <td style="font-size:0.82em;color:#cbd5e1">{fields_text}</td>
        </tr>"""

    return f"""
    <div class="incident-card">
      <div class="incident-header">
        <div>
          <span class="incident-id">{inc_id}</span>
          <span class="host-tag">{computer}</span>
        </div>
        <div class="score-badge" style="background:{score_color}">{score}<span class="score-denom">/100</span></div>
      </div>

      <div class="meta-grid">
        <div class="meta-item"><div class="meta-label">Alerts</div><div class="meta-value">{alert_count}</div></div>
        <div class="meta-item"><div class="meta-label">Duration</div><div class="meta-value">{duration}s</div></div>
        <div class="meta-item"><div class="meta-label">First Seen</div><div class="meta-value mono">{first_seen}</div></div>
        <div class="meta-item"><div class="meta-label">Last Seen</div><div class="meta-value mono">{last_seen}</div></div>
      </div>

      <div class="section-label">ATT&amp;CK Tactics</div>
      <div class="pill-row">{tactic_pills}</div>

      <div class="section-label" style="margin-top:12px">Kill Chains</div>
      <div class="pill-row">{chain_badges}</div>

      <div class="section-label" style="margin-top:16px">Alert Timeline</div>
      <div class="table-wrap">
        <table class="alert-table">
          <thead>
            <tr>
              <th class="ts-col">Time</th>
              <th class="ruleid-col">Rule ID</th>
              <th>Rule Name</th>
              <th>Severity</th>
              <th>Technique</th>
              <th>Matched Fields</th>
            </tr>
          </thead>
          <tbody>{alert_rows}</tbody>
        </table>
      </div>
    </div>"""


def _render_summary_bar(stats: dict, incident_count: int) -> str:
    """
    Render the top-level run-summary stats bar.

    Args:
        stats: Aggregate stats dict from AlertStore.get_stats().
        incident_count: Number of correlated incidents in this run.

    Returns:
        HTML string for the summary bar section.
    """
    total = stats.get("total", 0)
    by_sev = stats.get("by_severity", {})
    critical = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)
    medium = by_sev.get("medium", 0)
    low = by_sev.get("low", 0)

    return f"""
    <div class="summary-bar">
      <div class="stat-box"><div class="stat-num">{total}</div><div class="stat-label">Total Alerts</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#ef4444">{critical}</div><div class="stat-label">Critical</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#f97316">{high}</div><div class="stat-label">High</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#eab308">{medium}</div><div class="stat-label">Medium</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#06b6d4">{low}</div><div class="stat-label">Low</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#8b5cf6">{incident_count}</div><div class="stat-label">Incidents</div></div>
    </div>"""


def generate_html_report(
    incidents: list[dict],
    all_alerts: list[dict],
    stats: dict,
    output_path: str,
    title: str = "SOC Threat Detection \u2014 Incident Report",
) -> str:
    """
    Generate a self-contained HTML incident report and write it to disk.

    The report includes: a summary stats bar, per-incident cards with alert
    timelines and ATT&CK tactic coverage, and a full flat alert table at the
    bottom. All styling is inlined — no external dependencies. All user-
    controlled field values are HTML-escaped before insertion.

    Args:
        incidents: List of incident dicts from score_incidents().
        all_alerts: Complete list of alert dicts from the pipeline run.
        stats: Aggregate stats dict from AlertStore.get_stats().
        output_path: File path to write the HTML output to.
        title: Report title shown in the browser tab and page header.

    Returns:
        The output_path string (for logging by the caller).
    """
    generated_at = _now_utc()
    incident_cards = "\n".join(_render_incident_card(inc) for inc in incidents)
    summary_bar = _render_summary_bar(stats, len(incidents))

    flat_rows = ""
    for a in all_alerts:
        sev = a.get("severity", "low")
        color = _sev_color(sev)
        ts = _e(_short_ts(a.get("timestamp", "")))
        rule_id = _e(a.get("rule_id", ""))
        rule_name = _e(a.get("rule_name", ""))
        technique = _e(a.get("mitre_technique", ""))
        tactic = _e(a.get("mitre_tactic", ""))
        computer = _e(a.get("computer", ""))
        flat_rows += f"""
        <tr>
          <td class="mono ts-col">{ts}</td>
          <td class="ruleid-col"><code>{rule_id}</code></td>
          <td>{rule_name}</td>
          <td><span class="sev-badge" style="background:{color}">{_e(sev.upper())}</span></td>
          <td class="mono" style="font-size:0.82em">{technique}</td>
          <td style="font-size:0.82em">{tactic}</td>
          <td style="font-size:0.82em">{computer}</td>
        </tr>"""

    no_incidents_msg = ""
    if not incidents:
        no_incidents_msg = (
            '<p style="color:#64748b;text-align:center;padding:40px">'
            "No correlated incidents detected in this run.</p>"
        )

    html_title = _e(title)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html_title}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 0;
    }}
    .topbar {{
      background: #1e293b; border-bottom: 1px solid #334155;
      padding: 18px 32px; display: flex; align-items: center; gap: 16px;
    }}
    .topbar-title {{ font-size: 1.2em; font-weight: 700; color: #f8fafc; letter-spacing: -0.02em; }}
    .topbar-sub {{ font-size: 0.82em; color: #64748b; margin-left: auto; }}
    .container {{ max-width: 1280px; margin: 0 auto; padding: 32px 24px; }}
    .section-heading {{
      font-size: 0.75em; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.08em; color: #64748b; margin-bottom: 16px; margin-top: 36px;
    }}
    .summary-bar {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; }}
    .stat-box {{
      background: #1e293b; border: 1px solid #334155; border-radius: 10px;
      padding: 16px 24px; flex: 1; min-width: 100px; text-align: center;
    }}
    .stat-num {{ font-size: 2em; font-weight: 700; line-height: 1; color: #f8fafc; }}
    .stat-label {{ font-size: 0.75em; color: #64748b; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}
    .incident-card {{
      background: #1e293b; border: 1px solid #334155; border-radius: 12px;
      padding: 24px; margin-bottom: 20px;
    }}
    .incident-header {{
      display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;
    }}
    .incident-id {{ font-size: 1.1em; font-weight: 700; color: #f8fafc; margin-right: 12px; }}
    .host-tag {{
      background: #0f172a; border: 1px solid #334155; border-radius: 6px;
      padding: 3px 10px; font-size: 0.82em; color: #94a3b8; font-family: monospace;
    }}
    .score-badge {{
      font-size: 1.3em; font-weight: 800; border-radius: 50%; width: 72px; height: 72px;
      display: flex; align-items: center; justify-content: center; color: white;
      flex-shrink: 0; letter-spacing: -0.03em; flex-direction: column;
    }}
    .score-denom {{ font-size: 0.45em; opacity: 0.7; margin-top: 1px; }}
    .meta-grid {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }}
    .meta-item {{
      background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 10px 16px;
    }}
    .meta-label {{ font-size: 0.7em; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
    .meta-value {{ font-size: 0.95em; font-weight: 600; color: #f1f5f9; margin-top: 2px; }}
    .section-label {{ font-size: 0.72em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.07em; color: #475569; margin-bottom: 8px; }}
    .pill-row {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .pill {{ border-radius: 20px; padding: 4px 12px; font-size: 0.78em; font-weight: 600; color: white; opacity: 0.9; }}
    .chain-badge {{
      background: #1e3a5f; border: 1px solid #1d4ed8; border-radius: 6px;
      padding: 3px 10px; font-size: 0.78em; color: #93c5fd; text-transform: capitalize;
    }}
    .table-wrap {{ overflow-x: auto; margin-top: 8px; border-radius: 8px; border: 1px solid #334155; }}
    .alert-table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
    .alert-table thead {{ background: #0f172a; }}
    .alert-table th {{
      padding: 10px 14px; text-align: left; font-size: 0.72em; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.06em; color: #64748b; white-space: nowrap;
    }}
    .alert-table tbody tr {{ border-top: 1px solid #1e293b; }}
    .alert-table tbody tr:hover {{ background: #162032; }}
    .alert-table td {{ padding: 9px 14px; vertical-align: top; color: #cbd5e1; }}
    .ts-col    {{ width: 72px; min-width: 72px; white-space: nowrap; }}
    .ruleid-col {{ width: 90px; min-width: 90px; white-space: nowrap; }}
    .sev-badge {{ border-radius: 4px; padding: 2px 8px; font-size: 0.75em; font-weight: 700; color: white; white-space: nowrap; }}
    .mono {{ font-family: "SF Mono", "Fira Code", "Consolas", monospace; }}
    code {{ background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 1px 6px; font-size: 0.88em; color: #7dd3fc; white-space: nowrap; }}
    .flat-section {{ margin-top: 48px; }}
  </style>
</head>
<body>
  <div class="topbar">
    <div><div class="topbar-title">&#9889; {html_title}</div></div>
    <div class="topbar-sub">Generated {generated_at}</div>
  </div>

  <div class="container">
    <div class="section-heading">Run Summary</div>
    {summary_bar}

    <div class="section-heading" style="margin-top:36px">Correlated Incidents</div>
    {incident_cards}
    {no_incidents_msg}

    <div class="flat-section">
      <div class="section-heading">All Alerts</div>
      <div class="table-wrap">
        <table class="alert-table">
          <thead>
            <tr>
              <th class="ts-col">Time</th>
              <th class="ruleid-col">Rule ID</th>
              <th>Rule Name</th>
              <th>Severity</th>
              <th>Technique</th>
              <th>Tactic</th>
              <th>Host</th>
            </tr>
          </thead>
          <tbody>{flat_rows}</tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>"""

    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"HTML report written to {output_path}")
    except OSError as e:
        logger.warning(f"Failed to write HTML report to {output_path}: {e}")

    return output_path
