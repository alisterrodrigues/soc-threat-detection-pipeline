"""
Risk scorer — assigns a 0–100 risk score to correlated incidents.

Scoring weights:
  - Severity of member alerts: critical=25, high=15, medium=8, low=3 (capped at 40)
  - Tactic diversity: 5 points per unique MITRE tactic (capped at 30)
  - Kill chain match: +20 per matched chain (capped at 20)
  - Alert volume bonus: +1 per alert beyond the first two (capped at 10)

Score is clamped to [0, 100].
"""

import logging

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


def score_incident(incident: dict) -> int:
    """
    Compute a 0–100 risk score for a single incident.

    Combines four independent components — alert severity, tactic diversity,
    kill chain presence, and raw alert volume — each capped individually so
    no single dimension can dominate the total score.

    Args:
        incident: Incident dict produced by correlator.correlate_alerts().

    Returns:
        Integer risk score between 0 and 100 inclusive.
    """
    score = 0

    try:
        alerts = incident.get("alerts", [])

        # Severity contribution — sum per-alert weights, cap at 40
        sev_score = 0
        for alert in alerts:
            sev = alert.get("severity", "low").lower()
            sev_score += SEVERITY_WEIGHTS.get(sev, 0)
        score += min(sev_score, 40)

        # Tactic diversity — 5 points per unique tactic, cap at 30
        tactic_count = len(set(incident.get("tactics", [])))
        score += min(tactic_count * 5, 30)

        # Kill chain bonus — 20 per matched chain, cap at 20
        chain_count = len(incident.get("kill_chains", []))
        score += min(chain_count * 20, 20)

        # Volume bonus — 1 per alert beyond the first two, cap at 10
        volume_bonus = max(0, incident.get("alert_count", 0) - 2)
        score += min(volume_bonus, 10)

    except Exception as e:
        logger.warning(f"Scoring failed for incident {incident.get('incident_id')}: {e}")

    return min(max(score, 0), 100)


def score_incidents(incidents: list[dict]) -> list[dict]:
    """
    Score all incidents and return them sorted by risk score descending.

    Adds a 'risk_score' key to each incident dict in place so downstream
    consumers (CLI printer, dashboard) can access the score without an
    additional lookup step.

    Args:
        incidents: List of incident dicts from correlate_alerts().

    Returns:
        The same list with 'risk_score' added to each item, sorted highest-first.
    """
    for incident in incidents:
        incident["risk_score"] = score_incident(incident)

    incidents.sort(key=lambda x: x["risk_score"], reverse=True)
    logger.info(
        f"Scored {len(incidents)} incidents. "
        f"Top score: {incidents[0]['risk_score'] if incidents else 'N/A'}"
    )
    return incidents
