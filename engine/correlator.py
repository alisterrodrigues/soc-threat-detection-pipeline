"""
Alert correlator — groups individual alerts into incidents based on
host identity and temporal proximity, then annotates each incident
with the MITRE ATT&CK tactics covered and the implied kill chain.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Known high-value kill chain sequences. Each entry is an ordered list of
# MITRE tactics. An incident that covers all tactics in a sequence (in any
# order) is flagged with that chain name.
KNOWN_CHAINS = {
    "macro_to_c2": ["Execution", "Command and Control"],
    "execution_to_persistence": ["Execution", "Persistence"],
    "execution_to_credential_access": ["Execution", "Credential Access"],
    "defense_evasion_and_privilege_escalation": ["Defense Evasion", "Privilege Escalation"],
    "full_compromise_chain": ["Execution", "Persistence", "Defense Evasion", "Credential Access"],
}


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """
    Parse an ISO 8601 timestamp string into a timezone-aware datetime.

    Handles both trailing 'Z' and '+00:00' offset formats. Returns None
    and logs a warning if the string is empty or cannot be parsed, so
    callers can decide how to handle the gap gracefully.

    Args:
        ts: ISO 8601 timestamp string, e.g. '2026-04-03T14:22:10.123Z'.

    Returns:
        A timezone-aware datetime, or None on parse failure.
    """
    if not ts:
        return None
    try:
        # Normalize trailing Z to +00:00 so fromisoformat works on all Python versions
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to parse timestamp '{ts}': {e}")
        return None


def correlate_alerts(
    alerts: list[dict],
    time_window_seconds: int = 120,
    min_alerts: int = 2,
) -> list[dict]:
    """
    Group alerts into incidents by host and time window.

    Algorithm:
      1. Sort alerts by (computer, timestamp).
      2. Walk the sorted list. Start a new group when the computer changes
         or the gap to the previous alert exceeds time_window_seconds.
      3. Only emit groups with at least min_alerts members as incidents.

    Each incident is annotated with unique MITRE tactics and techniques,
    a duration, and any matching kill chain patterns from KNOWN_CHAINS.

    Args:
        alerts: List of alert dicts from the pipeline run.
        time_window_seconds: Max seconds between consecutive alerts on the
                             same host for them to be considered related.
        min_alerts: Minimum group size required to emit an incident.

    Returns:
        List of incident dicts. Each incident contains:
          - incident_id: str  (e.g. "INC-001")
          - computer: str
          - alerts: list[dict]  (the member alerts)
          - tactics: list[str]  (unique MITRE tactics covered, insertion-ordered)
          - techniques: list[str]  (unique MITRE techniques covered)
          - first_seen: str  (ISO timestamp of earliest alert)
          - last_seen: str   (ISO timestamp of latest alert)
          - duration_seconds: int
          - kill_chains: list[str]  (matched KNOWN_CHAINS keys)
          - alert_count: int
    """
    if not alerts:
        return []

    def sort_key(a: dict):
        ts = _parse_timestamp(a.get("timestamp", ""))
        return (a.get("computer", ""), ts or datetime.min.replace(tzinfo=timezone.utc))

    sorted_alerts = sorted(alerts, key=sort_key)

    groups: list[list[dict]] = []
    current_group = [sorted_alerts[0]]

    for alert in sorted_alerts[1:]:
        prev = current_group[-1]
        same_host = alert.get("computer") == prev.get("computer")

        if same_host:
            prev_ts = _parse_timestamp(prev.get("timestamp", ""))
            curr_ts = _parse_timestamp(alert.get("timestamp", ""))
            if prev_ts and curr_ts:
                gap = abs((curr_ts - prev_ts).total_seconds())
                in_window = gap <= time_window_seconds
            else:
                # Can't determine the gap — keep together conservatively
                in_window = True
        else:
            in_window = False

        if same_host and in_window:
            current_group.append(alert)
        else:
            groups.append(current_group)
            current_group = [alert]

    groups.append(current_group)

    incidents = []
    for i, group in enumerate(groups):
        if len(group) < min_alerts:
            continue

        # dict.fromkeys preserves insertion order while deduplicating
        tactics = list(dict.fromkeys(
            a.get("mitre_tactic", "") for a in group if a.get("mitre_tactic")
        ))
        techniques = list(dict.fromkeys(
            a.get("mitre_technique", "") for a in group if a.get("mitre_technique")
        ))

        timestamps = [_parse_timestamp(a.get("timestamp", "")) for a in group]
        timestamps = [t for t in timestamps if t is not None]
        first_seen = min(timestamps).isoformat() if timestamps else ""
        last_seen = max(timestamps).isoformat() if timestamps else ""
        duration = (
            int((max(timestamps) - min(timestamps)).total_seconds())
            if len(timestamps) > 1
            else 0
        )

        tactic_set = set(tactics)
        matched_chains = [
            name for name, required in KNOWN_CHAINS.items()
            if all(t in tactic_set for t in required)
        ]

        incidents.append({
            "incident_id": f"INC-{i + 1:03d}",
            "computer": group[0].get("computer", ""),
            "alerts": group,
            "tactics": tactics,
            "techniques": techniques,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_seconds": duration,
            "kill_chains": matched_chains,
            "alert_count": len(group),
        })

    logger.info(f"Correlation complete: {len(alerts)} alerts → {len(incidents)} incidents")
    return incidents
