import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.correlator import correlate_alerts


def _make_alert(rule_id, tactic, computer, timestamp, severity="high"):
    return {
        "rule_id": rule_id,
        "rule_name": f"Test Rule {rule_id}",
        "severity": severity,
        "mitre_tactic": tactic,
        "mitre_technique": "T0000",
        "computer": computer,
        "timestamp": timestamp,
    }


def test_groups_alerts_on_same_host_within_window():
    """Two alerts on the same host within the time window form one incident."""
    alerts = [
        _make_alert("PROC-001", "Execution", "HOST-A", "2026-04-03T14:00:00+00:00"),
        _make_alert("PROC-002", "Execution", "HOST-A", "2026-04-03T14:00:30+00:00"),
    ]
    incidents = correlate_alerts(alerts, time_window_seconds=120, min_alerts=2)
    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 2


def test_separates_alerts_outside_window():
    """Alerts on the same host but beyond the time window are not grouped."""
    alerts = [
        _make_alert("PROC-001", "Execution", "HOST-A", "2026-04-03T14:00:00+00:00"),
        _make_alert("PROC-002", "Execution", "HOST-A", "2026-04-03T14:10:00+00:00"),
    ]
    # 10-minute gap against a 60-second window — must not group
    incidents = correlate_alerts(alerts, time_window_seconds=60, min_alerts=2)
    assert len(incidents) == 0


def test_separates_alerts_different_hosts():
    """Alerts on different hosts are never grouped together, regardless of timing."""
    alerts = [
        _make_alert("PROC-001", "Execution", "HOST-A", "2026-04-03T14:00:00+00:00"),
        _make_alert("PROC-002", "Execution", "HOST-B", "2026-04-03T14:00:05+00:00"),
    ]
    incidents = correlate_alerts(alerts, time_window_seconds=120, min_alerts=2)
    assert len(incidents) == 0


def test_min_alerts_threshold():
    """A single alert on a host never produces an incident when min_alerts=2."""
    alerts = [
        _make_alert("PROC-001", "Execution", "HOST-A", "2026-04-03T14:00:00+00:00"),
    ]
    incidents = correlate_alerts(alerts, time_window_seconds=120, min_alerts=2)
    assert len(incidents) == 0


def test_kill_chain_detection():
    """Execution + Persistence alerts on the same host trigger execution_to_persistence."""
    alerts = [
        _make_alert("PROC-001", "Execution", "HOST-A", "2026-04-03T14:00:00+00:00"),
        _make_alert("REG-001", "Persistence", "HOST-A", "2026-04-03T14:00:45+00:00"),
    ]
    incidents = correlate_alerts(alerts, time_window_seconds=120, min_alerts=2)
    assert len(incidents) == 1
    assert "execution_to_persistence" in incidents[0]["kill_chains"]


def test_incident_id_format():
    """Incident IDs follow the INC-NNN zero-padded format."""
    alerts = [
        _make_alert("PROC-001", "Execution", "HOST-A", "2026-04-03T14:00:00+00:00"),
        _make_alert("PROC-002", "Execution", "HOST-A", "2026-04-03T14:00:10+00:00"),
    ]
    incidents = correlate_alerts(alerts, time_window_seconds=120, min_alerts=2)
    assert incidents[0]["incident_id"].startswith("INC-")


def test_empty_alerts_returns_empty():
    """An empty alert list produces no incidents without raising."""
    incidents = correlate_alerts([], time_window_seconds=120, min_alerts=2)
    assert incidents == []


def test_incident_contains_expected_fields():
    """Each incident dict exposes all required keys for downstream consumers."""
    alerts = [
        _make_alert("PROC-001", "Execution", "HOST-A", "2026-04-03T14:00:00+00:00"),
        _make_alert("REG-001", "Persistence", "HOST-A", "2026-04-03T14:01:00+00:00"),
    ]
    incidents = correlate_alerts(alerts, time_window_seconds=120, min_alerts=2)
    inc = incidents[0]
    for key in ("incident_id", "computer", "alerts", "tactics", "techniques",
                "first_seen", "last_seen", "duration_seconds", "kill_chains", "alert_count"):
        assert key in inc, f"Missing key: {key}"


def test_multiple_hosts_produce_separate_incidents():
    """Alerts on two distinct hosts within the same window produce two incidents."""
    alerts = [
        _make_alert("PROC-001", "Execution", "HOST-A", "2026-04-03T14:00:00+00:00"),
        _make_alert("PROC-002", "Execution", "HOST-A", "2026-04-03T14:00:10+00:00"),
        _make_alert("PROC-001", "Execution", "HOST-B", "2026-04-03T14:00:00+00:00"),
        _make_alert("PROC-002", "Persistence", "HOST-B", "2026-04-03T14:00:20+00:00"),
    ]
    incidents = correlate_alerts(alerts, time_window_seconds=120, min_alerts=2)
    assert len(incidents) == 2
    computers = {inc["computer"] for inc in incidents}
    assert computers == {"HOST-A", "HOST-B"}
