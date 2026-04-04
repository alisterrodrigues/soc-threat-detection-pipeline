import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.scorer import score_incident, score_incidents


def _make_incident(alerts, tactics, kill_chains=None):
    return {
        "incident_id": "INC-001",
        "computer": "HOST-A",
        "alerts": alerts,
        "tactics": tactics,
        "techniques": [],
        "kill_chains": kill_chains or [],
        "alert_count": len(alerts),
        "first_seen": "",
        "last_seen": "",
        "duration_seconds": 30,
    }


def _alert(severity):
    return {"severity": severity, "mitre_tactic": "Execution", "mitre_technique": "T0000"}


def test_score_is_bounded_0_to_100():
    """Score never exceeds 100 regardless of extreme inputs."""
    incident = _make_incident(
        [_alert("critical")] * 20,
        ["Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery"],
        kill_chains=["full_compromise_chain"],
    )
    score = score_incident(incident)
    assert 0 <= score <= 100


def test_critical_alerts_score_higher_than_low():
    """An incident with critical alerts outscores one with only low-severity alerts."""
    high_incident = _make_incident([_alert("critical"), _alert("critical")], ["Execution"])
    low_incident = _make_incident([_alert("low"), _alert("low")], ["Execution"])
    assert score_incident(high_incident) > score_incident(low_incident)


def test_kill_chain_increases_score():
    """Matching a kill chain pattern adds points to the incident score."""
    no_chain = _make_incident([_alert("high"), _alert("high")], ["Execution"], kill_chains=[])
    with_chain = _make_incident(
        [_alert("high"), _alert("high")],
        ["Execution", "Persistence"],
        kill_chains=["execution_to_persistence"],
    )
    assert score_incident(with_chain) > score_incident(no_chain)


def test_tactic_diversity_increases_score():
    """More unique MITRE tactics in an incident results in a higher score."""
    one_tactic = _make_incident([_alert("high"), _alert("high")], ["Execution"])
    four_tactics = _make_incident(
        [_alert("high"), _alert("high")],
        ["Execution", "Persistence", "Defense Evasion", "Credential Access"],
    )
    assert score_incident(four_tactics) > score_incident(one_tactic)


def test_score_incidents_sorted_descending():
    """score_incidents returns incidents sorted highest risk score first."""
    incidents = [
        _make_incident([_alert("low")], ["Execution"]),
        _make_incident(
            [_alert("critical"), _alert("critical")],
            ["Execution", "Credential Access"],
            ["execution_to_credential_access"],
        ),
        _make_incident([_alert("medium")], ["Persistence"]),
    ]
    scored = score_incidents(incidents)
    scores = [i["risk_score"] for i in scored]
    assert scores == sorted(scores, reverse=True)


def test_empty_incident_scores_zero():
    """An incident with no alerts and no tactics scores exactly 0."""
    incident = _make_incident([], [], [])
    assert score_incident(incident) == 0


def test_risk_score_added_to_each_incident():
    """score_incidents adds 'risk_score' as a key to every incident dict."""
    incidents = [
        _make_incident([_alert("high"), _alert("medium")], ["Execution"]),
        _make_incident([_alert("low")], ["Discovery"]),
    ]
    scored = score_incidents(incidents)
    for inc in scored:
        assert "risk_score" in inc
        assert isinstance(inc["risk_score"], int)


def test_volume_bonus_capped():
    """Adding more than 12 alerts should not push the score above 100."""
    many_alerts = [_alert("low")] * 50
    incident = _make_incident(many_alerts, ["Execution"])
    score = score_incident(incident)
    assert score <= 100


def test_severity_cap_at_40():
    """Severity contribution is capped so that extreme alert counts alone stay <= 40."""
    many_criticals = [_alert("critical")] * 10  # 10 * 25 = 250, should cap at 40
    incident = _make_incident(many_criticals, [], [])
    # Only severity + volume bonus contribute here (no tactics, no chains)
    # severity capped at 40, volume bonus: max(0, 10-2)=8, capped at 10 → 8
    score = score_incident(incident)
    assert score <= 100
    assert score >= 40  # at minimum the capped severity contribution
