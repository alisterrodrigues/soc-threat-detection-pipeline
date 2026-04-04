import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.alert_store import AlertStore


SAMPLE_ALERT = {
    "timestamp": "2026-04-03T14:22:10Z",
    "rule_id": "PROC-001",
    "rule_name": "Suspicious PowerShell Encoded Command",
    "severity": "high",
    "mitre_technique": "T1059.001",
    "mitre_tactic": "Execution",
    "computer": "WORKSTATION-01",
    "event_id": 1,
    "matched_fields": json.dumps({"Image": "powershell.exe", "CommandLine": "-EncodedCommand"}),
    "raw_event": json.dumps({"EventID": 1, "Image": "powershell.exe"}),
}


def test_store_and_retrieve(tmp_path):
    """An alert stored via store_alert is retrievable with the correct rule_id."""
    db_path = str(tmp_path / "test_alerts.db")
    store = AlertStore(db_path)
    row_id = store.store_alert(SAMPLE_ALERT)
    assert row_id is not None
    alerts = store.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "PROC-001"


def test_filter_by_severity(tmp_path):
    """get_alerts with a severity filter returns only alerts of that severity."""
    db_path = str(tmp_path / "test_alerts.db")
    store = AlertStore(db_path)
    store.store_alert(SAMPLE_ALERT)

    low_alert = dict(SAMPLE_ALERT)
    low_alert["rule_id"] = "PROC-004"
    low_alert["severity"] = "low"
    store.store_alert(low_alert)

    high_alerts = store.get_alerts(severity="high")
    assert len(high_alerts) == 1
    assert high_alerts[0]["severity"] == "high"


def test_mark_disposition(tmp_path):
    """mark_disposition persists analyst verdict and notes on the correct alert row."""
    db_path = str(tmp_path / "test_alerts.db")
    store = AlertStore(db_path)
    row_id = store.store_alert(SAMPLE_ALERT)
    success = store.mark_disposition(row_id, "false_positive", notes="Legitimate admin script")
    assert success
    alerts = store.get_alerts()
    assert alerts[0]["analyst_disposition"] == "false_positive"
    assert alerts[0]["notes"] == "Legitimate admin script"


def test_get_stats(tmp_path):
    """get_stats returns accurate totals broken down by severity and rule_id."""
    db_path = str(tmp_path / "test_alerts.db")
    store = AlertStore(db_path)
    store.store_alert(SAMPLE_ALERT)
    stats = store.get_stats()
    assert stats["total"] == 1
    assert stats["by_severity"].get("high") == 1
    assert "PROC-001" in stats["by_rule"]


def test_invalid_disposition(tmp_path):
    """mark_disposition rejects any value outside the allowed disposition set."""
    db_path = str(tmp_path / "test_alerts.db")
    store = AlertStore(db_path)
    row_id = store.store_alert(SAMPLE_ALERT)
    result = store.mark_disposition(row_id, "maybe")
    assert result is False
