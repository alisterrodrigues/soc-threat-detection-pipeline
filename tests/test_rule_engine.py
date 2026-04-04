import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.rule_engine import _apply_operator, evaluate_event, load_rules


# ---------------------------------------------------------------------------
# Operator unit tests
# ---------------------------------------------------------------------------

def test_contains_operator():
    """'contains' returns True when the substring is present."""
    assert _apply_operator("powershell.exe", "powershell", "contains", True)
    assert not _apply_operator("cmd.exe", "powershell", "contains", True)


def test_not_contains_operator():
    """'not_contains' returns True when the substring is absent."""
    assert _apply_operator("cmd.exe", "powershell", "not_contains", True)
    assert not _apply_operator("powershell.exe", "powershell", "not_contains", True)


def test_equals_operator():
    """'equals' returns True only on an exact match (including empty strings)."""
    assert _apply_operator("", "", "equals", False)
    assert not _apply_operator("lsass.exe", "", "equals", False)


def test_endswith_operator():
    """'endswith' matches the trailing suffix of the event value."""
    assert _apply_operator("C:\\Windows\\System32\\whoami.exe", "whoami.exe", "endswith", True)
    assert not _apply_operator("C:\\Windows\\System32\\cmd.exe", "whoami.exe", "endswith", True)


def test_startswith_operator():
    """'startswith' matches the leading prefix of the event value."""
    assert _apply_operator("powershell.exe -EncodedCommand", "powershell", "startswith", True)


# ---------------------------------------------------------------------------
# Rule-level evaluation tests
# ---------------------------------------------------------------------------

PROC_001_RULE = {
    "id": "PROC-001",
    "name": "Suspicious PowerShell Encoded Command",
    "severity": "high",
    "mitre_technique": "T1059.001",
    "mitre_tactic": "Execution",
    "event_id": 1,
    "conditions": [
        {"field": "Image", "operator": "contains", "value": "powershell.exe", "case_insensitive": True},
        {"field": "CommandLine", "operator": "contains", "value": "-EncodedCommand", "case_insensitive": True},
    ],
    "logic": "AND",
}

REG_001_RULE = {
    "id": "REG-001",
    "name": "Run Key Persistence",
    "severity": "high",
    "mitre_technique": "T1547.001",
    "mitre_tactic": "Persistence",
    "event_id": 13,
    "conditions": [
        {
            "field": "TargetObject",
            "operator": "contains",
            "value": "\\CurrentVersion\\Run",
            "case_insensitive": True,
        },
    ],
    "logic": "AND",
}


def test_proc001_fires_on_match():
    """PROC-001 fires when both Image and CommandLine conditions are satisfied."""
    event = {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand dABlAHMAdA==",
        "Timestamp": "2026-04-03T14:00:00Z",
        "Computer": "WORKSTATION-01",
    }
    alerts = evaluate_event(event, [PROC_001_RULE])
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "PROC-001"


def test_proc001_no_fire_on_mismatch():
    """PROC-001 does not fire when the Image field does not match."""
    event = {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c dir",
        "Timestamp": "2026-04-03T14:00:00Z",
        "Computer": "WORKSTATION-01",
    }
    alerts = evaluate_event(event, [PROC_001_RULE])
    assert len(alerts) == 0


def test_reg001_fires_on_match():
    """REG-001 fires when TargetObject contains the Run key path."""
    event = {
        "EventID": 13,
        "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
        "Timestamp": "2026-04-03T14:00:00Z",
        "Computer": "WORKSTATION-01",
    }
    alerts = evaluate_event(event, [REG_001_RULE])
    assert len(alerts) == 1


def test_wrong_event_id_no_match():
    """Rules are skipped entirely when the event EventID does not match rule event_id."""
    event = {
        "EventID": 3,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand dABlAHMAdA==",
    }
    alerts = evaluate_event(event, [PROC_001_RULE])
    assert len(alerts) == 0


def test_load_rules_from_dir(tmp_path):
    """load_rules reads all YAML rule files from a directory and returns a flat list."""
    rule_content = """
rules:
  - id: "TEST-001"
    name: "Test Rule"
    severity: "low"
    mitre_technique: "T0000"
    mitre_tactic: "Test"
    event_id: 1
    conditions:
      - field: "Image"
        operator: contains
        value: "test.exe"
        case_insensitive: true
    logic: AND
"""
    rule_file = tmp_path / "test_rules.yaml"
    rule_file.write_text(rule_content)
    rules = load_rules(str(tmp_path))
    assert len(rules) == 1
    assert rules[0]["id"] == "TEST-001"
