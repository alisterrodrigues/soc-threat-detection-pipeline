import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.reporter import generate_html_report


def _make_incident(score=85):
    return {
        "incident_id": "INC-001",
        "computer": "WORKSTATION-01",
        "risk_score": score,
        "alert_count": 2,
        "duration_seconds": 30,
        "first_seen": "2026-04-03T14:22:10+00:00",
        "last_seen": "2026-04-03T14:22:40+00:00",
        "tactics": ["Execution", "Credential Access"],
        "techniques": ["T1059.001", "T1003.001"],
        "kill_chains": ["execution_to_credential_access"],
        "alerts": [
            {
                "rule_id": "PROC-001",
                "rule_name": "Suspicious PowerShell Encoded Command",
                "severity": "high",
                "mitre_technique": "T1059.001",
                "mitre_tactic": "Execution",
                "computer": "WORKSTATION-01",
                "timestamp": "2026-04-03T14:22:10+00:00",
                "matched_fields": json.dumps(
                    {"Image": "powershell.exe", "CommandLine": "-EncodedCommand"}
                ),
            }
        ],
    }


def _make_stats():
    return {
        "total": 2,
        "by_severity": {"high": 1, "critical": 1, "medium": 0, "low": 0},
        "by_rule": {},
        "by_tactic": {},
        "fp_rate": None,
    }


def test_report_generates_file(tmp_path):
    """generate_html_report creates the output file and returns its path."""
    out = str(tmp_path / "report.html")
    result = generate_html_report([_make_incident()], [], _make_stats(), out)
    assert result == out
    assert os.path.exists(out)


def test_report_file_is_valid_html(tmp_path):
    """Output file contains required HTML boilerplate and incident identifiers."""
    out = str(tmp_path / "report.html")
    generate_html_report([_make_incident()], [], _make_stats(), out)
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert "<!DOCTYPE html>" in content
    assert "<html" in content
    assert "INC-001" in content
    assert "WORKSTATION-01" in content


def test_report_contains_risk_score(tmp_path):
    """The incident risk score is present as a visible value in the report."""
    out = str(tmp_path / "report.html")
    generate_html_report([_make_incident(score=92)], [], _make_stats(), out)
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert "92" in content


def test_report_no_incidents(tmp_path):
    """When no incidents are passed, the 'No correlated incidents' message is shown."""
    out = str(tmp_path / "report.html")
    generate_html_report([], [], _make_stats(), out)
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert "No correlated incidents" in content


def test_report_contains_all_alerts_table(tmp_path):
    """Alert data passed via all_alerts appears in the flat alerts table."""
    alerts = [
        {
            "rule_id": "PROC-001",
            "rule_name": "PowerShell Rule",
            "severity": "high",
            "mitre_technique": "T1059.001",
            "mitre_tactic": "Execution",
            "computer": "WORKSTATION-01",
            "timestamp": "2026-04-03T14:22:10+00:00",
            "matched_fields": "{}",
        }
    ]
    out = str(tmp_path / "report.html")
    generate_html_report([], alerts, _make_stats(), out)
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert "PROC-001" in content
    assert "PowerShell Rule" in content


def test_report_handles_write_error_gracefully():
    """Writing to a non-existent directory logs a warning and does not raise."""
    result = generate_html_report([], [], _make_stats(), "/nonexistent/dir/report.html")
    assert result == "/nonexistent/dir/report.html"


def test_report_is_self_contained(tmp_path):
    """Output HTML contains no external http/https resource references."""
    out = str(tmp_path / "report.html")
    generate_html_report([_make_incident()], [], _make_stats(), out)
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert "https://" not in content
    assert "http://" not in content


def test_report_custom_title(tmp_path):
    """Custom title is reflected in both the <title> tag and the visible header."""
    out = str(tmp_path / "report.html")
    generate_html_report([], [], _make_stats(), out, title="Custom Report Title")
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert "Custom Report Title" in content
