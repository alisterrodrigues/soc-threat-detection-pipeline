import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.parser import parse_sysmon_xml


SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>1</EventID>
      <TimeCreated SystemTime="2026-04-03T14:22:10.123456700Z"/>
      <Computer>WORKSTATION-01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">cmd.exe /c whoami</Data>
      <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
      <Data Name="ProcessId">1234</Data>
      <Data Name="ParentProcessId">5678</Data>
    </EventData>
  </Event>
</Events>"""


def test_parse_valid_xml():
    """Parser returns one event dict with correct field values from valid XML."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(SAMPLE_XML)
        tmp_path = f.name
    try:
        events = parse_sysmon_xml(tmp_path)
        assert len(events) == 1
        event = events[0]
        assert event["EventID"] == 1
        assert event["Computer"] == "WORKSTATION-01"
        assert "cmd.exe" in event["Image"]
        assert event["CommandLine"] == "cmd.exe /c whoami"
    finally:
        os.unlink(tmp_path)


def test_parse_missing_file():
    """Parser returns an empty list rather than raising when the file does not exist."""
    events = parse_sysmon_xml("/nonexistent/path/file.xml")
    assert events == []


def test_parse_malformed_xml():
    """Parser returns an empty list rather than raising on invalid XML syntax."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write("<not valid xml <<>>")
        tmp_path = f.name
    try:
        events = parse_sysmon_xml(tmp_path)
        assert events == []
    finally:
        os.unlink(tmp_path)


def test_event_fields_extracted():
    """All EventData Name/Value pairs are present as top-level keys in the event dict."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(SAMPLE_XML)
        tmp_path = f.name
    try:
        events = parse_sysmon_xml(tmp_path)
        assert events[0].get("ParentImage") == "C:\\Windows\\explorer.exe"
        assert events[0].get("ProcessId") == "1234"
    finally:
        os.unlink(tmp_path)
