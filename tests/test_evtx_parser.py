import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engine.evtx_parser import _parse_record_xml, parse_evtx


VALID_RECORD_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-04-03T14:22:10.123456700Z"/>
    <Computer>WORKSTATION-01</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ProcessId">1234</Data>
  </EventData>
</Event>"""

MALFORMED_XML = "<not valid xml <<>>"

MISSING_SYSTEM_XML = """<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData><Data Name="Image">test.exe</Data></EventData>
</Event>"""


def test_parse_record_xml_valid():
    """Valid EVTX record XML produces a normalized event dict with all expected fields."""
    event = _parse_record_xml(VALID_RECORD_XML)
    assert event is not None
    assert event["EventID"] == 1
    assert event["Computer"] == "WORKSTATION-01"
    assert event["Image"] == "C:\\Windows\\System32\\cmd.exe"
    assert event["CommandLine"] == "cmd.exe /c whoami"


def test_parse_record_xml_malformed_returns_none():
    """Malformed XML returns None rather than raising an exception."""
    event = _parse_record_xml(MALFORMED_XML)
    assert event is None


def test_parse_record_xml_missing_system_returns_none():
    """Records without a System element are skipped and return None."""
    event = _parse_record_xml(MISSING_SYSTEM_XML)
    assert event is None


def test_parse_evtx_missing_file_returns_empty():
    """A non-existent file path returns an empty list without raising."""
    events = parse_evtx("/nonexistent/path/to/file.evtx")
    assert events == []


def test_parse_evtx_no_python_evtx_installed(monkeypatch):
    """Verify graceful degradation when python-evtx is not installed."""
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "Evtx.Evtx" or name.startswith("Evtx"):
            raise ImportError("Mocked missing library")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    events = parse_evtx("any_path.evtx")
    assert events == []


def test_parse_record_xml_timestamp_extracted():
    """Timestamp is extracted from TimeCreated SystemTime attribute."""
    event = _parse_record_xml(VALID_RECORD_XML)
    assert event is not None
    assert event["Timestamp"] == "2026-04-03T14:22:10.123456700Z"


def test_parse_record_xml_eventdata_fields():
    """All EventData Name/Value pairs become top-level keys in the event dict."""
    event = _parse_record_xml(VALID_RECORD_XML)
    assert event is not None
    assert event.get("ProcessId") == "1234"
