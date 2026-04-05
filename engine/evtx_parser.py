"""
EVTX parser — reads Windows Event Log (.evtx) files directly.

Produces the same normalized event dict format as engine/parser.py so the
rest of the pipeline (rule engine, enricher, alert store) requires no changes.
Requires the `python-evtx` library (pip install python-evtx).

Typical usage:
    from engine.evtx_parser import parse_evtx
    events = parse_evtx("path/to/Security.evtx")
"""

import logging
import xml.etree.ElementTree as ET
from typing import Optional

logger = logging.getLogger(__name__)

SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _find(parent, tag: str, ns: str = SYSMON_NS):
    """
    Find a child element by tag, trying the namespaced lookup first.

    Uses an explicit is-not-None check rather than truth-value testing on the
    element to avoid Python 3.14 deprecation warnings from xml.etree.

    Args:
        parent: Parent XML element to search within.
        tag: Unqualified tag name (e.g. 'System', 'EventID').
        ns: XML namespace URI to try first.

    Returns:
        The first matching child element, or None if not found.
    """
    result = parent.find(f"{{{ns}}}{tag}")
    if result is not None:
        return result
    return parent.find(tag)


def _parse_record_xml(xml_str: str) -> Optional[dict]:
    """
    Parse a single EVTX record's XML string into a normalized event dict.

    Uses the same field extraction logic as engine/parser.py so output is
    structurally identical regardless of whether events came from an XML
    export or direct EVTX reading. EventData Name/Value pairs become
    top-level dict keys, matching the parser.py convention.

    Args:
        xml_str: Raw XML string for a single Windows event record.

    Returns:
        Normalized event dict with keys EventID, Timestamp, Computer and
        all EventData fields, or None if the record cannot be parsed.
    """
    try:
        root = ET.fromstring(xml_str)
        event = {}

        system = _find(root, "System")
        if system is None:
            logger.warning("EVTX record missing System element, skipping")
            return None

        event_id_elem = _find(system, "EventID")
        event["EventID"] = int(event_id_elem.text) if event_id_elem is not None else None

        time_created = _find(system, "TimeCreated")
        event["Timestamp"] = time_created.get("SystemTime", "") if time_created is not None else ""

        computer = _find(system, "Computer")
        event["Computer"] = computer.text if computer is not None else ""

        event_data = _find(root, "EventData")
        if event_data is not None:
            for data in event_data:
                name = data.get("Name")
                if name:
                    event[name] = data.text or ""

        return event

    except ET.ParseError as e:
        logger.warning(f"Failed to parse EVTX record XML: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error parsing EVTX record: {e}")
        return None


def parse_evtx(file_path: str) -> list[dict]:
    """
    Parse a Windows .evtx event log file and return normalized event dicts.

    Requires the python-evtx library. If the library is not installed, logs
    a clear error message with install instructions and returns an empty list
    rather than letting an ImportError propagate to the user.

    Each returned dict has the same structure as events from engine/parser.py:
    EventID, Timestamp, Computer, and all EventData Name/Value fields as
    top-level keys. Individual unreadable records are skipped with a warning
    so the rest of the file continues to be processed.

    Args:
        file_path: Absolute or relative path to the .evtx file.

    Returns:
        List of normalized event dicts. Empty list on any failure.
    """
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        logger.error(
            "python-evtx is not installed. Install it with: pip install python-evtx\n"
            "Alternatively, export your logs as XML from Event Viewer and use --input."
        )
        return []

    events = []
    try:
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    event = _parse_record_xml(xml_str)
                    if event:
                        events.append(event)
                except Exception as e:
                    logger.warning(f"Failed to read EVTX record: {e}")
                    continue
    except FileNotFoundError:
        logger.error(f"EVTX file not found: {file_path}")
    except Exception as e:
        logger.error(f"Failed to open EVTX file {file_path}: {e}")

    logger.info(f"Parsed {len(events)} events from EVTX file {file_path}")
    return events
