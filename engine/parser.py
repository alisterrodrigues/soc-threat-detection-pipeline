import logging
import xml.etree.ElementTree as ET
from typing import Optional

logger = logging.getLogger(__name__)

SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def parse_sysmon_xml(file_path: str) -> list[dict]:
    """
    Parse a Sysmon XML export file and return a list of normalized event dicts.

    Each dict contains at minimum: EventID, Timestamp, Computer, and all
    EventData Name/Value fields. Skips malformed events with a logged warning
    rather than crashing the pipeline.

    Args:
        file_path: Absolute or relative path to the Sysmon XML log file.

    Returns:
        List of event dicts. Empty list if the file is missing or unparseable.
    """
    events = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML file {file_path}: {e}")
        return events
    except FileNotFoundError:
        logger.error(f"Log file not found: {file_path}")
        return events

    # Handle both <Events> root and <Event> root (single-event files).
    # Try the namespaced path first; fall back to non-namespaced only when the
    # namespaced search returns an empty list (never falsy-test an element).
    event_elements = root.findall(f".//{{{SYSMON_NS}}}Event")
    if not event_elements:
        event_elements = root.findall(".//Event")

    for elem in event_elements:
        event = _parse_event(elem)
        if event:
            events.append(event)

    logger.info(f"Parsed {len(events)} events from {file_path}")
    return events


def _parse_event(elem) -> Optional[dict]:
    """
    Extract a single Event XML element into a normalized dict.

    Attempts both namespaced and non-namespaced element lookups to handle
    variations in Sysmon XML exports. Returns None and logs a warning if
    the element is critically malformed.

    Args:
        elem: An xml.etree.ElementTree.Element representing one <Event>.

    Returns:
        A normalized event dict, or None if the element cannot be parsed.
    """
    try:
        event = {}

        ns = SYSMON_NS

        # Always try the namespaced lookup first; fall back to no-namespace only
        # when the namespaced result is explicitly None. Python 3.14 deprecated
        # using element truth-value for emptiness checks, so we use `is None`.
        def _find(parent, tag: str):
            result = parent.find(f"{{{ns}}}{tag}")
            if result is not None:
                return result
            return parent.find(tag)

        system = _find(elem, "System")
        if system is None:
            logger.warning("Event missing System element, skipping")
            return None

        event_id_elem = _find(system, "EventID")
        event["EventID"] = int(event_id_elem.text) if event_id_elem is not None else None

        time_created = _find(system, "TimeCreated")
        event["Timestamp"] = time_created.get("SystemTime", "") if time_created is not None else ""

        computer = _find(system, "Computer")
        event["Computer"] = computer.text if computer is not None else ""

        # EventData fields: all Sysmon-specific fields live here as Name/Value pairs
        event_data = _find(elem, "EventData")
        if event_data is not None:
            for data in event_data:
                name = data.get("Name")
                if name:
                    event[name] = data.text or ""

        return event

    except Exception as e:
        logger.warning(f"Failed to parse event element: {e}")
        return None
