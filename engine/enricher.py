import logging

logger = logging.getLogger(__name__)


def enrich_event(event: dict, all_events: list[dict], max_depth: int = 3) -> dict:
    """
    Add process tree ancestry and suspicious-parent flag to an event dict.

    Builds a pid->event lookup from all_events, then climbs the parent chain
    up to max_depth levels, collecting image name and command line at each level.
    Also calls flag_suspicious_parent() and stores the result as 'suspicious_parent'
    so downstream rules and the alert pipeline can reference it without an
    additional call. Returns a copy of the event; the caller's dict is not modified.

    Args:
        event: The event dict to enrich. Must contain 'ProcessId' and
               'ParentProcessId' fields to produce useful ancestry.
        all_events: Full list of parsed events used to resolve parent PIDs.
        max_depth: Maximum number of parent levels to walk. Defaults to 3.

    Returns:
        A new event dict with:
          - 'ancestors': list of {'pid', 'image', 'command_line'} dicts ordered
            from immediate parent outward. Empty list if ancestry cannot be resolved.
          - 'suspicious_parent': bool — True if the parent-child process pair
            matches a known-suspicious pattern (e.g. Word spawning PowerShell).
    """
    event = dict(event)  # avoid mutating the caller's dict
    event["ancestors"] = []
    event["suspicious_parent"] = flag_suspicious_parent(event)

    if not event.get("ProcessId"):
        return event

    try:
        pid_map = {}
        for e in all_events:
            pid = e.get("ProcessId")
            if pid:
                pid_map[str(pid)] = e

        current_pid = str(event.get("ParentProcessId", ""))
        depth = 0

        while current_pid and depth < max_depth:
            parent = pid_map.get(current_pid)
            if not parent:
                break
            event["ancestors"].append({
                "pid": current_pid,
                "image": parent.get("Image", ""),
                "command_line": parent.get("CommandLine", ""),
            })
            current_pid = str(parent.get("ParentProcessId", ""))
            depth += 1

    except Exception as e:
        logger.warning(f"Process tree enrichment failed for event: {e}")

    return event


def flag_suspicious_parent(event: dict) -> bool:
    """
    Detect anomalous parent-child process relationships.

    Compares the lowercase basenames of ParentImage and Image against a
    hardcoded list of known-suspicious pairs — e.g. Office spawning shells,
    script hosts spawning PowerShell. Does not require all_events.

    Args:
        event: Event dict containing 'ParentImage' and 'Image' fields.

    Returns:
        True if the parent-child pair matches a suspicious pattern.
        False if no match or if either field is missing.
    """
    suspicious_pairs = [
        ("winword.exe", "cmd.exe"),
        ("winword.exe", "powershell.exe"),
        ("excel.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("outlook.exe", "powershell.exe"),
        ("wscript.exe", "powershell.exe"),
        ("mshta.exe", "powershell.exe"),
        ("mshta.exe", "cmd.exe"),
    ]

    parent = event.get("ParentImage", "").lower()
    child = event.get("Image", "").lower()

    for suspicious_parent, suspicious_child in suspicious_pairs:
        if suspicious_parent in parent and suspicious_child in child:
            return True

    return False
