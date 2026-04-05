import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


def load_rules(rules_dir: str) -> list[dict]:
    """
    Load all YAML rule files from the given rules directory.

    Iterates over every *.yaml file in rules_dir, parses the top-level
    'rules' list from each, and returns all rules combined. Files that
    cannot be read or parsed are skipped with a logged warning.

    Args:
        rules_dir: Path to the directory containing YAML rule files.

    Returns:
        Flat list of rule dicts loaded from all discovered YAML files.
    """
    rules = []
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        logger.error(f"Rules directory not found: {rules_dir}")
        return rules

    for yaml_file in rules_path.glob("*.yaml"):
        try:
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)
            file_rules = data.get("rules", [])
            rules.extend(file_rules)
            logger.info(f"Loaded {len(file_rules)} rules from {yaml_file.name}")
        except Exception as e:
            logger.warning(f"Failed to load rules from {yaml_file}: {e}")

    logger.info(f"Total rules loaded: {len(rules)}")
    return rules


def evaluate_event(event: dict, rules: list[dict], benchmark_mode: bool = False) -> list[dict]:
    """
    Evaluate a single event against all applicable rules.

    Filters rules by matching event_id before condition evaluation.
    In benchmark_mode, logs per-rule evaluation time at DEBUG level.

    Args:
        event: Normalized event dict produced by the parser.
        rules: Full list of loaded rule dicts.
        benchmark_mode: When True, records and logs microsecond timing per rule.

    Returns:
        List of alert dicts — one per matched rule. Empty if nothing fired.
    """
    alerts = []
    event_id = event.get("EventID")

    for rule in rules:
        if rule.get("event_id") != event_id:
            continue

        start = time.perf_counter() if benchmark_mode else None

        matched, matched_fields = _evaluate_conditions(event, rule)

        if benchmark_mode and start is not None:
            elapsed = time.perf_counter() - start
            logger.debug(f"Rule {rule['id']} evaluated in {elapsed * 1000:.3f}ms")

        if matched:
            alert = _build_alert(event, rule, matched_fields)
            alerts.append(alert)

    return alerts


def _evaluate_conditions(event: dict, rule: dict) -> tuple[bool, dict]:
    """
    Evaluate all conditions defined in a rule against a single event.

    Returns (False, {}) immediately if the rule has no conditions — an empty
    condition list should never match, not match everything (which is what
    Python's all([]) would do by default).

    Applies AND or OR logic across all condition results. Collects the
    fields and values that individually triggered for inclusion in alerts.

    Args:
        event: Normalized event dict.
        rule: Rule dict containing 'conditions' and 'logic' keys.

    Returns:
        Tuple of (matched: bool, matched_fields: dict of field->value pairs).
    """
    conditions = rule.get("conditions", [])

    # Guard: a rule with no conditions must not fire on every event.
    # all([]) is True in Python, which would cause mass false positives.
    if not conditions:
        logger.warning(f"Rule {rule.get('id', 'unknown')} has no conditions — skipping to prevent mass firing.")
        return False, {}

    logic = rule.get("logic", "AND").upper()
    matched_fields = {}

    results = []
    for condition in conditions:
        field = condition.get("field", "")
        operator = condition.get("operator", "contains")
        value = condition.get("value", "")
        case_insensitive = condition.get("case_insensitive", True)

        event_value = event.get(field, "")
        if event_value is None:
            event_value = ""

        result = _apply_operator(str(event_value), str(value), operator, case_insensitive)
        results.append(result)
        if result:
            matched_fields[field] = event_value

    if logic == "AND":
        return all(results), matched_fields
    elif logic == "OR":
        return any(results), matched_fields
    return False, {}


def _apply_operator(event_value: str, rule_value: str, operator: str, case_insensitive: bool) -> bool:
    """
    Apply a single condition operator and return whether it matches.

    Supported operators: contains, not_contains, equals, not_equals,
    startswith, endswith, regex. Unknown operators log a warning and return False.

    Args:
        event_value: The string value extracted from the event field.
        rule_value: The comparison value from the rule condition.
        operator: One of the supported operator strings.
        case_insensitive: When True, comparison is performed in lowercase.

    Returns:
        True if the condition matches, False otherwise.
    """
    if case_insensitive:
        ev = event_value.lower()
        rv = rule_value.lower()
    else:
        ev = event_value
        rv = rule_value

    try:
        if operator == "contains":
            return rv in ev
        elif operator == "not_contains":
            return rv not in ev
        elif operator == "equals":
            return ev == rv
        elif operator == "not_equals":
            return ev != rv
        elif operator == "startswith":
            return ev.startswith(rv)
        elif operator == "endswith":
            return ev.endswith(rv)
        elif operator == "regex":
            flags = re.IGNORECASE if case_insensitive else 0
            return bool(re.search(rule_value, event_value, flags))
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False
    except Exception as e:
        logger.warning(f"Operator evaluation error ({operator}): {e}")
        return False


def _build_alert(event: dict, rule: dict, matched_fields: dict) -> dict:
    """
    Construct an alert dict from a matched rule and the triggering event.

    The alert dict schema matches the AlertStore schema exactly so it can
    be passed directly to AlertStore.store_alert() without transformation.

    Args:
        event: The full normalized event dict.
        rule: The rule dict that fired.
        matched_fields: Dict of field->value pairs that satisfied conditions.

    Returns:
        Alert dict ready for storage and display.
    """
    return {
        "timestamp": event.get("Timestamp", ""),
        "rule_id": rule.get("id", ""),
        "rule_name": rule.get("name", ""),
        "severity": rule.get("severity", "low"),
        "mitre_technique": rule.get("mitre_technique", ""),
        "mitre_tactic": rule.get("mitre_tactic", ""),
        "computer": event.get("Computer", ""),
        "event_id": event.get("EventID"),
        "matched_fields": json.dumps(matched_fields),
        "raw_event": json.dumps(event),
    }
