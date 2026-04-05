"""
Sigma rule converter — translates Sigma detection rules into the pipeline's
native YAML rule format.

Sigma is an open standard for SIEM detection rules. This converter handles
the most common Sigma constructs used in Windows/Sysmon rules. It is not a
full Sigma implementation — unsupported constructs are flagged with warnings
rather than silently dropped.

Supported Sigma features:
  - title, description, status, author fields
  - logsource: product/service/category mapping to Sysmon event IDs
  - detection: keywords and field-value conditions
  - condition: simple 'selection' and 'selection and not filter' patterns
  - falsepositives, tags (for MITRE ATT&CK extraction)

Usage:
    python tools/sigma_converter.py --input rule.yml --output rules/converted.yaml
    python tools/sigma_converter.py --input rule.yml          # prints to stdout
    python tools/sigma_converter.py --input rules_dir/        # batch convert a directory
"""

import argparse
import logging
import re
import sys
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Map Sigma logsource category/service to Sysmon Event IDs
LOGSOURCE_TO_EVENT_ID = {
    "process_creation":       1,
    "network_connection":     3,
    "process_access":         10,
    "registry_event":         13,
    "registry_add":           12,
    "registry_set":           13,
    "registry_delete":        12,
    "file_creation":          11,
    "image_load":             7,
    "pipe_created":           17,
    "raw_access_read":        9,
    "sysmon":                 1,
}

SIGMA_OP_MAP = {
    "|contains":      "contains",
    "|startswith":    "startswith",
    "|endswith":      "endswith",
    "|re":            "regex",
    "|contains|all":  "contains",
}

MITRE_TAG_PATTERN = re.compile(r"attack\.t(\d+)(?:\.(\d+))?", re.IGNORECASE)
MITRE_TACTIC_MAP = {
    "initial_access":          "Initial Access",
    "execution":               "Execution",
    "persistence":             "Persistence",
    "privilege_escalation":    "Privilege Escalation",
    "defense_evasion":         "Defense Evasion",
    "credential_access":       "Credential Access",
    "discovery":               "Discovery",
    "lateral_movement":        "Lateral Movement",
    "collection":              "Collection",
    "command_and_control":     "Command and Control",
    "exfiltration":            "Exfiltration",
    "impact":                  "Impact",
}


def _extract_mitre(tags: list) -> tuple:
    """
    Extract the first MITRE ATT&CK technique ID and tactic from a Sigma tags list.

    Args:
        tags: List of Sigma tag strings (e.g. ['attack.execution', 'attack.t1059.001']).

    Returns:
        Tuple of (technique_id, tactic_name). Either may be empty string if not found.
    """
    technique = ""
    tactic = ""

    for tag in tags:
        tag_lower = tag.lower()

        if not technique:
            m = MITRE_TAG_PATTERN.search(tag_lower)
            if m:
                main = m.group(1)
                sub = m.group(2)
                technique = f"T{main}.{sub.zfill(3)}" if sub else f"T{main}"

        if not tactic:
            for key, name in MITRE_TACTIC_MAP.items():
                if f"attack.{key}" == tag_lower:
                    tactic = name
                    break

    return technique, tactic


def _resolve_event_id(logsource: dict) -> tuple:
    """
    Map a Sigma logsource block to a Sysmon Event ID.

    Args:
        logsource: Dict with keys like product, service, category.

    Returns:
        Tuple of (event_id, warnings). event_id is 0 if no mapping found.
    """
    warnings = []
    category = logsource.get("category", "").lower().replace(" ", "_")
    service = logsource.get("service", "").lower()

    if category in LOGSOURCE_TO_EVENT_ID:
        return LOGSOURCE_TO_EVENT_ID[category], warnings

    if service in LOGSOURCE_TO_EVENT_ID:
        return LOGSOURCE_TO_EVENT_ID[service], warnings

    warnings.append(
        f"Could not map logsource (category='{category}', service='{service}') "
        f"to a Sysmon Event ID. Set event_id manually in the output."
    )
    return 0, warnings


def _parse_detection_block(detection: dict) -> tuple:
    """
    Convert a Sigma detection block into a list of pipeline condition dicts.

    Args:
        detection: The 'detection' dict from a Sigma rule.

    Returns:
        Tuple of (conditions, logic, warnings).
    """
    conditions = []
    warnings = []
    logic = "AND"

    condition_expr = str(detection.get("condition", "selection")).lower()
    selection_key = "selection"
    if "selection" not in detection:
        for key in detection:
            if key != "condition":
                selection_key = key
                break

    selection = detection.get(selection_key, {})

    if not selection:
        warnings.append("No usable selection block found in detection.")
        return conditions, logic, warnings

    if isinstance(selection, list):
        logic = "OR"
        blocks = selection
    else:
        blocks = [selection]

    for block in blocks:
        if not isinstance(block, dict):
            continue
        for raw_field, value in block.items():
            parts = raw_field.split("|", 1)
            field = parts[0]
            modifier = f"|{parts[1]}" if len(parts) > 1 else ""
            operator = SIGMA_OP_MAP.get(modifier, "contains" if modifier else "equals")

            if modifier and modifier not in SIGMA_OP_MAP:
                warnings.append(
                    f"Unsupported Sigma modifier '{modifier}' on field '{field}' "
                    f"— defaulting to 'contains'."
                )

            if isinstance(value, list):
                for v in value:
                    conditions.append({
                        "field": field,
                        "operator": operator,
                        "value": str(v),
                        "case_insensitive": True,
                    })
                if logic == "AND" and len(value) > 1:
                    logic = "OR"
            elif value is None:
                conditions.append({
                    "field": field,
                    "operator": "equals",
                    "value": "",
                    "case_insensitive": False,
                })
            else:
                conditions.append({
                    "field": field,
                    "operator": operator,
                    "value": str(value),
                    "case_insensitive": True,
                })

    if "filter" in condition_expr:
        warnings.append(
            "Sigma 'filter' condition detected. Exclusion/filter logic is not yet supported "
            "— review and add manually as a not_contains condition."
        )
    if "1 of" in condition_expr or "all of" in condition_expr:
        warnings.append(
            "Sigma 'X of selection*' pattern detected. Only the first selection block was "
            "converted. Review the output and combine conditions manually if needed."
        )

    return conditions, logic, warnings


def convert_sigma_rule(sigma_path: str) -> tuple:
    """
    Load a single Sigma YAML file and convert it to a pipeline rule dict.

    Args:
        sigma_path: Path to the Sigma YAML rule file.

    Returns:
        Tuple of (pipeline_rule_dict, warnings). Returns empty dict on failure.
    """
    all_warnings = []

    try:
        with open(sigma_path, "r", encoding="utf-8") as f:
            sigma = yaml.safe_load(f)
    except Exception as e:
        return {}, [f"Failed to read Sigma file {sigma_path}: {e}"]

    if not isinstance(sigma, dict):
        return {}, [f"Sigma file {sigma_path} did not parse as a YAML dict."]

    title = sigma.get("title", Path(sigma_path).stem)
    description = sigma.get("description", sigma.get("title", ""))
    status = sigma.get("status", "")
    tags = sigma.get("tags", [])
    false_positives = sigma.get("falsepositives", [])

    status_to_severity = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "stable":   "medium",
        "test":     "low",
        "experimental": "low",
    }
    severity = status_to_severity.get(status.lower() if status else "", "medium")

    level = sigma.get("level", "")
    if level:
        severity = status_to_severity.get(level.lower(), severity)

    technique, tactic = _extract_mitre(tags)
    if not technique:
        all_warnings.append("No MITRE ATT&CK technique tag found. Set mitre_technique manually.")
    if not tactic:
        all_warnings.append("No MITRE ATT&CK tactic tag found. Set mitre_tactic manually.")

    logsource = sigma.get("logsource", {})
    event_id, ls_warnings = _resolve_event_id(logsource)
    all_warnings.extend(ls_warnings)

    detection = sigma.get("detection", {})
    conditions, logic, det_warnings = _parse_detection_block(detection)
    all_warnings.extend(det_warnings)

    rule_id = "SIGMA-" + re.sub(r"[^A-Z0-9]", "", title.upper())[:12]

    fp_notes = " ".join(str(fp) for fp in false_positives) if false_positives else ""

    rule = {
        "id": rule_id,
        "name": title,
        "description": description,
        "severity": severity,
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "event_id": event_id,
        "conditions": conditions,
        "logic": logic,
        "false_positive_notes": fp_notes or "Review Sigma rule source for false positive guidance.",
        "tuning_tag": f"sigma_{rule_id.lower()}",
    }

    return rule, all_warnings


def convert_directory(input_dir: str, output_dir: str) -> int:
    """
    Batch convert all .yml/.yaml files in input_dir to pipeline rules in output_dir.

    Args:
        input_dir: Directory containing Sigma YAML rule files.
        output_dir: Directory to write converted pipeline YAML files.

    Returns:
        Count of successfully converted rules.
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    converted = 0
    sigma_files = list(input_path.glob("*.yml")) + list(input_path.glob("*.yaml"))

    if not sigma_files:
        print(f"No .yml or .yaml files found in {input_dir}")
        return 0

    for sigma_file in sigma_files:
        rule, warnings = convert_sigma_rule(str(sigma_file))
        if not rule:
            print(f"[SKIP] {sigma_file.name} — conversion failed")
            continue

        for w in warnings:
            print(f"[WARN] {sigma_file.name}: {w}")

        out_file = output_path / f"sigma_{sigma_file.stem}.yaml"
        output_doc = {"rules": [rule]}

        try:
            with open(out_file, "w", encoding="utf-8") as f:
                yaml.dump(output_doc, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"[OK]   {sigma_file.name} -> {out_file.name}")
            converted += 1
        except Exception as e:
            print(f"[FAIL] {sigma_file.name}: Failed to write output: {e}")

    return converted


def main():
    """Entry point for the Sigma rule converter CLI."""
    parser = argparse.ArgumentParser(
        description="Convert Sigma detection rules to the pipeline's native YAML format"
    )
    parser.add_argument("--input", required=True, help="Path to a Sigma .yml file or directory of rules")
    parser.add_argument("--output", default=None, help="Output file or directory (default: stdout for single files)")
    parser.add_argument("--verbose", action="store_true", help="Show all warnings during conversion")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(message)s",
    )

    input_path = Path(args.input)

    if input_path.is_dir():
        if not args.output:
            print("--output is required when --input is a directory", file=sys.stderr)
            sys.exit(1)
        count = convert_directory(str(input_path), args.output)
        print(f"\nConverted {count} rule(s) to {args.output}")

    elif input_path.is_file():
        rule, warnings = convert_sigma_rule(str(input_path))
        if not rule:
            print(f"Conversion failed: {warnings[0] if warnings else 'unknown error'}", file=sys.stderr)
            sys.exit(1)

        for w in warnings:
            print(f"[WARN] {w}", file=sys.stderr)

        output_doc = {"rules": [rule]}
        yaml_str = yaml.dump(output_doc, default_flow_style=False, allow_unicode=True, sort_keys=False)

        if args.output:
            try:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(yaml_str)
                print(f"Written to {args.output}")
            except Exception as e:
                print(f"Failed to write output: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(yaml_str)

    else:
        print(f"Input path does not exist: {args.input}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
