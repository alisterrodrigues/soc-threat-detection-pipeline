import json
import logging
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    mitre_technique TEXT,
    mitre_tactic TEXT,
    computer TEXT,
    event_id INTEGER,
    matched_fields TEXT,
    raw_event TEXT,
    analyst_disposition TEXT DEFAULT NULL,
    notes TEXT DEFAULT NULL
);
"""

# Ordered severity ranks used for minimum-threshold filtering.
# Higher index = higher severity.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class AlertStore:
    """SQLite-backed persistent store for detection alerts."""

    def __init__(self, db_path: str):
        """
        Initialize the AlertStore and create the alerts table if needed.

        Creates any missing parent directories for the database file so
        the pipeline can run without manual directory setup.

        Args:
            db_path: File system path where the SQLite database should live.
        """
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """
        Apply the schema DDL to the database.

        Uses CREATE TABLE IF NOT EXISTS so existing data is never dropped.
        Logs an error and continues if the database cannot be initialized.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(SCHEMA)
                conn.commit()
            logger.info(f"Alert database initialized at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {e}")

    def store_alert(self, alert: dict) -> Optional[int]:
        """
        Insert a single alert record and return its auto-assigned row ID.

        Args:
            alert: Dict with keys matching the alerts table columns.

        Returns:
            Integer row ID of the inserted row, or None on failure.
        """
        sql = """
        INSERT INTO alerts (
            timestamp, rule_id, rule_name, severity, mitre_technique,
            mitre_tactic, computer, event_id, matched_fields, raw_event
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(sql, (
                    alert.get("timestamp"),
                    alert.get("rule_id"),
                    alert.get("rule_name"),
                    alert.get("severity"),
                    alert.get("mitre_technique"),
                    alert.get("mitre_tactic"),
                    alert.get("computer"),
                    alert.get("event_id"),
                    alert.get("matched_fields"),
                    alert.get("raw_event"),
                ))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.warning(f"Failed to store alert {alert.get('rule_id')}: {e}")
            return None

    def get_alerts(
        self,
        severity: Optional[str] = None,
        rule_id: Optional[str] = None,
        min_severity: Optional[str] = None,
    ) -> list[dict]:
        """
        Retrieve alerts with optional filters on severity and rule_id.

        Two severity filter modes are available and are mutually exclusive:
          - severity: exact equality match on the severity string.
          - min_severity: minimum-threshold filter — returns alerts at the
            given severity and all higher severities. For example,
            min_severity='high' returns both 'high' and 'critical' alerts.
            Unknown severity values are treated as 'low' (match everything).

        Results are ordered newest-first (descending by auto-increment id).

        Args:
            severity: If provided, only return alerts with this exact severity.
            rule_id: If provided, only return alerts matching this rule ID.
            min_severity: If provided, return alerts at this severity or above.
                          Takes precedence over severity if both are given.

        Returns:
            List of alert dicts. Empty list on query failure or no results.
        """
        sql = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if min_severity:
            min_rank = _SEVERITY_RANK.get(min_severity.lower(), 0)
            # Collect all severity labels that meet or exceed the minimum rank.
            qualifying = [
                sev for sev, rank in _SEVERITY_RANK.items() if rank >= min_rank
            ]
            placeholders = ",".join("?" * len(qualifying))
            sql += f" AND severity IN ({placeholders})"
            params.extend(qualifying)
        elif severity:
            sql += " AND severity = ?"
            params.append(severity)

        if rule_id:
            sql += " AND rule_id = ?"
            params.append(rule_id)

        sql += " ORDER BY id DESC"

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql, params).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.warning(f"Failed to retrieve alerts: {e}")
            return []

    def mark_disposition(self, alert_id: int, disposition: str, notes: str = "") -> bool:
        """
        Set the analyst verdict on an alert and attach optional free-text notes.

        Only 'true_positive' and 'false_positive' are accepted dispositions.
        Any other value is rejected without touching the database.

        Args:
            alert_id: The integer primary key of the alert to update.
            disposition: Either 'true_positive' or 'false_positive'.
            notes: Optional analyst commentary stored alongside the disposition.

        Returns:
            True if the update succeeded, False otherwise.
        """
        if disposition not in ("true_positive", "false_positive"):
            logger.warning(f"Invalid disposition value: {disposition}")
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE alerts SET analyst_disposition = ?, notes = ? WHERE id = ?",
                    (disposition, notes, alert_id),
                )
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.warning(f"Failed to mark disposition for alert {alert_id}: {e}")
            return False

    def get_stats(self) -> dict:
        """
        Compute aggregate statistics across all stored alerts.

        Returns counts broken down by severity, rule ID, and MITRE tactic.
        Also computes a false-positive rate as a percentage of dispositioned alerts.

        Returns:
            Dict with keys: total, by_severity, by_rule, by_tactic, fp_rate.
            fp_rate is None when no alerts have been dispositioned yet.
        """
        stats = {
            "total": 0,
            "by_severity": {},
            "by_rule": {},
            "by_tactic": {},
            "fp_rate": None,
        }
        try:
            with sqlite3.connect(self.db_path) as conn:
                stats["total"] = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

                for row in conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity"):
                    stats["by_severity"][row[0]] = row[1]

                for row in conn.execute(
                    "SELECT rule_id, rule_name, COUNT(*) FROM alerts GROUP BY rule_id ORDER BY COUNT(*) DESC"
                ):
                    stats["by_rule"][row[0]] = {"name": row[1], "count": row[2]}

                for row in conn.execute("SELECT mitre_tactic, COUNT(*) FROM alerts GROUP BY mitre_tactic"):
                    stats["by_tactic"][row[0]] = row[1]

                total_dispositioned = conn.execute(
                    "SELECT COUNT(*) FROM alerts WHERE analyst_disposition IS NOT NULL"
                ).fetchone()[0]
                fp_count = conn.execute(
                    "SELECT COUNT(*) FROM alerts WHERE analyst_disposition = 'false_positive'"
                ).fetchone()[0]
                if total_dispositioned > 0:
                    stats["fp_rate"] = round(fp_count / total_dispositioned * 100, 1)

        except sqlite3.Error as e:
            logger.warning(f"Failed to compute stats: {e}")

        return stats
