import sqlite3
from typing import Tuple, Optional, List, Dict, Any
from datetime import datetime
import os

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "audit_journal.db")
BUGZILLA_PREFIX = "bsc#"
FINDING_BUGZILLA_PREFIX = "bsc#"


def import_kb_entries(entries: List[Dict[str, Any]]) -> int:
    """
    Imports a list of KB entries (dictionaries) into the database.
    Uses INSERT OR REPLACE based on cwe_id.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    count = 0
    required_keys = [
        "cwe_id",
        "title",
        "description_template",
        "impact_template",
        "recommendation_template",
    ]

    for entry in entries:
        if not all(key in entry for key in required_keys):
            print(f"Skipping entry: Missing required keys in entry: {entry.keys()}")
            continue

        try:
            c.execute(
                "INSERT OR REPLACE INTO kb_entries (cwe_id, title, description_template, impact_template, recommendation_template) VALUES (?, ?, ?, ?, ?)",
                (
                    entry["cwe_id"],
                    entry["title"],
                    entry["description_template"],
                    entry["impact_template"],
                    entry["recommendation_template"],
                ),
            )
            count += 1
        except Exception as e:
            print(f"Error importing KB entry for CWE {entry['cwe_id']}: {e}")

    conn.commit()
    conn.close()
    return count


def init_db():
    """Creates the database file and tables if they do not exist."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY,
            bugzilla_id TEXT UNIQUE NOT NULL,
            project_name TEXT NOT NULL,
            start_date TEXT NOT NULL,
            is_active INTEGER DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            audit_fk INTEGER NOT NULL,
            finding_bugzilla_id TEXT UNIQUE, 
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_v4_vector TEXT, 
            cvss_v4_score REAL,
            notes TEXT,
            cwe_id INTEGER,
            FOREIGN KEY (audit_fk) REFERENCES audits (id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS kb_entries (
            cwe_id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            description_template TEXT,
            impact_template TEXT,
            recommendation_template TEXT
        )
    """)
    conn.commit()
    conn.close()


def get_kb_entry(cwe_id: int) -> Optional[Dict]:
    """Retrieves a single KB entry by its CWE ID."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM kb_entries WHERE cwe_id = ?", (cwe_id,))
    entry_row = c.fetchone()
    conn.close()

    return dict(entry_row) if entry_row else None


def get_audit_details(audit_id: int) -> Optional[Dict]:
    """Retrieves all details for a given audit ID."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute(
        "SELECT bugzilla_id, project_name, start_date FROM audits WHERE id = ?",
        (audit_id,),
    )
    audit_row = c.fetchone()
    conn.close()

    return dict(audit_row) if audit_row else None


def get_findings_for_report(audit_id: int) -> List[Dict]:
    """Retrieves all findings for a given audit, ordered by severity."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    order_clause = """
        CASE severity 
            WHEN 'CRITICAL' THEN 1 
            WHEN 'HIGH' THEN 2 
            WHEN 'MEDIUM' THEN 3 
            WHEN 'LOW' THEN 4 
            ELSE 5 
        END, 
        cvss_v4_score DESC
    """

    c.execute(
        f"SELECT id, finding_bugzilla_id, title, severity, cvss_v4_vector, cvss_v4_score, notes FROM findings WHERE audit_fk = ? ORDER BY {order_clause}",
        (audit_id,),
    )
    findings = [dict(row) for row in c.fetchall()]
    conn.close()
    return findings
