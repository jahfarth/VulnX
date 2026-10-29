import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "vulnx.sqlite3"

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                total_findings INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                remediation TEXT NOT NULL,
                risk_score REAL NOT NULL,
                priority TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
        """)

        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        if "assessment_kind" not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN assessment_kind TEXT NOT NULL DEFAULT 'actual'")

def list_scans():
    with connect() as conn:
        scans = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
        return [dict(row) for row in scans]

def get_scan(scan_id: int):
    with connect() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return None
        findings = conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY risk_score DESC", (scan_id,)).fetchall()
        result = dict(scan)
        result["findings"] = [dict(row) for row in findings]
        return result

def save_scan(target, created_at, findings, assessment_kind="actual"):
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans(target,status,created_at,total_findings,assessment_kind) VALUES(?,?,?,?,?)",
            (target, "Simulated" if assessment_kind == "simulated" else "Completed", created_at, len(findings), assessment_kind)
        )
        scan_id = cur.lastrowid
        for f in findings:
            conn.execute("""
                INSERT INTO findings(scan_id,title,severity,description,evidence,remediation,risk_score,priority)
                VALUES(?,?,?,?,?,?,?,?)
            """, (scan_id, f["title"], f["severity"], f["description"], f["evidence"],
                  f["remediation"], f["risk_score"], f["priority"]))
        return scan_id
