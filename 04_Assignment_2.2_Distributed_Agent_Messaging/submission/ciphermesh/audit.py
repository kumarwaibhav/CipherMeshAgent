"""SQLite audit log; stores metadata only, never raw prompt text or secret values."""
import json
import sqlite3
from .models import AuditEvent


class AuditLog:
    def __init__(self, path: str = "ciphermesh_audit.db"):
        self.path = path
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL, decision TEXT,
                categories_json TEXT NOT NULL, message_id TEXT,
                details_json TEXT NOT NULL
            )""")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def write(self, event: AuditEvent) -> None:
        with self._connect() as db:
            db.execute("""INSERT INTO audit
                (timestamp, agent_id, event_type, decision, categories_json, message_id, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (event.timestamp.isoformat(), event.agent_id, event.event_type,
                 event.decision.value if event.decision else None,
                 json.dumps(event.categories), event.message_id, json.dumps(event.details)))
