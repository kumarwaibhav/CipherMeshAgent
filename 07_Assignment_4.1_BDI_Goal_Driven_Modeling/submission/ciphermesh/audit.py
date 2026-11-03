"""SQLite audit log; stores metadata only, never raw prompt text or secret values."""
import json
import sqlite3
import threading
from contextlib import contextmanager
from .models import AuditEvent


class AuditLog:
    def __init__(self, path: str = "ciphermesh_audit.db"):
        self.path = path
        self._lock = threading.Lock()
        # ':memory:' databases are per-connection, so the in-memory mode keeps one shared handle.
        self._shared = sqlite3.connect(":memory:", check_same_thread=False) if path == ":memory:" else None
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL, decision TEXT,
                categories_json TEXT NOT NULL, message_id TEXT,
                details_json TEXT NOT NULL
            )""")

    @contextmanager
    def _connect(self):
        if self._shared is not None:
            with self._shared:
                yield self._shared
            return
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            with db:
                yield db
        finally:
            db.close()

    def write(self, event: AuditEvent) -> None:
        with self._lock, self._connect() as db:
            db.execute("""INSERT INTO audit
                (timestamp, agent_id, event_type, decision, categories_json, message_id, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (event.timestamp.isoformat(), event.agent_id, event.event_type,
                 event.decision.value if event.decision else None,
                 json.dumps(event.categories), event.message_id, json.dumps(event.details, default=str)))

    def recent(self, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        with self._lock, self._connect() as db:
            rows = db.execute("""SELECT timestamp, agent_id, event_type, decision, categories_json,
                                 message_id, details_json FROM audit ORDER BY id DESC LIMIT ?""",
                              (limit,)).fetchall()
        return [{"timestamp": r[0], "agent_id": r[1], "event_type": r[2], "decision": r[3],
                 "categories": json.loads(r[4]), "message_id": r[5], "details": json.loads(r[6])}
                for r in rows]

    def count(self) -> int:
        with self._lock, self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM audit").fetchone()[0])
