"""SQLite storage for validated audit events."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from pydantic import TypeAdapter

from secure_agent.common.schemas import AuditEvent, NonEmptyText


class AuditRepository:
    """Store events in a SQLite file; each operation closes its connection.

    The database parent directory must already exist. SQLite errors propagate
    to the caller, including IntegrityError for duplicate event identifiers.
    """

    def __init__(self, database_path: str | Path):
        if str(database_path) in ("", ":memory:"):
            raise ValueError("Use a SQLite file path, not an in-memory database.")
        self.database_path = str(database_path)
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY NOT NULL,
                        request_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        metadata TEXT NOT NULL
                    )
                """)
                connection.execute("""
                    CREATE INDEX IF NOT EXISTS audit_events_request_id
                    ON audit_events (request_id)
                """)

    def add(self, event: AuditEvent) -> None:
        """Validate and persist one event without replacing existing records."""
        event = AuditEvent.model_validate(event)
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO audit_events "
                    "(event_id, request_id, event_type, timestamp, metadata) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (event.event_id, event.request_id, event.event_type,
                     event.timestamp.isoformat(),
                     json.dumps(event.metadata, ensure_ascii=False, allow_nan=False)),
                )

    def get_by_request_id(self, request_id: str) -> list[AuditEvent]:
        """Return matching events in insertion order, or an empty list."""
        request_id = TypeAdapter(NonEmptyText).validate_python(request_id, strict=True)
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT event_id, request_id, event_type, timestamp, metadata "
                "FROM audit_events WHERE request_id = ? ORDER BY rowid",
                (request_id,),
            ).fetchall()
        events = []
        for row in rows:
            data = dict(row)
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
            data["metadata"] = json.loads(data["metadata"])
            events.append(AuditEvent.model_validate(data))
        return events
