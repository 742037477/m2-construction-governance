"""One-writer SQLite hash chain and operation reservation."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3

from .contracts import canonical, bytes_hash, digest, require, strict_json


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as db:
            for statement in ("""
                CREATE TABLE IF NOT EXISTS events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, prev_hash TEXT NOT NULL,
                    body_hash TEXT NOT NULL, event_hash TEXT NOT NULL, body_json TEXT NOT NULL)""", """
                CREATE TABLE IF NOT EXISTS grants(
                    grant_id TEXT PRIMARY KEY, envelope_json TEXT NOT NULL,
                    envelope_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)""", """
                CREATE TABLE IF NOT EXISTS operations(
                    operation_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL,
                    task_id TEXT NOT NULL, kind TEXT NOT NULL, path TEXT NOT NULL,
                    request_hash TEXT NOT NULL, content_size INTEGER NOT NULL,
                    status TEXT NOT NULL, before_sha256 TEXT NOT NULL,
                    after_sha256 TEXT, result_json TEXT)""", """
                CREATE TABLE IF NOT EXISTS resource_locks(
                    path TEXT PRIMARY KEY, operation_id TEXT NOT NULL)"""):
                db.execute(statement)

    @staticmethod
    def ensure_multifile_locks(db):
        """After chain validation, preserve legacy locks and allow one op many files."""
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' "
                         "AND name='resource_locks'").fetchone()
        require(row is not None and type(row[0]) is str, "RESOURCE_LOCK_SCHEMA")
        schema = " ".join(row[0].upper().split())
        if "OPERATION_ID TEXT NOT NULL UNIQUE" not in schema:
            require("OPERATION_ID TEXT NOT NULL" in schema and
                    "PATH TEXT PRIMARY KEY" in schema, "RESOURCE_LOCK_SCHEMA")
            return
        db.execute("CREATE TABLE resource_locks_multi(path TEXT PRIMARY KEY, "
                   "operation_id TEXT NOT NULL)")
        db.execute("INSERT INTO resource_locks_multi(path,operation_id) "
                   "SELECT path,operation_id FROM resource_locks")
        db.execute("DROP TABLE resource_locks")
        db.execute("ALTER TABLE resource_locks_multi RENAME TO resource_locks")
        Ledger.event(db, {"kind": "RESOURCE_LOCK_SCHEMA_MIGRATED",
                          "target": "MULTIFILE_OPERATION_1"})

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def event(db, body):
        last = db.execute("SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = 1 if last is None else last[0] + 1
        prev = "0" * 64 if last is None else last[1]
        body_hash = digest(body)
        event_hash = digest({"schema": "M2_CONSTRUCTION_EVENT_1", "seq": seq,
                             "prev_hash": prev, "body_hash": body_hash})
        db.execute("INSERT INTO events(seq,prev_hash,body_hash,event_hash,body_json) VALUES(?,?,?,?,?)",
                   (seq, prev, body_hash, event_hash, canonical(body).decode("utf-8")))
        return event_hash

    def events(self):
        with sqlite3.connect(self.path) as db:
            return db.execute("SELECT seq,prev_hash,body_hash,event_hash,body_json FROM events ORDER BY seq").fetchall()

    @staticmethod
    def verify_chain(db):
        expected_seq = 1
        previous = "0" * 64
        rows = db.execute("SELECT seq,prev_hash,body_hash,event_hash,body_json FROM events ORDER BY seq")
        for seq, prev, body_hash, event_hash, body_json in rows:
            body = strict_json(body_json)
            require(seq == expected_seq and prev == previous and
                    canonical(body).decode("utf-8") == body_json and
                    digest(body) == body_hash and
                    digest({"schema": "M2_CONSTRUCTION_EVENT_1", "seq": seq,
                            "prev_hash": prev, "body_hash": body_hash}) == event_hash,
                    "EVENT_CHAIN_TAMPERED")
            expected_seq += 1
            previous = event_hash
        if expected_seq == 1:
            require(db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0 and
                    db.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 0,
                    "EVENT_CHAIN_MISSING")
