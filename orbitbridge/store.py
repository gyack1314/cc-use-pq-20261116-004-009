"""SQLite 持久化边界与原子事务。"""
from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS stations (
  station_id TEXT PRIMARY KEY, label TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
  subscription_id TEXT PRIMARY KEY, region TEXT NOT NULL, minimum_severity INTEGER NOT NULL
    CHECK(minimum_severity BETWEEN 1 AND 5), minimum_confidence TEXT NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1)), created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS subscriptions_region ON subscriptions(region, active);
CREATE TABLE IF NOT EXISTS batches (
  batch_id INTEGER PRIMARY KEY AUTOINCREMENT, station_id TEXT NOT NULL REFERENCES stations(station_id),
  sequence INTEGER NOT NULL CHECK(sequence > 0), packet_id TEXT NOT NULL, digest TEXT NOT NULL,
  packet_time TEXT NOT NULL, received_at TEXT NOT NULL, source_name TEXT NOT NULL,
  record_count INTEGER NOT NULL, UNIQUE(station_id, sequence), UNIQUE(packet_id)
);
CREATE TABLE IF NOT EXISTS station_cursors (
  station_id TEXT PRIMARY KEY REFERENCES stations(station_id), committed_sequence INTEGER NOT NULL DEFAULT 0,
  last_batch_id INTEGER REFERENCES batches(batch_id), updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
  observation_id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id INTEGER NOT NULL REFERENCES batches(batch_id),
  station_id TEXT NOT NULL REFERENCES stations(station_id), external_id TEXT NOT NULL, observed_at TEXT NOT NULL,
  region TEXT NOT NULL, latitude TEXT NOT NULL, longitude TEXT NOT NULL, confidence TEXT NOT NULL,
  severity INTEGER NOT NULL, source TEXT NOT NULL, fingerprint TEXT NOT NULL,
  UNIQUE(station_id, external_id), UNIQUE(batch_id, external_id)
);
CREATE INDEX IF NOT EXISTS observations_region ON observations(region, observed_at);
CREATE TABLE IF NOT EXISTS handoffs (
  handoff_id INTEGER PRIMARY KEY AUTOINCREMENT, observation_id INTEGER NOT NULL REFERENCES observations(observation_id),
  subscription_id TEXT NOT NULL REFERENCES subscriptions(subscription_id),
  status TEXT NOT NULL CHECK(status IN ('pending','acknowledged')),
  created_at TEXT NOT NULL, acknowledged_at TEXT, operator TEXT,
  UNIQUE(observation_id, subscription_id),
  CHECK((status='pending' AND acknowledged_at IS NULL AND operator IS NULL) OR
        (status='acknowledged' AND acknowledged_at IS NOT NULL AND operator IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS handoffs_status ON handoffs(status, subscription_id);
CREATE TABLE IF NOT EXISTS quarantine (
  quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT, station_id TEXT, sequence INTEGER, source_name TEXT NOT NULL,
  content_digest TEXT NOT NULL, reason_code TEXT NOT NULL, detail TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 1,
  UNIQUE(station_id, sequence, content_digest, reason_code)
);
CREATE TABLE IF NOT EXISTS activity (
  activity_id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL, occurred_at TEXT NOT NULL, details_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS activity_entity ON activity(entity_type, entity_id, activity_id);
"""


def open_database(path: str | Path) -> sqlite3.Connection:
    database = Path(path)
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database, timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(SCHEMA)
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def one(connection: sqlite3.Connection, query: str, args: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    row = connection.execute(query, args).fetchone()
    return dict(row) if row is not None else None


def many(connection: sqlite3.Connection, query: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, args)]


def record_activity(connection: sqlite3.Connection, event_type: str, entity_type: str, entity_id: str,
                    occurred_at: str, details: dict[str, Any]) -> int:
    cursor = connection.execute(
        "INSERT INTO activity(event_type,entity_type,entity_id,occurred_at,details_json) VALUES(?,?,?,?,?)",
        (event_type, entity_type, entity_id, occurred_at, json.dumps(details, ensure_ascii=False, sort_keys=True)),
    )
    return int(cursor.lastrowid)


def insert_batch(connection: sqlite3.Connection, station_id: str, sequence: int, packet_id: str, digest: str,
                 packet_time: str, received_at: str, source_name: str, record_count: int) -> int:
    cursor = connection.execute(
        "INSERT INTO batches(station_id,sequence,packet_id,digest,packet_time,received_at,source_name,record_count) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (station_id, sequence, packet_id, digest, packet_time, received_at, source_name, record_count),
    )
    return int(cursor.lastrowid)


def insert_observation(connection: sqlite3.Connection, batch_id: int, station_id: str, observation: dict[str, Any]) -> int:
    cursor = connection.execute(
        "INSERT INTO observations(batch_id,station_id,external_id,observed_at,region,latitude,longitude,"
        "confidence,severity,source,fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (batch_id, station_id, observation["external_id"], observation["observed_at"], observation["region"],
         observation["latitude"], observation["longitude"], observation["confidence"],
         observation["severity"], observation["source"], observation["fingerprint"]),
    )
    return int(cursor.lastrowid)


def update_cursor(connection: sqlite3.Connection, station_id: str, sequence: int, batch_id: int, when: str) -> None:
    changed = connection.execute(
        "UPDATE station_cursors SET committed_sequence=?,last_batch_id=?,updated_at=? "
        "WHERE station_id=? AND committed_sequence=?",
        (sequence, batch_id, when, station_id, sequence - 1),
    ).rowcount
    if changed != 1:
        raise RuntimeError("站点游标未能原子更新")


def quarantine(connection: sqlite3.Connection, station_id: str | None, sequence: int | None,
               source_name: str, content_digest: str, reason_code: str, detail: str, when: str) -> int:
    existing = one(connection, "SELECT quarantine_id FROM quarantine WHERE station_id IS ? AND sequence IS ? "
                   "AND content_digest=? AND reason_code=?", (station_id, sequence, content_digest, reason_code))
    if existing:
        connection.execute("UPDATE quarantine SET attempts=attempts+1,last_seen=? WHERE quarantine_id=?",
                           (when, existing["quarantine_id"]))
        return int(existing["quarantine_id"])
    cursor = connection.execute(
        "INSERT INTO quarantine(station_id,sequence,source_name,content_digest,reason_code,detail,first_seen,last_seen) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (station_id, sequence, source_name, content_digest, reason_code, detail[:1000], when, when),
    )
    return int(cursor.lastrowid)


def station_cursor(connection: sqlite3.Connection, station_id: str) -> dict[str, Any] | None:
    return one(connection, "SELECT * FROM station_cursors WHERE station_id=?", (station_id,))


def batch_for_sequence(connection: sqlite3.Connection, station_id: str, sequence: int) -> dict[str, Any] | None:
    return one(connection, "SELECT * FROM batches WHERE station_id=? AND sequence=?", (station_id, sequence))


def get_batch(connection: sqlite3.Connection, batch_id: int) -> dict[str, Any] | None:
    return one(connection, "SELECT * FROM batches WHERE batch_id=?", (batch_id,))


def get_observation(connection: sqlite3.Connection, observation_id: int) -> dict[str, Any] | None:
    return one(connection, "SELECT * FROM observations WHERE observation_id=?", (observation_id,))


def get_handoff(connection: sqlite3.Connection, handoff_id: int) -> dict[str, Any] | None:
    return one(connection, "SELECT * FROM handoffs WHERE handoff_id=?", (handoff_id,))


def counts(connection: sqlite3.Connection) -> dict[str, int]:
    names = ("stations", "subscriptions", "batches", "observations", "handoffs", "quarantine", "activity")
    return {name: int(connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]) for name in names}


def integrity_check(connection: sqlite3.Connection) -> list[str]:
    issues = []
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        issues.append("sqlite_integrity")
    for row in connection.execute("PRAGMA foreign_key_check"):
        issues.append(f"foreign_key:{row[0]}:{row[1]}")
    for row in connection.execute(
        "SELECT c.station_id,c.committed_sequence,MAX(b.sequence) AS max_seq FROM station_cursors c "
        "LEFT JOIN batches b ON b.station_id=c.station_id GROUP BY c.station_id"
    ):
        if row["committed_sequence"] != (row["max_seq"] or 0):
            issues.append(f"cursor:{row['station_id']}")
    for row in connection.execute(
        "SELECT b.batch_id,b.record_count,COUNT(o.observation_id) AS actual FROM batches b "
        "LEFT JOIN observations o ON o.batch_id=b.batch_id GROUP BY b.batch_id"
    ):
        if row["record_count"] != row["actual"]:
            issues.append(f"batch_count:{row['batch_id']}")
    return issues
