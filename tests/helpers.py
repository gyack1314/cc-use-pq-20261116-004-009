from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from orbitbridge import catalog, protocol, store

STAMP = "2026-10-28T12:03:00Z"
PACKET_TIME = "2026-10-28T12:02:00Z"


def observation(identifier: str = "sim-1", *, region: str = "north", severity: int = 4,
                confidence: str = "0.8", observed_at: str = "2026-10-28T12:01:00Z",
                latitude: object = 31.2, longitude: object = 121.4, source: str = "infrared") -> dict:
    return {"kind": "observation", "id": identifier, "observed_at": observed_at, "region": region,
            "latitude": latitude, "longitude": longitude, "confidence": confidence,
            "severity": severity, "source": source}


def packet(sequence: int = 1, records: list[dict] | None = None, *, station: str = "sat-a",
           created_at: str = PACKET_TIME) -> bytes:
    return protocol.encode_packet(station, sequence, created_at, records or [observation()])


class DatabaseCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db_path = self.root / "store.sqlite3"
        self.db = store.open_database(self.db_path)
        self.addCleanup(lambda: self.db.close())
        catalog.register_station(self.db, "sat-a", "合成观测站", when=STAMP)
        catalog.register_subscription(self.db, "north-watch", "north", 3, "0.7", when=STAMP)

    def write_packet(self, sequence: int = 1, records: list[dict] | None = None, *,
                     name: str | None = None, station: str = "sat-a") -> Path:
        path = self.root / (name or f"packet-{sequence}.jsonl")
        path.write_bytes(packet(sequence, records, station=station))
        return path
