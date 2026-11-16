"""针对收件异常提供不修改状态的操作诊断。"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

from . import catalog, protocol, store


def inspect_packet(connection: sqlite3.Connection, source: str | Path) -> dict[str, Any]:
    path = Path(source)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"source_name": path.name, "status": "unreadable", "reason": str(exc)}
    digest = hashlib.sha256(data).hexdigest()
    try:
        packet = protocol.parse_packet_bytes(data, path.name)
    except protocol.PacketError as exc:
        return {"source_name": path.name, "status": "invalid", "reason": exc.code,
                "line": exc.line, "raw_sha256": digest}
    station_id = packet.envelope.station_id
    sequence = packet.envelope.sequence
    identity = protocol.packet_identity(packet)
    station = catalog.station(connection, station_id)
    previous = store.batch_for_sequence(connection, station_id, sequence)
    if station is None:
        status = "station_unknown"
    elif not station["active"]:
        status = "station_inactive"
    elif previous and previous["packet_id"] == identity:
        status = "duplicate"
    elif previous:
        status = "sequence_conflict"
    elif sequence == station["committed_sequence"] + 1:
        status = "next"
    elif sequence > station["committed_sequence"] + 1:
        status = "gap"
    else:
        status = "old"
    return {"source_name": path.name, "status": status, "station_id": station_id, "sequence": sequence,
            "packet_id": identity, "raw_sha256": digest, "record_count": packet.envelope.record_count,
            "committed_sequence": station["committed_sequence"] if station else None,
            "prior_batch_id": previous["batch_id"] if previous else None}


def inspect_directory(connection: sqlite3.Connection, directory: str | Path) -> dict[str, Any]:
    root = Path(directory)
    if not root.is_dir():
        raise ValueError("诊断目录不存在")
    files = [entry for entry in sorted(root.iterdir()) if entry.is_file() and entry.suffix.lower() == ".jsonl"]
    results = [inspect_packet(connection, entry) for entry in files]
    statuses: dict[str, int] = {}
    for result in results:
        key = result["status"]
        statuses[key] = statuses.get(key, 0) + 1
    return {"directory": str(root), "files": results, "status_counts": dict(sorted(statuses.items()))}
