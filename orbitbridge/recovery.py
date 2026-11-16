"""隔离包重检与按站点游标的恢复计划。"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

from . import catalog, ingest, protocol, store


class RecoveryError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def plan_station(connection: sqlite3.Connection, station_id: str, directory: str | Path) -> dict[str, Any]:
    station = catalog.station(connection, station_id)
    if station is None:
        raise RecoveryError("station_missing", "站点不存在")
    root = Path(directory)
    if not root.is_dir():
        raise RecoveryError("directory_missing", "恢复目录不存在")
    packages: list[dict[str, Any]] = []
    unreadable: list[dict[str, str]] = []
    for file in sorted(root.iterdir()):
        if not file.is_file() or file.suffix.lower() != ".jsonl":
            continue
        try:
            packet = protocol.parse_packet_file(file)
        except protocol.PacketError as exc:
            unreadable.append({"source_name": file.name, "reason": exc.code})
            continue
        if packet.envelope.station_id != station_id:
            continue
        packages.append({"source_name": file.name, "sequence": packet.envelope.sequence,
                         "packet_id": protocol.packet_identity(packet)})
    packages.sort(key=lambda row: (row["sequence"], row["source_name"]))
    cursor = int(station["committed_sequence"])
    next_sequence = cursor + 1
    ready, blocked, duplicate = [], [], []
    seen: dict[int, str] = {}
    for package in packages:
        sequence = package["sequence"]
        if sequence in seen:
            if seen[sequence] == package["packet_id"]:
                duplicate.append(package)
            else:
                blocked.append({**package, "reason": "sequence_conflict"})
            continue
        seen[sequence] = package["packet_id"]
        if sequence <= cursor:
            prior = store.batch_for_sequence(connection, station_id, sequence)
            if prior and prior["packet_id"] == package["packet_id"]:
                duplicate.append(package)
            else:
                blocked.append({**package, "reason": "already_committed_conflict"})
            continue
        if sequence == next_sequence:
            ready.append(package)
            next_sequence += 1
        else:
            blocked.append({**package, "reason": "waiting_for_gap", "expected": next_sequence})
    return {"station_id": station_id, "cursor": cursor, "ready": ready, "blocked": blocked,
            "duplicates": duplicate, "unreadable": unreadable, "next_expected": next_sequence}


def resume_station(connection: sqlite3.Connection, station_id: str, directory: str | Path,
                   *, when: str | None = None) -> dict[str, Any]:
    plan = plan_station(connection, station_id, directory)
    root = Path(directory)
    results = []
    for entry in plan["ready"]:
        path = root / entry["source_name"]
        try:
            result = ingest.ingest_file(connection, path, when=when)
            results.append({"source_name": path.name, **result.as_dict()})
        except ingest.IngestError as exc:
            results.append({"source_name": path.name, **exc.as_dict()})
            break
    current = catalog.station(connection, station_id)
    return {"plan": plan, "results": results, "cursor_after": current["committed_sequence"]}


def quarantine_retry_plan(connection: sqlite3.Connection, quarantine_id: int, source: str | Path) -> dict[str, Any]:
    item = store.one(connection, "SELECT * FROM quarantine WHERE quarantine_id=?", (quarantine_id,))
    if item is None:
        raise RecoveryError("quarantine_missing", "隔离记录不存在")
    file = Path(source)
    try:
        data = file.read_bytes()
    except OSError as exc:
        raise RecoveryError("source_unreadable", "无法读取待重试包") from exc
    raw_digest = hashlib.sha256(data).hexdigest()
    try:
        packet = protocol.parse_packet_bytes(data, file.name)
    except protocol.PacketError as exc:
        if item["station_id"] is not None or raw_digest != item["content_digest"]:
            raise RecoveryError("retry_mismatch", "文件与隔离记录不符") from exc
        return {"quarantine_id": quarantine_id, "same_content": True, "still_invalid": exc.code}
    if item["station_id"] is not None:
        if packet.envelope.station_id != item["station_id"] or packet.envelope.sequence != item["sequence"]:
            raise RecoveryError("retry_mismatch", "站点或序号与隔离记录不符")
        if protocol.packet_identity(packet) != item["content_digest"]:
            raise RecoveryError("retry_mismatch", "包身份与隔离记录不符")
    elif raw_digest != item["content_digest"]:
        raise RecoveryError("retry_mismatch", "文件内容与隔离记录不符")
    station = catalog.station(connection, packet.envelope.station_id)
    return {"quarantine_id": quarantine_id, "same_content": True, "station": station,
            "sequence": packet.envelope.sequence, "reason_code": item["reason_code"]}


def retry_file(connection: sqlite3.Connection, quarantine_id: int, source: str | Path,
               *, when: str | None = None) -> dict[str, Any]:
    plan = quarantine_retry_plan(connection, quarantine_id, source)
    if plan.get("still_invalid"):
        raise RecoveryError("still_invalid", "隔离包仍未通过协议校验")
    file = Path(source)
    try:
        result = ingest.ingest_file(connection, file, when=when)
    except ingest.IngestError as exc:
        return {"quarantine_id": quarantine_id, "result": exc.as_dict()}
    with store.transaction(connection):
        store.record_activity(connection, "quarantine_retried", "quarantine", str(quarantine_id),
                              when or catalog.utc_now(), {"batch_id": result.batch_id, "status": result.status})
    return {"quarantine_id": quarantine_id, "result": result.as_dict()}
