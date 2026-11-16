"""批次清单驱动的本地观测包收件和执行计划。"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import catalog, ingest, protocol, store

MAX_MANIFEST_BYTES = 1_000_000
MAX_FILES = 500


class ManifestError(ValueError):
    def __init__(self, code: str, message: str, entry: int | None = None):
        super().__init__(message)
        self.code = code
        self.entry = entry


@dataclass(frozen=True)
class ManifestEntry:
    file: str
    station_id: str
    sequence: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class Manifest:
    name: str
    entries: tuple[ManifestEntry, ...]
    fingerprint: str


def _safe_file(value: object, number: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 180:
        raise ManifestError("file_name", "清单文件名无效", number)
    if value in {".", ".."} or Path(value).name != value or ":" in value or "\\" in value:
        raise ManifestError("file_name", "清单仅允许同目录中的文件名", number)
    if not value.endswith(".jsonl"):
        raise ManifestError("file_suffix", "包文件须使用 .jsonl 后缀", number)
    return value


def _digest(value: object, number: int) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ManifestError("sha256", "清单 SHA-256 格式无效", number)
    return value


def parse_manifest(data: bytes) -> Manifest:
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest_size", "清单为空或过大")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("manifest_json", "清单不是有效 UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "name", "packets"}:
        raise ManifestError("manifest_fields", "清单顶层字段无效")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise ManifestError("manifest_schema", "仅支持清单版本 1")
    name = value["name"]
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise ManifestError("manifest_name", "清单名称无效")
    packets = value["packets"]
    if not isinstance(packets, list) or not 1 <= len(packets) <= MAX_FILES:
        raise ManifestError("manifest_entries", "清单须包含 1 到 500 个包")
    entries = []
    seen_files: set[str] = set()
    seen_sequences: dict[tuple[str, int], str] = {}
    for index, packet in enumerate(packets, 1):
        if not isinstance(packet, dict) or set(packet) != {"file", "station_id", "sequence", "sha256"}:
            raise ManifestError("entry_fields", "清单条目字段无效", index)
        file = _safe_file(packet["file"], index)
        station_id = packet["station_id"]
        sequence = packet["sequence"]
        digest = _digest(packet["sha256"], index)
        if not isinstance(station_id, str) or not 1 <= len(station_id) <= 64 or not all(
            character.isalnum() or character in "_-" for character in station_id
        ):
            raise ManifestError("station_id", "清单站点标识无效", index)
        if type(sequence) is not int or sequence < 1:
            raise ManifestError("sequence", "清单序号无效", index)
        if file in seen_files:
            raise ManifestError("duplicate_file", "清单文件名重复", index)
        seen_files.add(file)
        key = (station_id, sequence)
        if key in seen_sequences:
            raise ManifestError("duplicate_sequence", "清单站点序号重复", index)
        seen_sequences[key] = file
        entries.append(ManifestEntry(file, station_id, sequence, digest))
    fingerprint = hashlib.sha256(protocol.canonical_json(value)).hexdigest()
    return Manifest(name.strip(), tuple(entries), fingerprint)


def read_manifest(path: str | Path) -> Manifest:
    try:
        with Path(path).open("rb") as handle:
            return parse_manifest(handle.read(MAX_MANIFEST_BYTES + 1))
    except OSError as exc:
        raise ManifestError("manifest_unreadable", "无法读取清单文件") from exc


def _inspect_entry(root: Path, entry: ManifestEntry) -> dict[str, Any]:
    path = root / entry.file
    if not path.is_file() or path.is_symlink():
        return {**entry.as_dict(), "status": "missing"}
    try:
        data = path.read_bytes()
    except OSError:
        return {**entry.as_dict(), "status": "unreadable"}
    digest = hashlib.sha256(data).hexdigest()
    if digest != entry.sha256:
        return {**entry.as_dict(), "status": "checksum_mismatch", "actual_sha256": digest}
    try:
        packet = protocol.parse_packet_bytes(data, entry.file)
    except protocol.PacketError as exc:
        return {**entry.as_dict(), "status": "invalid_packet", "reason": exc.code}
    if packet.envelope.station_id != entry.station_id or packet.envelope.sequence != entry.sequence:
        return {**entry.as_dict(), "status": "identity_mismatch"}
    return {**entry.as_dict(), "status": "ready", "packet_id": protocol.packet_identity(packet),
            "record_count": packet.envelope.record_count}


def preflight(connection: sqlite3.Connection, manifest_path: str | Path, *, strict: bool = False) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = read_manifest(manifest_file)
    root = manifest_file.parent
    inspected = [_inspect_entry(root, entry) for entry in manifest.entries]
    for item in inspected:
        if item["status"] != "ready":
            continue
        station = catalog.station(connection, item["station_id"])
        if station is None:
            item["status"] = "station_unknown"
        elif not station["active"]:
            item["status"] = "station_inactive"
        else:
            previous = store.batch_for_sequence(connection, item["station_id"], item["sequence"])
            if previous:
                item["status"] = "duplicate" if previous["packet_id"] == item["packet_id"] else "sequence_conflict"
    if strict and any(item["status"] not in {"ready", "duplicate"} for item in inspected):
        raise ManifestError("preflight_failed", "严格预检发现不可接受的条目")
    by_station: dict[str, list[dict[str, Any]]] = {}
    for item in inspected:
        by_station.setdefault(item["station_id"], []).append(item)
    ordered = []
    for station_id in sorted(by_station):
        rows = sorted(by_station[station_id], key=lambda item: (item["sequence"], item["file"]))
        cursor = store.station_cursor(connection, station_id)
        expected = int(cursor["committed_sequence"]) + 1 if cursor else 1
        blocked = False
        for item in rows:
            if item["status"] == "duplicate":
                ordered.append(item)
            elif item["status"] != "ready":
                blocked = True
                ordered.append(item)
            elif item["sequence"] != expected or blocked:
                ordered.append({**item, "status": "waiting_for_gap", "expected": expected})
                blocked = True
            else:
                ordered.append(item)
                expected += 1
    return {"name": manifest.name, "fingerprint": manifest.fingerprint, "entries": ordered,
            "ready": sum(item["status"] == "ready" for item in ordered),
            "blocked": sum(item["status"] not in {"ready", "duplicate"} for item in ordered)}


def execute_manifest(connection: sqlite3.Connection, manifest_path: str | Path, *, strict: bool = False,
                     when: str | None = None) -> dict[str, Any]:
    plan = preflight(connection, manifest_path, strict=strict)
    root = Path(manifest_path).parent
    results = []
    for entry in plan["entries"]:
        if entry["status"] == "duplicate":
            results.append({"file": entry["file"], "status": "duplicate"})
            continue
        if entry["status"] != "ready":
            results.append({"file": entry["file"], "status": "skipped", "reason": entry["status"]})
            continue
        path = root / entry["file"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            results.append({"file": entry["file"], "status": "skipped", "reason": "changed_after_preflight"})
            continue
        try:
            outcome = ingest.ingest_file(connection, path, when=when)
            results.append({"file": entry["file"], **outcome.as_dict()})
        except ingest.IngestError as exc:
            results.append({"file": entry["file"], **exc.as_dict()})
            if strict:
                break
    return {"manifest": plan["name"], "fingerprint": plan["fingerprint"], "results": results,
            "accepted": sum(item["status"] == "accepted" for item in results),
            "rejected": sum(item["status"] == "rejected" for item in results)}
