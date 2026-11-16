"""本地观测包协议：严格解析、完整性校验与稳定摘要。"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

MAX_PACKET_BYTES = 2_000_000
MAX_RECORDS = 5000
MAX_LINE_BYTES = 16_384


class PacketError(ValueError):
    def __init__(self, code: str, message: str, line: int | None = None):
        super().__init__(message)
        self.code = code
        self.line = line

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "line": self.line}


@dataclass(frozen=True)
class Envelope:
    station_id: str
    sequence: int
    created_at: str
    record_count: int
    digest: str
    schema: int


@dataclass(frozen=True)
class Packet:
    envelope: Envelope
    records: tuple[dict[str, Any], ...]
    canonical_digest: str
    source_name: str


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PacketError("not_json", "无法生成规范 JSON") from exc


def records_digest(records: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update(canonical_json(record))
        digest.update(b"\n")
    return digest.hexdigest()


def _is_int(value: object) -> bool:
    return type(value) is int


def _parse_line(raw: bytes, number: int) -> dict[str, Any]:
    if len(raw) > MAX_LINE_BYTES:
        raise PacketError("line_size", "单行超过大小限制", number)
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except (UnicodeError, ValueError) as exc:
        raise PacketError("bad_json", "无效 UTF-8 JSON 行", number) from exc
    if not isinstance(value, dict):
        raise PacketError("line_type", "每一行必须是 JSON 对象", number)
    return value


def _header(value: dict[str, Any]) -> Envelope:
    expected = {"kind", "schema", "station_id", "sequence", "created_at", "record_count", "digest"}
    if set(value) != expected or value.get("kind") != "packet":
        raise PacketError("header_fields", "包头字段不完整或包含未知字段", 1)
    if not _is_int(value["schema"]) or value["schema"] != 1:
        raise PacketError("schema", "仅支持协议版本 1", 1)
    station = value["station_id"]
    if not isinstance(station, str) or not (1 <= len(station) <= 64) or not all(c.isalnum() or c in "_-" for c in station):
        raise PacketError("station_id", "站点标识无效", 1)
    if not _is_int(value["sequence"]) or value["sequence"] < 1:
        raise PacketError("sequence", "序号须为正整数", 1)
    if not _is_int(value["record_count"]) or not (1 <= value["record_count"] <= MAX_RECORDS):
        raise PacketError("record_count", "观测记录数无效", 1)
    digest = value["digest"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise PacketError("digest_format", "SHA-256 摘要格式无效", 1)
    created = value["created_at"]
    if not isinstance(created, str) or len(created) > 40:
        raise PacketError("created_at", "创建时间格式无效", 1)
    return Envelope(station, value["sequence"], created, value["record_count"], digest, value["schema"])


def parse_packet_bytes(data: bytes, source_name: str = "<memory>") -> Packet:
    if not data or len(data) > MAX_PACKET_BYTES:
        raise PacketError("packet_size", "观测包为空或超过大小限制")
    lines = data.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise PacketError("empty_line", "观测包不得包含空行")
    if len(lines) > MAX_RECORDS + 1:
        raise PacketError("record_limit", "观测记录数超过限制")
    header = _header(_parse_line(lines[0], 1))
    if len(lines) - 1 != header.record_count:
        raise PacketError("count_mismatch", "包头记录数与正文不符", 1)
    records = []
    for number, line in enumerate(lines[1:], 2):
        record = _parse_line(line, number)
        if record.get("kind") != "observation":
            raise PacketError("record_kind", "正文必须为 observation", number)
        records.append(record)
    actual = records_digest(records)
    if actual != header.digest:
        raise PacketError("digest_mismatch", "包摘要与正文不一致")
    return Packet(header, tuple(records), actual, source_name)


def parse_packet_file(path: str | Path) -> Packet:
    source = Path(path)
    try:
        with source.open("rb") as handle:
            data = handle.read(MAX_PACKET_BYTES + 1)
    except OSError as exc:
        raise PacketError("source_unreadable", f"无法读取观测包：{source}") from exc
    return parse_packet_bytes(data, source.name)


def encode_packet(station_id: str, sequence: int, created_at: str, records: list[dict[str, Any]]) -> bytes:
    header = {"kind": "packet", "schema": 1, "station_id": station_id, "sequence": sequence,
              "created_at": created_at, "record_count": len(records), "digest": records_digest(records)}
    _header(header)
    return b"\n".join([canonical_json(header), *(canonical_json(row) for row in records)]) + b"\n"


def packet_identity(packet: Packet) -> str:
    value = {"station_id": packet.envelope.station_id, "sequence": packet.envelope.sequence,
             "created_at": packet.envelope.created_at, "digest": packet.canonical_digest}
    return hashlib.sha256(canonical_json(value)).hexdigest()
