"""可核对的交接清单导出与来源摘要。"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import catalog, protocol, store


class ExportError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ExportReceipt:
    subscription_id: str
    maximum_handoff_id: int
    rows: int
    sha256: str
    destination: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _validate_window(start_id: int, end_id: int | None) -> None:
    if type(start_id) is not int or start_id < 0:
        raise ExportError("start_id", "导出起点无效")
    if end_id is not None and (type(end_id) is not int or end_id < start_id):
        raise ExportError("end_id", "导出终点无效")


def snapshot_rows(connection: sqlite3.Connection, subscription_id: str, *, start_id: int = 0,
                  end_id: int | None = None, status: str | None = None) -> tuple[int, list[dict[str, Any]]]:
    _validate_window(start_id, end_id)
    if catalog.subscription(connection, subscription_id) is None:
        raise ExportError("subscription_missing", "订阅不存在")
    if status is not None and status not in {"pending", "acknowledged"}:
        raise ExportError("status", "交接状态无效")
    connection.execute("BEGIN")
    try:
        if end_id is None:
            maximum = int(connection.execute("SELECT COALESCE(MAX(handoff_id),0) FROM handoffs "
                                             "WHERE subscription_id=?", (subscription_id,)).fetchone()[0])
        else:
            maximum = end_id
        query = ("SELECT h.handoff_id,h.status,h.created_at,h.acknowledged_at,h.operator,h.subscription_id,"
                 "o.observation_id,o.station_id,o.external_id,o.observed_at,o.region,o.latitude,o.longitude,"
                 "o.confidence,o.severity,o.source,o.fingerprint,b.batch_id,b.sequence,b.packet_id,b.digest "
                 "FROM handoffs h JOIN observations o USING(observation_id) "
                 "JOIN batches b ON b.batch_id=o.batch_id "
                 "WHERE h.subscription_id=? AND h.handoff_id>? AND h.handoff_id<=?")
        args: list[Any] = [subscription_id, start_id, maximum]
        if status is not None:
            query += " AND h.status=?"
            args.append(status)
        query += " ORDER BY h.handoff_id"
        rows = store.many(connection, query, tuple(args))
        return maximum, rows
    finally:
        connection.rollback()


def serialize_rows(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(protocol.canonical_json(row) + b"\n" for row in rows)


def export_handoffs(connection: sqlite3.Connection, subscription_id: str, destination: str | Path,
                    *, start_id: int = 0, end_id: int | None = None,
                    status: str | None = None) -> ExportReceipt:
    maximum, rows = snapshot_rows(connection, subscription_id, start_id=start_id, end_id=end_id, status=status)
    data = serialize_rows(rows)
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ExportError("destination_exists", "导出目标已存在，拒绝覆盖")
    try:
        with path.open("xb") as handle:
            handle.write(data)
    except OSError as exc:
        raise ExportError("write_failed", "无法写入导出目标") from exc
    return ExportReceipt(subscription_id, maximum, len(rows), hashlib.sha256(data).hexdigest(), str(path))


def verify_export(path: str | Path, sha256: str, *, expected_rows: int | None = None) -> dict[str, Any]:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ExportError("read_failed", "无法读取导出文件") from exc
    actual = hashlib.sha256(data).hexdigest()
    if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
        raise ExportError("digest_format", "摘要格式无效")
    rows = data.splitlines()
    previous = 0
    for number, line in enumerate(rows, 1):
        try:
            row = json.loads(line.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ExportError("row_json", f"第 {number} 行不是有效 JSON") from exc
        if not isinstance(row, dict) or type(row.get("handoff_id")) is not int:
            raise ExportError("row_fields", f"第 {number} 行缺少交接编号")
        if row["handoff_id"] <= previous:
            raise ExportError("row_order", "交接编号未严格递增")
        previous = row["handoff_id"]
    return {"ok": actual == sha256 and (expected_rows is None or len(rows) == expected_rows),
            "sha256": actual, "rows": len(rows), "last_handoff_id": previous}
