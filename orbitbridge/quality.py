"""跨表业务不变量和数据质量诊断。"""
from __future__ import annotations

import sqlite3
from collections import Counter
from decimal import Decimal
from typing import Any

from . import store


def check_all(connection: sqlite3.Connection) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    def issue(code: str, entity: str, identifier: str, detail: str) -> None:
        issues.append({"code": code, "entity": entity, "id": identifier, "detail": detail})
    for item in store.integrity_check(connection):
        issue("storage_integrity", "database", "0", item)
    for station in connection.execute("SELECT station_id,committed_sequence,last_batch_id FROM station_cursors"):
        station_id, cursor, last_id = station
        batches = list(connection.execute("SELECT batch_id,sequence FROM batches WHERE station_id=? ORDER BY sequence",
                                          (station_id,)))
        if len(batches) != cursor:
            issue("sequence_gap", "station", station_id, f"游标 {cursor}，批次数 {len(batches)}")
        for expected, batch in enumerate(batches, 1):
            if batch["sequence"] != expected:
                issue("sequence_gap", "batch", str(batch["batch_id"]),
                      f"预期序号 {expected}，实际 {batch['sequence']}")
        if batches and batches[-1]["batch_id"] != last_id:
            issue("last_batch", "station", station_id, "游标末尾批次不匹配")
        if not batches and last_id is not None:
            issue("last_batch", "station", station_id, "空站点不应引用批次")
    for row in connection.execute("SELECT o.*,b.station_id AS batch_station FROM observations o "
                                  "JOIN batches b ON b.batch_id=o.batch_id"):
        identifier = str(row["observation_id"])
        if row["station_id"] != row["batch_station"]:
            issue("station_mismatch", "observation", identifier, "观测站点与批次站点不符")
        if not Decimal("0") <= Decimal(row["confidence"]) <= Decimal("1"):
            issue("confidence_range", "observation", identifier, "置信度越界")
        if not 1 <= row["severity"] <= 5:
            issue("severity_range", "observation", identifier, "火情等级越界")
    for row in connection.execute("SELECT h.*,o.region,o.confidence,o.severity,s.region AS subscription_region,"
                                  "s.minimum_confidence,s.minimum_severity,b.received_at FROM handoffs h "
                                  "JOIN observations o USING(observation_id) JOIN subscriptions s USING(subscription_id) "
                                  "JOIN batches b ON b.batch_id=o.batch_id"):
        identifier = str(row["handoff_id"])
        if row["region"] != row["subscription_region"]:
            issue("region_mismatch", "handoff", identifier, "交接区域与订阅区域不符")
        if row["severity"] < row["minimum_severity"] or Decimal(row["confidence"]) < Decimal(row["minimum_confidence"]):
            issue("threshold_mismatch", "handoff", identifier, "交接项不满足订阅阈值")
        if row["created_at"] < row["received_at"]:
            issue("created_before_batch", "handoff", identifier, "交接时间早于批次接收时间")
        if row["status"] == "acknowledged" and row["acknowledged_at"] < row["created_at"]:
            issue("ack_before_create", "handoff", identifier, "确认时间早于交接创建时间")
    return {"ok": not issues, "issues": issues, "counts": store.counts(connection)}


def station_quality(connection: sqlite3.Connection, station_id: str) -> dict[str, Any]:
    cursor = store.station_cursor(connection, station_id)
    if cursor is None:
        raise ValueError("站点不存在")
    by_reason = Counter()
    for row in connection.execute("SELECT reason_code,attempts FROM quarantine WHERE station_id=?", (station_id,)):
        by_reason[row["reason_code"]] += row["attempts"]
    return {"station_id": station_id, "committed_sequence": cursor["committed_sequence"],
            "rejections_by_reason": dict(sorted(by_reason.items())),
            "observation_count": connection.execute("SELECT COUNT(*) FROM observations WHERE station_id=?",
                                                     (station_id,)).fetchone()[0]}


def quarantine_quality(connection: sqlite3.Connection) -> dict[str, Any]:
    rows = store.many(connection, "SELECT reason_code,COUNT(*) AS unique_packets,SUM(attempts) AS attempts "
                      "FROM quarantine GROUP BY reason_code ORDER BY reason_code")
    return {"reasons": rows, "total_unique": sum(row["unique_packets"] for row in rows),
            "total_attempts": sum(row["attempts"] for row in rows)}
