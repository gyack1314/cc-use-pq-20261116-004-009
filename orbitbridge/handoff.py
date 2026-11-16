"""从已提交观测生成交接项，并负责确认状态。"""
from __future__ import annotations

import sqlite3
from typing import Any

from . import catalog, store
from .normalize import Observation


class HandoffError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def route_observation(connection: sqlite3.Connection, observation_id: int, observation: Observation, when: str) -> int:
    matches = catalog.matching_subscriptions(connection, observation.region, observation.severity, observation.confidence)
    for subscription in matches:
        cursor = connection.execute(
            "INSERT INTO handoffs(observation_id,subscription_id,status,created_at) VALUES(?,?,'pending',?)",
            (observation_id, subscription["subscription_id"], when),
        )
        handoff_id = int(cursor.lastrowid)
        store.record_activity(connection, "handoff_created", "handoff", str(handoff_id), when,
                              {"observation_id": observation_id, "subscription_id": subscription["subscription_id"]})
    return len(matches)


def acknowledge(connection: sqlite3.Connection, handoff_id: int, operator: str, *, when: str | None = None) -> dict[str, Any]:
    if type(handoff_id) is not int or handoff_id < 1:
        raise HandoffError("handoff_id", "交接编号无效")
    if not isinstance(operator, str) or not 1 <= len(operator.strip()) <= 100:
        raise HandoffError("operator", "确认人无效")
    timestamp = when or catalog.utc_now()
    with store.transaction(connection):
        item = store.get_handoff(connection, handoff_id)
        if item is None:
            raise HandoffError("handoff_missing", "交接项不存在")
        if item["status"] == "acknowledged":
            if item["operator"] != operator.strip():
                raise HandoffError("already_acknowledged", "交接项已由其他人员确认")
            return {**item, "status": "duplicate"}
        changed = connection.execute(
            "UPDATE handoffs SET status='acknowledged',acknowledged_at=?,operator=? "
            "WHERE handoff_id=? AND status='pending'", (timestamp, operator.strip(), handoff_id),
        ).rowcount
        if changed != 1:
            raise HandoffError("acknowledge_conflict", "确认状态冲突")
        store.record_activity(connection, "handoff_acknowledged", "handoff", str(handoff_id), timestamp,
                              {"operator": operator.strip()})
    return {"status": "acknowledged", **store.get_handoff(connection, handoff_id)}


def list_handoffs(connection: sqlite3.Connection, *, subscription_id: str | None = None,
                  status: str | None = None, limit: int = 100, after_id: int = 0) -> list[dict[str, Any]]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise HandoffError("limit", "查询上限须在 1 到 1000 之间")
    if type(after_id) is not int or after_id < 0:
        raise HandoffError("after_id", "游标无效")
    if status is not None and status not in {"pending", "acknowledged"}:
        raise HandoffError("status", "交接状态无效")
    query = ("SELECT h.*,o.station_id,o.external_id,o.observed_at,o.region,o.latitude,o.longitude,"
             "o.confidence,o.severity,o.source,o.batch_id,b.sequence,b.packet_id "
             "FROM handoffs h JOIN observations o USING(observation_id) "
             "JOIN batches b ON b.batch_id=o.batch_id WHERE h.handoff_id>?")
    args: list[Any] = [after_id]
    if subscription_id is not None:
        query += " AND h.subscription_id=?"
        args.append(subscription_id)
    if status is not None:
        query += " AND h.status=?"
        args.append(status)
    query += " ORDER BY h.handoff_id LIMIT ?"
    args.append(limit)
    return store.many(connection, query, tuple(args))


def handoff_detail(connection: sqlite3.Connection, handoff_id: int) -> dict[str, Any] | None:
    rows = store.many(connection,
        "SELECT h.*,o.station_id,o.external_id,o.observed_at,o.region,o.latitude,o.longitude,o.confidence,"
        "o.severity,o.source,o.fingerprint,o.batch_id,b.sequence,b.packet_id,b.digest,b.source_name "
        "FROM handoffs h JOIN observations o USING(observation_id) JOIN batches b ON b.batch_id=o.batch_id "
        "WHERE h.handoff_id=?", (handoff_id,))
    return rows[0] if rows else None


def subscription_summary(connection: sqlite3.Connection, subscription_id: str) -> dict[str, Any]:
    subscription = catalog.subscription(connection, subscription_id)
    if not subscription:
        raise HandoffError("subscription_missing", "订阅不存在")
    rows = store.many(connection, "SELECT status,COUNT(*) AS amount FROM handoffs WHERE subscription_id=? GROUP BY status",
                      (subscription_id,))
    counts = {row["status"]: row["amount"] for row in rows}
    return {"subscription": subscription, "pending": counts.get("pending", 0),
            "acknowledged": counts.get("acknowledged", 0)}
