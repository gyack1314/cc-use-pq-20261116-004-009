"""值守人员的批次、来源、隔离及活动追溯查询。"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import catalog, handoff, store


class AuditError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _page(limit: int, after_id: int) -> None:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise AuditError("limit", "查询上限须为 1 到 1000")
    if type(after_id) is not int or after_id < 0:
        raise AuditError("after_id", "查询游标无效")


def list_batches(connection: sqlite3.Connection, *, station_id: str | None = None,
                 limit: int = 100, after_id: int = 0) -> list[dict[str, Any]]:
    _page(limit, after_id)
    if station_id is None:
        return store.many(connection, "SELECT * FROM batches WHERE batch_id>? ORDER BY batch_id LIMIT ?",
                          (after_id, limit))
    return store.many(connection, "SELECT * FROM batches WHERE batch_id>? AND station_id=? "
                      "ORDER BY batch_id LIMIT ?", (after_id, station_id, limit))


def batch_detail(connection: sqlite3.Connection, batch_id: int) -> dict[str, Any] | None:
    batch = store.get_batch(connection, batch_id)
    if batch is None:
        return None
    observations = store.many(connection, "SELECT * FROM observations WHERE batch_id=? ORDER BY observation_id",
                              (batch_id,))
    handoffs = store.many(connection, "SELECT h.* FROM handoffs h JOIN observations o USING(observation_id) "
                          "WHERE o.batch_id=? ORDER BY h.handoff_id", (batch_id,))
    return {"batch": batch, "observations": observations, "handoffs": handoffs}


def list_observations(connection: sqlite3.Connection, *, region: str | None = None, station_id: str | None = None,
                      limit: int = 100, after_id: int = 0) -> list[dict[str, Any]]:
    _page(limit, after_id)
    query = "SELECT * FROM observations WHERE observation_id>?"
    args: list[Any] = [after_id]
    if region is not None:
        query += " AND region=?"
        args.append(region)
    if station_id is not None:
        query += " AND station_id=?"
        args.append(station_id)
    query += " ORDER BY observation_id LIMIT ?"
    args.append(limit)
    return store.many(connection, query, tuple(args))


def observation_detail(connection: sqlite3.Connection, observation_id: int) -> dict[str, Any] | None:
    observation = store.get_observation(connection, observation_id)
    if not observation:
        return None
    batch = store.get_batch(connection, observation["batch_id"])
    handoffs = store.many(connection, "SELECT * FROM handoffs WHERE observation_id=? ORDER BY handoff_id",
                          (observation_id,))
    return {"observation": observation, "batch": batch, "handoffs": handoffs}


def list_quarantine(connection: sqlite3.Connection, *, station_id: str | None = None,
                    limit: int = 100, after_id: int = 0) -> list[dict[str, Any]]:
    _page(limit, after_id)
    if station_id is None:
        return store.many(connection, "SELECT * FROM quarantine WHERE quarantine_id>? "
                          "ORDER BY quarantine_id LIMIT ?", (after_id, limit))
    return store.many(connection, "SELECT * FROM quarantine WHERE quarantine_id>? AND station_id=? "
                      "ORDER BY quarantine_id LIMIT ?", (after_id, station_id, limit))


def list_activity(connection: sqlite3.Connection, *, entity_type: str | None = None, entity_id: str | None = None,
                  limit: int = 100, after_id: int = 0) -> list[dict[str, Any]]:
    _page(limit, after_id)
    query = "SELECT * FROM activity WHERE activity_id>?"
    args: list[Any] = [after_id]
    if entity_type is not None:
        query += " AND entity_type=?"
        args.append(entity_type)
    if entity_id is not None:
        if entity_type is None:
            raise AuditError("entity_filter", "按实体编号过滤时必须指定实体类型")
        query += " AND entity_id=?"
        args.append(entity_id)
    query += " ORDER BY activity_id LIMIT ?"
    args.append(limit)
    rows = store.many(connection, query, tuple(args))
    for row in rows:
        row["details"] = json.loads(row.pop("details_json"))
    return rows


def station_report(connection: sqlite3.Connection, station_id: str) -> dict[str, Any]:
    item = catalog.station(connection, station_id)
    if item is None:
        raise AuditError("station_missing", "站点不存在")
    batches = int(connection.execute("SELECT COUNT(*) FROM batches WHERE station_id=?", (station_id,)).fetchone()[0])
    observations = int(connection.execute("SELECT COUNT(*) FROM observations WHERE station_id=?", (station_id,)).fetchone()[0])
    quarantined = int(connection.execute("SELECT COUNT(*) FROM quarantine WHERE station_id=?", (station_id,)).fetchone()[0])
    return {"station": item, "batches": batches, "observations": observations, "quarantined": quarantined}


def region_report(connection: sqlite3.Connection, region: str) -> dict[str, Any]:
    observations = store.one(connection, "SELECT COUNT(*) AS count,MAX(observed_at) AS latest FROM observations WHERE region=?",
                             (region,))
    status_rows = store.many(connection, "SELECT h.status,COUNT(*) AS count FROM handoffs h "
                             "JOIN observations o USING(observation_id) WHERE o.region=? GROUP BY h.status", (region,))
    status = {row["status"]: row["count"] for row in status_rows}
    return {"region": region, "observations": observations["count"], "latest": observations["latest"],
            "pending": status.get("pending", 0), "acknowledged": status.get("acknowledged", 0),
            "subscriptions": catalog.list_subscriptions(connection, region)}


def handoff_trace(connection: sqlite3.Connection, handoff_id: int) -> dict[str, Any]:
    detail = handoff.handoff_detail(connection, handoff_id)
    if detail is None:
        raise AuditError("handoff_missing", "交接项不存在")
    history = list_activity(connection, entity_type="handoff", entity_id=str(handoff_id), limit=1000)
    return {"handoff": detail, "activity": history}


def summary(connection: sqlite3.Connection) -> dict[str, Any]:
    return {"counts": store.counts(connection), "stations": catalog.list_stations(connection),
            "integrity_issues": store.integrity_check(connection)}


def verify_lineage(connection: sqlite3.Connection) -> list[str]:
    issues = store.integrity_check(connection)
    for row in connection.execute("SELECT h.handoff_id,h.created_at,b.received_at,o.region,s.region AS subscription_region "
                                  "FROM handoffs h JOIN observations o USING(observation_id) "
                                  "JOIN batches b ON b.batch_id=o.batch_id "
                                  "JOIN subscriptions s USING(subscription_id)"):
        if row["region"] != row["subscription_region"]:
            issues.append(f"region_mismatch:{row['handoff_id']}")
        if row["created_at"] < row["received_at"]:
            issues.append(f"handoff_before_batch:{row['handoff_id']}")
    for row in connection.execute("SELECT b.batch_id,b.station_id,b.sequence,c.committed_sequence "
                                  "FROM batches b JOIN station_cursors c USING(station_id)"):
        if row["sequence"] > row["committed_sequence"]:
            issues.append(f"uncommitted_batch:{row['batch_id']}")
    return issues
