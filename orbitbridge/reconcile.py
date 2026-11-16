"""按站点和区域核对采集、隔离及交接数量。"""
from __future__ import annotations

import sqlite3
from typing import Any

from . import catalog, store


class ReconcileError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def batch_counts(connection: sqlite3.Connection, batch_id: int) -> dict[str, Any]:
    batch = store.get_batch(connection, batch_id)
    if batch is None:
        raise ReconcileError("batch_missing", "批次不存在")
    observations = store.many(connection,
        "SELECT region,COUNT(*) AS count,MIN(observed_at) AS first_observed,MAX(observed_at) AS last_observed "
        "FROM observations WHERE batch_id=? GROUP BY region ORDER BY region", (batch_id,))
    handoffs = store.many(connection,
        "SELECT h.subscription_id,h.status,COUNT(*) AS count FROM handoffs h "
        "JOIN observations o USING(observation_id) WHERE o.batch_id=? "
        "GROUP BY h.subscription_id,h.status ORDER BY h.subscription_id,h.status", (batch_id,))
    total = sum(item["count"] for item in observations)
    return {"batch": batch, "observation_total": total, "expected_total": batch["record_count"],
            "observations_by_region": observations, "handoffs": handoffs,
            "balanced": total == batch["record_count"]}


def station_counts(connection: sqlite3.Connection, station_id: str) -> dict[str, Any]:
    station = catalog.station(connection, station_id)
    if station is None:
        raise ReconcileError("station_missing", "站点不存在")
    batches = store.many(connection, "SELECT batch_id,sequence,record_count FROM batches WHERE station_id=? ORDER BY sequence",
                         (station_id,))
    batch_total = sum(row["record_count"] for row in batches)
    observed = connection.execute("SELECT COUNT(*) FROM observations WHERE station_id=?", (station_id,)).fetchone()[0]
    rejected = store.many(connection, "SELECT reason_code,COUNT(*) AS unique_packets,SUM(attempts) AS attempts "
                          "FROM quarantine WHERE station_id=? GROUP BY reason_code ORDER BY reason_code", (station_id,))
    cursor = station["committed_sequence"]
    contiguous = cursor == len(batches) and all(row["sequence"] == index for index, row in enumerate(batches, 1))
    return {"station": station, "batch_count": len(batches), "batch_record_count": batch_total,
            "observation_count": observed, "rejections": rejected,
            "balanced": batch_total == observed and contiguous}


def subscription_counts(connection: sqlite3.Connection, subscription_id: str) -> dict[str, Any]:
    subscription = catalog.subscription(connection, subscription_id)
    if subscription is None:
        raise ReconcileError("subscription_missing", "订阅不存在")
    rows = store.many(connection, "SELECT h.status,COUNT(*) AS count,MIN(h.handoff_id) AS first_id,"
                      "MAX(h.handoff_id) AS last_id FROM handoffs h WHERE h.subscription_id=? GROUP BY h.status",
                      (subscription_id,))
    station_rows = store.many(connection, "SELECT o.station_id,COUNT(*) AS count FROM handoffs h "
                              "JOIN observations o USING(observation_id) WHERE h.subscription_id=? "
                              "GROUP BY o.station_id ORDER BY o.station_id", (subscription_id,))
    received = sum(row["count"] for row in rows)
    by_station = sum(row["count"] for row in station_rows)
    return {"subscription": subscription, "handoff_count": received, "by_status": rows,
            "by_station": station_rows, "balanced": received == by_station}


def day_counts(connection: sqlite3.Connection, day: str) -> dict[str, Any]:
    if len(day) != 10 or day[4] != "-" or day[7] != "-" or not day.replace("-", "").isdigit():
        raise ReconcileError("day_format", "日期格式须为 YYYY-MM-DD")
    batches = store.many(connection, "SELECT station_id,COUNT(*) AS batches,SUM(record_count) AS records "
                         "FROM batches WHERE substr(received_at,1,10)=? GROUP BY station_id ORDER BY station_id", (day,))
    handoffs = store.many(connection, "SELECT subscription_id,COUNT(*) AS handoffs FROM handoffs "
                          "WHERE substr(created_at,1,10)=? GROUP BY subscription_id ORDER BY subscription_id", (day,))
    rejected = store.many(connection, "SELECT reason_code,COUNT(*) AS unique_packets FROM quarantine "
                          "WHERE substr(first_seen,1,10)=? GROUP BY reason_code ORDER BY reason_code", (day,))
    return {"day": day, "stations": batches, "subscriptions": handoffs, "rejections": rejected,
            "batch_count": sum(row["batches"] for row in batches),
            "observation_count": sum(row["records"] for row in batches),
            "handoff_count": sum(row["handoffs"] for row in handoffs)}


def full_reconciliation(connection: sqlite3.Connection) -> dict[str, Any]:
    stations = [station_counts(connection, row["station_id"]) for row in catalog.list_stations(connection)]
    subscriptions = [subscription_counts(connection, row["subscription_id"])
                     for row in catalog.list_subscriptions(connection)]
    problems = []
    for item in stations:
        if not item["balanced"]:
            problems.append({"kind": "station", "id": item["station"]["station_id"]})
    for item in subscriptions:
        if not item["balanced"]:
            problems.append({"kind": "subscription", "id": item["subscription"]["subscription_id"]})
    return {"ok": not problems, "stations": stations, "subscriptions": subscriptions,
            "problems": problems}
