"""交接责任安排的修订历史。

外部回执只证明某一次交付中的接收情况。责任是否可以解除取决于回执所对应的
修订是否仍是当前修订，因此每一步责任变化都保留为不可变的事件。
"""
from __future__ import annotations

import sqlite3
from typing import Any

from . import catalog, store


class ResponsibilityError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _handoff(connection: sqlite3.Connection, handoff_id: int) -> dict[str, Any]:
    item = store.get_handoff(connection, handoff_id)
    if item is None:
        raise ResponsibilityError("handoff_missing", "交接项不存在")
    return item


def _label(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 100:
        raise ResponsibilityError("assignee", "责任人或岗位无效")
    return value.strip()


def ensure_created(connection: sqlite3.Connection, handoff_id: int, when: str) -> dict[str, Any]:
    """确保交接项至少有一条责任事件；旧库中的交接项按当前确认状态补齐。"""
    item = _handoff(connection, handoff_id)
    connection.execute(
        "INSERT OR IGNORE INTO responsibility_events"
        "(handoff_id,subscription_id,revision,event_type,state,assignee,occurred_at,reason) "
        "VALUES(?,?,1,'created','open',NULL,?, 'handoff_created')",
        (handoff_id, item["subscription_id"], item["created_at"]),
    )
    if connection.execute("SELECT COUNT(*) FROM responsibility_events WHERE handoff_id=?",
                          (handoff_id,)).fetchone()[0] == 1 and item["status"] == "acknowledged":
        connection.execute(
            "INSERT OR IGNORE INTO responsibility_events"
            "(handoff_id,subscription_id,revision,event_type,state,assignee,occurred_at,reason) "
            "VALUES(?,?,2,'acknowledged','acknowledged',?,?, 'legacy_local_ack')",
            (handoff_id, item["subscription_id"], item["operator"], item["acknowledged_at"]),
        )
    row = store.one(connection, "SELECT * FROM responsibility_events WHERE handoff_id=? "
                    "ORDER BY revision DESC LIMIT 1", (handoff_id,))
    assert row is not None
    return row


def current(connection: sqlite3.Connection, handoff_id: int, when: str) -> dict[str, Any]:
    return ensure_created(connection, handoff_id, when)


def local_acknowledge(connection: sqlite3.Connection, handoff_id: int, operator: str, when: str,
                      *, reason: str = "local_ack") -> dict[str, Any]:
    """记录值守人员在本地完成处置，与外部回执是两条独立的证据链。"""
    latest = current(connection, handoff_id, when)
    if latest["state"] == "acknowledged":
        return latest
    if latest["state"] == "released_external":
        raise ResponsibilityError("responsibility_released", "外部回执已解除责任，不能倒回本地确认")
    return _append(connection, latest, "acknowledged", "acknowledged", operator, when, reason, None)


def reassign(connection: sqlite3.Connection, handoff_id: int, assignee: str, *,
             reason: str | None = None, when: str | None = None) -> dict[str, Any]:
    operator = _label(assignee)
    timestamp = when or catalog.utc_now()
    if reason is not None and (not isinstance(reason, str) or len(reason) > 500):
        raise ResponsibilityError("reason", "改派理由无效")
    with store.transaction(connection):
        latest = current(connection, handoff_id, timestamp)
        if latest["state"] == "released_external":
            raise ResponsibilityError("responsibility_released", "外部回执已解除责任，不能再改派")
        event = _append(connection, latest, "reassigned", "open", operator, timestamp,
                        reason or "reassigned", None)
        store.record_activity(connection, "responsibility_reassigned", "handoff",
                              str(handoff_id), timestamp,
                              {"revision": event["revision"], "assignee": operator, "reason": reason})
    return event


def external_release(connection: sqlite3.Connection, handoff_id: int, receiver_id: str,
                     receipt_id: str, delivery_id: int, when: str,
                     *, delivered_revision: int) -> dict[str, Any]:
    """只有回执对应的修订仍是当前修订时才能解除当前责任。"""
    latest = current(connection, handoff_id, when)
    if latest["revision"] != delivered_revision:
        raise ResponsibilityError("responsibility_changed", "回执对应的责任修订已不是当前修订")
    if latest["state"] != "open":
        raise ResponsibilityError("responsibility_closed", "当前责任已由本地处置关闭")
    return _append(connection, latest, "externally_released", "released_external", receiver_id, when,
                   f"receipt:{receipt_id}", delivery_id)


def _append(connection: sqlite3.Connection, latest: dict[str, Any], event_type: str, state: str,
            assignee: str | None, when: str, reason: str, delivery_id: int | None) -> dict[str, Any]:
    revision = int(latest["revision"]) + 1
    connection.execute(
        "INSERT INTO responsibility_events"
        "(handoff_id,subscription_id,revision,event_type,state,assignee,occurred_at,reason,delivery_id) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (latest["handoff_id"], latest["subscription_id"], revision, event_type, state, assignee,
         when, reason[:500], delivery_id),
    )
    return store.one(connection, "SELECT * FROM responsibility_events WHERE handoff_id=? AND revision=?",
                     (latest["handoff_id"], revision))


def history(connection: sqlite3.Connection, handoff_id: int, when: str) -> list[dict[str, Any]]:
    current(connection, handoff_id, when)
    return store.many(connection, "SELECT * FROM responsibility_events WHERE handoff_id=? ORDER BY revision",
                      (handoff_id,))


def list_current(connection: sqlite3.Connection, *, subscription_id: str | None = None,
                 state: str | None = None, when: str | None = None, limit: int = 100,
                 after_id: int = 0) -> list[dict[str, Any]]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ResponsibilityError("limit", "查询上限须在 1 到 1000 之间")
    if state is not None and state not in {"open", "acknowledged", "released_external"}:
        raise ResponsibilityError("state", "责任状态无效")
    timestamp = when or catalog.utc_now()
    query = ("SELECT r.*,h.status AS handoff_status,h.created_at AS handoff_created_at,"
             "o.external_id,o.region,o.observed_at FROM responsibility_events r "
             "JOIN handoffs h USING(handoff_id) JOIN observations o USING(observation_id) "
             "WHERE r.responsibility_id=(SELECT MAX(r2.responsibility_id) FROM responsibility_events r2 "
             "WHERE r2.handoff_id=r.handoff_id) AND r.handoff_id>?")
    args: list[Any] = [after_id]
    if subscription_id is not None:
        query += " AND r.subscription_id=?"
        args.append(subscription_id)
    if state is not None:
        query += " AND r.state=?"
        args.append(state)
    query += " ORDER BY r.handoff_id LIMIT ?"
    args.append(limit)
    return store.many(connection, query, tuple(args))
