"""外部离线交接回执的接收、核对与责任判定。

回执不是按交接号直接销账的凭证。每条回执必须同时引用：

* 交付标识（delivery_key）——确认的是哪一份清单；
* 清单中每一项的交接编号、观测指纹与责任修订——确认的是哪次责任安排。

清单或接收方尚未补齐时回执保持"待核"；内容、身份或逐项覆盖不成立时保留
"争议"。相同身份重复送同一内容只累加尝试次数，不重复销账；相同身份换成
不同内容时保留第一份并记录冲突。回执只在责任修订仍为交付时的修订、且本地
尚未完成处置时才能解除当前责任。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from . import catalog, export, protocol, responsibility, store
from .normalize import ObservationError, parse_time

RECEIPT_KIND = "handoff-receipt"
RECEIPT_SCHEMA = 1
RECEIPT_MANIFEST_KIND = "handoff-receipts"
MAX_RECEIPT_BYTES = 1_000_000
MAX_RECEIPT_MANIFEST_BYTES = 1_000_000
MAX_RECEIPT_FILES = 500


class ReceiptError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ReceiptItem:
    handoff_id: int
    observation_fingerprint: str
    result: str
    note: str | None = None


@dataclass(frozen=True)
class ParsedReceipt:
    receipt_id: str
    receiver_id: str
    delivery_key: str
    received_at: str
    items: tuple[ReceiptItem, ...]
    payload: dict[str, Any]

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(protocol.canonical_json(self.payload)).hexdigest()


def _identifier(value: object, code: str, message: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not all(
            character.isalnum() or character in "_.:-" for character in value):
        raise ReceiptError(code, message)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ReceiptError(code, "摘要格式无效")
    return value


def parse_receipt_bytes(data: bytes) -> ParsedReceipt:
    if not data or len(data) > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt_size", "回执为空或过大")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ReceiptError("receipt_json", "回执不是有效 UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != {
            "kind", "schema", "receipt_id", "receiver_id", "delivery_key", "received_at", "items"}:
        raise ReceiptError("receipt_fields", "回执字段不完整或包含未知字段")
    if value["kind"] != RECEIPT_KIND:
        raise ReceiptError("receipt_kind", "文件不是交接回执")
    if type(value["schema"]) is not int or value["schema"] != RECEIPT_SCHEMA:
        raise ReceiptError("receipt_schema", "仅支持回执版本 1")
    receipt_id = _identifier(value["receipt_id"], "receipt_id", "回执编号无效")
    receiver_id = _identifier(value["receiver_id"], "receiver_id", "接收方标识无效")
    delivery_key = _digest(value["delivery_key"], "delivery_key")
    try:
        parse_time(value["received_at"], 1, "received_at")
    except ObservationError as exc:
        raise ReceiptError("received_at", "接收时间无效") from exc
    items = value["items"]
    if not isinstance(items, list) or not items:
        raise ReceiptError("receipt_items", "回执须包含逐项结果")
    parsed: list[ReceiptItem] = []
    seen: set[int] = set()
    for item in items:
        if not isinstance(item, dict) or not {"handoff_id", "observation_fingerprint", "result"}.issubset(item) \
                or set(item) - {"handoff_id", "observation_fingerprint", "result", "note"}:
            raise ReceiptError("item_fields", "回执条目字段无效")
        handoff_id = item["handoff_id"]
        if type(handoff_id) is not int or handoff_id < 1:
            raise ReceiptError("item_handoff", "回执交接编号无效")
        if handoff_id in seen:
            raise ReceiptError("item_duplicate", "回执交接编号重复")
        seen.add(handoff_id)
        fingerprint = _digest(item["observation_fingerprint"], "item_fingerprint")
        if item["result"] not in {"received", "not_received"}:
            raise ReceiptError("item_result", "回执条目结果无效")
        note = item.get("note")
        if note is not None and (not isinstance(note, str) or len(note) > 300):
            raise ReceiptError("item_note", "回执条目说明无效")
        parsed.append(ReceiptItem(handoff_id, fingerprint, item["result"], note))
    return ParsedReceipt(receipt_id, receiver_id, delivery_key, value["received_at"], tuple(parsed), value)


def register_receiver(connection: sqlite3.Connection, receiver_id: str, label: str, *,
                      when: str | None = None) -> dict[str, Any]:
    identifier = _identifier(receiver_id, "receiver_id", "接收方标识无效")
    if not isinstance(label, str) or not 1 <= len(label.strip()) <= 120:
        raise ReceiptError("receiver_label", "接收方名称无效")
    timestamp = when or catalog.utc_now()
    with store.transaction(connection):
        if store.one(connection, "SELECT 1 FROM receivers WHERE receiver_id=?", (identifier,)):
            raise ReceiptError("receiver_exists", "接收方已登记")
        connection.execute("INSERT INTO receivers(receiver_id,label,active,created_at) VALUES(?,?,1,?)",
                           (identifier, label.strip(), timestamp))
        store.record_activity(connection, "receiver_registered", "receiver", identifier, timestamp,
                              {"label": label.strip()})
    return receiver(connection, identifier)


def set_receiver_active(connection: sqlite3.Connection, receiver_id: str, active: bool) -> dict[str, Any]:
    if type(active) is not bool:
        raise ReceiptError("active_type", "接收方状态必须为布尔值")
    with store.transaction(connection):
        changed = connection.execute("UPDATE receivers SET active=? WHERE receiver_id=?",
                                     (int(active), receiver_id)).rowcount
        if not changed:
            raise ReceiptError("receiver_missing", "接收方不存在")
        store.record_activity(connection, "receiver_state", "receiver", receiver_id, catalog.utc_now(),
                              {"active": active})
    return receiver(connection, receiver_id)


def receiver(connection: sqlite3.Connection, receiver_id: str) -> dict[str, Any] | None:
    return store.one(connection, "SELECT * FROM receivers WHERE receiver_id=?", (receiver_id,))


def list_receivers(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    return store.many(connection, "SELECT * FROM receivers ORDER BY receiver_id")


def _delivery_integrity(connection: sqlite3.Connection, delivery: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    try:
        header = json.loads(delivery["header_json"])
    except ValueError:
        return ["descriptor_json"]
    if not isinstance(header, dict):
        return ["descriptor_json"]
    body = delivery["body_text"].encode("utf-8")
    if hashlib.sha256(body).hexdigest() != delivery["body_sha256"]:
        problems.append("body_digest")
    if hashlib.sha256(protocol.canonical_json(header) + b"\n").hexdigest() != delivery["descriptor_sha256"]:
        problems.append("descriptor_digest")
    if header.get("delivery_key") != delivery["delivery_key"]:
        problems.append("delivery_key")
    if header.get("body_sha256") != delivery["body_sha256"]:
        problems.append("descriptor_body_digest")
    rows = [line for line in delivery["body_text"].splitlines() if line]
    items = export.delivery_items(connection, delivery["delivery_id"])
    if len(rows) != delivery["rows"] or len(items) != delivery["rows"]:
        problems.append("coverage")
    for line, item in zip(rows, items):
        try:
            row = json.loads(line)
        except ValueError:
            problems.append("body_row")
            continue
        if row.get("handoff_id") != item["handoff_id"]:
            problems.append("item_order")
        if row.get("fingerprint") != item["observation_fingerprint"]:
            problems.append("item_fingerprint")
    return problems


def _coverage_problems(delivery_items: list[dict[str, Any]], parsed: ParsedReceipt) -> list[dict[str, Any]]:
    delivered = {item["handoff_id"]: item for item in delivery_items}
    received = {item.handoff_id: item for item in parsed.items}
    problems: list[dict[str, Any]] = []
    for handoff_id in sorted(set(delivered) - set(received)):
        problems.append({"code": "coverage_missing", "handoff_id": handoff_id})
    for handoff_id in sorted(set(received) - set(delivered)):
        problems.append({"code": "coverage_unknown", "handoff_id": handoff_id})
    for handoff_id in sorted(set(delivered) & set(received)):
        if received[handoff_id].observation_fingerprint != delivered[handoff_id]["observation_fingerprint"]:
            problems.append({"code": "fingerprint_mismatch", "handoff_id": handoff_id})
    return problems


def _verdict(connection: sqlite3.Connection, delivered: dict[str, Any], item: ReceiptItem,
             when: str) -> dict[str, Any]:
    latest = responsibility.current(connection, delivered["handoff_id"], when)
    current_revision = int(latest["revision"])
    facts = {"handoff_id": delivered["handoff_id"], "delivered_revision": delivered["responsibility_revision"],
             "current_revision": current_revision,
             "record_status_at_delivery": delivered["status_at_delivery"],
             "current_status": latest["state"]}
    if item.result == "not_received":
        return {**facts, "accepted": False, "verdict": "retained", "reason_code": "not_received"}
    if latest["state"] == "released_external":
        return {**facts, "accepted": True, "verdict": "already_released", "reason_code": "already_released"}
    if latest["state"] == "acknowledged":
        return {**facts, "accepted": True, "verdict": "retained", "reason_code": "locally_acknowledged"}
    if current_revision != delivered["responsibility_revision"]:
        return {**facts, "accepted": True, "verdict": "retained", "reason_code": "responsibility_changed"}
    return {**facts, "accepted": True, "verdict": "released", "reason_code": "responsibility_confirmed"}


def _coverage_verdicts(delivery_items: list[dict[str, Any]], parsed: ParsedReceipt,
                       when: str, connection: sqlite3.Connection) -> list[dict[str, Any]]:
    received = {item.handoff_id: item for item in parsed.items}
    verdicts = []
    for delivered in delivery_items:
        entry = received.get(delivered["handoff_id"])
        latest = responsibility.current(connection, delivered["handoff_id"], when)
        facts = {"handoff_id": delivered["handoff_id"],
                 "delivered_revision": delivered["responsibility_revision"],
                 "current_revision": int(latest["revision"]),
                 "record_status_at_delivery": delivered["status_at_delivery"],
                 "current_status": latest["state"]}
        if entry is None:
            verdicts.append({**facts, "accepted": False, "verdict": "unmatched",
                             "reason_code": "coverage_missing"})
        elif entry.observation_fingerprint != delivered["observation_fingerprint"]:
            verdicts.append({**facts, "accepted": False, "verdict": "unmatched",
                             "reason_code": "fingerprint_mismatch"})
        else:
            verdicts.append({**facts, "accepted": bool(entry.result == "received"),
                             "verdict": "pending", "reason_code": "coverage_incomplete"})
    known = {item["handoff_id"] for item in delivery_items}
    for entry in parsed.items:
        if entry.handoff_id in known:
            continue
        verdicts.append({"handoff_id": entry.handoff_id, "delivered_revision": None, "current_revision": None,
                         "record_status_at_delivery": None, "current_status": None, "accepted": False,
                         "verdict": "unmatched", "reason_code": "coverage_unknown"})
    return verdicts


def _delete_items(connection: sqlite3.Connection, receipt_pk: int) -> None:
    connection.execute("DELETE FROM receipt_items WHERE receipt_pk=?", (receipt_pk,))


def _record_items(connection: sqlite3.Connection, receipt_pk: int, delivery_id: int | None,
                  verdicts: list[dict[str, Any]]) -> None:
    _delete_items(connection, receipt_pk)
    for verdict in verdicts:
        connection.execute(
            "INSERT INTO receipt_items(receipt_pk,handoff_id,delivery_id,accepted,verdict,reason_code,"
            "delivered_revision,current_revision,record_status_at_delivery,current_status) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (receipt_pk, verdict["handoff_id"], delivery_id, int(verdict["accepted"]), verdict["verdict"],
             verdict["reason_code"], verdict["delivered_revision"], verdict["current_revision"],
             verdict["record_status_at_delivery"], verdict["current_status"]),
        )


def _set_status(connection: sqlite3.Connection, receipt_pk: int, status: str, reason_code: str | None,
                reason: str | None, when: str, *, verified: bool = False) -> None:
    previous = store.one(connection, "SELECT status,reason_code,receipt_id FROM receipts WHERE receipt_pk=?",
                         (receipt_pk,))
    connection.execute(
        "UPDATE receipts SET status=?,reason_code=?,reason=?,verified_at=? WHERE receipt_pk=?",
        (status, reason_code, (reason or "")[:500] or None, when if verified else None, receipt_pk),
    )
    if previous is not None and (previous["status"] != status or previous["reason_code"] != reason_code):
        if status == "verified":
            return  # 由核对完成路径记录更完整的活动
        store.record_activity(connection, "receipt_" + status, "receipt", str(receipt_pk), when,
                              {"receipt_id": previous["receipt_id"], "reason_code": reason_code,
                               "reason": (reason or "")[:500]})


def _evaluate(connection: sqlite3.Connection, receipt_pk: int, when: str, *,
              allow_disputed: bool = False) -> dict[str, Any]:
    """核对一条已登记回执；所有状态变化与责任解除在同一事务中。

    只有"待核"会随清单/接收方补齐而重新判定；"已核"保持结果，换内容冲突
    保留首次内容作为证据。显式重核可重新判定已争议回执。
    """
    receipt = store.one(connection, "SELECT * FROM receipts WHERE receipt_pk=?", (receipt_pk,))
    if receipt is None:
        raise ReceiptError("receipt_missing", "回执记录不存在")
    if receipt["status"] == "verified":
        return _receipt_view(connection, receipt_pk)
    if receipt["reason_code"] == "receipt_content_conflict":
        return _receipt_view(connection, receipt_pk)
    if receipt["status"] == "disputed" and not allow_disputed:
        return _receipt_view(connection, receipt_pk)
    payload = json.loads(receipt["payload_json"])
    parsed = parse_receipt_bytes(protocol.canonical_json(payload))
    with store.transaction(connection):
        owner = receiver(connection, receipt["receiver_id"])
        if owner is None:
            _set_status(connection, receipt_pk, "pending", "receiver_unknown", "接收方尚未登记", when)
            return _receipt_view(connection, receipt_pk)
        if not owner["active"]:
            _set_status(connection, receipt_pk, "pending", "receiver_inactive", "接收方已停用", when)
            return _receipt_view(connection, receipt_pk)
        delivery = export.find_delivery(connection, receipt["delivery_key"])
        if delivery is None:
            _set_status(connection, receipt_pk, "pending", "delivery_unknown",
                        "缺少对应清单，等待交付登记", when)
            return _receipt_view(connection, receipt_pk)
        if delivery["status"] != "registered":
            _set_status(connection, receipt_pk, "pending", "delivery_unregistered",
                        "交付登记未完成，等待恢复核对", when)
            return _receipt_view(connection, receipt_pk)
        if delivery["receiver_id"] is not None and delivery["receiver_id"] != receipt["receiver_id"]:
            _set_status(connection, receipt_pk, "disputed", "receiver_mismatch",
                        "回执接收方与交付对象不符", when)
            _record_items(connection, receipt_pk, delivery["delivery_id"], [])
            return _receipt_view(connection, receipt_pk)
        problems = _delivery_integrity(connection, delivery)
        if problems:
            _set_status(connection, receipt_pk, "disputed", "delivery_integrity",
                        "交付版本摘要不一致：" + ",".join(sorted(set(problems))), when)
            _record_items(connection, receipt_pk, delivery["delivery_id"], [])
            return _receipt_view(connection, receipt_pk)
        try:
            received = parse_time(parsed.received_at, 1, "received_at")
            created = parse_time(json.loads(delivery["header_json"])["created_at"], 1, "created_at")
            submitted = parse_time(receipt["submitted_at"], 1, "submitted_at")
        except (ObservationError, KeyError, ValueError):
            _set_status(connection, receipt_pk, "disputed", "receipt_time", "回执时间无效", when)
            _record_items(connection, receipt_pk, delivery["delivery_id"], [])
            return _receipt_view(connection, receipt_pk)
        if received < created or received > submitted + timedelta(minutes=10):
            _set_status(connection, receipt_pk, "disputed", "receipt_time", "回执时间与交付时间不符", when)
            _record_items(connection, receipt_pk, delivery["delivery_id"], [])
            return _receipt_view(connection, receipt_pk)
        delivered_items = export.delivery_items(connection, delivery["delivery_id"])
        coverage = _coverage_problems(delivered_items, parsed)
        if coverage:
            missing = [item["handoff_id"] for item in coverage if item["code"] == "coverage_missing"]
            unknown = [item["handoff_id"] for item in coverage if item["code"] == "coverage_unknown"]
            mismatched = [item["handoff_id"] for item in coverage if item["code"] == "fingerprint_mismatch"]
            detail = {"missing": missing, "unknown": unknown, "fingerprint": mismatched}
            _record_items(connection, receipt_pk, delivery["delivery_id"],
                          _coverage_verdicts(delivered_items, parsed, when, connection))
            _set_status(connection, receipt_pk, "disputed", "coverage_incomplete",
                        "逐项覆盖不成立：" + json.dumps(detail, ensure_ascii=False, sort_keys=True), when)
            return _receipt_view(connection, receipt_pk)
        verdicts = []
        for delivered in delivered_items:
            item = next(entry for entry in parsed.items if entry.handoff_id == delivered["handoff_id"])
            verdict = _verdict(connection, delivered, item, when)
            if verdict["verdict"] == "released":
                responsibility.external_release(connection, delivered["handoff_id"], receipt["receiver_id"],
                                                receipt["receipt_id"], delivery["delivery_id"], when,
                                                delivered_revision=delivered["responsibility_revision"])
            verdicts.append(verdict)
        _record_items(connection, receipt_pk, delivery["delivery_id"], verdicts)
        _set_status(connection, receipt_pk, "verified", None, None, when, verified=True)
        connection.execute("UPDATE receipts SET delivery_id=?,responsibility_revision=? WHERE receipt_pk=?",
                           (delivery["delivery_id"], delivery["responsibility_revision"], receipt_pk))
        released = sum(verdict["verdict"] == "released" for verdict in verdicts)
        store.record_activity(connection, "receipt_verified", "receipt", str(receipt_pk), when,
                              {"receipt_id": receipt["receipt_id"], "receiver_id": receipt["receiver_id"],
                               "delivery_key": receipt["delivery_key"], "released": released,
                               "retained": len(verdicts) - released})
    return _receipt_view(connection, receipt_pk)


def submit_receipt(connection: sqlite3.Connection, source: str | Path, *,
                   when: str | None = None) -> dict[str, Any]:
    timestamp = when or catalog.utc_now()
    path = Path(source)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ReceiptError("receipt_unreadable", "无法读取回执文件") from exc
    return submit_receipt_bytes(connection, data, source_name=path.name, when=timestamp)


def submit_receipt_bytes(connection: sqlite3.Connection, data: bytes, *, source_name: str,
                         when: str | None = None) -> dict[str, Any]:
    """接收回执内容；无法解析的回执进入隔离，而不是静默丢弃。"""
    timestamp = when or catalog.utc_now()
    try:
        parsed = parse_receipt_bytes(data)
    except ReceiptError as exc:
        quarantine_id = _quarantine_receipt(connection, source_name, data, exc.code, str(exc), timestamp)
        raise ReceiptError(exc.code, str(exc)) from exc
    content_sha = parsed.content_sha256
    raw_sha = hashlib.sha256(data).hexdigest()
    existing = store.one(connection, "SELECT * FROM receipts WHERE receiver_id=? AND receipt_id=?",
                         (parsed.receiver_id, parsed.receipt_id))
    if existing is not None:
        if existing["content_sha256"] == content_sha:
            with store.transaction(connection):
                connection.execute("UPDATE receipts SET attempts=attempts+1 WHERE receipt_pk=?",
                                   (existing["receipt_pk"],))
                store.record_activity(connection, "receipt_duplicate", "receipt",
                                      str(existing["receipt_pk"]), timestamp,
                                      {"receipt_id": parsed.receipt_id, "receiver_id": parsed.receiver_id})
            if existing["status"] == "pending":
                _evaluate(connection, existing["receipt_pk"], timestamp)
            return {"submission": "duplicate", **_receipt_view(connection, existing["receipt_pk"])}
        with store.transaction(connection):
            connection.execute(
                "INSERT OR IGNORE INTO receipt_conflicts(receipt_pk,content_sha256,raw_sha256,source_name,"
                "payload_json,observed_at) VALUES(?,?,?,?,?,?)",
                (existing["receipt_pk"], content_sha, raw_sha, source_name,
                 protocol.canonical_json(parsed.payload).decode("utf-8"), timestamp),
            )
            connection.execute("UPDATE receipts SET conflict=1 WHERE receipt_pk=?",
                               (existing["receipt_pk"],))
            if existing["status"] != "verified":
                _set_status(connection, existing["receipt_pk"], "disputed", "receipt_content_conflict",
                            "相同回执编号对应不同内容，保留首次内容", timestamp)
            store.record_activity(connection, "receipt_conflict", "receipt", str(existing["receipt_pk"]),
                                  timestamp, {"receipt_id": parsed.receipt_id,
                                              "receiver_id": parsed.receiver_id,
                                              "content_sha256": content_sha})
        return {"submission": "conflict", **_receipt_view(connection, existing["receipt_pk"])}
    with store.transaction(connection):
        cursor = connection.execute(
            "INSERT INTO receipts(receiver_id,receipt_id,content_sha256,raw_sha256,source_name,payload_json,"
            "delivery_key,responsibility_revision,status,received_at,submitted_at) "
            "VALUES(?,?,?,?,?,?,?,0,'pending',?,?)",
            (parsed.receiver_id, parsed.receipt_id, content_sha, raw_sha, source_name,
             protocol.canonical_json(parsed.payload).decode("utf-8"), parsed.delivery_key,
             timestamp, timestamp),
        )
        receipt_pk = int(cursor.lastrowid)
        # 同一内容先前若因无法解析而隔离，现在可解析即视为已恢复。
        connection.execute("UPDATE receipt_quarantine SET resolved_at=?,receipt_pk=? "
                           "WHERE raw_sha256=? AND resolved_at IS NULL", (timestamp, receipt_pk, raw_sha))
        store.record_activity(connection, "receipt_received", "receipt", str(receipt_pk), timestamp,
                              {"receipt_id": parsed.receipt_id, "receiver_id": parsed.receiver_id,
                               "delivery_key": parsed.delivery_key, "source_name": source_name})
    _evaluate(connection, receipt_pk, timestamp)
    return {"submission": "recorded", **_receipt_view(connection, receipt_pk)}


def _quarantine_receipt(connection: sqlite3.Connection, source_name: str, data: bytes,
                        reason_code: str, detail: str, when: str) -> int:
    raw_sha = hashlib.sha256(data).hexdigest()
    with store.transaction(connection):
        row = store.one(connection, "SELECT * FROM receipt_quarantine WHERE raw_sha256=? AND reason_code=?",
                        (raw_sha, reason_code))
        if row is not None:
            connection.execute("UPDATE receipt_quarantine SET attempts=attempts+1,last_seen=? "
                               "WHERE receipt_quarantine_id=?", (when, row["receipt_quarantine_id"]))
            return int(row["receipt_quarantine_id"])
        cursor = connection.execute(
            "INSERT INTO receipt_quarantine(source_name,raw_sha256,reason_code,detail,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?)", (source_name, raw_sha, reason_code, detail[:1000], when, when))
        return int(cursor.lastrowid)


def ingest_receipt_directory(connection: sqlite3.Connection, directory: str | Path, *,
                             when: str | None = None) -> list[dict[str, Any]]:
    """清单收件：按文件名收取目录中的回执；单件失败不影响其余回执。"""
    root = Path(directory)
    if not root.is_dir():
        raise ReceiptError("directory_missing", "回执目录不存在")
    results = []
    for entry in sorted(root.iterdir()):
        if not entry.is_file() or entry.suffix.lower() != ".json":
            continue
        try:
            outcome = submit_receipt(connection, entry, when=when)
            results.append({"source_name": entry.name,
                            "submission": outcome["submission"],
                            "status": outcome["receipt"]["status"],
                            "receipt_pk": outcome["receipt"]["receipt_pk"]})
        except ReceiptError as exc:
            results.append({"source_name": entry.name, "submission": "quarantined",
                            "code": exc.code, "message": str(exc)})
    return results


def list_receipt_quarantine(connection: sqlite3.Connection, *,
                            limit: int = 100, after_id: int = 0) -> list[dict[str, Any]]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ReceiptError("limit", "查询上限须在 1 到 1000 之间")
    if type(after_id) is not int or after_id < 0:
        raise ReceiptError("after_id", "查询游标无效")
    return store.many(connection, "SELECT * FROM receipt_quarantine WHERE receipt_quarantine_id>? "
                      "ORDER BY receipt_quarantine_id LIMIT ?", (after_id, limit))


def retry_receipt(connection: sqlite3.Connection, receipt_quarantine_id: int, source: str | Path, *,
                  when: str | None = None) -> dict[str, Any]:
    """隔离恢复：只允许重试与隔离记录内容一致的原始回执。"""
    timestamp = when or catalog.utc_now()
    item = store.one(connection, "SELECT * FROM receipt_quarantine WHERE receipt_quarantine_id=?",
                     (receipt_quarantine_id,))
    if item is None:
        raise ReceiptError("quarantine_missing", "回执隔离记录不存在")
    path = Path(source)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ReceiptError("receipt_unreadable", "无法读取待重试回执") from exc
    if hashlib.sha256(data).hexdigest() != item["raw_sha256"]:
        raise ReceiptError("retry_mismatch", "回执内容与隔离记录不符")
    try:
        outcome = submit_receipt_bytes(connection, data, source_name=item["source_name"], when=timestamp)
    except ReceiptError as exc:
        return {"receipt_quarantine_id": receipt_quarantine_id, "status": "still_invalid",
                "code": exc.code, "message": str(exc)}
    with store.transaction(connection):
        connection.execute("UPDATE receipt_quarantine SET resolved_at=?,receipt_pk=? "
                           "WHERE receipt_quarantine_id=?", (timestamp,
                                                              outcome["receipt"]["receipt_pk"],
                                                              receipt_quarantine_id))
        store.record_activity(connection, "receipt_quarantine_retried", "receipt_quarantine",
                              str(receipt_quarantine_id), timestamp,
                              {"receipt_pk": outcome["receipt"]["receipt_pk"]})
    return {"receipt_quarantine_id": receipt_quarantine_id, "status": "recovered",
            "submission": outcome["submission"], "receipt": outcome["receipt"]}


def recheck_receipt(connection: sqlite3.Connection, receipt_pk: int, *,
                    when: str | None = None) -> dict[str, Any]:
    """显式重核：待核回执随清单补齐重新判定；争议回执可在证据修复后重核。

    同一接收方同一回执编号换内容的冲突不回退，始终保留首次内容。
    """
    timestamp = when or catalog.utc_now()
    receipt = store.one(connection, "SELECT * FROM receipts WHERE receipt_pk=?", (receipt_pk,))
    if receipt is None:
        raise ReceiptError("receipt_missing", "回执记录不存在")
    if receipt["status"] == "verified":
        return _receipt_view(connection, receipt_pk)
    _evaluate(connection, receipt_pk, timestamp, allow_disputed=True)
    return _receipt_view(connection, receipt_pk)


def recheck_pending(connection: sqlite3.Connection, *, when: str | None = None) -> dict[str, Any]:
    timestamp = when or catalog.utc_now()
    rows = store.many(connection, "SELECT receipt_pk FROM receipts WHERE status='pending' ORDER BY receipt_pk")
    results = []
    for row in rows:
        view = recheck_receipt(connection, row["receipt_pk"], when=timestamp)
        results.append({"receipt_pk": row["receipt_pk"], "status": view["receipt"]["status"],
                        "reason_code": view["receipt"]["reason_code"]})
    return {"checked": len(results), "results": results}


def _receipt_view(connection: sqlite3.Connection, receipt_pk: int) -> dict[str, Any]:
    receipt = store.one(connection, "SELECT * FROM receipts WHERE receipt_pk=?", (receipt_pk,))
    if receipt is None:
        raise ReceiptError("receipt_missing", "回执记录不存在")
    receipt.pop("payload_json", None)
    items = store.many(connection, "SELECT i.*,h.status AS handoff_status FROM receipt_items i "
                      "LEFT JOIN handoffs h USING(handoff_id) WHERE i.receipt_pk=? ORDER BY i.handoff_id",
                      (receipt_pk,))
    conflicts = store.many(connection, "SELECT conflict_id,content_sha256,raw_sha256,source_name,observed_at "
                           "FROM receipt_conflicts WHERE receipt_pk=? ORDER BY conflict_id", (receipt_pk,))
    released = sum(item["verdict"] == "released" for item in items)
    return {"receipt": receipt, "items": items, "conflicts": conflicts,
            "released": released, "retained": sum(
                item["verdict"] in {"retained", "pending", "unmatched"} for item in items),
            "external_received": receipt["status"] == "verified" and any(item["accepted"] for item in items)}


def list_receipts(connection: sqlite3.Connection, *, status: str | None = None,
                  receiver_id: str | None = None, limit: int = 100, after_id: int = 0) -> list[dict[str, Any]]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ReceiptError("limit", "查询上限须在 1 到 1000 之间")
    if type(after_id) is not int or after_id < 0:
        raise ReceiptError("after_id", "查询游标无效")
    if status is not None and status not in {"pending", "verified", "disputed"}:
        raise ReceiptError("status", "回执状态无效")
    query = ("SELECT receipt_pk,receiver_id,receipt_id,content_sha256,delivery_key,delivery_id,status,"
             "reason_code,reason,attempts,conflict,received_at,submitted_at,verified_at "
             "FROM receipts WHERE receipt_pk>?")
    args: list[Any] = [after_id]
    if status is not None:
        query += " AND status=?"
        args.append(status)
    if receiver_id is not None:
        query += " AND receiver_id=?"
        args.append(receiver_id)
    query += " ORDER BY receipt_pk LIMIT ?"
    args.append(limit)
    rows = store.many(connection, query, tuple(args))
    for row in rows:
        counts = store.one(connection, "SELECT SUM(verdict='released') AS released,COUNT(*) AS total "
                           "FROM receipt_items WHERE receipt_pk=?", (row["receipt_pk"],))
        row["released_items"] = int(counts["released"] or 0)
        row["item_count"] = int(counts["total"] or 0)
    return rows


def receipt_detail(connection: sqlite3.Connection, receipt_pk: int) -> dict[str, Any]:
    return _receipt_view(connection, receipt_pk)


def receipt_history(connection: sqlite3.Connection, handoff_id: int) -> list[dict[str, Any]]:
    return store.many(connection,
                      "SELECT i.receipt_pk,r.receiver_id,r.receipt_id,r.status AS receipt_status,"
                      "r.reason_code AS receipt_reason_code,i.accepted,i.verdict,i.reason_code,i.delivered_revision,"
                      "i.current_revision,r.submitted_at FROM receipt_items i "
                      "JOIN receipts r USING(receipt_pk) WHERE i.handoff_id=? ORDER BY i.receipt_pk",
                      (handoff_id,))


# ---------------------------------------------------------------------------
# 回执清单收件
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReceiptManifestEntry:
    file: str
    sha256: str


@dataclass(frozen=True)
class ReceiptManifest:
    name: str
    entries: tuple[ReceiptManifestEntry, ...]
    fingerprint: str


def _manifest_file(value: object, index: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 180:
        raise ReceiptError("manifest_file", "清单文件名无效")
    if value in {".", ".."} or Path(value).name != value or ":" in value or "\\" in value:
        raise ReceiptError("manifest_file", "清单仅允许同目录中的文件名")
    if not value.endswith(".json"):
        raise ReceiptError("manifest_suffix", "回执文件须使用 .json 后缀")
    return value


def parse_receipt_manifest(data: bytes) -> ReceiptManifest:
    if not data or len(data) > MAX_RECEIPT_MANIFEST_BYTES:
        raise ReceiptError("manifest_size", "回执清单为空或过大")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ReceiptError("manifest_json", "回执清单不是有效 UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != {"kind", "schema", "name", "receipts"}:
        raise ReceiptError("manifest_fields", "回执清单顶层字段无效")
    if value["kind"] != RECEIPT_MANIFEST_KIND or value["schema"] != 1:
        raise ReceiptError("manifest_schema", "仅支持回执清单版本 1")
    name = value["name"]
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise ReceiptError("manifest_name", "回执清单名称无效")
    rows = value["receipts"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_RECEIPT_FILES:
        raise ReceiptError("manifest_entries", "回执清单须包含 1 到 500 个文件")
    entries = []
    seen: set[str] = set()
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or set(row) != {"file", "sha256"}:
            raise ReceiptError("manifest_entry", "回执清单条目字段无效")
        file = _manifest_file(row["file"], index)
        digest = _digest(row["sha256"], "manifest_sha256")
        if file in seen:
            raise ReceiptError("manifest_duplicate", "回执清单文件名重复")
        seen.add(file)
        entries.append(ReceiptManifestEntry(file, digest))
    fingerprint = hashlib.sha256(protocol.canonical_json(value)).hexdigest()
    return ReceiptManifest(name.strip(), tuple(entries), fingerprint)


def preflight_receipts(connection: sqlite3.Connection, manifest_path: str | Path) -> dict[str, Any]:
    path = Path(manifest_path)
    try:
        manifest = parse_receipt_manifest(path.read_bytes())
    except OSError as exc:
        raise ReceiptError("manifest_unreadable", "无法读取回执清单") from exc
    entries = []
    for entry in manifest.entries:
        file = path.parent / entry.file
        result: dict[str, Any] = {"file": entry.file, "sha256": entry.sha256}
        if not file.is_file() or file.is_symlink():
            entries.append({**result, "status": "missing"})
            continue
        data = file.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            entries.append({**result, "status": "checksum_mismatch"})
            continue
        try:
            parsed = parse_receipt_bytes(data)
        except ReceiptError as exc:
            entries.append({**result, "status": "invalid_receipt", "reason": exc.code})
            continue
        existing = store.one(connection, "SELECT * FROM receipts WHERE receiver_id=? AND receipt_id=?",
                             (parsed.receiver_id, parsed.receipt_id))
        if existing is not None and existing["content_sha256"] != parsed.content_sha256:
            status = "receipt_conflict"
        elif existing is not None:
            status = "duplicate"
        else:
            status = "ready"
        entries.append({**result, "status": status, "receipt_id": parsed.receipt_id,
                        "receiver_id": parsed.receiver_id, "delivery_key": parsed.delivery_key})
    return {"name": manifest.name, "fingerprint": manifest.fingerprint, "entries": entries,
            "ready": sum(item["status"] == "ready" for item in entries),
            "blocked": sum(item["status"] not in {"ready", "duplicate"} for item in entries)}


def execute_receipt_manifest(connection: sqlite3.Connection, manifest_path: str | Path, *,
                             when: str | None = None, stop_on_error: bool = False) -> dict[str, Any]:
    path = Path(manifest_path)
    plan = preflight_receipts(connection, path)
    root = path.parent
    results = []
    for entry in plan["entries"]:
        if entry["status"] == "duplicate":
            results.append({"file": entry["file"], "submission": "duplicate"})
            continue
        if entry["status"] != "ready":
            results.append({"file": entry["file"], "submission": "skipped", "reason": entry["status"]})
            if stop_on_error and entry["status"] != "receipt_conflict":
                break
            continue
        file = root / entry["file"]
        if hashlib.sha256(file.read_bytes()).hexdigest() != entry["sha256"]:
            results.append({"file": entry["file"], "submission": "skipped",
                            "reason": "changed_after_preflight"})
            continue
        try:
            outcome = submit_receipt(connection, file, when=when)
            results.append({"file": entry["file"], "submission": outcome["submission"],
                            "status": outcome["receipt"]["status"],
                            "receipt_pk": outcome["receipt"]["receipt_pk"]})
        except ReceiptError as exc:
            results.append({"file": entry["file"], "submission": "rejected", "code": exc.code})
            if stop_on_error:
                break
    return {"manifest": plan["name"], "fingerprint": plan["fingerprint"], "results": results,
            "verified": sum(1 for item in results if item.get("status") == "verified"),
            "pending": sum(1 for item in results if item.get("status") == "pending"),
            "disputed": sum(1 for item in results if item.get("status") == "disputed")}
