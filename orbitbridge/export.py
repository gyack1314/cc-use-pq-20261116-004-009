"""可核对的交接清单导出、交付版本与来源摘要。

`export-handoffs` 保留为不含交付描述的最小行文件；`export-delivery` 在其旁边
写出自描述的交付版本（descriptor），并把清单条目、责任修订和文件摘要登记到
数据库。回执必须同时引用交付版本与责任安排，不能只按交接号销账。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import catalog, protocol, responsibility, store

DELIVERY_KIND = "handoff-delivery"
DELIVERY_SCHEMA = 1


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


# ---------------------------------------------------------------------------
# 交付版本（descriptor + body）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeliveryReceipt:
    delivery_id: int
    delivery_key: str
    subscription_id: str
    rows: int
    body_sha256: str
    descriptor_sha256: str
    first_handoff_id: int | None
    last_handoff_id: int | None
    status: str
    destination: str
    descriptor: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def descriptor_path_for(destination: str | Path) -> Path:
    path = Path(destination)
    return path.with_name(path.name + ".delivery.json")


def _delivery_key(payload: dict[str, Any]) -> str:
    identity = {
        "subscription_id": payload["subscription_id"],
        "window": payload["window"],
        "receiver_id": payload.get("receiver_id"),
        "body_sha256": payload["body_sha256"],
        "items": [{key: item[key] for key in
                   ("handoff_id", "responsibility_revision", "observation_fingerprint", "status_at_delivery")}
                  for item in payload["items"]],
    }
    return hashlib.sha256(protocol.canonical_json(identity)).hexdigest()


def _build_descriptor(connection: sqlite3.Connection, subscription_id: str, rows: list[dict[str, Any]],
                      body: bytes, body_name: str, timestamp: str, *, start_id: int, end_id: int | None,
                      status: str | None, receiver_id: str | None) -> dict[str, Any]:
    items = []
    for ordinal, row in enumerate(rows, 1):
        items.append({
            "ordinal": ordinal,
            "handoff_id": row["handoff_id"],
            "responsibility_revision": int(responsibility.current(connection, row["handoff_id"], timestamp)["revision"]),
            "observation_fingerprint": row["fingerprint"],
            "status_at_delivery": row["status"],
            "batch_id": row["batch_id"],
            "packet_id": row["packet_id"],
        })
    payload = {
        "kind": DELIVERY_KIND,
        "schema": DELIVERY_SCHEMA,
        "subscription_id": subscription_id,
        "window": {"start_id": start_id, "end_id": end_id, "status": status},
        "rows": len(rows),
        "first_handoff_id": rows[0]["handoff_id"] if rows else None,
        "last_handoff_id": rows[-1]["handoff_id"] if rows else None,
        "body_name": body_name,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "created_at": timestamp,
        "receiver_id": receiver_id,
        "items": items,
    }
    payload["delivery_key"] = _delivery_key(payload)
    return payload


def _check_receiver(connection: sqlite3.Connection, receiver_id: str | None) -> None:
    if receiver_id is None:
        return
    receiver = store.one(connection, "SELECT * FROM receivers WHERE receiver_id=?", (receiver_id,))
    if receiver is None:
        raise ExportError("receiver_missing", "接收方尚未登记")
    if not receiver["active"]:
        raise ExportError("receiver_inactive", "接收方已停用")


def export_delivery(connection: sqlite3.Connection, subscription_id: str, destination: str | Path,
                    *, start_id: int = 0, end_id: int | None = None, status: str | None = None,
                    receiver_id: str | None = None, when: str | None = None) -> DeliveryReceipt:
    timestamp = when or catalog.utc_now()
    _check_receiver(connection, receiver_id)
    _, rows = snapshot_rows(connection, subscription_id, start_id=start_id, end_id=end_id, status=status)
    body = serialize_rows(rows)
    path = Path(destination)
    descriptor_path = descriptor_path_for(path)
    if path.exists():
        raise ExportError("destination_exists", "导出目标已存在，拒绝覆盖")
    if descriptor_path.exists():
        raise ExportError("descriptor_exists", "交付描述已存在，拒绝覆盖")
    payload = _build_descriptor(connection, subscription_id, rows, body, path.name, timestamp,
                                start_id=start_id, end_id=end_id, status=status, receiver_id=receiver_id)
    if store.one(connection, "SELECT delivery_id FROM deliveries WHERE delivery_key=?", (payload["delivery_key"],)):
        raise ExportError("delivery_exists", "相同内容的交付版本已登记")
    descriptor = protocol.canonical_json(payload) + b"\n"
    body_sha = hashlib.sha256(body).hexdigest()
    descriptor_sha = hashlib.sha256(descriptor).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    delivery_id = _insert_delivery(connection, payload, path, descriptor_path, body.decode("utf-8"),
                                   body_sha, descriptor_sha, len(rows), timestamp, status="prepared")
    # 登记已建立后才落盘；若写入中断，delivery-recover 按登记的原始字节恢复。
    try:
        _write_missing_file(path, body)
        _write_missing_file(descriptor_path, descriptor)
    except ExportError:
        raise
    except OSError as exc:
        raise ExportError("write_failed", "无法写入导出文件，可用 delivery-recover 恢复") from exc
    return DeliveryReceipt(delivery_id, payload["delivery_key"], subscription_id, len(rows), body_sha,
                           descriptor_sha, payload["first_handoff_id"], payload["last_handoff_id"],
                           "prepared", str(path), str(descriptor_path))


def _write_missing_file(path: Path, data: bytes) -> None:
    if path.exists():
        if path.read_bytes() != data:
            raise ExportError("destination_exists", "目标文件已存在且内容不同，拒绝覆盖")
        return
    with path.open("xb") as handle:
        handle.write(data)


def _insert_delivery(connection: sqlite3.Connection, payload: dict[str, Any], path: Path,
                     descriptor_path: Path, body_text: str, body_sha: str, descriptor_sha: str,
                     rows: int, timestamp: str, *, status: str) -> int:
    try:
        with store.transaction(connection):
            cursor = connection.execute(
                "INSERT INTO deliveries(delivery_key,subscription_id,file_name,file_path,file_sha256,"
                "descriptor_name,descriptor_path,descriptor_sha256,body_sha256,header_json,body_text,rows,"
                "first_handoff_id,last_handoff_id,receiver_id,responsibility_revision,status,created_at,"
                "registered_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (payload["delivery_key"], payload["subscription_id"], path.name, str(path), body_sha,
                 descriptor_path.name, str(descriptor_path), descriptor_sha, body_sha,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True), body_text, rows,
                 payload["first_handoff_id"], payload["last_handoff_id"], payload.get("receiver_id"),
                 max((item["responsibility_revision"] for item in payload["items"]), default=0),
                 status, timestamp, timestamp if status == "registered" else None),
            )
            delivery_id = int(cursor.lastrowid)
            for item in payload["items"]:
                connection.execute(
                    "INSERT INTO delivery_items(delivery_id,handoff_id,ordinal,responsibility_revision,"
                    "observation_fingerprint,status_at_delivery) VALUES(?,?,?,?,?,?)",
                    (delivery_id, item["handoff_id"], item["ordinal"], item["responsibility_revision"],
                     item["observation_fingerprint"], item["status_at_delivery"]),
                )
            store.record_activity(connection, "delivery_prepared" if status == "prepared" else "delivery_recovered",
                                  "delivery", str(delivery_id), timestamp,
                                  {"delivery_key": payload["delivery_key"], "rows": rows,
                                   "receiver_id": payload.get("receiver_id")})
    except sqlite3.IntegrityError as exc:
        raise ExportError("delivery_conflict", "交付登记冲突") from exc
    return delivery_id


def register_delivery(connection: sqlite3.Connection, delivery_key: str, *,
                      when: str | None = None) -> dict[str, Any]:
    """交付登记完成：只有登记后的版本才被视为可以核对回执的交付版本。"""
    timestamp = when or catalog.utc_now()
    with store.transaction(connection):
        item = find_delivery(connection, delivery_key)
        if item is None:
            raise ExportError("delivery_missing", "交付版本不存在")
        if item["status"] == "registered":
            return {**item, "status": "duplicate"}
        connection.execute("UPDATE deliveries SET status='registered',registered_at=? "
                           "WHERE delivery_id=? AND status='prepared'", (timestamp, item["delivery_id"]))
        store.record_activity(connection, "delivery_registered", "delivery", str(item["delivery_id"]),
                              timestamp, {"delivery_key": item["delivery_key"]})
    return store.one(connection, "SELECT * FROM deliveries WHERE delivery_id=?", (item["delivery_id"],))


def find_delivery(connection: sqlite3.Connection, delivery_key: str) -> dict[str, Any] | None:
    if not isinstance(delivery_key, str) or len(delivery_key) != 64 or any(
            char not in "0123456789abcdef" for char in delivery_key):
        raise ExportError("delivery_key", "交付标识格式无效")
    return store.one(connection, "SELECT * FROM deliveries WHERE delivery_key=?", (delivery_key,))


def get_delivery(connection: sqlite3.Connection, delivery_id: int) -> dict[str, Any] | None:
    return store.one(connection, "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,))


def list_deliveries(connection: sqlite3.Connection, *, subscription_id: str | None = None,
                    limit: int = 100) -> list[dict[str, Any]]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ExportError("limit", "查询上限须在 1 到 1000 之间")
    if subscription_id is None:
        rows = store.many(connection, "SELECT * FROM deliveries ORDER BY delivery_id DESC LIMIT ?", (limit,))
    else:
        rows = store.many(connection, "SELECT * FROM deliveries WHERE subscription_id=? "
                          "ORDER BY delivery_id DESC LIMIT ?", (subscription_id, limit))
    for row in rows:
        row.pop("body_text", None)
    return rows


def delivery_items(connection: sqlite3.Connection, delivery_id: int) -> list[dict[str, Any]]:
    return store.many(connection, "SELECT d.*,h.status AS handoff_status,o.external_id,o.region "
                      "FROM delivery_items d JOIN handoffs h USING(handoff_id) "
                      "JOIN observations o USING(observation_id) "
                      "WHERE d.delivery_id=? ORDER BY d.ordinal", (delivery_id,))


def _check_body_file(item: dict[str, Any]) -> tuple[bytes | None, str | None]:
    try:
        body = Path(item["file_path"]).read_bytes()
    except OSError:
        return None, "body_unreadable"
    if hashlib.sha256(body).hexdigest() != item["body_sha256"]:
        return body, "body_digest"
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        return body, "body_encoding"
    return body, None


def verify_delivery(connection: sqlite3.Connection, delivery_key: str) -> dict[str, Any]:
    """重新核对交付版本：正文摘要、描述摘要、逐项覆盖与责任修订。"""
    item = find_delivery(connection, delivery_key)
    if item is None:
        raise ExportError("delivery_missing", "交付版本不存在")
    problems: list[str] = []
    _, problem = _check_body_file(item)
    if problem:
        problems.append(problem)
    try:
        descriptor = Path(item["descriptor_path"]).read_bytes()
    except OSError:
        descriptor = b""
        problems.append("descriptor_unreadable")
    if hashlib.sha256(descriptor).hexdigest() != item["descriptor_sha256"]:
        problems.append("descriptor_digest")
    try:
        header = json.loads(item["header_json"])
        described = json.loads(descriptor.decode("utf-8"))
    except (ValueError, UnicodeError):
        problems.append("descriptor_json")
        header, described = {}, {}
    if described and protocol.canonical_json(described) != descriptor.rstrip(b"\n"):
        problems.append("descriptor_canonical")
    if described.get("body_sha256") != item["body_sha256"]:
        problems.append("descriptor_body_digest")
    rows = [line for line in item["body_text"].splitlines() if line]
    items = delivery_items(connection, item["delivery_id"])
    if len(rows) != item["rows"] or len(items) != item["rows"]:
        problems.append("coverage")
    body_ids: list[int] = []
    for line in rows:
        try:
            value = json.loads(line)
        except ValueError:
            problems.append("body_row")
            body_ids = []
            break
        if not isinstance(value, dict) or type(value.get("handoff_id")) is not int:
            problems.append("body_row")
            body_ids = []
            break
        body_ids.append(value["handoff_id"])
    if body_ids and body_ids != [entry["handoff_id"] for entry in items]:
        problems.append("item_order")
    for row, entry in zip(rows, items):
        try:
            body_row = json.loads(row)
        except ValueError:
            problems.append("body_row")
            continue
        if body_row.get("fingerprint") != entry["observation_fingerprint"]:
            problems.append("item_fingerprint")
        if int(responsibility.current(connection, entry["handoff_id"], catalog.utc_now())["revision"]) < \
                int(entry["responsibility_revision"]):
            problems.append("revision_regressed")
    if header.get("items") and len(header["items"]) != len(items):
        problems.append("descriptor_items")
    return {"ok": not problems, "problems": sorted(set(problems)), "delivery_id": item["delivery_id"],
            "delivery_key": item["delivery_key"], "status": item["status"], "rows": item["rows"],
            "body_sha256": item["body_sha256"], "descriptor_sha256": item["descriptor_sha256"],
            "first_handoff_id": item["first_handoff_id"], "last_handoff_id": item["last_handoff_id"]}


def recover_delivery(connection: sqlite3.Connection, file_path: str | Path, *,
                     when: str | None = None) -> dict[str, Any]:
    """文件已写出但交付登记未完成时，从磁盘恢复核对，不重新导出另一内容。"""
    timestamp = when or catalog.utc_now()
    path = Path(file_path)
    descriptor_path = descriptor_path_for(path)
    existing = store.one(connection, "SELECT * FROM deliveries WHERE file_path=?", (str(path),))
    if existing is not None:
        if existing["status"] == "prepared":
            problems: list[str] = []
            if path.exists():
                _, problem = _check_body_file(existing)
                if problem:
                    raise ExportError("delivery_changed", "正文摘要与交付登记不符，不能冒充原版")
            else:
                # 登记已建立但正文未写出：按登记的原始正文恢复，而不是重新导出。
                _write_missing_file(path, existing["body_text"].encode("utf-8"))
            if descriptor_path.exists():
                try:
                    raw = descriptor_path.read_bytes()
                except OSError as exc:
                    raise ExportError("delivery_files_missing", "交付描述不可读，无法恢复") from exc
                if hashlib.sha256(raw).hexdigest() != existing["descriptor_sha256"]:
                    raise ExportError("descriptor_changed", "交付描述与登记不符，不能重新导出冒充原版")
            else:
                header = json.loads(existing["header_json"])
                _write_missing_file(descriptor_path, protocol.canonical_json(header) + b"\n")
            return {"delivery": register_delivery(connection, existing["delivery_key"], when=timestamp),
                    "recovered": True}
        return {"delivery": existing, "recovered": False}
    try:
        body = path.read_bytes()
        raw = descriptor_path.read_bytes()
    except OSError as exc:
        raise ExportError("delivery_files_missing", "交付正文或描述缺失，无法恢复") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ExportError("descriptor_json", "交付描述不是有效 JSON") from exc
    if not isinstance(payload, dict) or payload.get("kind") != DELIVERY_KIND:
        raise ExportError("descriptor_kind", "文件不是交付描述")
    if payload.get("schema") != DELIVERY_SCHEMA:
        raise ExportError("descriptor_schema", "交付描述版本不支持")
    body_sha = hashlib.sha256(body).hexdigest()
    if payload.get("body_sha256") != body_sha:
        raise ExportError("delivery_changed", "正文摘要与交付描述不符，不能冒充原版")
    if payload.get("delivery_key") != _delivery_key(payload):
        raise ExportError("delivery_key_mismatch", "交付标识与描述内容不符")
    items = payload.get("items")
    if not isinstance(items, list) or type(payload.get("rows")) is not int or len(items) != payload["rows"]:
        raise ExportError("descriptor_items", "交付描述条目无效")
    if store.one(connection, "SELECT delivery_id FROM deliveries WHERE delivery_key=?",
                 (payload["delivery_key"],)):
        raise ExportError("delivery_exists", "交付版本已登记，不能重复恢复")
    _validate_recovered_items(items)
    problems = validate_items_against_database(connection, payload.get("subscription_id"), items)
    if problems:
        raise ExportError("delivery_items_mismatch",
                          "交付条目与本地记录不符：" + ",".join(sorted(set(problems))))
    delivery_id = _insert_delivery(connection, payload, path, descriptor_path, body.decode("utf-8"),
                                   body_sha, hashlib.sha256(raw).hexdigest(), len(items), timestamp,
                                   status="registered")
    return {"delivery": get_delivery(connection, delivery_id), "recovered": True}


def _validate_recovered_items(items: list[Any]) -> None:
    ordinals = []
    for item in items:
        if not isinstance(item, dict):
            raise ExportError("descriptor_items", "交付描述条目无效")
        for field in ("handoff_id", "ordinal", "responsibility_revision", "observation_fingerprint",
                      "status_at_delivery"):
            if field not in item:
                raise ExportError("descriptor_fields", "交付描述字段不完整")
        if type(item["handoff_id"]) is not int or type(item["ordinal"]) is not int:
            raise ExportError("descriptor_fields", "交付描述字段类型无效")
        if item["status_at_delivery"] not in {"pending", "acknowledged"}:
            raise ExportError("descriptor_fields", "交付描述状态无效")
        ordinals.append(item["ordinal"])
    if ordinals != list(range(1, len(items) + 1)):
        raise ExportError("descriptor_order", "交付描述顺序无效")


def validate_items_against_database(connection: sqlite3.Connection, subscription_id: str,
                                    items: list[dict[str, Any]]) -> list[str]:
    """逐项核对交付条目确实属于该订阅及原始观测，防止伪造清单。"""
    problems: list[str] = []
    if catalog.subscription(connection, subscription_id) is None:
        return ["subscription_missing"]
    previous = 0
    for item in items:
        handoff_id = item.get("handoff_id")
        if type(handoff_id) is not int or handoff_id <= previous:
            problems.append("item_order")
            continue
        previous = handoff_id
        row = store.one(connection, "SELECT h.handoff_id,h.subscription_id,o.fingerprint,o.batch_id,"
                        "b.packet_id FROM handoffs h JOIN observations o USING(observation_id) "
                        "JOIN batches b ON b.batch_id=o.batch_id WHERE h.handoff_id=?", (handoff_id,))
        if row is None:
            problems.append("item_unknown")
            continue
        if row["subscription_id"] != subscription_id:
            problems.append("item_subscription")
        if item.get("observation_fingerprint") != row["fingerprint"]:
            problems.append("item_fingerprint")
        if item.get("batch_id") is not None and item["batch_id"] != row["batch_id"]:
            problems.append("item_batch")
        if item.get("packet_id") is not None and item["packet_id"] != row["packet_id"]:
            problems.append("item_packet")
        if item.get("responsibility_revision") is not None and (
                type(item["responsibility_revision"]) is not int or item["responsibility_revision"] < 1):
            problems.append("item_revision")
    return problems
