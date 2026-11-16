"""候选火情字段、坐标和时间的严格规范化。"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from typing import Any

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$")
REGIONS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class ObservationError(ValueError):
    def __init__(self, code: str, message: str, index: int):
        super().__init__(message)
        self.code = code
        self.index = index


@dataclass(frozen=True)
class Observation:
    external_id: str
    observed_at: str
    region: str
    latitude: str
    longitude: str
    confidence: str
    severity: int
    source: str
    fingerprint: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def parse_time(value: object, index: int, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise ObservationError("time_format", f"{field} 必须为带时区的时间", index)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ObservationError("time_format", f"{field} 无效", index) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ObservationError("timezone_missing", f"{field} 缺少时区", index)
    if not (2020 <= parsed.year <= 2100):
        raise ObservationError("time_range", f"{field} 超出支持范围", index)
    return parsed.astimezone(dt.timezone.utc)


def iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _decimal(value: object, lower: str, upper: str, places: int, index: int, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise ObservationError("number_type", f"{field} 不是数值", index)
    try:
        number = Decimal(str(value))
    except InvalidOperation as exc:
        raise ObservationError("number_type", f"{field} 不是数值", index) from exc
    if not number.is_finite() or not (Decimal(lower) <= number <= Decimal(upper)):
        raise ObservationError("number_range", f"{field} 超出范围", index)
    quantizer = Decimal(1).scaleb(-places)
    return format(number.quantize(quantizer, rounding=ROUND_HALF_EVEN), f".{places}f")


def normalize_record(record: dict[str, Any], index: int, station_id: str, packet_time: dt.datetime) -> Observation:
    fields = {"kind", "id", "observed_at", "region", "latitude", "longitude",
              "confidence", "severity", "source"}
    if set(record) != fields:
        raise ObservationError("fields", "观测字段不完整或包含未知字段", index)
    external_id = record["id"]
    if not isinstance(external_id, str) or not IDENTIFIER.fullmatch(external_id):
        raise ObservationError("id", "观测标识无效", index)
    region = record["region"]
    if not isinstance(region, str) or not REGIONS.fullmatch(region):
        raise ObservationError("region", "区域标识无效", index)
    observed = parse_time(record["observed_at"], index, "observed_at")
    if observed > packet_time + dt.timedelta(minutes=10):
        raise ObservationError("future_observation", "观测时间晚于包时间允许窗口", index)
    if packet_time - observed > dt.timedelta(days=30):
        raise ObservationError("stale_observation", "观测时间过旧", index)
    latitude = _decimal(record["latitude"], "-90", "90", 5, index, "latitude")
    longitude = _decimal(record["longitude"], "-180", "180", 5, index, "longitude")
    confidence = _decimal(record["confidence"], "0", "1", 3, index, "confidence")
    severity = record["severity"]
    if type(severity) is not int or not 1 <= severity <= 5:
        raise ObservationError("severity", "severity 必须为 1 到 5 的整数", index)
    source = record["source"]
    if source not in {"infrared", "optical", "thermal"}:
        raise ObservationError("source", "不支持的观测来源", index)
    payload = f"{station_id}|{external_id}|{iso_utc(observed)}|{region}|{latitude}|{longitude}|{confidence}|{severity}|{source}"
    fingerprint = hashlib.sha256(payload.encode()).hexdigest()
    return Observation(external_id, iso_utc(observed), region, latitude, longitude, confidence, severity, source, fingerprint)


def normalize_batch(records: tuple[dict[str, Any], ...], station_id: str, created_at: str) -> tuple[Observation, ...]:
    packet_time = parse_time(created_at, 1, "created_at")
    seen: set[str] = set()
    normalized = []
    for index, record in enumerate(records, 2):
        observation = normalize_record(record, index, station_id, packet_time)
        if observation.external_id in seen:
            raise ObservationError("duplicate_id", "同一包中观测标识重复", index)
        seen.add(observation.external_id)
        normalized.append(observation)
    return tuple(normalized)
