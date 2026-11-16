from __future__ import annotations

import json
from decimal import Decimal

from orbitbridge import protocol
from orbitbridge.normalize import ObservationError, normalize_batch, parse_time
from helpers import DatabaseCase, PACKET_TIME, observation, packet


class ProtocolTests(DatabaseCase):
    def test_round_trip_preserves_packet_identity(self):
        encoded = packet()
        parsed = protocol.parse_packet_bytes(encoded, "source.jsonl")
        self.assertEqual(parsed.envelope.station_id, "sat-a")
        self.assertEqual(parsed.envelope.sequence, 1)
        self.assertEqual(parsed.envelope.record_count, 1)
        self.assertEqual(parsed.source_name, "source.jsonl")
        self.assertEqual(parsed.records[0]["id"], "sim-1")
        self.assertEqual(parsed.canonical_digest, protocol.records_digest(parsed.records))
        self.assertEqual(protocol.packet_identity(parsed), protocol.packet_identity(protocol.parse_packet_bytes(encoded)))

    def test_digest_catches_mutated_record(self):
        encoded = packet().replace(b"sim-1", b"sim-2")
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_bytes(encoded)
        self.assertEqual(error.exception.code, "digest_mismatch")

    def test_count_rejects_missing_record(self):
        lines = packet().splitlines()
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_bytes(lines[0] + b"\n")
        self.assertEqual(error.exception.code, "count_mismatch")

    def test_non_object_line_is_rejected(self):
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_bytes(b"[]\n")
        self.assertEqual(error.exception.code, "line_type")

    def test_unsupported_schema_is_rejected(self):
        data = packet().replace(b'"schema":1', b'"schema":2')
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_bytes(data)
        self.assertEqual(error.exception.code, "schema")

    def test_bad_utf8_reports_line(self):
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_bytes(b"{\xff}\n")
        self.assertEqual(error.exception.code, "bad_json")
        self.assertEqual(error.exception.line, 1)

    def test_oversized_line_is_rejected_before_json_parse(self):
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_bytes(b"x" * 16385)
        self.assertEqual(error.exception.code, "line_size")

    def test_empty_line_is_rejected(self):
        data = packet().replace(b"\n", b"\n\n", 1)
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_bytes(data)
        self.assertEqual(error.exception.code, "empty_line")

    def test_header_unknown_field_is_rejected(self):
        lines = packet().splitlines()
        header = json.loads(lines[0])
        header["unlisted"] = 1
        data = protocol.canonical_json(header) + b"\n" + lines[1] + b"\n"
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_bytes(data)
        self.assertEqual(error.exception.code, "header_fields")

    def test_digest_is_independent_of_key_order(self):
        row = observation()
        self.assertEqual(protocol.records_digest([row]), protocol.records_digest([dict(reversed(list(row.items())))]))

    def test_file_parse_reads_packet(self):
        path = self.write_packet()
        self.assertEqual(protocol.parse_packet_file(path).envelope.sequence, 1)
        self.assertEqual(protocol.parse_packet_file(path).source_name, path.name)

    def test_missing_file_is_protocol_error(self):
        with self.assertRaises(protocol.PacketError) as error:
            protocol.parse_packet_file(self.root / "missing.jsonl")
        self.assertEqual(error.exception.code, "source_unreadable")

    def test_observation_timezone_normalizes_to_utc(self):
        row = observation(observed_at="2026-10-28T20:01:00+08:00")
        normalized = normalize_batch((row,), "sat-a", PACKET_TIME)[0]
        self.assertEqual(normalized.observed_at, "2026-10-28T12:01:00Z")
        self.assertEqual(normalized.latitude, "31.20000")
        self.assertEqual(normalized.confidence, "0.800")

    def test_observation_rejects_timezone_missing(self):
        with self.assertRaises(ObservationError) as error:
            normalize_batch((observation(observed_at="2026-10-28T12:01:00"),), "sat-a", PACKET_TIME)
        self.assertEqual(error.exception.code, "timezone_missing")

    def test_observation_rejects_future_time(self):
        with self.assertRaises(ObservationError) as error:
            normalize_batch((observation(observed_at="2026-10-28T12:20:00Z"),), "sat-a", PACKET_TIME)
        self.assertEqual(error.exception.code, "future_observation")

    def test_observation_rejects_stale_time(self):
        with self.assertRaises(ObservationError) as error:
            normalize_batch((observation(observed_at="2026-09-01T12:00:00Z"),), "sat-a", PACKET_TIME)
        self.assertEqual(error.exception.code, "stale_observation")

    def test_coordinate_bounds_are_enforced(self):
        for value in (91, -91, "NaN"):
            with self.subTest(value=value), self.assertRaises(ObservationError):
                normalize_batch((observation(latitude=value),), "sat-a", PACKET_TIME)

    def test_confidence_bounds_are_enforced(self):
        for value in ("1.01", "-0.1", True):
            with self.subTest(value=value), self.assertRaises(ObservationError):
                normalize_batch((observation(confidence=value),), "sat-a", PACKET_TIME)

    def test_severity_requires_integer(self):
        for value in (0, 6, 3.0, True):
            with self.subTest(value=value), self.assertRaises(ObservationError):
                normalize_batch((observation(severity=value),), "sat-a", PACKET_TIME)

    def test_duplicate_observation_id_in_packet(self):
        with self.assertRaises(ObservationError) as error:
            normalize_batch((observation(), observation()), "sat-a", PACKET_TIME)
        self.assertEqual(error.exception.code, "duplicate_id")

    def test_source_must_be_declared(self):
        with self.assertRaises(ObservationError) as error:
            normalize_batch((observation(source="unknown"),), "sat-a", PACKET_TIME)
        self.assertEqual(error.exception.code, "source")

    def test_parsed_time_has_utc_offset(self):
        parsed = parse_time("2026-10-28T20:00:00+08:00", 1, "created_at")
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)
