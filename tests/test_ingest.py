from __future__ import annotations

import sqlite3

from orbitbridge import audit, catalog, handoff, ingest, protocol, store
from helpers import DatabaseCase, STAMP, observation, packet


class IngestTests(DatabaseCase):
    def test_ingest_creates_batch_observation_and_handoff_atomically(self):
        result = ingest.ingest_bytes(self.db, packet(), when=STAMP)
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.observation_count, 1)
        self.assertEqual(result.handoff_count, 1)
        self.assertEqual(store.counts(self.db)["batches"], 1)
        self.assertEqual(store.counts(self.db)["observations"], 1)
        self.assertEqual(store.counts(self.db)["handoffs"], 1)
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 1)
        self.assertEqual(audit.batch_detail(self.db, result.batch_id)["batch"]["packet_id"], result.packet_id)

    def test_same_packet_is_idempotent(self):
        first = ingest.ingest_bytes(self.db, packet(), when=STAMP)
        second = ingest.ingest_bytes(self.db, packet(), when=STAMP)
        self.assertEqual(second.status, "duplicate")
        self.assertEqual(second.batch_id, first.batch_id)
        self.assertEqual(second.handoff_count, first.handoff_count)
        self.assertEqual(store.counts(self.db)["batches"], 1)
        self.assertEqual(store.counts(self.db)["quarantine"], 0)

    def test_same_sequence_different_digest_is_isolated(self):
        ingest.ingest_bytes(self.db, packet(), when=STAMP)
        changed = packet(records=[observation("changed")])
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, changed, when=STAMP)
        self.assertEqual(error.exception.code, "sequence_conflict")
        self.assertIsNotNone(error.exception.quarantine_id)
        self.assertEqual(store.counts(self.db)["batches"], 1)
        self.assertEqual(store.counts(self.db)["observations"], 1)
        self.assertEqual(store.counts(self.db)["quarantine"], 1)

    def test_gap_does_not_advance_cursor(self):
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, packet(2), when=STAMP)
        self.assertEqual(error.exception.code, "sequence_gap")
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 0)
        self.assertEqual(store.counts(self.db)["batches"], 0)
        ingest.ingest_bytes(self.db, packet(1), when=STAMP)
        self.assertEqual(ingest.ingest_bytes(self.db, packet(2, [observation("sim-2")]), when=STAMP).status, "accepted")
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 2)

    def test_invalid_record_rolls_back_whole_batch(self):
        rows = [observation("good"), observation("bad", latitude=95)]
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, packet(records=rows), when=STAMP)
        self.assertEqual(error.exception.code, "number_range")
        counts = store.counts(self.db)
        self.assertEqual(counts["batches"], 0)
        self.assertEqual(counts["observations"], 0)
        self.assertEqual(counts["handoffs"], 0)
        self.assertEqual(counts["quarantine"], 1)

    def test_invalid_digest_is_quarantined_without_station_identity(self):
        raw = packet().replace(b"sim-1", b"sim-9")
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, raw, when=STAMP)
        self.assertEqual(error.exception.code, "digest_mismatch")
        record = audit.list_quarantine(self.db)[0]
        self.assertIsNone(record["station_id"])
        self.assertIsNone(record["sequence"])
        self.assertEqual(store.counts(self.db)["batches"], 0)

    def test_repeated_rejection_increments_attempts(self):
        raw = packet(3)
        for _ in range(3):
            with self.assertRaises(ingest.IngestError):
                ingest.ingest_bytes(self.db, raw, when=STAMP)
        rows = audit.list_quarantine(self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["attempts"], 3)

    def test_inactive_station_is_rejected(self):
        catalog.set_station_active(self.db, "sat-a", False)
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, packet(), when=STAMP)
        self.assertEqual(error.exception.code, "station_inactive")
        self.assertEqual(store.counts(self.db)["batches"], 0)
        catalog.set_station_active(self.db, "sat-a", True)
        self.assertEqual(ingest.ingest_bytes(self.db, packet(), when=STAMP).status, "accepted")

    def test_unknown_station_is_rejected(self):
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, packet(station="sat-x"), when=STAMP)
        self.assertEqual(error.exception.code, "station_unknown")
        self.assertEqual(store.counts(self.db)["batches"], 0)

    def test_observation_identity_must_be_unique_across_batches(self):
        ingest.ingest_bytes(self.db, packet(), when=STAMP)
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, packet(2), when=STAMP)
        self.assertEqual(error.exception.code, "observation_conflict")
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 1)
        self.assertEqual(store.counts(self.db)["observations"], 1)

    def test_no_matching_subscription_keeps_observation(self):
        result = ingest.ingest_bytes(self.db, packet(records=[observation(region="south")]), when=STAMP)
        self.assertEqual(result.handoff_count, 0)
        self.assertEqual(store.counts(self.db)["observations"], 1)
        self.assertEqual(store.counts(self.db)["handoffs"], 0)

    def test_multiple_subscriptions_receive_same_observation(self):
        catalog.register_subscription(self.db, "north-backup", "north", 2, "0.5", when=STAMP)
        result = ingest.ingest_bytes(self.db, packet(), when=STAMP)
        self.assertEqual(result.handoff_count, 2)
        subscriptions = {row["subscription_id"] for row in handoff.list_handoffs(self.db)}
        self.assertEqual(subscriptions, {"north-watch", "north-backup"})

    def test_disabled_subscription_gets_no_new_handoff(self):
        catalog.set_subscription_active(self.db, "north-watch", False)
        result = ingest.ingest_bytes(self.db, packet(), when=STAMP)
        self.assertEqual(result.handoff_count, 0)
        self.assertEqual(store.counts(self.db)["observations"], 1)

    def test_confidence_threshold_filters_handoff(self):
        result = ingest.ingest_bytes(self.db, packet(records=[observation(confidence="0.69")]), when=STAMP)
        self.assertEqual(result.handoff_count, 0)
        self.assertEqual(handoff.list_handoffs(self.db), [])

    def test_severity_threshold_filters_handoff(self):
        result = ingest.ingest_bytes(self.db, packet(records=[observation(severity=2)]), when=STAMP)
        self.assertEqual(result.handoff_count, 0)
        self.assertEqual(store.counts(self.db)["observations"], 1)

    def test_file_source_name_is_retained(self):
        file = self.write_packet(name="ground-station.jsonl")
        result = ingest.ingest_file(self.db, file, when=STAMP)
        self.assertEqual(store.get_batch(self.db, result.batch_id)["source_name"], file.name)

    def test_directory_import_is_ordered_and_isolates_errors(self):
        folder = self.root / "incoming"
        folder.mkdir()
        (folder / "a.jsonl").write_bytes(packet(1))
        (folder / "b.jsonl").write_bytes(packet(3))
        (folder / "c.jsonl").write_bytes(packet(2, [observation("sim-2")]))
        results = ingest.ingest_directory(self.db, folder, when=STAMP)
        self.assertEqual([item["status"] for item in results], ["accepted", "rejected", "accepted"])
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 2)
        self.assertEqual(store.counts(self.db)["quarantine"], 1)

    def test_stop_on_error_prevents_later_files(self):
        folder = self.root / "incoming"
        folder.mkdir()
        (folder / "a.jsonl").write_bytes(packet(2))
        (folder / "b.jsonl").write_bytes(packet(1))
        result = ingest.ingest_directory(self.db, folder, stop_on_error=True, when=STAMP)
        self.assertEqual(len(result), 1)
        self.assertEqual(store.counts(self.db)["batches"], 0)

    def test_database_reopen_preserves_cursor_and_handoffs(self):
        ingest.ingest_bytes(self.db, packet(), when=STAMP)
        self.db.close()
        reopened = store.open_database(self.db_path)
        self.db = reopened
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 1)
        self.assertEqual(len(handoff.list_handoffs(self.db)), 1)
        result = ingest.ingest_bytes(self.db, packet(2, [observation("sim-2")]), when=STAMP)
        self.assertEqual(result.status, "accepted")

    def test_packet_created_in_future_is_rejected(self):
        raw = packet(created_at="2026-10-28T12:30:00Z")
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, raw, when=STAMP)
        self.assertEqual(error.exception.code, "packet_future")

    def test_packet_created_too_long_ago_is_rejected(self):
        raw = packet(created_at="2026-09-01T12:00:00Z")
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, raw, when=STAMP)
        self.assertEqual(error.exception.code, "packet_stale")

    def test_source_file_missing_is_quarantined(self):
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_file(self.db, self.root / "missing.jsonl", when=STAMP)
        self.assertEqual(error.exception.code, "source_unreadable")
        self.assertEqual(store.counts(self.db)["quarantine"], 1)
