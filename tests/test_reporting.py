from __future__ import annotations

import json

from orbitbridge import audit, diagnostics, export, handoff, ingest, quality, reconcile, store
from helpers import DatabaseCase, STAMP, observation, packet


class ReportingTests(DatabaseCase):
    def _seed_two(self):
        first = ingest.ingest_bytes(self.db, packet(), when=STAMP)
        second = ingest.ingest_bytes(self.db, packet(2, [observation("sim-2")]), when=STAMP)
        return first, second

    def test_export_contains_immutable_source_identifiers(self):
        first, _ = self._seed_two()
        destination = self.root / "handoffs.jsonl"
        receipt = export.export_handoffs(self.db, "north-watch", destination)
        self.assertEqual(receipt.rows, 2)
        rows = [json.loads(line) for line in destination.read_text().splitlines()]
        self.assertEqual(rows[0]["packet_id"], first.packet_id)
        self.assertEqual(rows[0]["batch_id"], first.batch_id)
        self.assertIn("fingerprint", rows[0])
        self.assertTrue(export.verify_export(destination, receipt.sha256, expected_rows=2)["ok"])

    def test_export_after_cursor_only_contains_newer_handoffs(self):
        self._seed_two()
        receipt = export.export_handoffs(self.db, "north-watch", self.root / "later.jsonl", start_id=1)
        self.assertEqual(receipt.rows, 1)
        self.assertEqual(json.loads((self.root / "later.jsonl").read_text())["handoff_id"], 2)

    def test_export_status_filter_uses_current_ack_state(self):
        self._seed_two()
        handoff.acknowledge(self.db, 1, "operator-a", when="2026-10-28T12:04:00Z")
        receipt = export.export_handoffs(self.db, "north-watch", self.root / "pending.jsonl", status="pending")
        self.assertEqual(receipt.rows, 1)
        row = json.loads((self.root / "pending.jsonl").read_text())
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["handoff_id"], 2)

    def test_export_never_overwrites_existing_file(self):
        self._seed_two()
        destination = self.root / "handoffs.jsonl"
        export.export_handoffs(self.db, "north-watch", destination)
        original = destination.read_bytes()
        with self.assertRaises(export.ExportError) as error:
            export.export_handoffs(self.db, "north-watch", destination)
        self.assertEqual(error.exception.code, "destination_exists")
        self.assertEqual(destination.read_bytes(), original)

    def test_export_verification_detects_mutation(self):
        self._seed_two()
        destination = self.root / "handoffs.jsonl"
        receipt = export.export_handoffs(self.db, "north-watch", destination)
        destination.write_bytes(destination.read_bytes().replace(b"sim-1", b"sim-9"))
        result = export.verify_export(destination, receipt.sha256, expected_rows=2)
        self.assertFalse(result["ok"])
        self.assertEqual(result["rows"], 2)

    def test_export_uses_explicit_end_boundary(self):
        self._seed_two()
        destination = self.root / "first.jsonl"
        receipt = export.export_handoffs(self.db, "north-watch", destination, end_id=1)
        self.assertEqual(receipt.maximum_handoff_id, 1)
        self.assertEqual(receipt.rows, 1)

    def test_batch_reconciliation_matches_observation_count(self):
        first, _ = self._seed_two()
        report = reconcile.batch_counts(self.db, first.batch_id)
        self.assertTrue(report["balanced"])
        self.assertEqual(report["observation_total"], 1)
        self.assertEqual(report["handoffs"][0]["count"], 1)

    def test_station_reconciliation_tracks_sequence_and_counts(self):
        self._seed_two()
        report = reconcile.station_counts(self.db, "sat-a")
        self.assertTrue(report["balanced"])
        self.assertEqual(report["batch_count"], 2)
        self.assertEqual(report["observation_count"], 2)
        self.assertEqual(report["station"]["committed_sequence"], 2)

    def test_subscription_reconciliation_tracks_acknowledgments(self):
        self._seed_two()
        handoff.acknowledge(self.db, 1, "operator-a", when="2026-10-28T12:04:00Z")
        report = reconcile.subscription_counts(self.db, "north-watch")
        self.assertTrue(report["balanced"])
        self.assertEqual(report["handoff_count"], 2)
        self.assertEqual({row["status"]: row["count"] for row in report["by_status"]},
                         {"pending": 1, "acknowledged": 1})

    def test_day_report_uses_receipt_time(self):
        self._seed_two()
        report = reconcile.day_counts(self.db, "2026-10-28")
        self.assertEqual(report["batch_count"], 2)
        self.assertEqual(report["observation_count"], 2)
        self.assertEqual(report["handoff_count"], 2)

    def test_quality_check_accepts_clean_database(self):
        self._seed_two()
        report = quality.check_all(self.db)
        self.assertTrue(report["ok"])
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["counts"]["batches"], 2)

    def test_quality_check_detects_manual_threshold_corruption(self):
        self._seed_two()
        self.db.execute("UPDATE subscriptions SET minimum_severity=5 WHERE subscription_id='north-watch'")
        report = quality.check_all(self.db)
        self.assertFalse(report["ok"])
        self.assertIn("threshold_mismatch", {item["code"] for item in report["issues"]})

    def test_diagnostics_identifies_sequence_gap_without_mutating_database(self):
        path = self.write_packet(3)
        result = diagnostics.inspect_packet(self.db, path)
        self.assertEqual(result["status"], "gap")
        self.assertEqual(result["committed_sequence"], 0)
        self.assertEqual(store.counts(self.db)["batches"], 0)
        self.assertEqual(store.counts(self.db)["quarantine"], 0)

    def test_diagnostics_distinguishes_duplicate_from_conflict(self):
        original = self.write_packet(1, name="original.jsonl")
        ingest.ingest_file(self.db, original, when=STAMP)
        changed = self.write_packet(1, [observation("changed")], name="changed.jsonl")
        self.assertEqual(diagnostics.inspect_packet(self.db, original)["status"], "duplicate")
        self.assertEqual(diagnostics.inspect_packet(self.db, changed)["status"], "sequence_conflict")

    def test_full_reconciliation_has_station_and_subscription_views(self):
        self._seed_two()
        report = reconcile.full_reconciliation(self.db)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["stations"]), 1)
        self.assertEqual(len(report["subscriptions"]), 1)
        self.assertEqual(report["problems"], [])

    def test_audit_observation_links_back_to_batch_and_handoff(self):
        self._seed_two()
        detail = audit.observation_detail(self.db, 1)
        self.assertEqual(detail["batch"]["sequence"], 1)
        self.assertEqual(detail["handoffs"][0]["subscription_id"], "north-watch")
        self.assertEqual(detail["observation"]["external_id"], "sim-1")
