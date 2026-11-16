from __future__ import annotations

import hashlib
import json

from orbitbridge import audit, catalog, ingest, intake, protocol, recovery, store
from helpers import DatabaseCase, STAMP, observation, packet


class RecoveryTests(DatabaseCase):
    def test_plan_orders_sequence_instead_of_filename(self):
        folder = self.root / "incoming"
        folder.mkdir()
        (folder / "z-first.jsonl").write_bytes(packet(1))
        (folder / "a-second.jsonl").write_bytes(packet(2, [observation("sim-2")]))
        plan = recovery.plan_station(self.db, "sat-a", folder)
        self.assertEqual([entry["sequence"] for entry in plan["ready"]], [1, 2])
        self.assertEqual(plan["next_expected"], 3)

    def test_resume_advances_cursor_across_ready_packets(self):
        folder = self.root / "incoming"
        folder.mkdir()
        (folder / "z-first.jsonl").write_bytes(packet(1))
        (folder / "a-second.jsonl").write_bytes(packet(2, [observation("sim-2")]))
        outcome = recovery.resume_station(self.db, "sat-a", folder, when=STAMP)
        self.assertEqual([row["status"] for row in outcome["results"]], ["accepted", "accepted"])
        self.assertEqual(outcome["cursor_after"], 2)
        repeated = recovery.resume_station(self.db, "sat-a", folder, when=STAMP)
        self.assertEqual(repeated["results"], [])
        self.assertEqual(len(repeated["plan"]["duplicates"]), 2)

    def test_gap_is_planned_as_blocked(self):
        folder = self.root / "incoming"
        folder.mkdir()
        (folder / "three.jsonl").write_bytes(packet(3))
        plan = recovery.plan_station(self.db, "sat-a", folder)
        self.assertEqual(plan["ready"], [])
        self.assertEqual(plan["blocked"][0]["reason"], "waiting_for_gap")
        self.assertEqual(plan["blocked"][0]["expected"], 1)

    def test_plan_reports_conflicting_same_sequence(self):
        folder = self.root / "incoming"
        folder.mkdir()
        (folder / "a.jsonl").write_bytes(packet(1))
        (folder / "b.jsonl").write_bytes(packet(1, [observation("other")]))
        plan = recovery.plan_station(self.db, "sat-a", folder)
        self.assertEqual(len(plan["ready"]), 1)
        self.assertEqual(plan["blocked"][0]["reason"], "sequence_conflict")

    def test_plan_skips_unreadable_packet(self):
        folder = self.root / "incoming"
        folder.mkdir()
        (folder / "bad.jsonl").write_bytes(b"broken")
        plan = recovery.plan_station(self.db, "sat-a", folder)
        self.assertEqual(plan["unreadable"][0]["reason"], "bad_json")
        self.assertEqual(plan["ready"], [])

    def test_quarantine_retry_stays_on_same_packet_identity(self):
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, packet(2), when=STAMP)
        quarantine_id = error.exception.quarantine_id
        path = self.write_packet(2)
        plan = recovery.quarantine_retry_plan(self.db, quarantine_id, path)
        self.assertTrue(plan["same_content"])
        self.assertEqual(plan["sequence"], 2)
        ingest.ingest_bytes(self.db, packet(), when=STAMP)
        result = recovery.retry_file(self.db, quarantine_id, path, when=STAMP)
        self.assertEqual(result["result"]["status"], "rejected")
        self.assertEqual(result["result"]["code"], "observation_conflict")

    def test_quarantine_retry_rejects_different_content(self):
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, packet(3), when=STAMP)
        changed = self.write_packet(3, [observation("other")])
        with self.assertRaises(recovery.RecoveryError) as mismatch:
            recovery.quarantine_retry_plan(self.db, error.exception.quarantine_id, changed)
        self.assertEqual(mismatch.exception.code, "retry_mismatch")

    def test_manifest_preflight_resolves_order_across_filenames(self):
        first = self.write_packet(1, name="z.jsonl")
        second = self.write_packet(2, [observation("sim-2")], name="a.jsonl")
        manifest = self._manifest([first, second])
        plan = intake.preflight(self.db, manifest)
        self.assertEqual([entry["sequence"] for entry in plan["entries"]], [1, 2])
        self.assertEqual(plan["ready"], 2)
        self.assertEqual(plan["blocked"], 0)

    def test_manifest_executes_and_replay_is_idempotent(self):
        first = self.write_packet(1)
        second = self.write_packet(2, [observation("sim-2")])
        manifest = self._manifest([first, second])
        result = intake.execute_manifest(self.db, manifest, when=STAMP)
        self.assertEqual(result["accepted"], 2)
        self.assertEqual(store.counts(self.db)["batches"], 2)
        repeat = intake.execute_manifest(self.db, manifest, when=STAMP)
        self.assertEqual(repeat["accepted"], 0)
        self.assertEqual([row["status"] for row in repeat["results"]], ["duplicate", "duplicate"])

    def test_manifest_missing_file_is_reported(self):
        first = self.write_packet()
        manifest = self._manifest([first])
        first.unlink()
        plan = intake.preflight(self.db, manifest)
        self.assertEqual(plan["entries"][0]["status"], "missing")
        self.assertEqual(plan["blocked"], 1)

    def test_manifest_hash_mismatch_is_reported(self):
        first = self.write_packet()
        manifest = self._manifest([first])
        first.write_bytes(first.read_bytes() + b"x")
        plan = intake.preflight(self.db, manifest)
        self.assertEqual(plan["entries"][0]["status"], "checksum_mismatch")

    def test_manifest_rejects_path_traversal(self):
        raw = {"schema": 1, "name": "bad", "packets": [{"file": "../out.jsonl", "station_id": "sat-a",
              "sequence": 1, "sha256": "a" * 64}]}
        with self.assertRaises(intake.ManifestError) as error:
            intake.parse_manifest(json.dumps(raw).encode())
        self.assertEqual(error.exception.code, "file_name")

    def test_manifest_rejects_duplicate_sequence(self):
        first = self.write_packet()
        manifest = self._manifest([first])
        data = json.loads(manifest.read_text())
        data["packets"].append({**data["packets"][0], "file": "other.jsonl"})
        with self.assertRaises(intake.ManifestError) as error:
            intake.parse_manifest(json.dumps(data).encode())
        self.assertEqual(error.exception.code, "duplicate_sequence")

    def _manifest(self, paths):
        rows = []
        for path in paths:
            parsed = protocol.parse_packet_file(path)
            rows.append({"file": path.name, "station_id": parsed.envelope.station_id,
                         "sequence": parsed.envelope.sequence, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"schema": 1, "name": "synthetic-transfer", "packets": rows}))
        return manifest
