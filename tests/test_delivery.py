from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from orbitbridge import export, handoff, ingest, receipts, responsibility, store
from helpers import DatabaseCase, STAMP, observation, packet


class DeliveryCase(DatabaseCase):
    def setUp(self) -> None:
        super().setUp()
        receipts.register_receiver(self.db, "ext-a", "外部应急甲", when=STAMP)

    def _seed(self, count: int = 2):
        first = ingest.ingest_bytes(self.db, packet(), when=STAMP)
        if count > 1:
            ingest.ingest_bytes(self.db, packet(2, [observation("sim-2")]), when=STAMP)
        return first

    def _deliver(self, name: str = "delivery.jsonl", *, register: bool = True,
                 receiver: str | None = "ext-a") -> dict:
        receipt = export.export_delivery(self.db, "north-watch", self.root / name,
                                         receiver_id=receiver, when=STAMP)
        if register:
            export.register_delivery(self.db, receipt.delivery_key, when=STAMP)
        return receipt.as_dict()

    def _descriptor(self, delivery: dict) -> dict:
        return json.loads(Path(delivery["descriptor"]).read_text())

    def _receipt(self, delivery: dict, *, receipt_id: str = "r-1", receiver: str = "ext-a",
                 results: list[str] | None = None) -> dict:
        header = self._descriptor(delivery)
        items = []
        for index, item in enumerate(header["items"]):
            result = results[index] if results is not None else "received"
            items.append({"handoff_id": item["handoff_id"],
                          "observation_fingerprint": item["observation_fingerprint"],
                          "result": result})
        return {"kind": "handoff-receipt", "schema": 1, "receipt_id": receipt_id,
                "receiver_id": receiver, "delivery_key": header["delivery_key"],
                "received_at": "2026-10-28T12:05:00Z", "items": items}

    def _submit(self, payload: dict, *, name: str | None = None) -> dict:
        path = self.root / (name or f"{payload['receipt_id']}.json")
        path.write_text(json.dumps(payload, ensure_ascii=False))
        return receipts.submit_receipt(self.db, path, when=STAMP)

    def _responsibility(self, handoff_id: int) -> dict:
        return responsibility.current(self.db, handoff_id, STAMP)

    def test_delivery_descriptor_is_self_describing_and_registrable(self):
        self._seed()
        delivery = self._deliver(register=False)
        self.assertEqual(delivery["status"], "prepared")
        header = self._descriptor(delivery)
        self.assertEqual(header["kind"], "handoff-delivery")
        self.assertEqual(header["rows"], 2)
        self.assertEqual([item["ordinal"] for item in header["items"]], [1, 2])
        self.assertEqual(header["body_sha256"], hashlib.sha256(Path(delivery["destination"]).read_bytes()).hexdigest())
        registered = export.register_delivery(self.db, delivery["delivery_key"], when=STAMP)
        self.assertEqual(registered["status"], "registered")
        verified = export.verify_delivery(self.db, delivery["delivery_key"])
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["problems"], [])

    def test_receipt_requires_registered_matching_delivery(self):
        self._seed()
        delivery = self._deliver(register=False)
        outcome = self._submit(self._receipt(delivery))
        self.assertEqual(outcome["receipt"]["status"], "pending")
        self.assertEqual(outcome["receipt"]["reason_code"], "delivery_unregistered")
        self.assertEqual(self._responsibility(1)["state"], "open")
        export.register_delivery(self.db, delivery["delivery_key"], when=STAMP)
        rechecked = receipts.recheck_receipt(self.db, outcome["receipt"]["receipt_pk"], when=STAMP)
        self.assertEqual(rechecked["receipt"]["status"], "verified")
        self.assertEqual(rechecked["released"], 2)
        self.assertEqual(self._responsibility(1)["state"], "released_external")

    def test_unknown_delivery_stays_pending_until_manifest_recovered(self):
        self._seed()
        other_root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(other_root))
        other_db = store.open_database(other_root / "other.sqlite3")
        self.addCleanup(other_db.close)
        from orbitbridge import catalog
        catalog.register_station(other_db, "sat-a", "合成观测站", when=STAMP)
        catalog.register_subscription(other_db, "north-watch", "north", 3, "0.7", when=STAMP)
        receipts.register_receiver(other_db, "ext-a", "外部应急甲", when=STAMP)
        ingest.ingest_bytes(other_db, packet(), when=STAMP)
        ingest.ingest_bytes(other_db, packet(2, [observation("sim-2")]), when=STAMP)
        delivered = export.export_delivery(other_db, "north-watch", other_root / "remote.jsonl",
                                           receiver_id="ext-a", when=STAMP)
        payload = self._receipt(delivered.as_dict())
        outcome = self._submit(payload)
        self.assertEqual(outcome["receipt"]["status"], "pending")
        self.assertEqual(outcome["receipt"]["reason_code"], "delivery_unknown")
        moved_body = self.root / "remote.jsonl"
        moved_body.write_bytes(Path(delivered.destination).read_bytes())
        moved_descriptor = self.root / "remote.jsonl.delivery.json"
        moved_descriptor.write_bytes(Path(delivered.descriptor).read_bytes())
        recovered = export.recover_delivery(self.db, moved_body, when=STAMP)
        self.assertTrue(recovered["recovered"])
        rechecked = receipts.recheck_receipt(self.db, outcome["receipt"]["receipt_pk"], when=STAMP)
        self.assertEqual(rechecked["receipt"]["status"], "verified")
        self.assertEqual(rechecked["released"], 2)

    def test_missing_receiver_is_pending_then_verified_after_registration(self):
        self._seed()
        delivery = self._deliver()
        payload = self._receipt(delivery, receiver="ext-late")
        outcome = self._submit(payload)
        self.assertEqual(outcome["receipt"]["status"], "pending")
        self.assertEqual(outcome["receipt"]["reason_code"], "receiver_unknown")
        receipts.register_receiver(self.db, "ext-late", "外部应急迟到", when=STAMP)
        rechecked = receipts.recheck_receipt(self.db, outcome["receipt"]["receipt_pk"], when=STAMP)
        self.assertEqual(rechecked["receipt"]["status"], "disputed")
        self.assertEqual(rechecked["receipt"]["reason_code"], "receiver_mismatch")

    def test_blank_receiver_registration_allows_verification(self):
        self._seed()
        delivery = self._deliver(receiver=None)
        payload = self._receipt(delivery, receiver="ext-late")
        outcome = self._submit(payload)
        self.assertEqual(outcome["receipt"]["reason_code"], "receiver_unknown")
        receipts.register_receiver(self.db, "ext-late", "外部应急迟到", when=STAMP)
        rechecked = receipts.recheck_receipt(self.db, outcome["receipt"]["receipt_pk"], when=STAMP)
        self.assertEqual(rechecked["receipt"]["status"], "verified")
        self.assertEqual(self._responsibility(1)["state"], "released_external")

    def test_receipt_releases_only_matching_current_revision(self):
        self._seed()
        delivery = self._deliver()
        outcome = self._submit(self._receipt(delivery))
        self.assertEqual(outcome["receipt"]["status"], "verified")
        self.assertEqual(outcome["released"], 2)
        items = {item["handoff_id"]: item for item in outcome["items"]}
        self.assertEqual(items[1]["verdict"], "released")
        self.assertEqual(self._responsibility(1)["state"], "released_external")
        self.assertEqual(self._responsibility(1)["reason"], "receipt:r-1")
        self.assertEqual(store.get_handoff(self.db, 1)["status"], "pending")

    def test_not_received_retains_responsibility(self):
        self._seed()
        delivery = self._deliver()
        outcome = self._submit(self._receipt(delivery, results=["not_received", "received"]))
        self.assertEqual(outcome["receipt"]["status"], "verified")
        self.assertEqual(outcome["released"], 1)
        items = {item["handoff_id"]: item for item in outcome["items"]}
        self.assertEqual(items[1]["verdict"], "retained")
        self.assertEqual(items[1]["reason_code"], "not_received")
        self.assertEqual(self._responsibility(1)["state"], "open")
        self.assertEqual(self._responsibility(2)["state"], "released_external")

    def test_same_receipt_same_content_is_idempotent(self):
        self._seed()
        delivery = self._deliver()
        payload = self._receipt(delivery)
        first = self._submit(payload)
        self.assertEqual(first["receipt"]["status"], "verified")
        events_after_first = self.db.execute(
            "SELECT COUNT(*) FROM responsibility_events WHERE event_type='externally_released'").fetchone()[0]
        second = self._submit(payload, name="again.json")
        self.assertEqual(second["submission"], "duplicate")
        self.assertEqual(second["receipt"]["attempts"], 2)
        events_after_second = self.db.execute(
            "SELECT COUNT(*) FROM responsibility_events WHERE event_type='externally_released'").fetchone()[0]
        self.assertEqual(events_after_first, events_after_second)
        self.assertEqual(self._responsibility(1)["revision"], 2)

    def test_same_receipt_id_different_content_keeps_conflict(self):
        self._seed()
        delivery = self._deliver()
        first = self._submit(self._receipt(delivery))
        changed = self._receipt(delivery, results=["not_received", "not_received"])
        second = self._submit(changed, name="changed.json")
        self.assertEqual(second["submission"], "conflict")
        self.assertTrue(second["receipt"]["conflict"])
        self.assertEqual(second["receipt"]["status"], "verified")
        self.assertEqual(len(second["conflicts"]), 1)
        stored = receipts.receipt_detail(self.db, first["receipt"]["receipt_pk"])
        self.assertEqual(stored["receipt"]["content_sha256"], first["receipt"]["content_sha256"])
        self.assertEqual(self._responsibility(1)["state"], "released_external")

    def test_incomplete_coverage_is_disputed_and_does_not_release(self):
        self._seed()
        delivery = self._deliver()
        payload = self._receipt(delivery)
        payload["items"] = payload["items"][:1]
        outcome = self._submit(payload)
        self.assertEqual(outcome["receipt"]["status"], "disputed")
        self.assertEqual(outcome["receipt"]["reason_code"], "coverage_incomplete")
        self.assertIn("missing", outcome["receipt"]["reason"])
        self.assertEqual(self._responsibility(1)["state"], "open")
        self.assertEqual(store.get_handoff(self.db, 1)["status"], "pending")

    def test_fingerprint_mismatch_is_disputed(self):
        self._seed()
        delivery = self._deliver()
        payload = self._receipt(delivery)
        payload["items"][0]["observation_fingerprint"] = "a" * 64
        outcome = self._submit(payload)
        self.assertEqual(outcome["receipt"]["status"], "disputed")
        self.assertIn("fingerprint", outcome["receipt"]["reason"])
        self.assertEqual(self._responsibility(1)["state"], "open")

    def test_late_receipt_after_reassignment_only_confirms_original_delivery(self):
        self._seed()
        delivery = self._deliver()
        responsibility.reassign(self.db, 1, "值守员乙", reason="交接中途改派", when="2026-10-28T12:10:00Z")
        outcome = self._submit(self._receipt(delivery))
        self.assertEqual(outcome["receipt"]["status"], "verified")
        items = {item["handoff_id"]: item for item in outcome["items"]}
        self.assertEqual(items[1]["verdict"], "retained")
        self.assertEqual(items[1]["reason_code"], "responsibility_changed")
        latest = self._responsibility(1)
        self.assertEqual(latest["state"], "open")
        self.assertEqual(latest["assignee"], "值守员乙")
        self.assertEqual(self._responsibility(2)["state"], "released_external")

    def test_late_receipt_after_local_acknowledgment_does_not_reopen_or_release(self):
        self._seed()
        delivery = self._deliver()
        handoff.acknowledge(self.db, 1, "值守员甲", when="2026-10-28T12:10:00Z")
        outcome = self._submit(self._receipt(delivery))
        self.assertEqual(outcome["receipt"]["status"], "verified")
        items = {item["handoff_id"]: item for item in outcome["items"]}
        self.assertEqual(items[1]["reason_code"], "locally_acknowledged")
        latest = self._responsibility(1)
        self.assertEqual(latest["state"], "acknowledged")
        self.assertEqual(latest["event_type"], "acknowledged")

    def test_receipt_trace_records_pending_reason(self):
        from orbitbridge import audit
        self._seed()
        delivery = self._deliver(register=False)
        pending = self._submit(self._receipt(delivery))
        trace = audit.receipt_trace(self.db, pending["receipt"]["receipt_pk"])
        self.assertEqual(trace["receipt"]["status"], "pending")
        self.assertEqual(trace["receipt"]["reason_code"], "delivery_unregistered")
        self.assertIsNone(trace["delivery"])
        self.assertIn("receipt_pending", [event["event_type"] for event in trace["activity"]])

    def test_trace_separates_external_receipt_from_local_handling(self):
        from orbitbridge import audit
        self._seed()
        delivery = self._deliver()
        outcome = self._submit(self._receipt(delivery))
        trace = audit.handoff_trace(self.db, 1)
        self.assertEqual(trace["states"]["local_handoff"], "pending")
        self.assertTrue(trace["states"]["external_receipt"])
        self.assertEqual(trace["states"]["responsibility"], "released_external")
        self.assertEqual(trace["receipts"][0]["receipt_status"], "verified")
        self.assertEqual([row["event_type"] for row in trace["responsibility"]],
                         ["created", "externally_released"])
        self.assertEqual(outcome["receipt"]["status"], "verified")

    def test_receipt_after_registered_delivery_can_be_rechecked_in_batch(self):
        self._seed()
        delivery = self._deliver(register=False)
        pending = self._submit(self._receipt(delivery))
        self.assertEqual(pending["receipt"]["status"], "pending")
        export.register_delivery(self.db, delivery["delivery_key"], when=STAMP)
        report = receipts.recheck_pending(self.db, when=STAMP)
        self.assertEqual(report["checked"], 1)
        self.assertEqual(report["results"][0]["status"], "verified")

    def test_verify_delivery_detects_body_mutation(self):
        self._seed()
        delivery = self._deliver()
        body = Path(delivery["destination"])
        body.write_bytes(body.read_bytes().replace(b"sim-1", b"sim-9"))
        report = export.verify_delivery(self.db, delivery["delivery_key"])
        self.assertFalse(report["ok"])
        self.assertIn("body_digest", report["problems"])

    def test_export_delivery_refuses_duplicate_or_overwrite(self):
        self._seed()
        delivery = self._deliver()
        with self.assertRaises(export.ExportError) as duplicate:
            export.export_delivery(self.db, "north-watch", self.root / "copy.jsonl",
                                   receiver_id="ext-a", when=STAMP)
        self.assertEqual(duplicate.exception.code, "delivery_exists")
        with self.assertRaises(export.ExportError) as overwrite:
            export.export_delivery(self.db, "north-watch", self.root / "delivery.jsonl",
                                   receiver_id="ext-a", when=STAMP)
        self.assertEqual(overwrite.exception.code, "destination_exists")
        self.assertEqual(export.find_delivery(self.db, delivery["delivery_key"])["rows"], 2)

    def test_recovered_delivery_cannot_be_substituted(self):
        self._seed()
        delivery = self._deliver(register=False)
        self.expect_recovery_substitution(delivery["destination"])
        recovered = export.recover_delivery(self.db, delivery["destination"], when=STAMP)
        self.assertTrue(recovered["recovered"])
        self.assertEqual(recovered["delivery"]["status"], "registered")
        self.assertTrue(export.verify_delivery(self.db, delivery["delivery_key"])["ok"])

    def expect_recovery_substitution(self, destination: str) -> None:
        body = Path(destination)
        original = body.read_bytes()
        body.write_bytes(original.replace(b"sim-1", b"sim-9"))
        with self.assertRaises(export.ExportError) as error:
            export.recover_delivery(self.db, destination, when=STAMP)
        self.assertEqual(error.exception.code, "delivery_changed")
        prepared = export.find_delivery(self.db, json.loads(
            Path(destination + ".delivery.json").read_text())["delivery_key"])
        self.assertEqual(prepared["status"], "prepared")
        self.assertIsNone(prepared["registered_at"])
        body.write_bytes(original)

    def test_receipt_time_outside_delivery_window_is_disputed(self):
        self._seed()
        delivery = self._deliver()
        payload = self._receipt(delivery)
        payload["received_at"] = "2026-10-28T11:00:00Z"
        outcome = self._submit(payload)
        self.assertEqual(outcome["receipt"]["status"], "disputed")
        self.assertEqual(outcome["receipt"]["reason_code"], "receipt_time")
        self.assertEqual(self._responsibility(1)["state"], "open")

    def test_receipt_parser_rejects_unknown_fields_and_duplicates(self):
        with self.assertRaises(receipts.ReceiptError):
            receipts.parse_receipt_bytes(b"{}")
        payload = {"kind": "handoff-receipt", "schema": 1, "receipt_id": "r", "receiver_id": "ext-a",
                   "delivery_key": "a" * 64, "received_at": STAMP,
                   "items": [{"handoff_id": 1, "observation_fingerprint": "b" * 64, "result": "received"},
                             {"handoff_id": 1, "observation_fingerprint": "b" * 64, "result": "received"}]}
        with self.assertRaises(receipts.ReceiptError) as error:
            receipts.parse_receipt_bytes(json.dumps(payload).encode())
        self.assertEqual(error.exception.code, "item_duplicate")


class ReceiptIntakeTests(DeliveryCase):
    def test_directory_intake_isolates_invalid_receipt_and_recovers(self):
        self._seed()
        delivery = self._deliver()
        folder = self.root / "receipts"
        folder.mkdir()
        good = self._receipt(delivery, receipt_id="r-good")
        (folder / "good.json").write_text(json.dumps(good))
        (folder / "bad.json").write_text("{not json")
        results = receipts.ingest_receipt_directory(self.db, folder, when=STAMP)
        statuses = {row["source_name"]: row["submission"] for row in results}
        self.assertEqual(statuses["good.json"], "recorded")
        self.assertEqual(statuses["bad.json"], "quarantined")
        by_name = {row["source_name"]: row for row in results}
        self.assertEqual(by_name["good.json"]["status"], "verified")
        quarantined = receipts.list_receipt_quarantine(self.db)
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0]["reason_code"], "receipt_json")
        retried = receipts.retry_receipt(self.db, quarantined[0]["receipt_quarantine_id"],
                                         folder / "bad.json", when=STAMP)
        self.assertEqual(retried["status"], "still_invalid")
        self.assertEqual(retried["code"], "receipt_json")

    def test_receipt_retry_rejects_substituted_content(self):
        folder = self.root / "receipts"
        folder.mkdir()
        (folder / "bad.json").write_text("{not json")
        results = receipts.ingest_receipt_directory(self.db, folder, when=STAMP)
        self.assertEqual(results[0]["submission"], "quarantined")
        item = receipts.list_receipt_quarantine(self.db)[0]
        changed = folder / "other.json"
        changed.write_text("{\"kind\":\"handoff-receipt\"}")
        with self.assertRaises(receipts.ReceiptError) as error:
            receipts.retry_receipt(self.db, item["receipt_quarantine_id"], changed, when=STAMP)
        self.assertEqual(error.exception.code, "retry_mismatch")

    def test_receipt_manifest_preflight_and_execution(self):
        self._seed()
        delivery = self._deliver(register=False)
        folder = self.root / "batch"
        folder.mkdir()
        payload = self._receipt(delivery)
        good = folder / "r1.json"
        good.write_text(json.dumps(payload))
        broken = folder / "r2.json"
        broken.write_text("{broken")
        manifest = folder / "manifest.json"
        manifest.write_text(json.dumps({"kind": "handoff-receipts", "schema": 1, "name": "external-batch",
                                        "receipts": [
                                            {"file": "r1.json",
                                             "sha256": hashlib.sha256(good.read_bytes()).hexdigest()},
                                            {"file": "r2.json",
                                             "sha256": hashlib.sha256(broken.read_bytes()).hexdigest()}]}))
        plan = receipts.preflight_receipts(self.db, manifest)
        self.assertEqual(plan["ready"], 1)
        self.assertEqual(plan["blocked"], 1)
        self.assertEqual(plan["entries"][1]["status"], "invalid_receipt")
        outcome = receipts.execute_receipt_manifest(self.db, manifest, when=STAMP)
        self.assertEqual(outcome["pending"], 1)
        self.assertEqual(outcome["results"][1]["submission"], "skipped")
        export.register_delivery(self.db, delivery["delivery_key"], when=STAMP)
        rechecked = receipts.recheck_pending(self.db, when=STAMP)
        self.assertEqual(rechecked["results"][0]["status"], "verified")
        repeat = receipts.execute_receipt_manifest(self.db, manifest, when=STAMP)
        self.assertEqual(repeat["results"][0]["submission"], "duplicate")

    def test_receipt_manifest_rejects_traversal(self):
        raw = {"kind": "handoff-receipts", "schema": 1, "name": "bad",
               "receipts": [{"file": "../x.json", "sha256": "a" * 64}]}
        with self.assertRaises(receipts.ReceiptError) as error:
            receipts.parse_receipt_manifest(json.dumps(raw).encode())
        self.assertEqual(error.exception.code, "manifest_file")


class DeliveryIntegrityTests(DeliveryCase):
    def test_forged_descriptor_items_cannot_be_recovered(self):
        self._seed()
        delivery = self._deliver(register=False)
        header = self._descriptor(delivery)
        header["items"][0]["observation_fingerprint"] = "a" * 64
        Path(delivery["descriptor"]).write_text(json.dumps(header, sort_keys=True))
        with self.assertRaises(export.ExportError) as error:
            export.recover_delivery(self.db, delivery["destination"], when=STAMP)
        self.assertEqual(error.exception.code, "descriptor_changed")

    def test_recovered_delivery_is_required_for_receipt(self):
        self._seed()
        delivery = self._deliver(register=False)
        pending = self._submit(self._receipt(delivery))
        self.assertEqual(pending["receipt"]["status"], "pending")
        export.recover_delivery(self.db, delivery["destination"], when=STAMP)
        detail = receipts.receipt_detail(self.db, pending["receipt"]["receipt_pk"])
        self.assertEqual(detail["receipt"]["status"], "pending")
        rechecked = receipts.recheck_receipt(self.db, pending["receipt"]["receipt_pk"], when=STAMP)
        self.assertEqual(rechecked["receipt"]["status"], "verified")

    def test_quality_and_verify_accept_receipt_lineage(self):
        from orbitbridge import audit, quality
        self._seed()
        delivery = self._deliver()
        self._submit(self._receipt(delivery))
        self.assertTrue(quality.check_all(self.db)["ok"])
        self.assertEqual(audit.verify_lineage(self.db), [])

    def test_quality_detects_released_without_responsibility(self):
        from orbitbridge import quality
        self._seed()
        delivery = self._deliver()
        self._submit(self._receipt(delivery))
        self.db.execute("DELETE FROM responsibility_events WHERE event_type='externally_released'")
        report = quality.check_all(self.db)
        self.assertFalse(report["ok"])
        self.assertIn("released_without_responsibility", {item["code"] for item in report["issues"]})


class RecoveredDescriptorTests(DeliveryCase):
    def test_self_consistent_forged_descriptor_is_still_rejected(self):
        self._seed()
        delivery = self._deliver(register=False)
        header = self._descriptor(delivery)
        # 攻击者改掉逐项指纹并重算交付标识，使描述与正文自洽。
        header["items"][0]["observation_fingerprint"] = "a" * 64
        header["delivery_key"] = export._delivery_key(header)
        Path(delivery["descriptor"]).write_text(json.dumps(header, sort_keys=True))
        self.db.execute("DELETE FROM delivery_items")
        self.db.execute("DELETE FROM deliveries")
        with self.assertRaises(export.ExportError) as error:
            export.recover_delivery(self.db, delivery["destination"], when=STAMP)
        self.assertEqual(error.exception.code, "delivery_items_mismatch")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 0)


class ResponsibilityBoundaryTests(DeliveryCase):
    def test_local_ack_cannot_reopen_released_responsibility(self):
        self._seed()
        delivery = self._deliver()
        self._submit(self._receipt(delivery))
        with self.assertRaises(responsibility.ResponsibilityError) as error:
            handoff.acknowledge(self.db, 1, "值守员甲", when=STAMP)
        self.assertEqual(error.exception.code, "responsibility_released")
        self.assertEqual(store.get_handoff(self.db, 1)["status"], "pending")

    def test_reassignment_after_external_release_is_refused(self):
        self._seed()
        delivery = self._deliver()
        self._submit(self._receipt(delivery))
        with self.assertRaises(responsibility.ResponsibilityError):
            responsibility.reassign(self.db, 1, "值守员乙", when=STAMP)
        self.assertEqual(self._responsibility(1)["state"], "released_external")

    def test_receipt_for_wrong_receiver_is_disputed(self):
        self._seed()
        delivery = self._deliver()
        receipts.register_receiver(self.db, "ext-other", "外部乙", when=STAMP)
        payload = self._receipt(delivery, receiver="ext-other")
        outcome = self._submit(payload)
        self.assertEqual(outcome["receipt"]["status"], "disputed")
        self.assertEqual(outcome["receipt"]["reason_code"], "receiver_mismatch")
        self.assertEqual(self._responsibility(1)["state"], "open")

    def test_receipt_before_delivery_creation_is_disputed(self):
        self._seed()
        delivery = self._deliver()
        payload = self._receipt(delivery)
        payload["received_at"] = "2026-10-28T11:00:00Z"
        outcome = self._submit(payload)
        self.assertEqual(outcome["receipt"]["reason_code"], "receipt_time")

    def test_disputed_receipt_is_not_silently_upgraded_by_duplicate(self):
        self._seed()
        delivery = self._deliver()
        payload = self._receipt(delivery)
        payload["items"] = payload["items"][:1]
        first = self._submit(payload)
        self.assertEqual(first["receipt"]["status"], "disputed")
        again = self._submit(payload, name="again.json")
        self.assertEqual(again["submission"], "duplicate")
        self.assertEqual(again["receipt"]["status"], "disputed")
        self.assertEqual(self._responsibility(1)["state"], "open")


class InterruptedWriteTests(DeliveryCase):
    def test_interrupted_body_write_is_recovered_from_registration(self):
        self._seed()
        delivery = self._deliver(register=False)
        recorded = export.find_delivery(self.db, delivery["delivery_key"])
        original = Path(delivery["destination"]).read_bytes()
        Path(delivery["destination"]).unlink()
        recovered = export.recover_delivery(self.db, delivery["destination"], when=STAMP)
        self.assertTrue(recovered["recovered"])
        self.assertEqual(Path(delivery["destination"]).read_bytes(), original)
        self.assertTrue(export.verify_delivery(self.db, delivery["delivery_key"])["ok"])
        self.assertEqual(export.find_delivery(self.db, delivery["delivery_key"])["status"], "registered")
        self.assertEqual(recorded["body_sha256"], export.find_delivery(self.db, delivery["delivery_key"])["body_sha256"])

    def test_interrupted_descriptor_write_is_recovered(self):
        self._seed()
        delivery = self._deliver(register=False)
        Path(delivery["descriptor"]).unlink()
        recovered = export.recover_delivery(self.db, delivery["destination"], when=STAMP)
        self.assertTrue(recovered["recovered"])
        header = json.loads(Path(delivery["descriptor"]).read_text())
        self.assertEqual(header["delivery_key"], delivery["delivery_key"])
        self.assertTrue(export.verify_delivery(self.db, delivery["delivery_key"])["ok"])
