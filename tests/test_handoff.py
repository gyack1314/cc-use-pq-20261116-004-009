from __future__ import annotations

from orbitbridge import audit, catalog, handoff, ingest, store
from helpers import DatabaseCase, STAMP, observation, packet


class HandoffTests(DatabaseCase):
    def _create(self):
        result = ingest.ingest_bytes(self.db, packet(), when=STAMP)
        item = handoff.list_handoffs(self.db)[0]
        return result, item

    def test_handoff_includes_packet_provenance(self):
        result, item = self._create()
        self.assertEqual(item["station_id"], "sat-a")
        self.assertEqual(item["sequence"], 1)
        self.assertEqual(item["batch_id"], result.batch_id)
        self.assertEqual(item["packet_id"], result.packet_id)
        self.assertEqual(item["region"], "north")
        self.assertEqual(item["external_id"], "sim-1")

    def test_acknowledge_updates_state_and_activity(self):
        _, item = self._create()
        response = handoff.acknowledge(self.db, item["handoff_id"], "operator-a", when="2026-10-28T12:04:00Z")
        self.assertEqual(response["status"], "acknowledged")
        self.assertEqual(response["operator"], "operator-a")
        self.assertEqual(len(handoff.list_handoffs(self.db, status="pending")), 0)
        self.assertEqual(len(handoff.list_handoffs(self.db, status="acknowledged")), 1)
        events = audit.list_activity(self.db, entity_type="handoff", entity_id=str(item["handoff_id"]))
        self.assertEqual([event["event_type"] for event in events], ["handoff_created", "handoff_acknowledged"])

    def test_same_operator_duplicate_ack_is_idempotent(self):
        _, item = self._create()
        handoff.acknowledge(self.db, item["handoff_id"], "operator-a", when="2026-10-28T12:04:00Z")
        activity_before = store.counts(self.db)["activity"]
        again = handoff.acknowledge(self.db, item["handoff_id"], "operator-a", when="2026-10-28T12:05:00Z")
        self.assertEqual(again["status"], "duplicate")
        self.assertEqual(again["acknowledged_at"], "2026-10-28T12:04:00Z")
        self.assertEqual(store.counts(self.db)["activity"], activity_before)

    def test_other_operator_cannot_claim_acknowledged_item(self):
        _, item = self._create()
        handoff.acknowledge(self.db, item["handoff_id"], "operator-a")
        with self.assertRaises(handoff.HandoffError) as error:
            handoff.acknowledge(self.db, item["handoff_id"], "operator-b")
        self.assertEqual(error.exception.code, "already_acknowledged")
        self.assertEqual(store.get_handoff(self.db, item["handoff_id"])["operator"], "operator-a")

    def test_missing_handoff_is_rejected(self):
        with self.assertRaises(handoff.HandoffError) as error:
            handoff.acknowledge(self.db, 100, "operator-a")
        self.assertEqual(error.exception.code, "handoff_missing")

    def test_operator_cannot_be_empty(self):
        _, item = self._create()
        with self.assertRaises(handoff.HandoffError) as error:
            handoff.acknowledge(self.db, item["handoff_id"], "  ")
        self.assertEqual(error.exception.code, "operator")

    def test_queue_filter_uses_subscription_and_status(self):
        catalog.register_subscription(self.db, "backup", "north", 1, "0.1")
        self._create()
        self.assertEqual(len(handoff.list_handoffs(self.db)), 2)
        self.assertEqual(len(handoff.list_handoffs(self.db, subscription_id="backup")), 1)
        self.assertEqual(len(handoff.list_handoffs(self.db, subscription_id="north-watch")), 1)
        self.assertEqual(len(handoff.list_handoffs(self.db, status="acknowledged")), 0)

    def test_queue_pagination_is_stable(self):
        self._create()
        ingest.ingest_bytes(self.db, packet(2, [observation("sim-2")]), when=STAMP)
        first = handoff.list_handoffs(self.db, limit=1)
        second = handoff.list_handoffs(self.db, limit=1, after_id=first[0]["handoff_id"])
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertLess(first[0]["handoff_id"], second[0]["handoff_id"])

    def test_subscription_summary_tracks_acknowledgment(self):
        _, item = self._create()
        before = handoff.subscription_summary(self.db, "north-watch")
        self.assertEqual((before["pending"], before["acknowledged"]), (1, 0))
        handoff.acknowledge(self.db, item["handoff_id"], "operator-a")
        after = handoff.subscription_summary(self.db, "north-watch")
        self.assertEqual((after["pending"], after["acknowledged"]), (0, 1))

    def test_trace_links_handoff_to_original_batch(self):
        result, item = self._create()
        trace = audit.handoff_trace(self.db, item["handoff_id"])
        self.assertEqual(trace["handoff"]["batch_id"], result.batch_id)
        self.assertEqual(trace["handoff"]["digest"], store.get_batch(self.db, result.batch_id)["digest"])
        self.assertEqual(trace["activity"][0]["details"]["observation_id"], item["observation_id"])

    def test_inactive_subscription_does_not_remove_existing_handoff(self):
        _, item = self._create()
        catalog.set_subscription_active(self.db, "north-watch", False)
        self.assertEqual(len(handoff.list_handoffs(self.db)), 1)
        self.assertEqual(handoff.handoff_detail(self.db, item["handoff_id"])["status"], "pending")

    def test_region_report_reconciles_pending_and_acknowledged(self):
        _, item = self._create()
        before = audit.region_report(self.db, "north")
        self.assertEqual(before["observations"], 1)
        self.assertEqual(before["pending"], 1)
        handoff.acknowledge(self.db, item["handoff_id"], "operator-a")
        after = audit.region_report(self.db, "north")
        self.assertEqual(after["pending"], 0)
        self.assertEqual(after["acknowledged"], 1)
