"""Regression checks for evidence-backed decision invariants."""
import csv
from copy import deepcopy
import unittest
from pathlib import Path

from main import DeletionAuditEngine


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"


class EvidenceDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = DeletionAuditEngine(str(DATASET))
        with (DATASET / "deletion_requests.csv").open(encoding="utf-8") as f:
            cls.requests = list(csv.DictReader(f))
        with (DATASET / "sample_deletion_requests.csv").open(encoding="utf-8") as f:
            cls.sample_requests = list(csv.DictReader(f))

    def test_request_emails_resolve_through_identity_history(self):
        unresolved = [r["case_id"] for r in self.requests
                      if r["email"].lower() not in self.engine.users_by_email]
        self.assertEqual(unresolved, [])

    def test_complete_never_has_an_empty_verification_sequence(self):
        unsupported = []
        for request in self.requests:
            status, steps = self.engine.audit_request(request)
            if status == "COMPLETE" and not steps:
                unsupported.append(request["case_id"])
        self.assertEqual(unsupported, [])

    def test_post_cutoff_observations_are_not_selected(self):
        request = next(r for r in self.requests if r["case_id"] == "case_33")
        status, steps = self.engine.audit_request(request)
        self.assertTrue(steps)
        for s in steps:
            ev_id = s.get("evidence_id")
            if ev_id and ev_id in self.engine.ev_manifest:
                self.assertLessEqual(self.engine.ev_manifest[ev_id]["captured_at"], request["audit_at"])

    def test_pre_request_tombstone_does_not_establish_current_state(self):
        request = next(r for r in self.sample_requests if r["case_id"] == "case_17")
        status, steps = self.engine.audit_request(request)
        self.assertEqual(status, "INCOMPLETE")
        self.assertFalse(any(s["resource_id"] == "tombstone_17" for s in steps))

    def test_latest_subject_linked_account_observation_beats_stale_map(self):
        request = next(r for r in self.sample_requests if r["case_id"] == "case_17")
        status, steps = self.engine.audit_request(request)
        account_steps = [s for s in steps if s["system_id"] == "account_service"]
        self.assertEqual([s["resource_id"] for s in account_steps], ["account_4092"])
        self.assertNotIn("account_6523", [s["resource_id"] for s in steps])

    def test_audit_cutoff_excludes_later_subject_linked_observations(self):
        request = deepcopy(next(r for r in self.sample_requests if r["case_id"] == "case_17"))
        request["audit_at"] = "2026-09-15T11:00:00Z"
        status, steps = self.engine.audit_request(request)
        resource_ids = [s["resource_id"] for s in steps]
        self.assertNotIn("account_4092", resource_ids)
        self.assertNotIn("backup_3245", resource_ids)

    def test_missing_or_ambiguous_account_evidence_keeps_fallback(self):
        request = next(r for r in self.sample_requests if r["case_id"] == "case_21")
        user_id = self.engine.users_by_email[request["email"].lower()]
        self.assertTrue(any(o["system_id"] == "account_service" and o["resource_id"] == "account_6440"
                            for o in self.engine.ev_obs))
        linked_accounts = [o for o in self.engine.ev_obs
                           if o["system_id"] == "account_service"
                           and request["requested_at"] <= o["captured_at"] <= request["audit_at"]
                           and self.engine.user_matches(user_id, o.get("user_id"), o.get("email"),
                                                        o.get("phone"), o.get("name"), o.get("hash"))]
        self.assertEqual(linked_accounts, [])
        status, steps = self.engine.audit_request(request)
        self.assertEqual(status, "COMPLETE")
        self.assertIn("account_021", [s["resource_id"] for s in steps])

    def test_document_identity_ignores_unlinked_pdf_metadata_email(self):
        user_id, email = self.engine.resolve_document_identity(
            {"priya.raman@gmail.com", "qK@aJ.x"}, set()
        )
        self.assertEqual((user_id, email), ("user_07", "priya.raman@gmail.com"))
        request = next(r for r in self.sample_requests if r["case_id"] == "case_07")
        status, steps = self.engine.audit_request(request)
        self.assertEqual(status, "INCOMPLETE")
        self.assertTrue(any(s["resource_id"] == "support_001" and s["evidence_id"] == "evidence_58"
                            for s in steps))

    def test_log_system_field_is_used_over_service_field(self):
        request = next(r for r in self.requests if r["case_id"] == "case_433")
        status, steps = self.engine.audit_request(request)
        self.assertTrue(steps, "identity-linked log lookups must produce steps")
        finding_systems = {s["system_id"] for s in steps if s["phase"] == "FINDING"}
        self.assertNotIn("downstream_delivery_service", finding_systems)
        self.assertTrue({"search_service", "integration_service"} & finding_systems)

    def test_later_account_not_found_overrides_earlier_found(self):
        request = next(r for r in self.requests if r["case_id"] == "case_86")
        status, steps = self.engine.audit_request(request)
        account_ops = [s for s in steps if s["resource_id"] == "account_8473"]
        self.assertTrue(account_ops)
        self.assertFalse(any(s["operation"] == "REPORT_REMAINING_RECORD" and s["resource_id"] == "account_8473"
                             for s in steps))


if __name__ == "__main__":
    unittest.main()
