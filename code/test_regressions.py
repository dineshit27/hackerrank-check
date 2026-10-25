"""Regression checks for evidence-backed decision invariants."""
import csv
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
