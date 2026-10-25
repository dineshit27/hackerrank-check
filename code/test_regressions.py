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
        uid = self.engine.users_by_email[request["email"].lower()]
        selected = [o for o in self.engine.ev_obs if o["captured_at"] <= request["audit_at"]
                    and self.engine.user_matches(uid, item_uid=o.get("user_id"),
                                                 item_email=o.get("email"), item_phone=o.get("phone"),
                                                 item_name=o.get("name"), item_hash=o.get("hash"))]
        self.assertEqual(selected, [])


if __name__ == "__main__":
    unittest.main()
