"""Write an evidence inventory for COMPLETE rows without verification steps."""
import csv
import json
from pathlib import Path

from main import DeletionAuditEngine


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUT = ROOT / "evaluation" / "complete_case_diagnostics.md"


def main():
    engine = DeletionAuditEngine(str(DATASET))
    with (DATASET / "deletion_requests.csv").open(encoding="utf-8") as f:
        requests = list(csv.DictReader(f))
    with (DATASET / "deletion_rules.csv").open(encoding="utf-8") as f:
        rules = list(csv.DictReader(f))

    lines = [
        "# COMPLETE Cases Without Verification Evidence",
        "",
        "Generated from participant-visible data only. A missing observation is not treated as proof of deletion.",
        "",
    ]
    count = 0
    for req in requests:
        status, steps = engine.audit_request(req)
        if status != "COMPLETE" or steps:
            continue
        count += 1
        uid = engine.users_by_email.get(req["email"].lower())
        matching = [
            o for o in engine.ev_obs
            if o["captured_at"] <= req["audit_at"]
            and engine.user_matches(uid, item_uid=o.get("user_id"), item_email=o.get("email"),
                                    item_phone=o.get("phone"), item_name=o.get("name"),
                                    item_hash=o.get("hash"))
        ]
        evidence = sorted({f"{o['file_id']} ({o['captured_at']})" for o in matching})
        lines.extend([
            f"## {req['case_id']}",
            "",
            f"- Request email / resolved identity: `{req['email']}` / `{uid or 'unresolved'}`",
            f"- Audit cutoff: `{req['audit_at']}`",
            "- Applicable rules: USER_PROFILE=DELETE; SECURITY_AUDIT_LOG=RETAIN; "
            "ACCOUNT_TOMBSTONE=REDACT when present; plus any resource-specific rule identified by evidence.",
            "- Matched evidence at or before cutoff: " + (", ".join(evidence) if evidence else "none"),
            "- Verification failure: no matching evidence observation establishes a compliant resource state; "
            "the current `COMPLETE` result is therefore unsupported.",
            "- Evidence supports COMPLETE at audit_at: **no**.",
            "",
        ])
    lines.insert(4, f"Affected cases: **{count}**.")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {count} cases to {OUT}")


if __name__ == "__main__":
    main()
