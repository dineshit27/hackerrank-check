import csv
import json
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
VALID_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
VALID_OPERATIONS = {
    # Findings
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    # Remediation
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
    # Verification
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"
}
VALID_STATES = {"PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"}

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    valid_evidence_ids = {r['file_id'] for r in csv.DictReader(f)}

print(f"Loaded {len(valid_evidence_ids)} valid evidence IDs from evidence_files.csv")

assert os.path.exists('output.csv'), "output.csv does not exist in root directory!"

with open('output.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    rows = list(reader)

print(f"CSV Header: {fieldnames}")
assert fieldnames == ['case_id', 'deletion_status', 'steps_json'], f"Header mismatch: {fieldnames}"

print(f"Total data rows: {len(rows)}")
assert len(rows) == 518, f"Row count mismatch: expected 518, got {len(rows)}"

# Check sorted
case_ids = [r['case_id'] for r in rows]
assert case_ids == sorted(case_ids, key=lambda x: int(x.split('_')[1])), "Rows are NOT strictly sorted by case_id!"
assert case_ids[0] == 'case_33', f"First case is {case_ids[0]}, expected case_33"
assert case_ids[-1] == 'case_550', f"Last case is {case_ids[-1]}, expected case_550"

status_counts = {}
errors = []

for idx, r in enumerate(rows, 1):
    cid = r['case_id']
    st = r['deletion_status']
    sj = r['steps_json']
    status_counts[st] = status_counts.get(st, 0) + 1

    if st not in VALID_STATUSES:
        errors.append(f"Row {idx} ({cid}): invalid status {st}")
        continue

    if st == "NOT_APPLICABLE":
        if sj != "[]":
            errors.append(f"Row {idx} ({cid}): NOT_APPLICABLE must have exactly '[]', got {sj}")
        continue

    # Parse JSON
    try:
        steps = json.loads(sj)
    except Exception as e:
        errors.append(f"Row {idx} ({cid}): JSON parse error: {e}")
        continue

    if not isinstance(steps, list):
        errors.append(f"Row {idx} ({cid}): steps_json is not an array")
        continue

    if len(steps) == 0:
        errors.append(f"Row {idx} ({cid}): {st} case has empty steps_json")
        continue

    # Check step structure, sequence, ordering
    current_phase_idx = 0
    phase_order_map = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

    for s_idx, s in enumerate(steps, 1):
        if s.get('step_no') != s_idx:
            errors.append(f"Row {idx} ({cid}) step #{s_idx}: step_no mismatch: expected {s_idx}, got {s.get('step_no')}")

        phase = s.get('phase')
        if phase not in VALID_PHASES:
            errors.append(f"Row {idx} ({cid}) step #{s_idx}: invalid phase {phase}")

        p_idx = phase_order_map.get(phase, -1)
        if p_idx < current_phase_idx:
            errors.append(f"Row {idx} ({cid}) step #{s_idx}: phase out of order ({phase} after earlier phase)")
        else:
            current_phase_idx = p_idx

        op = s.get('operation')
        if op not in VALID_OPERATIONS:
            errors.append(f"Row {idx} ({cid}) step #{s_idx}: invalid operation {op}")

        state = s.get('state')
        if state not in VALID_STATES:
            errors.append(f"Row {idx} ({cid}) step #{s_idx}: invalid state {state}")

        ev = s.get('evidence_id')
        if st == "COMPLETE":
            if not ev or ev not in valid_evidence_ids:
                errors.append(f"Row {idx} ({cid}) step #{s_idx}: COMPLETE step has invalid evidence_id '{ev}'")
        elif st == "INCOMPLETE":
            if phase == "FINDING":
                if not ev or ev not in valid_evidence_ids:
                    errors.append(f"Row {idx} ({cid}) step #{s_idx}: FINDING step has invalid evidence_id '{ev}'")
            else:
                if ev != "":
                    errors.append(f"Row {idx} ({cid}) step #{s_idx}: {phase} step in INCOMPLETE case must have empty evidence_id, got '{ev}'")

print(f"\nStatus Distribution across 518 cases:")
for k, v in sorted(status_counts.items()):
    print(f"  {k}: {v} ({v/518*100:.1f}%)")

if errors:
    print(f"\nVALIDATION FAILED with {len(errors)} errors! First 10 errors:")
    for e in errors[:10]:
        print("  -", e)
    sys.exit(1)
else:
    print("\nALL 518 ROWS PASSED 100% OF SCHEMA, ORDERING, SEQUENCING, AND FORMAT VALIDATIONS!")
