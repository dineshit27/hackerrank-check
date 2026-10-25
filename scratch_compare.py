import csv
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

with open("dataset/sample_output.csv", "r", encoding="utf-8") as f:
    expected_rows = {r["case_id"]: r for r in csv.DictReader(f)}

with open("sample_test_output.csv", "r", encoding="utf-8") as f:
    actual_rows = {r["case_id"]: r for r in csv.DictReader(f)}

total_cases = len(expected_rows)
status_matches = 0
exact_step_matches = 0

print(f"Total cases to compare: {total_cases}\n")

for cid in sorted(expected_rows.keys()):
    exp = expected_rows[cid]
    act = actual_rows.get(cid)
    if not act:
        print(f"Case {cid}: MISSING in output!")
        continue

    status_match = exp["deletion_status"] == act["deletion_status"]
    if status_match:
        status_matches += 1

    exp_steps = json.loads(exp["steps_json"])
    act_steps = json.loads(act["steps_json"])

    # Compare steps
    # We compare steps structurally: ignore step_number if we want, or exact
    step_match = (exp_steps == act_steps)
    if step_match:
        exact_step_matches += 1
    else:
        print(f"--- Case {cid} Diff ---")
        print(f"  Status: Exp={exp['deletion_status']}, Act={act['deletion_status']}")
        print(f"  Exp Steps ({len(exp_steps)}):")
        for s in exp_steps:
            print(f"    #{s.get('step_number')} | {s.get('phase')} | {s.get('operation')} | {s.get('system_id')} | {s.get('resource_id')} | ev={s.get('evidence_id')}")
        print(f"  Act Steps ({len(act_steps)}):")
        for s in act_steps:
            print(f"    #{s.get('step_number')} | {s.get('phase')} | {s.get('operation')} | {s.get('system_id')} | {s.get('resource_id')} | ev={s.get('evidence_id')}")

print("\n" + "="*50)
print(f"Status Accuracy: {status_matches}/{total_cases} ({status_matches/total_cases*100:.1f}%)")
print(f"Exact Steps Match: {exact_step_matches}/{total_cases} ({exact_step_matches/total_cases*100:.1f}%)")
