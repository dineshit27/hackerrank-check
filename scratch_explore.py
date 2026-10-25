import csv
import json
import os

cwd = os.getcwd()
print("Working directory:", cwd)

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    samples = list(reader)

print(f"Total samples: {len(samples)}")
for s in samples:
    steps = json.loads(s['steps_json'])
    print(f"{s['case_id']}: status={s['deletion_status']}, steps_count={len(steps)}")
    for step in steps:
        print(f"   {step['step_no']}: phase={step['phase']}, sys={step['system_id']}, res={step['resource_id']}, op={step['operation']}, state={step['state']}, ev={step['evidence_id']}")
