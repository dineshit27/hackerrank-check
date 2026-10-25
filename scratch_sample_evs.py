import csv
import json
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    sample_outs = list(csv.DictReader(f))

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = {r['file_id']: r for r in csv.DictReader(f)}

for s in sample_outs:
    cid = s['case_id']
    req = sample_reqs[cid]
    steps = json.loads(s['steps_json'])
    ev_ids = sorted(list(set(st['evidence_id'] for st in steps if st['evidence_id'])))
    print(f"{cid} (audit_at {req['audit_at']}): status={s['deletion_status']}, ev_ids={ev_ids}")
    for eid in ev_ids:
        ef = ev_files[eid]
        print(f"   -> {eid}: {ef['origin']} | {ef['captured_at']} | {ef['file_path']}")
