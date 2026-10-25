import csv
import json
import os
import glob
import re
import sqlite3
import base64
import zlib
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Let's inspect each of the 32 sample cases:
# - What resources does sample_output have?
# - In which evidence file were they found?
# - What activity in system_activity.csv touched them?

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    sample_outs = list(csv.DictReader(f))

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = {r['file_id']: r for r in csv.DictReader(f)}

with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

act_by_res = {}
for a in activities:
    r = a['resource_id']
    if r not in act_by_res:
        act_by_res[r] = []
    act_by_res[r].append(a)

for s in sample_outs:
    cid = s['case_id']
    req = sample_reqs[cid]
    status = s['deletion_status']
    steps = json.loads(s['steps_json'])
    print(f"\n{cid} | status={status} | audit_at={req['audit_at']} | reported_at={req['reported_at']}")
    for st in steps:
        res = st['resource_id']
        acts = act_by_res.get(res, [])
        act_summary = f"{acts[0]['event_type']} ({acts[0]['reported_result']})" if acts else "NO_ACT"
        print(f"  Step {st['step_no']}: {st['phase']} | {st['system_id']} | {res} | {st['operation']} | {st['state']} | ev={st['evidence_id']} | act={act_summary}")
