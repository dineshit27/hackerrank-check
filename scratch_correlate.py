import csv
import json
import os
import glob
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    samples = list(csv.DictReader(f))

# Map user to sample case
with open('dataset/user_identities.csv', 'r', encoding='utf-8') as f:
    users = {r['email'].lower(): r['user_id'] for r in csv.DictReader(f)}

with open('dataset/user_audit_log.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r['field_name'] == 'email':
            users[r['old_value'].lower()] = r['user_id']
            users[r['new_value'].lower()] = r['user_id']

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = {r['case_id']: r for r in csv.DictReader(f)}

# Let's inspect where sample resources appear in system_activity.csv
with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

act_by_res = {}
for act in activities:
    res = act['resource_id']
    if res not in act_by_res:
        act_by_res[res] = []
    act_by_res[res].append(act)

# Let's check for each sample:
for s in samples[:15]:
    cid = s['case_id']
    req = sample_reqs[cid]
    uid = users.get(req['email'].lower())
    steps = json.loads(s['steps_json'])
    print(f"\n=== {cid} ({uid}) - status: {s['deletion_status']} - audit_at: {req['audit_at']} ===")
    for st in steps:
        res = st['resource_id']
        acts = act_by_res.get(res, [])
        act_info = f"{len(acts)} acts" if acts else "NO activity"
        if acts:
            act_info += f" (types: {','.join(set(a['event_type'] for a in acts))}, results: {','.join(set(a['reported_result'] for a in acts))})"
        print(f"  Step {st['step_no']}: {st['phase']} | {st['system_id']} | {res} | {st['operation']} | {st['state']} | ev={st['evidence_id']} [{act_info}]")
