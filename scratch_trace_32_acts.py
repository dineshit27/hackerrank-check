import csv
import json
import datetime
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = list(csv.DictReader(f))

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    sample_outs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

# Map user_id
with open('dataset/user_identities.csv', 'r', encoding='utf-8') as f:
    users = {r['email'].lower(): r['user_id'] for r in csv.DictReader(f)}
with open('dataset/user_audit_log.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r['field_name'] == 'email':
            users[r['old_value'].lower()] = r['user_id']

for req in sample_reqs:
    cid = req['case_id']
    uid = users.get(req['email'].lower())
    rep_at = req['reported_at']
    out = sample_outs[cid]
    steps = json.loads(out['steps_json'])
    expected_res = list(dict.fromkeys(st['resource_id'] for st in steps))
    
    # Let's see all activities for expected_res
    acts_found = []
    for a in activities:
        if a['resource_id'] in expected_res:
            acts_found.append(a)
    print(f"\n{cid} ({uid}) | req_at={req['requested_at']} | rep_at={rep_at} | status={out['deletion_status']}")
    print(f"  Expected resources: {expected_res}")
    for a in acts_found:
        print(f"    act: {a['event_time']} | {a['event_type']} | {a['source_system']}->{a['target_system']} | res={a['resource_id']} | result={a['reported_result']}")
