import sys
import os
import csv
import json

sys.path.insert(0, os.path.abspath('code'))
import main

engine = main.DeletionAuditEngine('dataset')

with open('dataset/sample_deletion_requests.csv', encoding='utf-8') as f:
    sample_reqs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/sample_output.csv', encoding='utf-8') as f:
    sample_exp = {r['case_id']: r for r in csv.DictReader(f)}

for cid in ['case_07', 'case_10', 'case_12', 'case_15', 'case_16', 'case_17', 'case_19', 'case_22']:
    req = sample_reqs[cid]
    user_id = engine.users_by_email.get(req['email'])
    print(f"\n=================== {cid} (user={user_id}) ===================")
    print(f"Request: {req['request_text']}")
    print(f"Audit_at: {req['audit_at']}")
    
    # Expected
    exp_steps = json.loads(sample_exp[cid]['steps_json'])
    print(f"Expected Status: {sample_exp[cid]['deletion_status']}")
    print(f"Expected Steps ({len(exp_steps)}):")
    for s in exp_steps:
        print(f"  {s.get('phase')} | {s.get('operation')} | {s.get('system_id')} | {s.get('resource_id')} | {s.get('evidence_id')}")

    # All observations for this user
    all_obs = [o for o in engine.evidence_observations if engine.user_matches(user_id, item_uid=o.get('user_id'), item_email=o.get('email'), item_phone=o.get('phone'), item_name=o.get('name'))]
    print(f"\nAll observations found ({len(all_obs)}):")
    for o in all_obs:
        print(f"  file={o['file_id']} | cap={o['captured_at']} (<=audit: {o['captured_at'] <= req['audit_at']}) | sys={o['system_id']} | res={o['resource_id']} | stat={o['status']} | cat={o.get('category')}")
