import csv
import json
import os
import sqlite3
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Load identities
users_by_email = {}
users_by_id = {}
with open('dataset/user_identities.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        users_by_email[r['email'].lower()] = r['user_id']
        users_by_id[r['user_id']] = r

with open('dataset/user_audit_log.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r['field_name'] == 'email':
            users_by_email[r['old_value'].lower()] = r['user_id']
            users_by_email[r['new_value'].lower()] = r['user_id']

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    sample_outs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = list(csv.DictReader(f))

# For sample cases 1 to 10, let's see which evidence files (with captured_at <= audit_at) match the user
for cid in ['case_01', 'case_02', 'case_03', 'case_04', 'case_05', 'case_06', 'case_07', 'case_08', 'case_09', 'case_10']:
    req = sample_reqs[cid]
    out = sample_outs[cid]
    steps = json.loads(out['steps_json'])
    expected_eids = set(st['evidence_id'] for st in steps if st['evidence_id'])
    uid = users_by_email.get(req['email'].lower())
    email = req['email'].lower()
    audit_at = req['audit_at']
    print(f"\n{cid} ({uid}, {email}) | audit_at={audit_at} | Expected EIDs: {expected_eids}")
    
    # Check all evidence files where captured_at <= audit_at
    matching_efs = []
    for ef in ev_files:
        if ef['captured_at'] <= audit_at:
            p = os.path.join('dataset', ef['file_path'])
            # Fast check if file mentions uid or email
            if any(p.endswith(ext) for ext in ['.json', '.sql', '.log', '.txt']):
                try:
                    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                        text = f.read()
                        if uid and uid in text:
                            matching_efs.append((ef['file_id'], ef['captured_at'], ef['origin'], 'uid'))
                        elif email and email in text.lower():
                            matching_efs.append((ef['file_id'], ef['captured_at'], ef['origin'], 'email'))
                except Exception:
                    pass
    print(f"  Matching evidence files ({len(matching_efs)}):")
    for mef in matching_efs:
        is_exp = mef[0] in expected_eids
        print(f"    {mef[0]} ({mef[1]}) | {mef[2]} | matched by {mef[3]} | {'*** EXPECTED ***' if is_exp else ''}")
