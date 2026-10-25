import csv
import json
import os
import glob
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

# Check how all evidence files reference users or resources
with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = {r['file_id']: r for r in csv.DictReader(f)}

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    samples = list(csv.DictReader(f))

# Let's inspect each evidence file cited in sample_output
cited_eids = set()
for s in samples:
    steps = json.loads(s['steps_json'])
    for st in steps:
        if st['evidence_id']:
            cited_eids.add(st['evidence_id'])

print("Cited evidence IDs in samples:", sorted(list(cited_eids)))
for eid in sorted(list(cited_eids)):
    ef = ev_files[eid]
    print(f"  {eid}: {ef['origin']} | {ef['captured_at']} | {ef['file_path']}")
