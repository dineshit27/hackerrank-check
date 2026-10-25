"""
Check audit_at for the mismatching cases vs evidence timestamps.
"""
import csv, json

sample_reqs = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
req_map = {r['case_id']: r for r in sample_reqs}

target_cases = ['case_21', 'case_25', 'case_26', 'case_27', 'case_28', 'case_31', 'case_32', 'case_03', 'case_04', 'case_09']

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

print("Case audit_at vs evidence timestamps:")
for cid in target_cases:
    req = req_map.get(cid)
    if req:
        print(f"\n{cid}: audit_at={req['audit_at']} email={req['email']}")

print("\nKey evidence timestamps:")
for eid in ['evidence_02', 'evidence_92', 'evidence_94', 'evidence_51', 'evidence_54', 'evidence_56']:
    info = ev_manifest.get(eid)
    if info:
        print(f"  {eid}: captured_at={info['captured_at']} path={info['file_path'][:50]}")
