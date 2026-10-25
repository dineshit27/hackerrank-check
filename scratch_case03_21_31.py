import csv, json, re, os, sqlite3, hashlib

# Full investigation of case_03, case_21, case_31 (COMPLETE cases missing account step)
with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    sreqs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/evidence_files.csv', newline='', encoding='utf-8') as f:
    ev_manifest = {r['file_id']: r for r in csv.DictReader(f)}

# Reference sample output
with open('dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    ref = {r['case_id']: r for r in csv.DictReader(f)}

for cid in ['case_03', 'case_21', 'case_25', 'case_31']:
    r = sreqs[cid]
    ref_steps = json.loads(ref[cid]['steps_json'])
    print('=== %s ===' % cid)
    print('email=%s audit_at=%s' % (r['email'], r['audit_at']))
    print('Reference steps:')
    for s in ref_steps:
        print('  %s: %s %s/%s [%s]' % (s['step_no'], s['phase'], s['system_id'], s['resource_id'], s['evidence_id']))
    
    # What evidence IDs are cited?
    ev_ids = set(s['evidence_id'] for s in ref_steps if s['evidence_id'])
    print('Evidence IDs cited:', ev_ids)
    for eid in ev_ids:
        meta = ev_manifest.get(eid, {})
        print('  %s: %s cap=%s' % (eid, meta.get('file_path'), meta.get('captured_at')))
    print()

# For case_03: evidence_94
print('=== Investigating evidence_94 ===')
ev94 = ev_manifest.get('evidence_94', {})
path = 'dataset/' + ev94.get('file_path', '')
cap = ev94.get('captured_at', '')
print('File: %s cap=%s' % (path, cap))
if os.path.exists(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    # Find account_7566, analytics_9406, audit_record_2016
    for target in ['account_7566', 'analytics_9406', 'audit_record_2016', 'user_03', 'oliver']:
        if target.lower() in content.lower():
            # Find context around it
            idx = content.lower().find(target.lower())
            print('Found %s at pos %d: ...%s...' % (target, idx, content[max(0,idx-50):idx+100]))
    print('First 2000 chars:')
    print(content[:2000])
