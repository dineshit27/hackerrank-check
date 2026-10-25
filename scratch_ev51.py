"""Check evidence_51 for user_21/25 account mappings."""
import json, os, csv

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f): ev_manifest[r['file_id']] = r

info = ev_manifest['evidence_51']
print('evidence_51:', info['file_path'], 'captured:', info['captured_at'])
with open(os.path.join('dataset', info['file_path']), encoding='utf-8') as f:
    d = json.load(f)
print('Keys:', list(d.keys()))
for sn in d.get('snapshots', []):
    ds = sn.get('data_store')
    records = sn.get('records', [])
    if records:
        print('  ds=%s (%d records)' % (ds, len(records)))
        for r in records[:5]:
            uid = r.get('customer_reference') or r.get('user_id') or r.get('subject_reference')
            rid = r.get('resource_id')
            em = r.get('email')
            st = r.get('account_status')
            print('    uid=%s rid=%s em=%s status=%s' % (uid, rid, em, st))

# Check if user_21 or user_25 appear anywhere
import re
p = os.path.join('dataset', info['file_path'])
with open(p, encoding='utf-8') as f:
    raw = f.read()
for uid in ['user_21', 'user_25', 'amara-okeke', 's.yoon04']:
    if uid in raw:
        print('\nFound: %s' % uid)
        # Find context
        idx = raw.index(uid)
        print('  Context: %s' % raw[max(0,idx-100):idx+200])
