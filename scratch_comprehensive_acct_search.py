"""
Comprehensive search: find account_service resource IDs for ALL users
across ALL evidence types.
"""
import csv, json, os, sqlite3

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

target_users = {'user_21', 'user_25', 'user_26', 'user_27', 'user_28', 'user_31', 'user_32'}

results = {}  # uid -> {rid, fid, status}

# Scan ALL json files
for fid, info in sorted(ev_manifest.items()):
    p = os.path.join('dataset', info['file_path'])
    if not p.endswith('.json'): continue
    try:
        with open(p, encoding='utf-8') as f:
            raw = f.read()
        d = json.loads(raw)

        def scan_obj(obj, path=''):
            if isinstance(obj, dict):
                uid = obj.get('user_id') or obj.get('customer_reference')
                rid = obj.get('resource_id')
                orig = obj.get('origin_system') or obj.get('data_store') or obj.get('service') or ''
                em = obj.get('email')
                if uid in target_users and rid and 'account' in str(rid).lower():
                    st = obj.get('account_status') or obj.get('status') or 'unknown'
                    results.setdefault(uid, []).append({'rid': rid, 'fid': fid, 'orig': orig, 'status': st})
                for v in obj.values():
                    scan_obj(v, path)
            elif isinstance(obj, list):
                for item in obj:
                    scan_obj(item, path)

        scan_obj(d)
    except:
        pass

# Also scan snapshot bundles for analytics/security/other services for target users
for fid, info in sorted(ev_manifest.items()):
    p = os.path.join('dataset', info['file_path'])
    if not (p.endswith('.json') and 'snapshot_bundle' in p): continue
    try:
        with open(p, encoding='utf-8') as f:
            d = json.load(f)
        for sn in d.get('snapshots', []):
            ds = sn.get('data_store', '')
            for r in sn.get('records', []):
                uid = r.get('user_id') or r.get('customer_reference') or r.get('subject_reference')
                rid = r.get('resource_id')
                if uid in target_users and rid:
                    results.setdefault(uid, []).append({'rid': rid, 'fid': fid, 'ds': ds})
    except:
        pass

print("=== Account resource IDs found for target users ===")
for uid in sorted(target_users):
    recs = results.get(uid, [])
    if recs:
        for r in recs:
            print(f"  {uid}: {r}")
    else:
        print(f"  {uid}: NOT FOUND")
