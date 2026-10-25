"""
Search for user_21 and user_25 account resource mappings across ALL evidence.
Expected: user_21 -> account_6440, user_25 -> account_3136
"""
import json, os, csv, sqlite3

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

target = {'user_21', 'user_25', 'user_26', 'user_27', 'user_28'}

# Check snapshot bundles
print("=== Snapshot bundles ===")
for fid, info in sorted(ev_manifest.items()):
    p = os.path.join('dataset', info['file_path'])
    if not p.endswith('.json'): continue
    try:
        with open(p, encoding='utf-8') as f:
            d = json.load(f)
        for sn in d.get('snapshots', []):
            if sn.get('data_store') != 'account_service': continue
            for r in sn.get('records', []):
                uid = r.get('customer_reference') or r.get('user_id')
                rid = r.get('resource_id')
                if uid in target:
                    cap = info['captured_at']
                    print(f'  {fid} (cap={cap}): uid={uid} rid={rid} status={r.get("account_status")}')
    except Exception as e:
        pass

# Check SQL files for record_json with account_service origin for target users
print("\n=== SQL files (record_json) ===")
for fid, info in sorted(ev_manifest.items()):
    p = os.path.join('dataset', info['file_path'])
    if not p.endswith('.sql'): continue
    try:
        con = sqlite3.connect(':memory:')
        con.row_factory = sqlite3.Row
        with open(p, encoding='utf-8', errors='ignore') as f:
            con.executescript(f.read())
        cur = con.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for t in tables:
            rows = cur.execute(f"SELECT * FROM {t}").fetchall()
            for row in rows:
                d2 = dict(row)
                if 'record_json' not in d2: continue
                try:
                    rj = json.loads(d2['record_json'])
                except:
                    continue
                orig = d2.get('origin_system', '')
                if orig != 'account_service': continue
                uid = rj.get('user_id') or rj.get('customer_reference')
                rid = d2.get('resource_id') or rj.get('resource_id')
                if uid in target:
                    cap = info['captured_at']
                    print(f'  {fid} (cap={cap}): table={t} uid={uid} rid={rid} status={rj.get("account_status")}')
    except Exception as e:
        pass

# Check system_activity for these accounts
print("\n=== system_activity DELETE events for target accounts ===")
sa = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
target_accts = {'account_6440', 'account_3136', 'account_5482', 'account_5684', 'account_3866'}
for a in sa:
    if a.get('resource_id') in target_accts:
        print(f"  {a['activity_id']} {a['event_time']} rid={a['resource_id']} result={a['reported_result']} detail={a['details'][:100]}")
