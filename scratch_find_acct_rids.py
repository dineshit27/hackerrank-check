"""
Check ALL SQL tables with record_json for account_service records for target users.
Also check customer_data_snapshot_bundle JSONs.
"""
import csv, json, os, sqlite3, glob

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

target_users = {'user_21', 'user_25', 'user_26', 'user_27', 'user_28', 'user_31', 'user_32'}

# Check SQL files with record_json
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
            if t == 'snapshot_scope': continue
            rows = cur.execute(f"SELECT * FROM {t}").fetchall()
            for row in rows:
                d = dict(row)
                if 'record_json' in d:
                    try:
                        rj = json.loads(d['record_json'])
                    except:
                        continue
                    uid = rj.get('user_id') or rj.get('customer_reference') or rj.get('subject_reference')
                    orig = d.get('origin_system', '')
                    rid = d.get('resource_id')
                    if uid in target_users and orig == 'account_service':
                        st = rj.get('account_status', '?')
                        em = rj.get('email', '?')
                        print(f"{fid} | {t} | orig={orig} uid={uid} rid={rid} status={st} email={em}")
    except Exception as e:
        pass

# Check snapshot bundles
for fid, info in sorted(ev_manifest.items()):
    p = os.path.join('dataset', info['file_path'])
    if not (p.endswith('.json') and 'snapshot_bundle' in p): continue
    try:
        with open(p, encoding='utf-8') as f:
            d = json.load(f)
        for sn in d.get('snapshots', []):
            ds = sn.get('data_store', '')
            if ds != 'account_service': continue
            for r in sn.get('records', []):
                uid = r.get('user_id') or r.get('customer_reference')
                rid = r.get('resource_id')
                if uid in target_users:
                    print(f"{fid} | snapshot | ds={ds} uid={uid} rid={rid} status={r.get('account_status','?')}")
    except:
        pass
