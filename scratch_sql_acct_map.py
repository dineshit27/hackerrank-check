"""
Check evidence_54 (failover replica SQL) for account-to-user mappings.
Also check other SQL files for users 21,25,26,27,28.
"""
import csv, json, os, sqlite3

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

target_users = {'user_21', 'user_25', 'user_26', 'user_27', 'user_28', 'user_31', 'user_32'}

# Check all SQL files for account_service records for these users
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
            if 'customer_data_primary' in t or 'customer_profiles' in t or 'customer_accounts' in t:
                rows = cur.execute(f"SELECT * FROM {t}").fetchall()
                for row in rows:
                    d = dict(row)
                    uid = d.get('customer_reference') or d.get('user_id')
                    rid = d.get('resource_id')
                    if uid in target_users:
                        print(f"{fid} | {t} | uid={uid} rid={rid} status={d.get('account_status','?')} email={d.get('email','?')}")
    except Exception as e:
        pass
