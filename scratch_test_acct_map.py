import glob, json, sqlite3, os, csv, re
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/user_identities.csv', encoding='utf-8') as f:
    users_by_email = {r['email'].lower(): r['user_id'] for r in csv.DictReader(f)}

with open('dataset/user_audit_log.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r['field_name'] == 'email':
            if r['old_value']: users_by_email[r['old_value'].lower()] = r['user_id']
            if r['new_value']: users_by_email[r['new_value'].lower()] = r['user_id']

accts = {} # uid -> account_resource_id

# 1. Bundles
for p in glob.glob('dataset/evidence/records/customer_data_snapshot_bundle_*.json'):
    with open(p, encoding='utf-8') as f:
        d = json.load(f)
    for sn in d.get('snapshots', []):
        if sn.get('data_store') == 'account_service':
            for r in sn.get('records', []):
                uid = r.get('user_id') or r.get('customer_reference')
                em = r.get('email')
                if not uid and em and em.lower() in users_by_email:
                    uid = users_by_email[em.lower()]
                rid = r.get('resource_id')
                if uid and rid: accts[uid] = rid

# 2. SQL
for p in glob.glob('dataset/evidence/databases/*.sql'):
    try:
        con = sqlite3.connect(':memory:')
        con.row_factory = sqlite3.Row
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            con.executescript(f.read())
        cur = con.cursor()
        for t in ['customer_profiles', 'customer_profiles_failover_replica', 'customer_profiles_primary']:
            has_t = cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{t}'").fetchall()
            if has_t:
                for row in cur.execute(f"SELECT * FROM {t}").fetchall():
                    d = dict(row)
                    uid = d.get('customer_reference') or d.get('user_id')
                    em = d.get('email')
                    if not uid and em and em.lower() in users_by_email:
                        uid = users_by_email[em.lower()]
                    rid = d.get('resource_id')
                    if uid and rid: accts[uid] = rid
    except: pass

# 3. Handover
hp = 'dataset/evidence/records/customer_account_handover_20261001.txt'
if os.path.exists(hp):
    with open(hp, encoding='utf-8') as f:
        for line in f:
            if 'account_service' in line:
                parts = [x.strip() for x in line.split('|')]
                if len(parts) >= 6:
                    rid = parts[2]
                    em = parts[5].lower()
                    if em in users_by_email:
                        accts[users_by_email[em]] = rid

print(f"Total users with account_id directly mapped: {len(accts)}")
for u in ['user_01', 'user_02', 'user_07', 'user_10', 'user_27', 'user_28', 'user_31', 'user_32']:
    print(u, '->', accts.get(u))
