import json
import sqlite3

con = sqlite3.connect(':memory:')
with open('dataset/evidence/databases/customer_data_inventory_20260310.sql', 'r', encoding='utf-8') as f:
    con.executescript(f.read())

cur = con.cursor()
for row in cur.execute("SELECT * FROM security_audit_records WHERE subject_reference='user_45'").fetchall():
    print("user_45 audit record in inventory 20260310:", row)

with open('dataset/evidence/records/customer_data_snapshot_bundle_20260223.json', 'r', encoding='utf-8') as f:
    d = json.load(f)
for s in d['snapshots']:
    for r in s['records']:
        if r.get('subject_reference') == 'user_48' or r.get('customer_reference') == 'user_48':
            print("user_48 record in bundle 20260223:", s['data_store'], r)
