import glob, json, sqlite3, os, csv, re
import sys
sys.stdout.reconfigure(encoding='utf-8')

sec_records = {}

# 1. Bundles
for p in glob.glob('dataset/evidence/records/customer_data_snapshot_bundle_*.json'):
    with open(p, encoding='utf-8') as f:
        d = json.load(f)
    for sn in d.get('snapshots', []):
        if sn.get('data_store') == 'security_service':
            for r in sn.get('records', []):
                uid = r.get('subject_reference')
                rid = r.get('resource_id')
                if uid and rid: sec_records[uid] = rid

# 2. Service resource exports
for p in glob.glob('dataset/evidence/records/service_resource_export_*.json'):
    with open(p, encoding='utf-8') as f:
        d = json.load(f)
    for r in d.get('service_exports', {}).get('security_service', {}).get('audit_records', []):
        uid = r.get('subject_reference')
        rid = r.get('resource_id')
        if uid and rid: sec_records[uid] = rid

# 3. Security ledger
ledger_p = 'dataset/evidence/records/security_audit_ledger_20261001.json'
if os.path.exists(ledger_p):
    with open(ledger_p, encoding='utf-8') as f:
        d = json.load(f)
    for r in d.get('audit_entries', []):
        uid = r.get('subject_reference')
        rid = r.get('record_id')
        if uid and rid: sec_records[uid] = rid

# 4. SQL
for p in glob.glob('dataset/evidence/databases/*.sql'):
    try:
        con = sqlite3.connect(':memory:')
        con.row_factory = sqlite3.Row
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            con.executescript(f.read())
        cur = con.cursor()
        has_table = cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_audit_records'").fetchall()
        if has_table:
            for row in cur.execute("SELECT resource_id, subject_reference FROM security_audit_records").fetchall():
                uid = row['subject_reference']
                rid = row['resource_id']
                if uid and rid: sec_records[uid] = rid
    except: pass

print(f"Total mapped security audit records: {len(sec_records)}")
