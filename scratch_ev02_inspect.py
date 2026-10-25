"""
Inspect evidence_02 to understand its structure.
This is where user_26→account_5684, user_27→account_3866 come from.
"""
import csv, json, os

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

info = ev_manifest.get('evidence_02')
print(f"evidence_02: path={info['file_path']} captured={info['captured_at']}")

p = os.path.join('dataset', info['file_path'])
with open(p, encoding='utf-8') as f:
    d = json.load(f)

print("Top-level keys:", list(d.keys()))
print("Snapshots count:", len(d.get('snapshots', [])))

for sn in d.get('snapshots', []):
    ds = sn.get('data_store')
    records = sn.get('records', [])
    print(f"\n  data_store={ds} ({len(records)} records):")
    for r in records[:3]:
        print(f"    {json.dumps(r)[:200]}")

# Now show whether current parser handles this correctly
# The snapshot bundle parsing in main.py uses:
# uid = r.get('user_id') or r.get('customer_reference') or r.get('subject_reference')
# Let's verify
print("\n=== Checking parser compatibility ===")
for sn in d.get('snapshots', []):
    ds = sn.get('data_store')
    for r in sn.get('records', []):
        uid = r.get('user_id') or r.get('customer_reference') or r.get('subject_reference')
        rid = r.get('resource_id')
        em = r.get('email') or r.get('customer_email') or r.get('owner_email') or r.get('requester_email')
        if uid and rid and ds == 'account_service':
            print(f"  ACCOUNT: ds={ds} uid={uid} rid={rid} email={em} status={r.get('account_status','?')}")
