import json

with open('dataset/evidence/records/customer_data_snapshot_bundle_20260915.json', 'r', encoding='utf-8') as f:
    ev51 = json.load(f)

for s in ev51['snapshots']:
    print(s['data_store'])
    for r in s['records']:
        print(" ", r)
