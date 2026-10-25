import json
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence/records/customer_data_snapshot_bundle_20260915.json', 'r', encoding='utf-8') as f:
    ev51 = json.load(f)

for s in ev51['snapshots']:
    print(f"data_store={s['data_store']}, collection={s['collection']}, num_records={len(s['records'])}")
    if len(s['records']) > 0:
        print("  sample record:", s['records'][0])
