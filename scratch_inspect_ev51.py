import json
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence/records/customer_data_snapshot_bundle_20260915.json', 'r', encoding='utf-8') as f:
    ev51 = json.load(f)

print("Keys in ev51:", list(ev51.keys()))
for k, v in ev51.items():
    print(f"\n{k} (len={len(v) if isinstance(v, list) else type(v)}):")
    if isinstance(v, list) and len(v) > 0:
        print(f"  sample: {v[0]}")
