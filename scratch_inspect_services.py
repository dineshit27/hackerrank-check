import json
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r', encoding='utf-8') as f:
    ev92 = json.load(f)

exports = ev92['service_exports']
print("Services in service_exports:", list(exports.keys()))
for svc, data in exports.items():
    print(f"\n--- {svc} ---")
    if isinstance(data, dict):
        for k, v in data.items():
            print(f"  {k}: {len(v) if isinstance(v, list) else type(v)}")
            if isinstance(v, list) and len(v) > 0:
                print(f"    example: {v[0]}")
