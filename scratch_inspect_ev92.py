import json
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Let's inspect evidence_92: dataset/evidence/records/service_resource_export_20260915_114455.json
with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r', encoding='utf-8') as f:
    ev92 = json.load(f)

print("Evidence 92 type:", type(ev92))
if isinstance(ev92, dict):
    print("Keys in ev92:", list(ev92.keys()))
    for k in list(ev92.keys())[:3]:
        print(f"Key {k} (len={len(ev92[k]) if isinstance(ev92[k], list) else 'not list'}): sample:", ev92[k][:2] if isinstance(ev92[k], list) else str(ev92[k])[:100])
elif isinstance(ev92, list):
    print(f"ev92 is list of {len(ev92)} items. First item:")
    print(ev92[0])
