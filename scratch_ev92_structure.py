"""
Inspect evidence_92 service_exports structure in detail.
"""
import json

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', encoding='utf-8') as f:
    d = json.load(f)

print("exported_at:", d.get('exported_at'))
print("region:", d.get('region'))
print("source:", d.get('source'))

exports = d.get('service_exports', {})
print("\nservice_exports keys:", list(exports.keys()))

for svc, data in exports.items():
    if isinstance(data, dict):
        for subsection, records in data.items():
            if isinstance(records, list) and records:
                print(f"\n  {svc}.{subsection} ({len(records)} records):")
                for r in records[:3]:
                    print("   ", json.dumps(r)[:200])
    elif isinstance(data, list) and data:
        print(f"\n  {svc} ({len(data)} records):")
        for r in data[:3]:
            print("   ", json.dumps(r)[:200])
