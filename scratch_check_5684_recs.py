import json

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r', encoding='utf-8') as f:
    ev92 = json.load(f)

for item in ev92['service_exports']['account_service']['profile_lookups']:
    if item['resource_id'] == 'account_5684':
        print("ev92 account_5684:", item)

with open('dataset/evidence/records/customer_data_snapshot_bundle_20260917.json', 'r', encoding='utf-8') as f:
    ev02 = json.load(f)

for s in ev02['snapshots']:
    for r in s['records']:
        if r.get('resource_id') == 'account_5684':
            print("ev02 account_5684 in", s['data_store'], r)
