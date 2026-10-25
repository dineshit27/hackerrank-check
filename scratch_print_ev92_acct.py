import json
with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r', encoding='utf-8') as f:
    ev92 = json.load(f)

for item in ev92['service_exports']['account_service']['profile_lookups']:
    print(item)
