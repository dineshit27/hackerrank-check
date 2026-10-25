import json

with open('dataset/evidence/records/security_audit_ledger_20261001.json', 'r', encoding='utf-8') as f:
    d = json.load(f)

for r in d['records']:
    print(r)
