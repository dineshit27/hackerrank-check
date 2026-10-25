"""
Show the full evidence_92 to understand account-to-user mapping.
"""
import json

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', encoding='utf-8') as f:
    d = json.load(f)

sexp = d.get('service_exports', {})

# Show all accounts with full profile info
print("=== account_service.profile_lookups ===")
for r in sexp.get('account_service', {}).get('profile_lookups', []):
    print(json.dumps(r, indent=2))

# Show security which links user_ids to audit_records
print("\n=== security_service.audit_records ===")
for r in sexp.get('security_service', {}).get('audit_records', []):
    print(json.dumps(r))

# What are the user_ids for the accounts we need?
# For case_26: account_5684 should map to some user
# Let's cross-reference all user_ids from other services

print("\n=== Cross-reference: user_id -> which account_resource? ===")
# From backup
user_to_resources = {}
for svc in ['backup_service', 'integration_service', 'support_platform', 'security_service']:
    section_map = {
        'backup_service': 'restore_entries',
        'integration_service': 'connectors',
        'support_platform': 'tickets',
        'security_service': 'audit_records'
    }
    for r in sexp.get(svc, {}).get(section_map[svc], []):
        uid = r.get('customer_reference') or r.get('subject_reference')
        rid = r.get('resource_id')
        if uid:
            user_to_resources.setdefault(uid, {}).setdefault(svc, []).append(rid)

for uid, rmap in sorted(user_to_resources.items()):
    print(f"  {uid}: {rmap}")

# Now check analytics
print("\n=== analytics_platform.profiles (to see which user_ids) ===")
for r in sexp.get('analytics_platform', {}).get('profiles', []):
    print(json.dumps(r))
