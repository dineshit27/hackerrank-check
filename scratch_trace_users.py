import csv
import json

# 1. Load user_identities
user_by_id = {}
user_by_email = {}
user_by_phone = {}
user_by_hash = {}

with open('dataset/user_identities.csv', 'r', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        user_by_id[row['user_id']] = row
        user_by_email[row['email'].lower()] = row['user_id']
        if row['phone']:
            user_by_phone[row['phone']] = row['user_id']
        if row['email_hash']:
            user_by_hash[row['email_hash']] = row['user_id']

# 2. Load user_audit_log
historical_email_to_user = {}
with open('dataset/user_audit_log.csv', 'r', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        if row['field_name'] == 'email':
            historical_email_to_user[row['old_value'].lower()] = row['user_id']
            historical_email_to_user[row['new_value'].lower()] = row['user_id']

# 3. Check sample requests
with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = list(csv.DictReader(f))

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    sample_outs = {r['case_id']: r for r in csv.DictReader(f)}

print(f"Loaded {len(sample_reqs)} sample requests")
for req in sample_reqs[:10]:
    cid = req['case_id']
    email = req['email'].lower()
    uid = user_by_email.get(email) or historical_email_to_user.get(email)
    out = sample_outs.get(cid)
    status = out['deletion_status'] if out else 'UNKNOWN'
    steps = json.loads(out['steps_json']) if out else []
    print(f"\n{cid}: email={email} -> user_id={uid}, status={status}, audit_at={req['audit_at']}")
    print(f"  Request text: {req['request_text'][:80]}...")
    for st in steps:
        print(f"    Step {st['step_no']}: {st['phase']} | {st['system_id']} | {st['resource_id']} | {st['operation']} | {st['state']} | ev={st['evidence_id']}")
