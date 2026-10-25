"""
Find which user_ids correspond to the account resource IDs in evidence_92.
Check user_identities and user_audit_log for account associations.
"""
import csv, json

# Load user identities
users = {}
with open('dataset/user_identities.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        users[r['user_id']] = r

# We know from security audit records: user_21, user_25, user_26, user_27, user_28
# What are their emails?
for uid in ['user_21', 'user_24', 'user_25', 'user_26', 'user_27', 'user_28']:
    u = users.get(uid, {})
    print(f"{uid}: email={u.get('email')} name={u.get('name')}")

# What is the email for case_26 user (the request email)?
sample_reqs = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
for r in sample_reqs:
    if r['case_id'] in ['case_21', 'case_24', 'case_25', 'case_26', 'case_27', 'case_28', 'case_29', 'case_30']:
        print(f"\n{r['case_id']}: email={r['email']} audit_at={r['audit_at']}")

# The sample outputs show:
# case_26 COMPLETE: account_5684 → user_26
# case_27 COMPLETE: account_3866 → user_27
# case_28 COMPLETE: account_5482 → user_28
# case_25 COMPLETE: account_3136 → user_25
# case_21 COMPLETE: account_6440 → user_21

# In evidence_92 account lookups (404 = deleted):
# account_3136 → user_25 (who has audit_record_451)
# account_3866 → user_27 (who has audit_record_3830)
# account_5482 → user_28 (who has audit_record_9265)
# account_5684 → user_26 (who has audit_record_5416)
# account_6440 → user_21 (who has audit_record_3737)
# account_5334 → user_24? (200, still FOUND, so keiko.nakamura@gmail.com)

# Question: how do we know account_5684 maps to user_26?
# Check system_activity.csv for DELETE_RECORD events
print("\n=== system_activity for account_service DELETE ===")
activities = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
for a in activities:
    if a.get('target_system') == 'account_service' and a.get('event_type') == 'DELETE_RECORD':
        print(f"  {a['event_time']} user_id={a.get('user_id','?')} resource_id={a.get('resource_id','?')}")
