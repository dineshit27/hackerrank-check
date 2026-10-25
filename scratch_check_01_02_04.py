import csv, json

# Check case_01, case_02, case_04 - what emails do they use?
with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    sreqs = {r['case_id']: r for r in csv.DictReader(f)}

for cid in ['case_01', 'case_02', 'case_04']:
    r = sreqs[cid]
    print('%s: email=%s audit_at=%s reported_status=%s' % (cid, r['email'], r['audit_at'], r['reported_status']))

print()

# Check user_identities and audit log for these emails
with open('dataset/user_identities.csv', newline='', encoding='utf-8') as f:
    identities = list(csv.DictReader(f))

with open('dataset/user_audit_log.csv', newline='', encoding='utf-8') as f:
    audit_log = list(csv.DictReader(f))

target_emails = {
    'case_01': sreqs['case_01']['email'],
    'case_02': sreqs['case_02']['email'],
    'case_04': sreqs['case_04']['email'],
}
print('Target emails:', target_emails)

# Find in identities
emails_to_find = set(target_emails.values())
for row in identities:
    if row.get('email', '').lower() in emails_to_find:
        print('IDENTITY MATCH: %s -> uid=%s email=%s' % (row['email'], row['user_id'], row['email']))

# Find in audit log (old/new values)
for row in audit_log:
    if row.get('field_name') == 'email':
        for e in emails_to_find:
            if row.get('old_value', '').lower() == e or row.get('new_value', '').lower() == e:
                print('AUDIT LOG MATCH: uid=%s field=%s old=%s new=%s changed_at=%s' % (
                    row['user_id'], row['field_name'], row['old_value'], row['new_value'], row.get('changed_at', '')))
