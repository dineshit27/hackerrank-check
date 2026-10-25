import csv

# Check system_activity for DELETE events for user_01, user_02, user_04
with open('dataset/system_activity.csv', newline='', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

print('Total activities:', len(activities))
print('Fields:', activities[0].keys() if activities else 'none')
print()

# Filter for our target users/accounts
target_emails = {'amina.elmasri@gmail.com', 'mateo.rios@outlook.com', 'thandiwe.n@gmail.com'}
target_uids = {'user_01', 'user_02', 'user_04'}
target_accounts = {'account_001', 'account_002', 'account_004'}

for a in activities:
    details = a.get('details', '').lower()
    rid = a.get('resource_id', '')
    uid_in_act = a.get('user_id', '')
    
    if (rid in target_accounts or uid_in_act in target_uids or 
        any(em in details for em in target_emails) or
        any(uid in details for uid in target_uids) or
        rid in target_accounts):
        print('ACT: event_time=%s event_type=%s target=%s resource_id=%s user_id=%s details=%s' % (
            a.get('event_time'), a.get('event_type'), a.get('target_system'), 
            a.get('resource_id'), a.get('user_id'), a.get('details', '')[:200]))

print('\n--- Now looking for account_ resource IDs in system_activity for these users ---')
for a in activities:
    uid_in_act = a.get('user_id', '')
    rid = a.get('resource_id', '')
    details = a.get('details', '').lower()
    if uid_in_act in target_uids and rid and rid.startswith('account_'):
        print('UID=%s rid=%s event=%s time=%s' % (uid_in_act, rid, a.get('event_type'), a.get('event_time')))
    elif any(em in details for em in target_emails) and rid and rid.startswith('account_'):
        print('DETAIL MATCH: rid=%s event=%s time=%s detail_preview=%s' % (rid, a.get('event_type'), a.get('event_time'), details[:100]))
