import csv, os, re, json

# Check all evidence for user_04 / thandiwe.n@gmail.com
with open('dataset/evidence_files.csv', newline='', encoding='utf-8') as f:
    ev_manifest = {r['file_id']: r for r in csv.DictReader(f)}

target_email = 'thandiwe.n@gmail.com'
target_uid = 'user_04'
target_hash = 'f730ef60615bde7a8f5ee21138637b4e9d4094855fbb02da6afcdba9c076281f'  # from user_identities

print('Looking for user_04 evidence...')
for fid, info in sorted(ev_manifest.items()):
    path = 'dataset/' + info['file_path']
    if not os.path.exists(path):
        continue
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        if (target_email in content.lower() or target_uid in content or 
            'thandiwe' in content.lower() or target_hash in content.lower()):
            cap = info['captured_at']
            # Find relevant resource IDs
            accts = re.findall(r'account_\w+', content)
            analytics = re.findall(r'analytics_\w+', content)
            print('FOUND in %s (%s cap=%s):' % (fid, os.path.basename(path), cap))
            print('  accounts: %s' % set(accts))
            print('  analytics: %s' % set(analytics))
    except:
        pass

# Also check system_activity for analytics_901
print('\n--- system_activity for analytics_901 ---')
with open('dataset/system_activity.csv', newline='', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))
for a in activities:
    rid = a.get('resource_id', '')
    details = a.get('details', '')
    if rid == 'analytics_901' or 'analytics_901' in details:
        print('%s %s %s %s' % (a.get('event_time'), a.get('event_type'), rid, details[:200]))

# What links thandiwe to account_004 specifically?
# Check system_activity for account_004
print('\n--- system_activity for account_004 ---')
for a in activities:
    rid = a.get('resource_id', '')
    if rid == 'account_004':
        print('%s %s %s %s' % (a.get('event_time'), a.get('event_type'), rid, a.get('details', '')[:200]))
