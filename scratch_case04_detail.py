import json, re, csv

# Check evidence_56
path = 'dataset/evidence/records/customer_analytics_report_20260907.json'
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    data = json.load(f)

print('Top-level keys:', list(data.keys()))
print()

# Flatten and search for thandiwe / user_04
content = json.dumps(data)
# Find user_04 or thandiwe
if 'thandiwe' in content.lower():
    print('Found thandiwe in evidence_56!')
if 'user_04' in content:
    print('Found user_04 in evidence_56!')

# Find all account_XXXX refs
accts = set(re.findall(r'account_\w+', content))
print('Account IDs in evidence_56:', sorted(accts))

analytics = set(re.findall(r'analytics_\w+', content))
print('Analytics IDs:', sorted(analytics)[:10])

# Print some actual content
print('\nFirst 2000 chars:')
print(content[:2000])

print('\n--- Also check what system_activity says about account_004 ---')
with open('dataset/system_activity.csv', newline='', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

for a in activities:
    rid = a.get('resource_id', '')
    details = a.get('details', '')
    if rid == 'account_004' or 'account_004' in details:
        print('SYSTEM_ACT: %s %s %s %s' % (a.get('event_time'), a.get('event_type'), rid, details[:150]))

# Now look for user_04 or thandiwe.n@gmail.com in system_activity  
print('\n--- System activity for user_04 by email in details ---')
for a in activities:
    details = a.get('details', '').lower()
    if 'thandiwe' in details or 'user_04' in details:
        print('SYSTEM_ACT: %s %s %s %s' % (a.get('event_time'), a.get('event_type'), a.get('resource_id'), details[:200]))
