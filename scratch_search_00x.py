import csv

# Check system_activity for ALL account_00X resources referenced
with open('dataset/system_activity.csv', newline='', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

# Find what account_00X resource IDs appear in system_activity
import re
for a in activities:
    rid = a.get('resource_id', '')
    details = a.get('details', '')
    if re.match(r'account_0+\d+$', rid):
        print('event_time=%s type=%s rid=%s reported=%s' % (
            a.get('event_time'), a.get('event_type'), rid, a.get('reported_result')))

# Check the evidence files more broadly - search for account_001, account_002, account_004 in ALL files
print('\n--- Search in evidence ---')
import os
for root, dirs, files in os.walk('dataset/evidence'):
    for fname in files:
        p = os.path.join(root, fname)
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            for target in ['account_001', 'account_002', 'account_004']:
                if target in content:
                    print('FOUND %s in %s' % (target, p))
        except:
            pass
