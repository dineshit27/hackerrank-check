import csv
import json
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

# Check for user_43 or l.fontaine in details
matching_user = [a for a in activities if 'user_43' in a['details'] or 'fontaine' in a['details'].lower()]
print(f"Activities explicitly mentioning user_43 or fontaine: {len(matching_user)}")
for a in matching_user[:10]:
    print(a)

# Also check evidence_files for user_43 or fontaine
with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = list(csv.DictReader(f))

print(f"\nChecking evidence files for user_43 / fontaine...")
for ev in ev_files:
    path = os.path.join('dataset', ev['file_path'])
    if not os.path.exists(path):
        continue
    # If text/json/sql/log, check text
    if any(path.endswith(ext) for ext in ['.txt', '.json', '.sql', '.log']):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if 'user_43' in content or 'fontaine' in content.lower():
                    print(f"Match in {ev['file_id']} ({path})")
        except Exception as e:
            pass
