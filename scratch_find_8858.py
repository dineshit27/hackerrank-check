import csv

with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = [a for a in csv.DictReader(f) if '8858' in a['resource_id'] or '8858' in a['details']]

print(f"Activities with 8858: {len(activities)}")
for a in activities:
    print(a)
