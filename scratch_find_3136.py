import csv

with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    acts = [a for a in csv.DictReader(f) if 'account_3136' in a['resource_id']]

print(f"Acts for account_3136: {len(acts)}")
for a in acts:
    print(a)
