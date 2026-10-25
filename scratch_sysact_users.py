"""
Check full system_activity.csv schema and look for user_id=user_26 etc.
"""
import csv

rows = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
print("Columns:", list(rows[0].keys()))
print("Total rows:", len(rows))

# Look for user_26 specifically
for r in rows:
    if r.get('user_id') in {'user_21', 'user_25', 'user_26', 'user_27', 'user_28'}:
        print(r)

print()
# Look for account_5684 specifically in any field
for r in rows:
    row_str = str(r)
    if 'account_5684' in row_str or 'account_3866' in row_str or 'account_5482' in row_str or 'account_6440' in row_str or 'account_3136' in row_str:
        print("FOUND:", r)
