import os
import re

all_audit_ids = {} # audit_id -> set of files

for root, dirs, files in os.walk('dataset'):
    for f in files:
        if f.endswith(('.json', '.sql', '.log', '.txt', '.csv')):
            p = os.path.join(root, f)
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
                    matches = re.findall(r'audit_record_\d+', fh.read())
                    for m in matches:
                        if m not in all_audit_ids:
                            all_audit_ids[m] = set()
                        all_audit_ids[m].add(p)
            except Exception:
                pass

print(f"Total unique audit_record IDs found: {len(all_audit_ids)}")
print("Does audit_record_6645 exist?", 'audit_record_6645' in all_audit_ids, all_audit_ids.get('audit_record_6645'))
print("Does audit_record_5569 exist?", 'audit_record_5569' in all_audit_ids, all_audit_ids.get('audit_record_5569'))
print("Does audit_record_4902 exist?", 'audit_record_4902' in all_audit_ids, all_audit_ids.get('audit_record_4902'))
