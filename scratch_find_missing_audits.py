import os

for term in ['audit_record_5569', 'audit_record_4902', 'audit_record_6645']:
    for root, dirs, files in os.walk('dataset'):
        for file in files:
            p = os.path.join(root, file)
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    if term in f.read():
                        print(f"Found {term} in {p}")
            except Exception:
                pass
