import os

for term in ['5569', '6645']:
    for root, dirs, files in os.walk('dataset'):
        for file in files:
            p = os.path.join(root, file)
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if term in content:
                        print(f"Found {term} in {p}")
            except Exception:
                pass
