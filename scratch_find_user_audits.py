import os

for uid in ['user_45', 'user_48']:
    for root, dirs, files in os.walk('dataset/evidence'):
        for file in files:
            p = os.path.join(root, file)
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if uid in content:
                        print(f"Found {uid} in {p}")
            except Exception:
                pass
