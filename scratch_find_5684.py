import os

for root, dirs, files in os.walk('dataset'):
    for file in files:
        if file.endswith(('.json', '.sql', '.log', '.txt', '.csv')):
            p = os.path.join(root, file)
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    txt = f.read()
                    if 'account_5684' in txt:
                        print(f"Found account_5684 in {p}")
            except Exception:
                pass
