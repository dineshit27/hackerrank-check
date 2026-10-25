import os
import glob

search_terms = ['account_8858', 'activity_3685', 'user_542', 'addo.kofi']

for root, dirs, files in os.walk('dataset'):
    for file in files:
        if file.endswith(('.py', '.csv', '.json', '.txt', '.log', '.sql')):
            p = os.path.join(root, file)
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for term in search_terms:
                        if term in content:
                            print(f"Found '{term}' in {p}")
            except Exception as e:
                pass
