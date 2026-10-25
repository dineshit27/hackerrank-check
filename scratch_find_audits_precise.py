import os
import re

for uid in ['user_50', 'user_48']:
    for root, dirs, files in os.walk('dataset/evidence'):
        for file in files:
            p = os.path.join(root, file)
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Check for audit_record with this user_id
                    matches = re.findall(r'audit_record_\d+', content)
                    for m in set(matches):
                        if uid in content:
                            # verify proximity
                            idx = content.find(m)
                            window = content[max(0, idx-100):min(len(content), idx+200)]
                            if uid in window:
                                print(f"Match: {m} for {uid} in {file}")
            except Exception:
                pass
