import csv
from collections import Counter
import os

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = list(csv.DictReader(f))

print(f"Total evidence files: {len(ev_files)}")
exts = Counter(os.path.splitext(r['file_path'])[1] for r in ev_files)
print("File extensions:", exts)

origins = Counter(r['origin'] for r in ev_files)
print("\nOrigins:")
for org, count in origins.most_common():
    print(f"  {org}: {count}")
