import csv
from collections import Counter
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = list(csv.DictReader(f))

print(f"Sample audit_at counts ({len(sample_reqs)} reqs):")
print(Counter(r['audit_at'] for r in sample_reqs))

print(f"\nFull dataset audit_at counts ({len(requests)} reqs):")
c = Counter(r['audit_at'] for r in requests)
for ts, count in sorted(c.items()):
    print(f"  {ts}: {count}")
