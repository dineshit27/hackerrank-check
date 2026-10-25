import csv
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

print(f"Total requests: {len(requests)}")
for r in requests[:15]:
    print(r)
