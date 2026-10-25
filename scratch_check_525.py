import csv
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

for r in requests:
    cid_num = int(r['case_id'].split('_')[1])
    if cid_num >= 525:
        print(f"{r['case_id']}: {r['request_text']}")
