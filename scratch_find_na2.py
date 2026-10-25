import csv
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

# Let's inspect cases from 500 onwards or search for "leave the account", "keep the account", "opt-out", "export", etc.
for r in requests:
    cid_num = int(r['case_id'].split('_')[1])
    text = r['request_text'].lower()
    if any(phrase in text for phrase in ['leave the account', 'keep the account', 'portable format', 'invoices for my records', 'continue using', 'opt-out', 'opt out', 'do not delete', 'don\'t delete']):
        print(f"{r['case_id']}: {r['request_text']}")
