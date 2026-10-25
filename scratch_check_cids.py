import csv

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

print("Total requests in deletion_requests.csv:", len(requests))
case_ids = [r['case_id'] for r in requests]
print("First 5 case_ids:", case_ids[:5])
print("Last 5 case_ids:", case_ids[-5:])
