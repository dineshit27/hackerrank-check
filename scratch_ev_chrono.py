import csv
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = list(csv.DictReader(f))

ev_files.sort(key=lambda x: x['captured_at'])
print(f"Evidence files chronologically:")
for ev in ev_files:
    print(f"{ev['captured_at']} | {ev['file_id']} | {ev['origin']} | {ev['file_path']}")
