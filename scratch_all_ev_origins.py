import csv
import json
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = list(csv.DictReader(f))

by_origin = {}
for ev in ev_files:
    org = ev['origin']
    if org not in by_origin:
        by_origin[org] = []
    by_origin[org].append(ev)

for org, files in by_origin.items():
    print(f"\nOrigin: {org} ({len(files)} files)")
    sample = files[0]
    p = os.path.join('dataset', sample['file_path'])
    sz = os.path.getsize(p) if os.path.exists(p) else -1
    print(f"  Example: {sample['file_id']} -> {sample['file_path']} ({sz} bytes, captured_at: {sample['captured_at']})")
