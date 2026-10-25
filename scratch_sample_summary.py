import csv
import json
import os
import glob
import re
import sqlite3
import base64
import zlib
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Let's inspect the exact steps for all 32 sample cases and understand every single case
with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    sample_outs = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(f)}

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = {r['case_id']: r for r in csv.DictReader(f)}

print(f"Loaded {len(sample_reqs)} sample requests.")

# Summary of sample cases
complete_cases = [cid for cid, (status, steps) in sample_outs.items() if status == 'COMPLETE']
incomplete_cases = [cid for cid, (status, steps) in sample_outs.items() if status == 'INCOMPLETE']
print(f"COMPLETE cases ({len(complete_cases)}): {complete_cases}")
print(f"INCOMPLETE cases ({len(incomplete_cases)}): {incomplete_cases}")
