import csv
import json
import os
import glob
import re
import base64
import zlib
import sqlite3
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = {r['file_id']: r for r in csv.DictReader(f)}

# Let's inspect SQL files
sql_files = [ef for ef in ev_files.values() if ef['file_path'].endswith('.sql')]
print(f"Total SQL files: {len(sql_files)}")

# Check what tables exist in each SQL file
tables_by_file = {}
for sf in sql_files:
    p = os.path.join('dataset', sf['file_path'])
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        sql_text = f.read()
    tables = re.findall(r'CREATE TABLE (\w+)', sql_text)
    tables_by_file[sf['file_id']] = tables

print("\nSQL Tables sample:")
for fid, tbls in list(tables_by_file.items())[:8]:
    print(f"  {fid}: {tbls}")
