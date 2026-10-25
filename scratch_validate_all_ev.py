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

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = list(csv.DictReader(f))

print(f"Loaded {len(ev_files)} evidence files from manifest.")

# Check parsing for each format:
# 1. JSON files
json_files = [e for e in ev_files if e['file_path'].endswith('.json')]
print(f"JSON files ({len(json_files)}):")
for jf in json_files:
    p = os.path.join('dataset', jf['file_path'])
    try:
        with open(p, 'r', encoding='utf-8') as f:
            d = json.load(f)
        print(f"  OK: {jf['file_id']} ({len(d) if isinstance(d, (list, dict)) else 0} top-level items)")
    except Exception as e:
        print(f"  ERR: {jf['file_id']} - {e}")

# 2. SQL files
sql_files = [e for e in ev_files if e['file_path'].endswith('.sql')]
print(f"\nSQL files ({len(sql_files)}):")
for sf in sql_files:
    p = os.path.join('dataset', sf['file_path'])
    try:
        con = sqlite3.connect(':memory:')
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            sql = f.read()
        con.executescript(sql)
        tbls = con.cursor().execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        print(f"  OK: {sf['file_id']} - tables: {[t[0] for t in tbls]}")
    except Exception as e:
        print(f"  ERR: {sf['file_id']} - {e}")

# 3. Log files
log_files = [e for e in ev_files if e['file_path'].endswith('.log')]
print(f"\nLog files ({len(log_files)}):")
for lf in log_files:
    p = os.path.join('dataset', lf['file_path'])
    try:
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        print(f"  OK: {lf['file_id']} - {len(lines)} lines")
    except Exception as e:
        print(f"  ERR: {lf['file_id']} - {e}")

# 4. PDF files
pdf_files = [e for e in ev_files if e['file_path'].endswith('.pdf')]
print(f"\nPDF files ({len(pdf_files)}):")
for pf in pdf_files:
    p = os.path.join('dataset', pf['file_path'])
    try:
        with open(p, 'rb') as f:
            raw = f.read()
        print(f"  OK: {pf['file_id']} - {len(raw)} bytes")
    except Exception as e:
        print(f"  ERR: {pf['file_id']} - {e}")

# 5. TXT files
txt_files = [e for e in ev_files if e['file_path'].endswith('.txt')]
print(f"\nTXT files ({len(txt_files)}):")
for tf in txt_files:
    p = os.path.join('dataset', tf['file_path'])
    with open(p, 'r', encoding='utf-8') as f:
        print(f"  OK: {tf['file_id']} - {len(f.readlines())} lines")
