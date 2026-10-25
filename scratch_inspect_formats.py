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

# Let's inspect a sample of each origin to see how they structure their records:

# 1. service_readback_logs (e.g. evidence_94, evidence_64, evidence_73, etc.)
with open('dataset/evidence/logs/resource_lookup_trace_20260218_083911.log', 'r', encoding='utf-8') as f:
    sample_readback = f.readlines()[:10]
print("Readback log sample:")
for l in sample_readback:
    print(" ", l.strip())

# 2. customer_data_inventory_capture (e.g. evidence_63, evidence_93, etc.)
con = sqlite3.connect(':memory:')
with open('dataset/evidence/databases/customer_data_inventory_20260213.sql', 'r', encoding='utf-8') as f:
    con.executescript(f.read())
cur = con.cursor()
tbls = [t[0] for t in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("\nInventory SQL tables:", tbls)
for t in tbls[:5]:
    cols = [c[1] for c in cur.execute(f"PRAGMA table_info({t})").fetchall()]
    print(f"  Table {t} cols: {cols}")
    row = cur.execute(f"SELECT * FROM {t} LIMIT 1").fetchone()
    print(f"    sample row: {row}")

# 3. records_assurance_snapshot_bundle (e.g. evidence_02, evidence_51, etc.)
with open('dataset/evidence/records/customer_data_snapshot_bundle_20260917.json', 'r', encoding='utf-8') as f:
    sample_bundle = json.load(f)
print("\nSnapshot bundle snapshots count:", len(sample_bundle['snapshots']))
for s in sample_bundle['snapshots']:
    print(f"  store={s['data_store']}, col={s['collection']}, recs={len(s['records'])}")

# 4. central_observability_export (e.g. evidence_01, evidence_06, etc.)
with open('dataset/evidence/logs/service_events_ap_south_20260915.log', 'r', encoding='utf-8') as f:
    sample_events = f.readlines()[:10]
print("\nService events sample:")
for l in sample_events:
    print(" ", l.strip())
