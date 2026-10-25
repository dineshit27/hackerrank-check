import os
import glob
import csv
import sqlite3
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    ev_files = {r['file_path']: r for r in csv.DictReader(f)}

sql_files = glob.glob('dataset/evidence/databases/*.sql')
print(f"Total SQL files: {len(sql_files)}")

total_obs = 0
for sp in sorted(sql_files):
    rel_p = os.path.normpath(os.path.relpath(sp, 'dataset')).replace('\\', '/')
    ev_info = ev_files.get(rel_p, {})
    fid = ev_info.get('file_id', os.path.basename(sp))
    cap_time = ev_info.get('captured_at', '2026-09-30T23:59:59Z')

    try:
        con = sqlite3.connect(':memory:')
        con.row_factory = sqlite3.Row
        with open(sp, 'r', encoding='utf-8', errors='ignore') as f:
            con.executescript(f.read())
        cur = con.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

        file_obs = 0
        for t in tables:
            if t == 'snapshot_scope':
                continue
            cols = [c[1] for c in cur.execute(f"PRAGMA table_info({t})").fetchall()]
            rows = cur.execute(f"SELECT * FROM {t}").fetchall()
            file_obs += len(rows)

        total_obs += file_obs
        print(f"{fid} ({os.path.basename(sp)}): {file_obs} rows extracted across {len(tables)} tables")
    except Exception as e:
        print(f"{fid} ERROR: {e}")

print(f"\nTotal SQL observations: {total_obs}")
