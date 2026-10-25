import os
import sqlite3
import sys

sys.stdout.reconfigure(encoding='utf-8')

for fn in os.listdir('dataset/evidence/databases'):
    try:
        con = sqlite3.connect(':memory:')
        with open(os.path.join('dataset/evidence/databases', fn), 'r', encoding='utf-8', errors='ignore') as f:
            con.executescript(f.read())
        cur = con.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print(f"{fn}: {tables}")
    except Exception as e:
        print(f"{fn} FAILED: {e}")
