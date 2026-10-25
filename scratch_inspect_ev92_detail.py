"""
Investigate what evidence_92 and evidence_94 contain,
and how they connect to specific user/account resource IDs.
This will reveal why wrong account IDs are being resolved.
"""
import csv, json, os, glob, sqlite3

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

# Focus on evidence_92, evidence_94, evidence_51, evidence_54, evidence_56, evidence_57, evidence_58, evidence_59
targets = ['evidence_92', 'evidence_94', 'evidence_51', 'evidence_54', 'evidence_56', 'evidence_57', 'evidence_58', 'evidence_59', 'evidence_93']
for t in targets:
    info = ev_manifest.get(t)
    if info:
        print(f"\n{t}: path={info['file_path']} captured={info['captured_at']} origin={info.get('origin_system','?')}")

# For evidence_92, load and inspect
ev92 = ev_manifest.get('evidence_92')
if ev92:
    p = os.path.join('dataset', ev92['file_path'])
    print(f"\n--- evidence_92 content (first 80 lines) ---")
    if p.endswith('.sql'):
        con = sqlite3.connect(':memory:')
        con.row_factory = sqlite3.Row
        with open(p, encoding='utf-8', errors='ignore') as f:
            con.executescript(f.read())
        cur = con.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print(f"Tables: {tables}")
        for t in tables[:3]:
            rows = cur.execute(f"SELECT * FROM {t} LIMIT 5").fetchall()
            print(f"\nTable {t} ({len(rows)} sample rows):")
            for row in rows:
                print(dict(row))
    elif p.endswith('.json'):
        with open(p, encoding='utf-8') as f:
            d = json.load(f)
        if isinstance(d, list):
            print(json.dumps(d[:3], indent=2))
        else:
            keys = list(d.keys())[:5]
            print("Keys:", keys)
            for k in keys:
                v = d[k]
                if isinstance(v, list) and v:
                    print(f"  {k}: [{len(v)} items], first:", json.dumps(v[0], indent=4)[:400])
    elif p.endswith('.log'):
        with open(p, encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[:30]
        for l in lines:
            print(l.rstrip())
