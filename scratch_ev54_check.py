"""
Check what evidence_54 contains for users 01, 02, 04, 06, 07, 08, 09, 10.
"""
import csv, json, os, sqlite3

sample_reqs = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

info = ev_manifest['evidence_54']
print(f"evidence_54: {info['file_path']} captured={info['captured_at']}")

p = os.path.join('dataset', info['file_path'])
con = sqlite3.connect(':memory:')
con.row_factory = sqlite3.Row
with open(p, encoding='utf-8', errors='ignore') as f:
    con.executescript(f.read())
cur = con.cursor()
tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("Tables:", tables)

for t in tables:
    if t == 'snapshot_scope': continue
    rows = cur.execute(f"SELECT * FROM {t}").fetchall()
    print(f"\nTable {t} ({len(rows)} rows, first 5):")
    for row in rows[:5]:
        d = dict(row)
        if 'record_json' in d:
            try:
                rj = json.loads(d['record_json'])
                print(f"  rid={d.get('resource_id')} orig={d.get('origin_system')} uid={rj.get('user_id')} email={rj.get('email')} status={rj.get('account_status')}")
            except:
                print(f"  rid={d.get('resource_id')} [JSON parse error]")
        else:
            print(f"  {dict(row)}")

# Check case_01, 02, 04 emails
print("\n=== Case user emails from sample requests ===")
for r in sample_reqs:
    if r['case_id'] in ['case_01', 'case_02', 'case_04', 'case_06', 'case_07', 'case_08', 'case_09', 'case_10']:
        print(f"{r['case_id']}: email={r['email']} audit_at={r['audit_at']}")
