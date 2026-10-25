"""
Search ALL evidence for account resource IDs for cases 01, 02, 04, 07, 08, 09, 10.
These are the cases where we're missing account resource IDs.
"""
import csv, json, os, sqlite3, glob

case_emails = {
    'case_01': 'amina.elmasri@gmail.com',
    'case_02': 'mateo.rios@outlook.com',
    'case_04': 'thandiwe.n@gmail.com',
    'case_06': 'jonas.berg@outlook.com',
    'case_07': 'priya.raman@gmail.com',
    'case_08': 'gabriel.costa@proton.me',
    'case_09': 'k.appiah88@gmail.com',
    'case_10': 'nadia.ionescu@yahoo.com',
}
emails_of_interest = set(case_emails.values())
# also include historical email changes
users_emails = {}
with open('dataset/user_identities.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r.get('email') in emails_of_interest:
            users_emails[r['user_id']] = r['email']
with open('dataset/user_audit_log.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r.get('old_value') in emails_of_interest or r.get('new_value') in emails_of_interest:
            if r.get('field_name') == 'email':
                print(f"  Audit log: user_id={r['user_id']} old={r['old_value']} new={r['new_value']}")

print("Users of interest:", users_emails)

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

found = {}

# Check ALL JSON files
for fid, info in sorted(ev_manifest.items()):
    p = os.path.join('dataset', info['file_path'])
    if not p.endswith('.json'): continue
    try:
        with open(p, encoding='utf-8') as f:
            raw = f.read()
        for email in emails_of_interest:
            if email.lower() in raw.lower():
                # Found the email, now extract resource IDs
                d = json.loads(raw)
                def scan(obj, email):
                    results = []
                    if isinstance(obj, dict):
                        obj_str = json.dumps(obj).lower()
                        if email.lower() in obj_str:
                            rid = obj.get('resource_id')
                            uid = obj.get('user_id') or obj.get('customer_reference') or obj.get('subject_reference')
                            if rid and rid.startswith('account'):
                                results.append((fid, email, rid, uid))
                        for v in obj.values():
                            results.extend(scan(v, email))
                    elif isinstance(obj, list):
                        for item in obj:
                            results.extend(scan(item, email))
                    return results
                for r in scan(d, email):
                    found.setdefault(email, []).append(r)
    except:
        pass

# Check all SQL files
for fid, info in sorted(ev_manifest.items()):
    p = os.path.join('dataset', info['file_path'])
    if not p.endswith('.sql'): continue
    try:
        with open(p, encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        for email in emails_of_interest:
            if email.lower() in raw.lower():
                con = sqlite3.connect(':memory:')
                con.row_factory = sqlite3.Row
                con.executescript(raw)
                cur = con.cursor()
                tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                for t in tables:
                    rows = cur.execute(f"SELECT * FROM {t}").fetchall()
                    for row in rows:
                        d = dict(row)
                        row_str = json.dumps(d).lower()
                        if email.lower() in row_str:
                            rid = d.get('resource_id', '')
                            uid = d.get('user_id') or d.get('customer_reference')
                            # Check record_json too
                            if 'record_json' in d:
                                try:
                                    rj = json.loads(d['record_json'])
                                    if email.lower() in json.dumps(rj).lower():
                                        rid = d.get('resource_id') or rj.get('resource_id')
                                        uid = rj.get('user_id') or rj.get('customer_reference') or uid
                                except:
                                    pass
                            if rid and rid.startswith('account'):
                                found.setdefault(email, []).append((fid, email, rid, uid))
    except:
        pass

print("\n=== Account resource IDs found per email ===")
for email, results in found.items():
    print(f"\n  {email}:")
    for r in results:
        print(f"    fid={r[0]} rid={r[2]} uid={r[3]}")

# Also check system_activity for account deletion events near each case's reported_at
print("\n=== Matching system_activity.csv account DELETE events ===")
sa = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
for a in sa:
    if a.get('target_system') == 'account_service' and a.get('event_type') == 'DELETE_RECORD':
        rid = a.get('resource_id', '')
        if rid in ['account_001', 'account_002', 'account_004', 'account_006', 'account_007', 'account_008', 'account_009', 'account_010']:
            print(f"  {a['activity_id']} {a['event_time']} rid={rid} result={a['reported_result']}")
