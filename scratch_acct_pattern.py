import csv, os, json, re, sqlite3

with open('dataset/evidence_files.csv', newline='', encoding='utf-8') as f:
    ev_manifest = {r['file_id']: r for r in csv.DictReader(f)}

# Look at ALL databases and find ALL account resource IDs to understand the naming pattern
all_acct_rids = {}  # uid -> [rid, ...]

for fid, info in sorted(ev_manifest.items()):
    path = 'dataset/' + info['file_path']
    cap = info['captured_at']
    if not os.path.exists(path) or not path.endswith('.sql'):
        continue
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            sql_text = re.sub(r'CHECK\s*\(\s*json_valid\s*\([^)]*\)\s*\)', '', f.read(), flags=re.IGNORECASE)
        con = sqlite3.connect(':memory:')
        con.row_factory = sqlite3.Row
        con.executescript(sql_text)
        cur = con.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        
        for t in tables:
            if 'customer_profile' not in t: continue
            try:
                rows = cur.execute('SELECT * FROM %s' % t).fetchall()
                for row in rows:
                    d = dict(row)
                    uid = d.get('user_id', '')
                    rid = d.get('resource_id', '')
                    if uid and rid:
                        all_acct_rids.setdefault(uid, set()).add(rid)
            except:
                pass
    except:
        pass

# Print the pattern: user_XX -> account_XXX
print('Sample of uid -> account_rid mappings (first 20):')
for uid, rids in sorted(all_acct_rids.items())[:20]:
    print('  %s -> %s' % (uid, rids))

# Check specifically: is account_001 -> user_01 etc?
print('\nLooking for user_0X -> account_00X pattern:')
for i in range(1, 10):
    uid = 'user_%02d' % i
    expected_rid = 'account_%03d' % i
    actual_rids = all_acct_rids.get(uid, set())
    print('  user_%02d: expected=%s actual=%s' % (i, expected_rid, actual_rids))

# Check user_identities.csv for any account field
print('\nChecking user_identities.csv structure:')
with open('dataset/user_identities.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    print('Fields:', reader.fieldnames)
    for i, row in enumerate(reader):
        if i < 5:
            print(dict(row))
