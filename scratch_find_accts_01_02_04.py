import sqlite3, re, csv, os, glob

# Load all user identities to find uid -> account_res_id mappings
users_by_email = {}
users = {}
with open('dataset/user_identities.csv', newline='', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        if uid not in users:
            users[uid] = {'emails': set(), 'names': set(), 'phones': set()}
        if r.get('email'):
            em = r['email'].strip().lower()
            users[uid]['emails'].add(em)
            users_by_email[em] = uid

with open('dataset/user_audit_log.csv', newline='', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        fn = r.get('field_name')
        if uid not in users:
            users[uid] = {'emails': set(), 'names': set(), 'phones': set()}
        for v in [r.get('old_value'), r.get('new_value')]:
            if not v or v.lower() == 'null': continue
            if fn == 'email':
                em = v.strip().lower()
                users[uid]['emails'].add(em)
                users_by_email[em] = uid

# Now scan ALL SQL files to find account resources for user_01, user_02, user_04
target_uids = {'user_01', 'user_02', 'user_04'}
target_emails = {
    'user_01': 'amina.elmasri@gmail.com',
    'user_02': 'mateo.rios@outlook.com', 
    'user_04': 'thandiwe.n@gmail.com',
}

accts_found = {}

with open('dataset/evidence_files.csv', newline='', encoding='utf-8') as f:
    ev_manifest = {r['file_id']: r for r in csv.DictReader(f)}

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
            rows = cur.execute('SELECT * FROM %s' % t).fetchall()
            for row in rows:
                d = dict(row)
                uid = d.get('user_id', '')
                email = d.get('email', '').lower()
                status = d.get('account_status', '')
                rid = d.get('resource_id', '')
                if uid in target_uids or email in target_emails.values():
                    matched_uid = uid if uid in target_uids else users_by_email.get(email)
                    print('FOUND! fid=%s table=%s cap=%s: uid=%s email=%s rid=%s status=%s' % (
                        fid, t, cap, uid, email, rid, status))
                    if matched_uid:
                        accts_found.setdefault(matched_uid, []).append((fid, t, rid, status, cap))
    except Exception as e:
        pass

print('\nSummary of account resource IDs:')
for uid, entries in accts_found.items():
    print('%s:' % uid)
    for e in entries:
        print('  %s' % str(e))

# Also check non-SQL evidence files (JSON records, logs)
print('\nChecking JSON and text records...')
for fid, info in sorted(ev_manifest.items()):
    path = 'dataset/' + info['file_path']
    cap = info['captured_at']
    if not os.path.exists(path) or not (path.endswith('.json') or path.endswith('.txt')):
        continue
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        for tgt_em in target_emails.values():
            if tgt_em in content.lower():
                tgt_uid = users_by_email.get(tgt_em)
                # Find account resource IDs near this email
                acct_rids = re.findall(r'account_\w+', content)
                print('FOUND in fid=%s cap=%s for %s: accounts=%s' % (fid, cap, tgt_em, set(acct_rids)))
                break
    except:
        pass
