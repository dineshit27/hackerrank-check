import csv, json, os, sys, glob, hashlib, re, sqlite3, zlib, base64

sys.path.insert(0, 'code')

# Load identities 
users = {}
users_by_email = {}
with open('dataset/user_identities.csv', newline='', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        if uid not in users:
            users[uid] = {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()}
        if r.get('email'):
            em = r['email'].strip().lower()
            users[uid]['emails'].add(em)
            users_by_email[em] = uid

with open('dataset/user_audit_log.csv', newline='', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        fn = r.get('field_name')
        ov, nv = r.get('old_value'), r.get('new_value')
        if uid not in users:
            users[uid] = {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()}
        for v in [ov, nv]:
            if not v or v.lower() == 'null': continue
            if fn == 'email':
                em = v.strip().lower()
                users[uid]['emails'].add(em)
                users_by_email[em] = uid

# Target cases
targets = {
    'case_01': {'email': 'amina.elmasri@gmail.com', 'audit_at': '2026-09-03T11:30:00Z'},
    'case_02': {'email': 'mateo.rios@outlook.com', 'audit_at': '2026-09-04T15:00:00Z'},
    'case_04': {'email': 'thandiwe.n@gmail.com', 'audit_at': '2026-09-07T10:20:00Z'},
}

# Check what user_ids they map to and what evidence refers to them
for cid, info in targets.items():
    em = info['email']
    uid = users_by_email.get(em)
    audit_at = info['audit_at']
    print('%s: email=%s -> uid=%s' % (cid, em, uid))
    if uid:
        print('  All emails for user: %s' % users[uid]['emails'])

# Now check evidence_files.csv to find relevant evidence
with open('dataset/evidence_files.csv', newline='', encoding='utf-8') as f:
    ev_manifest = {r['file_id']: r for r in csv.DictReader(f)}

# Look specifically at evidence_54 (referenced in sample for case_01, 02, 04)
ev54 = ev_manifest.get('evidence_54')
print('\nevidence_54:', ev54)
ev56 = ev_manifest.get('evidence_56') 
print('evidence_56:', ev56)

# Check the actual file content of evidence_54
if ev54:
    path = os.path.join('dataset', ev54['file_path'])
    print('\nLooking for: %s' % path)
    if os.path.exists(path):
        print('FILE EXISTS - captured_at: %s' % ev54['captured_at'])
        # Read its contents (it's a SQL/database file)
        ext = os.path.splitext(path)[1]
        print('Extension: %s' % ext)
        if ext == '.sql':
            with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
                content = fp.read(3000)
            print('Content preview:\n%s' % content[:2000])
    else:
        print('FILE NOT FOUND at: %s' % path)
