import sqlite3, re

# Read the full evidence_54 SQL file and see what's there for user_01, user_02, user_04
path = 'dataset/evidence/databases/customer_accounts_failover_replica_20260902.sql'
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    sql_text = re.sub(r'CHECK\s*\(\s*json_valid\s*\([^)]*\)\s*\)', '', f.read(), flags=re.IGNORECASE)

con = sqlite3.connect(':memory:')
con.row_factory = sqlite3.Row
con.executescript(sql_text)
cur = con.cursor()
tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print('Tables:', tables)

for t in tables:
    rows = cur.execute('SELECT * FROM %s' % t).fetchall()
    for row in rows:
        d = dict(row)
        # Check for user_01, user_02, user_04
        uid = d.get('user_id', '')
        email = d.get('email', '')
        status = d.get('account_status', '')
        rid = d.get('resource_id', '')
        if uid in ['user_01', 'user_02', 'user_04'] or email in ['amina.elmasri@gmail.com', 'mateo.rios@outlook.com', 'thandiwe.n@gmail.com']:
            print('TABLE: %s, RID: %s, UID: %s, EMAIL: %s, STATUS: %s' % (t, rid, uid, email, status))

print('\nAll rows in tables:')
for t in tables:
    rows = cur.execute('SELECT * FROM %s' % t).fetchall()
    print('%s: %d rows' % (t, len(rows)))
    for row in rows[:5]:
        d = dict(row)
        print('  RID=%s UID=%s EMAIL=%s STATUS=%s' % (d.get('resource_id'), d.get('user_id'), d.get('email'), d.get('account_status')))
