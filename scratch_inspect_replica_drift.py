import sqlite3

con = sqlite3.connect(':memory:')
with open('dataset/evidence/databases/customer_data_read_replica_20260921.sql', 'r', encoding='utf-8') as f:
    sql = f.read()

con.executescript(sql)
cur = con.cursor()

print("Primary table rows:")
for r in cur.execute('SELECT * FROM customer_data_primary').fetchall():
    print(" ", r)

print("\nReplica table rows:")
for r in cur.execute('SELECT * FROM customer_data_read_replica').fetchall():
    print(" ", r)
