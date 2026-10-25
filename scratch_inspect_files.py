import csv
import json
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Let's inspect evidence_54 (sql)
with open('dataset/evidence/databases/customer_accounts_failover_replica_20260902.sql', 'r', encoding='utf-8') as f:
    print("=== evidence_54 (first 20 lines) ===")
    print("".join(f.readlines()[:20]))

# Let's inspect evidence_56 (json)
with open('dataset/evidence/records/customer_analytics_report_20260907.json', 'r', encoding='utf-8') as f:
    print("=== evidence_56 ===")
    print(f.read())

# Let's inspect evidence_57 (sql)
with open('dataset/evidence/databases/customer_search_primary_20260910.sql', 'r', encoding='utf-8') as f:
    print("=== evidence_57 ===")
    print(f.read())

# Let's inspect evidence_59 (json)
with open('dataset/evidence/records/customer_export_jobs_20260914.json', 'r', encoding='utf-8') as f:
    print("=== evidence_59 ===")
    print(f.read())

# Let's inspect evidence_61 (log)
with open('dataset/evidence/logs/support_replica.log', 'r', encoding='utf-8') as f:
    print("=== evidence_61 ===")
    print(f.read())
