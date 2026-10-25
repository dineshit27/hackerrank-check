import csv
import json
import os
import glob
import re
import sqlite3
import base64
import zlib
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Load identities
users_by_email = {}
users_by_id = {}
all_user_identifiers = {}

with open('dataset/user_identities.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        users_by_id[uid] = r
        em = r['email'].strip().lower()
        users_by_email[em] = uid
        if uid not in all_user_identifiers:
            all_user_identifiers[uid] = {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()}
        all_user_identifiers[uid]['emails'].add(em)
        if r['phone']:
            all_user_identifiers[uid]['phones'].add(r['phone'].strip())
        if r['name']:
            all_user_identifiers[uid]['names'].add(r['name'].strip())
        if r['email_hash']:
            all_user_identifiers[uid]['hashes'].add(r['email_hash'].strip().lower())

with open('dataset/user_audit_log.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        field = r['field_name']
        if uid not in all_user_identifiers:
            all_user_identifiers[uid] = {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()}
        if field == 'email':
            old_e = r['old_value'].strip().lower()
            new_e = r['new_value'].strip().lower()
            users_by_email[old_e] = uid
            users_by_email[new_e] = uid
            all_user_identifiers[uid]['emails'].add(old_e)
            all_user_identifiers[uid]['emails'].add(new_e)
        elif field == 'phone':
            all_user_identifiers[uid]['phones'].add(r['old_value'].strip())
            all_user_identifiers[uid]['phones'].add(r['new_value'].strip())
        elif field == 'name':
            all_user_identifiers[uid]['names'].add(r['old_value'].strip())
            all_user_identifiers[uid]['names'].add(r['new_value'].strip())

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

# Check user mapping for all 518 requests
matched_uids = []
unmatched = []
for r in requests:
    em = r['email'].strip().lower()
    uid = users_by_email.get(em)
    if uid:
        matched_uids.append((r['case_id'], uid))
    else:
        unmatched.append((r['case_id'], em))

print(f"Total requests: {len(requests)}")
print(f"Matched users: {len(matched_uids)} / {len(requests)}")
print(f"Unmatched: {len(unmatched)}")
if unmatched:
    print("Unmatched sample:", unmatched[:5])
