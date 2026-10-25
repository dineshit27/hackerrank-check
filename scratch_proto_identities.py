import csv
import json
import os
import sqlite3
import re
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Load identities
users_by_email = {}
users_by_id = {}
all_user_identifiers = {} # uid -> set of (emails, phones, hashes, names)

with open('dataset/user_identities.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        users_by_id[uid] = r
        em = r['email'].lower()
        users_by_email[em] = uid
        if uid not in all_user_identifiers:
            all_user_identifiers[uid] = {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()}
        all_user_identifiers[uid]['emails'].add(em)
        if r['phone']:
            all_user_identifiers[uid]['phones'].add(r['phone'])
        if r['name']:
            all_user_identifiers[uid]['names'].add(r['name'])
        if r['email_hash']:
            all_user_identifiers[uid]['hashes'].add(r['email_hash'])

with open('dataset/user_audit_log.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        field = r['field_name']
        if uid not in all_user_identifiers:
            all_user_identifiers[uid] = {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()}
        if field == 'email':
            users_by_email[r['old_value'].lower()] = uid
            users_by_email[r['new_value'].lower()] = uid
            all_user_identifiers[uid]['emails'].add(r['old_value'].lower())
            all_user_identifiers[uid]['emails'].add(r['new_value'].lower())
        elif field == 'phone':
            all_user_identifiers[uid]['phones'].add(r['old_value'])
            all_user_identifiers[uid]['phones'].add(r['new_value'])
        elif field == 'name':
            all_user_identifiers[uid]['names'].add(r['old_value'])
            all_user_identifiers[uid]['names'].add(r['new_value'])

print(f"Loaded {len(users_by_id)} users and their audit identities.")
