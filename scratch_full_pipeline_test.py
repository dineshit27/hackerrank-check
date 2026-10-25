import csv
import json
import os
import glob
import re
import sqlite3
import base64
import zlib
import datetime
import sys
sys.stdout.reconfigure(encoding='utf-8')

print("Starting pipeline test on sample cases...")

# 1. LOAD IDENTITIES
users_by_email = {}
users_by_id = {}
all_user_identifiers = {} # uid -> dict of sets: emails, phones, names, hashes

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

# 2. EVIDENCE MANIFEST
with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = {r['file_id']: r for r in csv.DictReader(f)}

# 3. NON-DELETION DETECTION
def is_not_applicable(text):
    t = text.lower()
    non_del_phrases = [
        'not asking for deletion', 'do not close', "don't close", 'do not delete', "don't delete",
        'leave the account', 'keep the account', 'as it is', 'in place', 'continue using',
        'without removing', 'information request', 'portable format', 'copy of last year',
        'misspelled', 'out of date', 'promotional emails', 'marketing lists only', 'resetting the login'
    ]
    return any(p in t for p in non_del_phrases)

print("Identities loaded successfully.")
