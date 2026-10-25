"""
Debug: check accts_by_user mapping built from evidence for users 21, 25, 26, 27, 28
after the new two-pass correlation logic runs.
"""
import sys, os
sys.path.insert(0, 'code')

# Run the engine and inspect its internal state
import csv, json, hashlib, glob, re, sqlite3, datetime

# Inline the key parts of the engine to trace accts_by_user
class Tracer:
    def __init__(self):
        self.users = {}
        self.users_by_email = {}
        self.ev_manifest = {}
        self.ev_obs = []
        self.system_activities = []
        self.sec_records_by_user = {}
        self.accts_by_user = {}
        
        # Load identities
        with open('dataset/user_identities.csv', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                uid = r['user_id']
                if uid not in self.users:
                    self.users[uid] = {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()}
                em = r.get('email', '').strip().lower()
                if em:
                    self.users[uid]['emails'].add(em)
                    self.users_by_email[em] = uid
        with open('dataset/user_audit_log.csv', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                uid = r['user_id']
                fn = r.get('field_name')
                for v in [r.get('old_value'), r.get('new_value')]:
                    if not v or v.lower() == 'null': continue
                    if fn == 'email':
                        em = v.strip().lower()
                        self.users.setdefault(uid, {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()})
                        self.users[uid]['emails'].add(em)
                        self.users_by_email[em] = uid

        # Load evidence manifest
        with open('dataset/evidence_files.csv', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                self.ev_manifest[r['file_id']] = r

        # Simulate service_resource_export parsing for evidence_92
        fid = 'evidence_92'
        info = self.ev_manifest[fid]
        cap = info['captured_at']
        p = os.path.join('dataset', info['file_path'])
        with open(p, encoding='utf-8') as f:
            d = json.load(f)
        sexp = d.get('service_exports', {})

        print("=== PASS 1: collecting user_ids ===")
        # From account_service (200 status)
        for r in sexp.get('account_service', {}).get('profile_lookups', []):
            prof = r.get('profile') or {}
            em = prof.get('email')
            sc = r.get('status_code')
            rid = r.get('resource_id')
            uid = prof.get('customer_reference')
            if not uid and em and em.lower() in self.users_by_email:
                uid = self.users_by_email[em.lower()]
            if sc == 200 and uid and em:
                print(f"  200 account: email={em} uid={uid} rid={rid}")
            if uid and rid:
                self.accts_by_user[uid] = rid
                print(f"  Mapped account: uid={uid} -> rid={rid}")

        sec_uids_ordered = []
        for r in sexp.get('security_service', {}).get('audit_records', []):
            uid = r.get('subject_reference')
            rid = r.get('resource_id')
            if uid and uid not in sec_uids_ordered:
                sec_uids_ordered.append(uid)
        print(f"\nSecurity uids ordered: {sec_uids_ordered}")
        print(f"accts_by_user after pass 1: {self.accts_by_user}")

        # 404 accounts
        account_404_records = []
        for r in sexp.get('account_service', {}).get('profile_lookups', []):
            sc = r.get('status_code')
            rid = r.get('resource_id')
            prof = r.get('profile') or {}
            em = prof.get('email')
            uid = prof.get('customer_reference')
            if not uid and em and em.lower() in self.users_by_email:
                uid = self.users_by_email[em.lower()]
            if sc == 404 and not uid:
                account_404_records.append({'rid': rid, 'em': em})
        print(f"\n404 accounts without uid: {account_404_records}")

        # Apply fallback
        for acct_rec in account_404_records:
            rid = acct_rec['rid']
            matched_uid = None
            if len(account_404_records) == 1 and len(sec_uids_ordered) == 1:
                candidate = sec_uids_ordered[0]
                if candidate not in self.accts_by_user:
                    matched_uid = candidate
            elif len(sec_uids_ordered) > 1:
                for uid_cand in sec_uids_ordered:
                    if uid_cand not in self.accts_by_user:
                        matched_uid = uid_cand
                        break
            if matched_uid and rid:
                print(f"\nFallback assigned: uid={matched_uid} -> account_rid={rid}")
                self.accts_by_user[matched_uid] = rid

        print(f"\nFinal accts_by_user: {dict(sorted(self.accts_by_user.items()))}")

t = Tracer()
