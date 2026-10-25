import os
import re
import csv
import json
import sqlite3
import datetime
import glob
import sys

sys.stdout.reconfigure(encoding='utf-8')

# Let's write the complete unified audit engine and evaluate on the 32 samples!
class ComprehensiveAuditEngine:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.users = {}            # uid -> {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()}
        self.users_by_email = {}   # email -> uid
        self.users_by_phone = {}   # phone -> uid
        self.users_by_hash = {}    # hash -> uid
        self.ev_manifest = {}      # file_id -> info
        self.ev_obs = []           # all parsed observations
        self.system_activities = []
        self.load_all()

    def load_all(self):
        # 1. Identities
        with open(os.path.join(self.dataset_dir, 'user_identities.csv'), 'r', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                uid = r['user_id']
                if uid not in self.users:
                    self.users[uid] = {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()}
                if r.get('name'): self.users[uid]['names'].add(r['name'].strip())
                if r.get('email'):
                    em = r['email'].strip().lower()
                    self.users[uid]['emails'].add(em)
                    self.users_by_email[em] = uid
                if r.get('phone'):
                    ph = r['phone'].strip()
                    self.users[uid]['phones'].add(ph)
                    self.users_by_phone[ph] = uid
                if r.get('email_hash'):
                    eh = r['email_hash'].strip()
                    self.users[uid]['hashes'].add(eh)
                    self.users_by_hash[eh] = uid

        # 2. Audit log
        with open(os.path.join(self.dataset_dir, 'user_audit_log.csv'), 'r', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                uid = r['user_id']
                fn = r.get('field_name')
                ov = r.get('old_value')
                nv = r.get('new_value')
                if uid not in self.users:
                    self.users[uid] = {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()}
                for v in [ov, nv]:
                    if not v or v.lower() == 'null': continue
                    v_s = v.strip()
                    if fn == 'email':
                        self.users[uid]['emails'].add(v_s.lower())
                        self.users_by_email[v_s.lower()] = uid
                    elif fn == 'phone':
                        self.users[uid]['phones'].add(v_s)
                        self.users_by_phone[v_s] = uid
                    elif fn in ['full_name', 'name']:
                        self.users[uid]['names'].add(v_s)

        # 3. Evidence manifest
        with open(os.path.join(self.dataset_dir, 'evidence_files.csv'), 'r', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                self.ev_manifest[r['file_id']] = r

        # 4. System activity
        with open(os.path.join(self.dataset_dir, 'system_activity.csv'), 'r', encoding='utf-8') as f:
            self.system_activities = list(csv.DictReader(f))

        # 5. Parse evidence files
        self.parse_all_evidence()

    def user_matches(self, user_id, item_uid=None, item_email=None, item_phone=None, item_name=None, item_hash=None):
        if not user_id or user_id not in self.users:
            return False
        u = self.users[user_id]
        if item_uid and item_uid == user_id:
            return True
        if item_email and item_email.strip().lower() in u['emails']:
            return True
        if item_phone and item_phone.strip() in u['phones']:
            return True
        if item_name and item_name.strip() in u['names']:
            return True
        if item_hash and item_hash.strip() in u['hashes']:
            return True
        return False

    def parse_all_evidence(self):
        ev_dir = os.path.join(self.dataset_dir, 'evidence')

        # Helper to get file_id and captured_at from relative path
        def get_meta(filepath):
            rel = os.path.normpath(os.path.relpath(filepath, self.dataset_dir)).replace('\\', '/')
            for fid, info in self.ev_manifest.items():
                if os.path.normpath(info['file_path']).replace('\\', '/') == rel:
                    return fid, info['captured_at']
            return None, '2026-09-30T23:59:59Z'

        # --- A. Records (JSON + TXT) ---
        for p in glob.glob(os.path.join(ev_dir, 'records', '*.*')):
            fid, cap = get_meta(p)
            if not fid: continue
            fn = os.path.basename(p)

            if fn.endswith('.txt'):
                with open(p, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('- ') and '|' in line:
                            parts = [x.strip() for x in line[2:].split('|')]
                            if len(parts) >= 6:
                                t_str, sys_id, rid, rtype, stat, ident = parts[:6]
                                u_m = ident if ident.startswith('user_') else None
                                em_m = ident.lower() if '@' in ident else None
                                self.ev_obs.append({
                                    'file_id': fid, 'captured_at': cap, 'system_id': sys_id,
                                    'resource_id': rid, 'user_id': u_m, 'email': em_m,
                                    'status': stat, 'raw': line
                                })

            elif fn.startswith('customer_data_snapshot_bundle'):
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                recs = d.get('records', [])
                for r in recs:
                    sys_id = r.get('system_id')
                    rid = r.get('resource_id')
                    pl = r.get('payload', {})
                    uid = pl.get('user_id') or pl.get('customer_reference') or pl.get('subject_reference')
                    em = pl.get('email') or pl.get('customer_email') or pl.get('owner_email') or pl.get('requester_email')
                    ph = pl.get('phone') or pl.get('requester_phone')
                    eh = pl.get('email_hash')
                    nm = pl.get('name') or pl.get('full_name') or pl.get('requester_name')
                    st = r.get('status')
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': sys_id,
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'phone': ph, 'name': nm, 'hash': eh, 'status': st
                    })

            elif fn.startswith('service_resource_export'):
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                sexp = d.get('service_exports', {})
                # account_service
                for r in sexp.get('account_service', {}).get('profile_lookups', []):
                    rid = r.get('resource_id')
                    sc = r.get('status_code')
                    prof = r.get('profile') or {}
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'account_service',
                        'resource_id': rid, 'user_id': prof.get('customer_reference'),
                        'email': prof.get('email').lower() if prof.get('email') else None,
                        'phone': prof.get('phone'), 'status': 'NOT_FOUND' if sc == 404 else 'FOUND'
                    })
                # analytics_platform
                for r in sexp.get('analytics_platform', {}).get('profiles', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('email')
                    ph = r.get('phone')
                    eh = r.get('email_hash')
                    stat = 'IDENTIFIABLE' if (uid or em or ph or eh) else 'ANONYMIZED'
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'analytics_platform',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'phone': ph, 'hash': eh, 'status': stat
                    })
                # backup_service
                for r in sexp.get('backup_service', {}).get('restore_entries', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('customer_email')
                    ra = r.get('restore_allowed', False)
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'backup_service',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'status': 'ACTIVE' if ra else 'BLOCKED'
                    })
                # export_service
                for r in sexp.get('export_service', {}).get('exports', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('owner_email')
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'export_service',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'status': 'FOUND'
                    })
                # integration_service
                for r in sexp.get('integration_service', {}).get('connectors', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('customer_email')
                    en = r.get('enabled', False)
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'integration_service',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'status': 'ACTIVE' if en else 'DISABLED'
                    })
                # search_service
                for r in sexp.get('search_service', {}).get('index_queries', []):
                    rid = r.get('resource_id')
                    q = r.get('query')
                    hits = r.get('hits', {}).get('documents', [])
                    doc_em = hits[0].get('email') if hits else None
                    doc_uid = hits[0].get('customer_reference') if hits else None
                    tot = r.get('hits', {}).get('total', 0)
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'search_service',
                        'resource_id': rid, 'user_id': doc_uid,
                        'email': (doc_em or q).lower() if (doc_em or q) else None,
                        'status': 'FOUND' if tot > 0 else 'NOT_FOUND'
                    })
                # security_service
                for r in sexp.get('security_service', {}).get('audit_records', []):
                    rid = r.get('resource_id')
                    uid = r.get('subject_reference')
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'security_service',
                        'resource_id': rid, 'user_id': uid, 'status': 'FOUND'
                    })
                # support_platform
                for r in sexp.get('support_platform', {}).get('tickets', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('requester_email')
                    ph = r.get('requester_phone')
                    nm = r.get('requester_name')
                    stat = 'IDENTIFIABLE' if (em or ph or nm) else 'REDACTED'
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'support_platform',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'phone': ph, 'name': nm, 'status': stat
                    })

            elif fn.startswith('connector_configurations'):
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                for conn in d.get('connectors', []):
                    rid = conn.get('connector_id')
                    uid = conn.get('customer_reference')
                    em = conn.get('customer_email')
                    st = 'ACTIVE' if conn.get('enabled') else 'DISABLED'
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'integration_service',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'status': st
                    })

            elif fn.startswith('security_audit_ledger'):
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                for entry in d.get('audit_entries', []):
                    rid = entry.get('record_id')
                    uid = entry.get('subject_reference')
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'security_service',
                        'resource_id': rid, 'user_id': uid, 'status': 'FOUND'
                    })

        # --- B. Databases (All 24 SQL files) ---
        for p in glob.glob(os.path.join(ev_dir, 'databases', '*.sql')):
            fid, cap = get_meta(p)
            if not fid: continue
            try:
                con = sqlite3.connect(':memory:')
                con.row_factory = sqlite3.Row
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    con.executescript(f.read())
                cur = con.cursor()
                tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

                for t in tables:
                    if t == 'snapshot_scope': continue
                    cols = [c[1] for c in cur.execute(f"PRAGMA table_info({t})").fetchall()]
                    rows = cur.execute(f"SELECT * FROM {t}").fetchall()

                    for row in rows:
                        d = dict(row)
                        rid = d.get('resource_id')
                        
                        # JSON record column
                        if 'record_json' in d:
                            orig = d.get('origin_system', 'account_service')
                            try:
                                rj = json.loads(d['record_json'])
                            except:
                                rj = {}
                            uid = rj.get('user_id') or rj.get('customer_reference') or rj.get('subject_reference')
                            em = rj.get('email') or rj.get('customer_email') or rj.get('owner_email')
                            ph = rj.get('phone')
                            eh = rj.get('email_hash')
                            nm = rj.get('full_name') or rj.get('name')
                            st = rj.get('account_status')
                            
                            # Determine status for this origin system
                            stat = 'FOUND'
                            if orig == 'account_service':
                                stat = 'FOUND' if st != 'DELETED' else 'NOT_FOUND'
                            elif orig == 'analytics_platform':
                                stat = 'IDENTIFIABLE' if (uid or em or ph or eh) else 'ANONYMIZED'
                            elif orig == 'support_platform':
                                stat = 'IDENTIFIABLE' if (uid or em or ph or eh) else 'REDACTED'
                            elif orig == 'backup_service':
                                stat = 'ACTIVE' if rj.get('restore_allowed') else 'BLOCKED'
                            elif orig == 'integration_service':
                                stat = 'ACTIVE' if rj.get('enabled') else 'DISABLED'

                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': orig,
                                'resource_id': rid or rj.get('resource_id'),
                                'user_id': uid, 'email': em.lower() if em else None,
                                'phone': ph, 'name': nm, 'hash': eh, 'status': stat
                            })

                        # Specific inventory/profile tables
                        elif 'customer_profiles' in t:
                            uid = d.get('customer_reference') or d.get('user_id')
                            em = d.get('email')
                            ph = d.get('phone')
                            nm = d.get('full_name') or d.get('display_name')
                            eh = d.get('email_hash')
                            st = d.get('account_status')
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'account_service',
                                'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                                'phone': ph, 'name': nm, 'hash': eh,
                                'status': 'FOUND' if st == 'ACTIVE' else 'NOT_FOUND'
                            })
                        elif t in ['customer_search_documents', 'search_documents_primary']:
                            uid = d.get('customer_reference')
                            em = d.get('email')
                            ph = d.get('phone')
                            nm = d.get('display_name')
                            eh = d.get('email_hash')
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'search_service',
                                'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                                'phone': ph, 'name': nm, 'hash': eh, 'status': 'FOUND'
                            })
                        elif t == 'customer_analytics_profiles':
                            uid = d.get('customer_reference')
                            em = d.get('email')
                            ph = d.get('phone')
                            eh = d.get('email_hash')
                            stat = 'IDENTIFIABLE' if (uid or em or ph or eh) else 'ANONYMIZED'
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'analytics_platform',
                                'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                                'phone': ph, 'hash': eh, 'status': stat
                            })
                        elif t == 'support_records':
                            uid = d.get('customer_reference')
                            em = d.get('requester_email')
                            ph = d.get('requester_phone')
                            nm = d.get('requester_name')
                            stat = 'IDENTIFIABLE' if (uid or em or ph or nm) else 'REDACTED'
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'support_platform',
                                'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                                'phone': ph, 'name': nm, 'status': stat
                            })
                        elif t == 'customer_exports':
                            uid = d.get('customer_reference')
                            em = d.get('owner_email')
                            ph = d.get('owner_phone')
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'export_service',
                                'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                                'phone': ph, 'status': 'FOUND'
                            })
                        elif t == 'connector_subscriptions':
                            uid = d.get('customer_reference')
                            em = d.get('customer_email')
                            en = d.get('enabled')
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'integration_service',
                                'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                                'status': 'ACTIVE' if en else 'DISABLED'
                            })
                        elif t == 'backup_restore_entries':
                            uid = d.get('customer_reference')
                            em = d.get('customer_email')
                            ra = d.get('restore_allowed')
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'backup_service',
                                'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                                'status': 'ACTIVE' if ra else 'BLOCKED'
                            })
                        elif t == 'security_audit_records':
                            uid = d.get('subject_reference')
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'security_service',
                                'resource_id': rid, 'user_id': uid, 'status': 'FOUND'
                            })
            except Exception as e:
                pass

        # --- C. Logs (All 26 log files with trace & line correlation) ---
        for p in glob.glob(os.path.join(ev_dir, 'logs', '*.log')):
            fid, cap = get_meta(p)
            if not fid: continue

            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            traces = {}
            standalone_lines = []
            for line in lines:
                l_s = line.strip()
                if not l_s: continue
                # trace_id or requestId
                tr_m = re.search(r'(?:trace_id|requestId|trace)=([a-zA-Z0-9_\-]+)', l_s)
                if tr_m:
                    traces.setdefault(tr_m.group(1), []).append(l_s)
                else:
                    standalone_lines.append(l_s)

            for tid, tlines in traces.items():
                emails = set()
                user_ids = set()
                phones = set()
                resources = []
                system = None
                stat = 'FOUND'
                category = None

                for l in tlines:
                    # system
                    sys_m = re.search(r'(?:service|function|system)=([a-zA-Z0-9_]+)', l) or re.search(r'\[([a-zA-Z0-9_]+_service|[a-zA-Z0-9_]+_platform)\]', l)
                    if sys_m:
                        s_cand = sys_m.group(1)
                        if s_cand in ['account_service', 'search_service', 'support_platform', 'analytics_platform', 'integration_service', 'backup_service', 'export_service', 'security_service', 'identity_service', 'profile_service']:
                            system = 'account_service' if s_cand == 'profile_service' else s_cand

                    # identifiers
                    for em in re.findall(r'[\b\s\'\"=]([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', l):
                        emails.add(em.lower())
                    for u in re.findall(r'[\b\s\'\"=](user_\d+)', l):
                        user_ids.add(u)
                    for ph in re.findall(r'\+\d{1,3}\s(?:\d{1,4}\s)?\d{3,4}[\s\-]?\d{3,4}', l):
                        phones.add(ph)

                    # resources
                    for r in re.findall(r'resource_id=\\?"?([a-zA-Z0-9_]+)\\?"?', l):
                        if r not in resources:
                            resources.append(r)

                    # status clues
                    if any(x in l for x in ['http_status=404', 'http_status="404"', 'rows=0', 'rows="0"', 'result=miss', 'result="miss"', 'result="NOT_FOUND"', 'NOT_FOUND']):
                        stat = 'NOT_FOUND'
                    elif any(x in l for x in ['http_status=200', 'http_status="200"', 'rows=1', 'rows="1"', 'result=hit', 'result="hit"', 'result="FOUND"', 'FOUND']):
                        stat = 'FOUND'
                    if 'message_pii_scan' in l or 'attachment_pii_scan' in l:
                        stat = 'IDENTIFIABLE'
                    if 'attachment' in l:
                        category = 'ATTACHMENT'

                if resources and (emails or user_ids or phones):
                    em = list(emails)[0] if emails else None
                    uid = list(user_ids)[0] if user_ids else None
                    ph = list(phones)[0] if phones else None
                    for r in resources:
                        # guess system from resource prefix if missing
                        cur_sys = system
                        if not cur_sys:
                            for spref in ['account', 'search', 'support', 'analytics', 'backup', 'export', 'security']:
                                if r.startswith(spref):
                                    cur_sys = f"{spref}_service" if spref in ['account', 'search', 'backup', 'export', 'security'] else f"{spref}_platform"
                        self.ev_obs.append({
                            'file_id': fid, 'captured_at': cap, 'system_id': cur_sys or 'account_service',
                            'resource_id': r, 'user_id': uid, 'email': em, 'phone': ph,
                            'status': stat, 'category': category
                        })

            for l in standalone_lines:
                res_m = re.findall(r'resource_id=\\?"?([a-zA-Z0-9_]+)\\?"?', l)
                em_m = re.findall(r'[\b\s\'\"=]([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', l)
                u_m = re.findall(r'[\b\s\'\"=](user_\d+)', l)
                ph_m = re.findall(r'\+\d{1,3}\s(?:\d{1,4}\s)?\d{3,4}[\s\-]?\d{3,4}', l)
                if res_m and (em_m or u_m or ph_m):
                    em = em_m[0].lower() if em_m else None
                    uid = u_m[0] if u_m else None
                    ph = ph_m[0] if ph_m else None
                    sys_m = re.search(r'(?:service|function|system)=([a-zA-Z0-9_]+)', l)
                    cur_sys = sys_m.group(1) if sys_m else None
                    stat = 'FOUND'
                    if any(x in l for x in ['404', 'rows=0', 'NOT_FOUND', 'miss']):
                        stat = 'NOT_FOUND'
                    for r in res_m:
                        if not cur_sys:
                            for spref in ['account', 'search', 'support', 'analytics', 'backup', 'export', 'security']:
                                if r.startswith(spref):
                                    cur_sys = f"{spref}_service" if spref in ['account', 'search', 'backup', 'export', 'security'] else f"{spref}_platform"
                        self.ev_obs.append({
                            'file_id': fid, 'captured_at': cap, 'system_id': cur_sys or 'account_service',
                            'resource_id': r, 'user_id': uid, 'email': em, 'phone': ph,
                            'status': stat
                        })

        # --- D. Documents (PDFs) ---
        # 1. delivery_correction_attachment.pdf (evidence_58)
        self.ev_obs.append({
            'file_id': 'evidence_58', 'captured_at': '2026-09-12T07:30:00Z',
            'system_id': 'support_platform', 'resource_id': 'support_001',
            'email': 'priya.raman@gmail.com', 'name': 'Priya Raman',
            'status': 'FOUND', 'category': 'ATTACHMENT'
        })
        # 2. account_history_report_20260718.pdf (evidence_18)
        self.ev_obs.append({
            'file_id': 'evidence_18', 'captured_at': '2026-07-18T11:00:00Z',
            'system_id': 'export_service', 'resource_id': 'export_1842',
            'email': 'ingrid.dahl@outlook.com', 'user_id': 'user_18',
            'status': 'FOUND'
        })

        print(f"Total parsed evidence observations across all sources: {len(self.ev_obs)}")

engine = ComprehensiveAuditEngine('dataset')
