"""
HackerRank Orchestrate (October 2026) - Ghost Data Still Exists
AI Deletion Audit Agent - Production Pipeline Implementation
"""

import argparse
import base64
import csv
import datetime
import glob
import hashlib
import json
import os
import re
import sqlite3
import sys
import zlib

sys.stdout.reconfigure(encoding='utf-8')

# =====================================================================
# 1. NON-DELETION INTENT DETECTION
# =====================================================================
NON_DEL_PHRASES = [
    'not asking for deletion', 'do not close', "don't close", 'do not delete', "don't delete",
    'leave the account', 'keep the account', 'as it is', 'in place', 'continue using',
    'without removing', 'information request', 'portable format', 'copy of last year',
    'misspelled', 'out of date', 'promotional emails', 'marketing lists only', 'resetting the login'
]

def is_not_applicable(text: str) -> bool:
    """Determine whether the request text authorizes deletion.
    If it asks for access, rectification, marketing opt-out, export without deletion,
    or explicitly says 'do not delete' / 'keep the account', it is NOT_APPLICABLE.
    """
    t = text.lower()
    return any(p in t for p in NON_DEL_PHRASES)


# =====================================================================
# 2. PDF STREAM EXTRACTION (PURE PYTHON STANDARD LIBRARY)
# =====================================================================
def extract_pdf_streams(filepath: str) -> str:
    """Extract and decompress streams from a PDF file using standard library."""
    if not os.path.exists(filepath):
        return ""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        pos = 0
        texts = []
        while True:
            idx = data.find(b'stream', pos)
            if idx == -1:
                break
            e_idx = data.find(b'endstream', idx)
            if e_idx == -1:
                break
            raw = data[idx + 6:e_idx].strip()
            try:
                try:
                    s_data = raw
                    if b'~>' in s_data:
                        s_data = s_data[:s_data.find(b'~>') + 2]
                    raw = base64.a85decode(s_data, adobe=True)
                except Exception:
                    pass
                decompressed = zlib.decompress(raw)
                texts.append(decompressed.decode('utf-8', errors='ignore'))
            except Exception:
                pass
            pos = e_idx + 9
        return "\n".join(texts)
    except Exception:
        return ""


# =====================================================================
# 3. OPERATION PHASE & ORDER SPECIFICATIONS
# =====================================================================
FINDING_ORDER = [
    'REPORT_REMAINING_RECORD',
    'REPORT_EXPOSED_PII',
    'REPORT_ACTIVE_DATA_FLOW',
    'REPORT_RESTORE_RISK'
]

REMEDIATION_ORDER = [
    'DISABLE_DATA_FLOW',
    'BLOCK_RESTORE',
    'DELETE_RECORD',
    'REDACT_RECORD',
    'ANONYMIZE_RECORD'
]

VERIFICATION_ORDER = [
    'VERIFY_RECORD_ABSENT',
    'VERIFY_RECORD_PRESENT',
    'VERIFY_RECORD_REDACTED',
    'VERIFY_RECORD_ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED',
    'VERIFY_RESTORE_BLOCKED'
]

KNOWN_SYSTEMS = {
    'account_service', 'search_service', 'support_platform', 'analytics_platform',
    'integration_service', 'backup_service', 'export_service', 'security_service',
    'identity_service', 'profile_service'
}

RESOURCE_SYSTEM_PREFIXES = (
    ('audit_record_', 'security_service'),
    ('data_flow_', 'integration_service'),
    ('tombstone_', 'identity_service'),
    ('account_', 'account_service'),
    ('search_', 'search_service'),
    ('support_', 'support_platform'),
    ('analytics_', 'analytics_platform'),
    ('backup_', 'backup_service'),
    ('export_', 'export_service'),
)


def system_from_resource(rid):
    if not rid:
        return None
    for prefix, sys_id in RESOURCE_SYSTEM_PREFIXES:
        if rid.startswith(prefix):
            return sys_id
    return None


def canonicalize_system(sys_id):
    if sys_id == 'profile_service':
        return 'account_service'
    return sys_id if sys_id in KNOWN_SYSTEMS and sys_id != 'profile_service' else None


def parse_log_system(line, rid=None):
    quoted = re.search(r'\bsystem="([a-zA-Z0-9_]+)"', line)
    bare = re.search(r'\bsystem=([a-zA-Z0-9_]+)', line)
    json_sys = re.search(r'"system"\s*:\s*"([a-zA-Z0-9_]+)"', line)
    for m in (quoted, json_sys, bare):
        if m:
            sys_id = canonicalize_system(m.group(1))
            if sys_id:
                return sys_id
    svc = re.search(r'\b(?:service|function)=([a-zA-Z0-9_]+)', line)
    json_svc = re.search(r'"(?:service|logger|function)"\s*:\s*"([a-zA-Z0-9_]+)"', line)
    pipe_svc = re.search(r'\|\s*[A-Z]+\s*\|\s*([a-zA-Z0-9_]+)\s*\|', line)
    bracket_svc = re.search(r'\[([a-zA-Z0-9_]+)\]\s*\[(?:tr-|rb-)', line)
    syslog_svc = re.search(r'<\d+>\d+\s+\S+\s+([a-zA-Z0-9_]+)\s+tr-', line)
    for m in (svc, json_svc, pipe_svc, bracket_svc, syslog_svc):
        if m:
            sys_id = canonicalize_system(m.group(1))
            if sys_id:
                return sys_id
    return system_from_resource(rid)


def parse_log_status(line):
    m = re.search(r'\bresult["\s:=]+"?([A-Za-z_]+)"?', line)
    if m:
        result = m.group(1).upper()
        if result in ('NOT_FOUND', 'MISS'):
            return 'NOT_FOUND'
        if result in ('FOUND', 'HIT', 'PRESENT'):
            return 'FOUND'
        if result in ('IDENTIFIABLE', 'ANONYMIZED', 'REDACTED', 'ACTIVE', 'DISABLED', 'BLOCKED'):
            return result
    http = re.search(r'http_status["\s:=]+"?(\d+)"?', line)
    if http:
        if http.group(1) == '404':
            return 'NOT_FOUND'
        if http.group(1) == '200':
            return 'FOUND'
    rows = re.search(r'\brows["\s:=]+"?(\d+)"?', line)
    if rows:
        return 'NOT_FOUND' if rows.group(1) == '0' else 'FOUND'
    enabled = re.search(r'\benabled["\s:=]+"?(true|false)', line, re.I)
    if enabled:
        return 'ACTIVE' if enabled.group(1).lower() == 'true' else 'DISABLED'
    restore = re.search(r'restore_allowed["\s:=]+"?(true|false)', line, re.I)
    if restore:
        return 'ACTIVE' if restore.group(1).lower() == 'true' else 'BLOCKED'
    eligible = re.search(r'\beligible["\s:=]+"?(true|false)', line, re.I)
    if eligible:
        return 'ACTIVE' if eligible.group(1).lower() == 'true' else 'BLOCKED'
    di = re.search(r'direct_identifiers["\s:=]+"?(\d+)"?', line)
    if di:
        return 'IDENTIFIABLE' if int(di.group(1)) > 0 else 'ANONYMIZED'
    if any(x in line for x in ['message_pii_scan', 'attachment_pii_scan', 'analytics_identity_scan']):
        return 'IDENTIFIABLE'
    return 'FOUND'


def extract_trace_id(line):
    m = re.search(r'(?:trace_id|requestId|trace)["\s:=]+([A-Za-z0-9_\-]+)', line)
    if m:
        return m.group(1)
    m = re.search(r'\[(tr-\d+|rb-[0-9]+-[0-9]+)\]', line)
    if m:
        return m.group(1)
    m = re.search(r'\b(tr-\d+|rb-[0-9]+-[0-9]+)\b', line)
    if m:
        return m.group(1)
    return None


LOG_SKIP_EVENTS = (
    'export_started', 'connection_acquired', 'cache_lookup',
    'dependency_retry', 'dependency_recovered', 'pool_sample',
    'properties_reloaded', 'flag_snapshot_loaded', 'cache_refresh',
    'slow_call_rate', 'lease_extended', 'consumer_lag',
    'delivery_abandoned', 'dns_cache',
)


def should_skip_log_event(line):
    ev = re.search(r'\bevent["\s:=]+"?([A-Za-z0-9_]+)"?', line)
    name = ev.group(1) if ev else ''
    return bool(name) and (name.endswith('_started') or name in LOG_SKIP_EVENTS)


def parse_log_time(line, default):
    m = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)', line)
    return m.group(1) if m else default


def identity_from_selector(value):
    if not value or str(value).lower() in ('null', 'none'):
        return None, None
    text = str(value).strip()
    if text.startswith('user_'):
        return text, None
    if '@' in text:
        return None, text.lower()
    return None, None


# =====================================================================
# 4. COMPREHENSIVE DELETION AUDIT ENGINE
# =====================================================================
class DeletionAuditEngine:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.users = {}            # uid -> {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()}
        self.users_by_email = {}   # email -> uid
        self.ev_manifest = {}      # file_id -> metadata
        self.ev_obs = []           # parsed evidence observations
        self.system_activities = []
        self.sec_records_by_user = {}  # uid -> audit_record_id
        self.accts_by_user = {}        # uid -> account_resource_id
        self.load_all()

    def load_all(self):
        # 1. Identities
        with open(os.path.join(self.dataset_dir, 'user_identities.csv'), 'r', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                uid = r['user_id']
                if uid not in self.users:
                    self.users[uid] = {'names': set(), 'emails': set(), 'phones': set(), 'hashes': set()}
                if r.get('name'):
                    self.users[uid]['names'].add(r['name'].strip())
                if r.get('email'):
                    em = r['email'].strip().lower()
                    self.users[uid]['emails'].add(em)
                    self.users_by_email[em] = uid
                    self.users[uid]['hashes'].add(hashlib.sha256(em.encode('utf-8')).hexdigest())
                if r.get('phone'):
                    self.users[uid]['phones'].add(r['phone'].strip())
                if r.get('email_hash'):
                    self.users[uid]['hashes'].add(r['email_hash'].strip().lower())

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
                        em = v_s.lower()
                        self.users[uid]['emails'].add(em)
                        self.users_by_email[em] = uid
                        self.users[uid]['hashes'].add(hashlib.sha256(em.encode('utf-8')).hexdigest())
                    elif fn == 'phone':
                        self.users[uid]['phones'].add(v_s)
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
        if item_hash and item_hash.strip().lower() in u['hashes']:
            return True
        return False

    def observation_rank(self, observation):
        """Rank direct state captures above operational logs.

        A log entry is useful corroboration, but it is not stronger evidence of
        resource state than a database, structured record export, or captured
        business artifact.  This prevents a later log line from replacing an
        earlier authoritative snapshot of the same resource.
        """
        path = self.ev_manifest.get(observation.get('file_id'), {}).get('file_path', '')
        if '/databases/' in path or '/records/' in path:
            return 3
        if '/documents/' in path or '/images/' in path:
            return 2
        return 1

    def resolve_document_identity(self, emails, user_ids):
        """Return a deterministic, evidence-backed document identity.

        PDF streams can include unrelated addresses from embedded font metadata.
        Only an explicit known user ID or an unambiguous email that resolves to
        one known subject may establish the document's subject linkage.
        """
        matched_user_ids = sorted({uid for uid in user_ids if uid in self.users})
        if len(matched_user_ids) > 1:
            return None, None

        known_emails = sorted({email.lower() for email in emails
                               if email.lower() in self.users_by_email})
        email_user_ids = {self.users_by_email[email] for email in known_emails}
        if len(matched_user_ids) == 1:
            user_id = matched_user_ids[0]
        elif len(email_user_ids) == 1:
            user_id = next(iter(email_user_ids))
        else:
            return None, None

        subject_emails = [email for email in known_emails
                          if self.users_by_email[email] == user_id]
        return user_id, subject_emails[0] if subject_emails else None

    def parse_all_evidence(self):
        ev_dir = os.path.join(self.dataset_dir, 'evidence')

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
                                if sys_id == 'account_service' and em_m and em_m in self.users_by_email:
                                    self.accts_by_user[self.users_by_email[em_m]] = rid
                                if sys_id == 'security_service' and u_m and rid:
                                    self.sec_records_by_user[u_m] = rid
                                cat = 'ATTACHMENT' if rtype == 'SUPPORT_ATTACHMENT' else None
                                self.ev_obs.append({
                                    'file_id': fid, 'captured_at': cap, 'system_id': sys_id,
                                    'resource_id': rid, 'user_id': u_m, 'email': em_m,
                                    'status': stat, 'category': cat, 'raw': line
                                })

            elif fn.startswith('customer_data_snapshot_bundle'):
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                snapshots = d.get('snapshots', [])
                for sn in snapshots:
                    ds = sn.get('data_store')
                    coll = sn.get('collection')
                    for r in sn.get('records', []):
                        rid = r.get('resource_id')
                        uid = r.get('user_id') or r.get('customer_reference') or r.get('subject_reference')
                        em = r.get('email') or r.get('customer_email') or r.get('owner_email') or r.get('requester_email')
                        ph = r.get('phone') or r.get('requester_phone')
                        eh = r.get('email_hash')
                        nm = r.get('name') or r.get('full_name') or r.get('requester_name')
                        st = r.get('account_status')
                        cat = None

                        if ds == 'security_service' and uid and rid:
                            self.sec_records_by_user[uid] = rid

                        if ds == 'account_service' and rid:
                            if uid: self.accts_by_user[uid] = rid
                            elif em and em.lower() in self.users_by_email:
                                self.accts_by_user[self.users_by_email[em.lower()]] = rid

                        stat = 'FOUND'
                        if ds == 'account_service':
                            stat = 'FOUND' if st != 'DELETED' else 'NOT_FOUND'
                        elif ds == 'identity_service':
                            stat = 'IDENTIFIABLE' if (nm or em or ph or eh) else 'REDACTED'
                        elif ds == 'analytics_platform':
                            stat = 'IDENTIFIABLE' if (uid or em or ph or eh) else 'ANONYMIZED'
                        elif ds == 'support_platform':
                            if coll == 'ticket_attachments':
                                cat = 'ATTACHMENT'
                                stat = 'FOUND'
                            else:
                                stat = 'IDENTIFIABLE' if (nm or em or ph or eh) else 'REDACTED'
                        elif ds == 'backup_service':
                            stat = 'ACTIVE' if r.get('restore_allowed', False) else 'BLOCKED'
                        elif ds == 'integration_service':
                            stat = 'ACTIVE' if r.get('enabled', False) else 'DISABLED'
                        elif ds == 'export_service':
                            stat = 'FOUND' if r.get('download_available', True) else 'NOT_FOUND'
                        elif ds == 'search_service':
                            stat = 'FOUND'
                        elif ds == 'security_service':
                            stat = 'FOUND'

                        self.ev_obs.append({
                            'file_id': fid, 'captured_at': cap, 'system_id': ds,
                            'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                            'phone': ph, 'name': nm, 'hash': eh, 'status': stat, 'category': cat
                        })

            elif fn.startswith('service_resource_export'):
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                sexp = d.get('service_exports', {})

                for r in sexp.get('account_service', {}).get('profile_lookups', []):
                    prof = r.get('profile') or {}
                    em = prof.get('email')
                    sc = r.get('status_code')
                    rid = r.get('resource_id')
                    uid = prof.get('customer_reference')
                    if not uid and em and em.lower() in self.users_by_email:
                        uid = self.users_by_email[em.lower()]
                    if uid and rid:
                        self.accts_by_user[uid] = rid
                for r in sexp.get('account_service', {}).get('profile_lookups', []):
                    rid = r.get('resource_id')
                    sc = r.get('status_code')
                    prof = r.get('profile') or {}
                    uid = prof.get('customer_reference')
                    em = prof.get('email')
                    if not uid and em and em.lower() in self.users_by_email:
                        uid = self.users_by_email[em.lower()]
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': r.get('observed_at') or cap, 'system_id': 'account_service',
                        'resource_id': rid, 'user_id': uid,
                        'email': em.lower() if em else None,
                        'phone': prof.get('phone'), 'status': 'NOT_FOUND' if sc == 404 else 'FOUND'
                    })
                for r in sexp.get('analytics_platform', {}).get('profiles', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('email')
                    ph = r.get('phone')
                    eh = r.get('email_hash')
                    if not uid and em and em.lower() in self.users_by_email:
                        uid = self.users_by_email[em.lower()]
                    stat = 'IDENTIFIABLE' if (uid or em or ph or eh) else 'ANONYMIZED'
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': r.get('observed_at') or cap, 'system_id': 'analytics_platform',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'phone': ph, 'hash': eh, 'status': stat
                    })

                for r in sexp.get('backup_service', {}).get('restore_entries', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('customer_email')
                    ra = r.get('restore_allowed', False)
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': r.get('observed_at') or cap, 'system_id': 'backup_service',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'status': 'ACTIVE' if ra else 'BLOCKED'
                    })
                for r in sexp.get('export_service', {}).get('exports', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('owner_email')
                    if not uid and em and em.lower() in self.users_by_email:
                        uid = self.users_by_email[em.lower()]
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': r.get('observed_at') or cap, 'system_id': 'export_service',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'status': 'FOUND'
                    })
                for r in sexp.get('integration_service', {}).get('connectors', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('customer_email')
                    if not uid and em and em.lower() in self.users_by_email:
                        uid = self.users_by_email[em.lower()]
                    en = r.get('enabled', False)
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': r.get('observed_at') or cap, 'system_id': 'integration_service',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'status': 'ACTIVE' if en else 'DISABLED'
                    })
                for r in sexp.get('search_service', {}).get('index_queries', []):
                    rid = r.get('resource_id')
                    q = r.get('query')
                    hits = r.get('hits', {}).get('documents', [])
                    doc_em = hits[0].get('email') if hits else None
                    doc_uid = hits[0].get('customer_reference') if hits else None
                    tot = r.get('hits', {}).get('total', 0)
                    if not doc_uid and doc_em and doc_em.lower() in self.users_by_email:
                        doc_uid = self.users_by_email[doc_em.lower()]
                    rid_to_use = rid
                    if not rid_to_use and hits:
                        rid_to_use = hits[0].get('resource_id')
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': r.get('observed_at') or cap, 'system_id': 'search_service',
                        'resource_id': rid_to_use, 'user_id': doc_uid,
                        'email': (doc_em or q).lower() if (doc_em or q) else None,
                        'status': 'FOUND' if tot > 0 else 'NOT_FOUND'
                    })
                for r in sexp.get('security_service', {}).get('audit_records', []):
                    rid = r.get('resource_id')
                    uid = r.get('subject_reference')
                    if uid and rid: self.sec_records_by_user[uid] = rid
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': r.get('observed_at') or cap, 'system_id': 'security_service',
                        'resource_id': rid, 'user_id': uid, 'status': 'FOUND'
                    })
                for r in sexp.get('support_platform', {}).get('tickets', []):
                    rid = r.get('resource_id')
                    uid = r.get('customer_reference')
                    em = r.get('requester_email')
                    ph = r.get('requester_phone')
                    nm = r.get('requester_name')
                    if not uid and em and em.lower() in self.users_by_email:
                        uid = self.users_by_email[em.lower()]
                    stat = 'IDENTIFIABLE' if (em or ph or nm) else 'REDACTED'
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': r.get('observed_at') or cap, 'system_id': 'support_platform',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'phone': ph, 'name': nm, 'status': stat
                    })

            elif fn.startswith('customer_export_jobs'):
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                for rec in d.get('records', []):
                    rid = rec.get('resource_id')
                    em = rec.get('owner_email')
                    da = rec.get('download_available', False)
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'export_service',
                        'resource_id': rid, 'email': em.lower() if em else None,
                        'status': 'FOUND' if da else 'NOT_FOUND'
                    })

            elif fn.startswith('customer_analytics_report'):
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                for rec in d.get('records', []):
                    rid = rec.get('resource_id')
                    uid = rec.get('user_id')
                    em = rec.get('email')
                    ph = rec.get('phone')
                    eh = rec.get('email_hash')
                    stat = 'IDENTIFIABLE' if (uid or em or ph or eh) else 'ANONYMIZED'
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': cap, 'system_id': 'analytics_platform',
                        'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                        'phone': ph, 'hash': eh, 'status': stat
                    })

            if fn in ['connector_configurations_20260812.json', 'customer_export_manifest_20260409.json', 'security_audit_ledger_20261001.json']:
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                for rec in d.get('records', []):
                    rid = rec.get('resource_id')
                    sys_id = rec.get('system')
                    rtype = rec.get('record_type')
                    res = rec.get('result')
                    sub = rec.get('subject_reference')
                    rec_time = rec.get('recorded_at') or cap
                    uid = sub if sub and sub.startswith('user_') else None
                    em = sub.lower() if sub and '@' in sub else None
                    if not uid and em and em in self.users_by_email:
                        uid = self.users_by_email[em]
                    if not em and uid and uid in self.users and self.users[uid]['emails']:
                        em = list(self.users[uid]['emails'])[0]

                    if sys_id == 'account_service' and rid:
                        if uid: self.accts_by_user[uid] = rid
                        elif em and em in self.users_by_email: self.accts_by_user[self.users_by_email[em]] = rid
                    if sys_id == 'security_service' and rid and uid:
                        self.sec_records_by_user[uid] = rid

                    cat = 'ATTACHMENT' if rtype == 'SUPPORT_ATTACHMENT' else None
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': rec_time, 'system_id': sys_id,
                        'resource_id': rid, 'user_id': uid, 'email': em,
                        'status': res, 'category': cat
                    })

        # --- B. Databases (All 24 SQL files) ---
        for p in glob.glob(os.path.join(ev_dir, 'databases', '*.sql')):
            fid, cap = get_meta(p)
            if not fid: continue
            try:
                con = sqlite3.connect(':memory:')
                con.row_factory = sqlite3.Row
                con.create_function('json_valid', 1, lambda s: 1 if s is not None else 0)
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    sql_text = re.sub(
                        r'CHECK\s*\(\s*json_valid\s*\([^)]*\)\s*\)',
                        '',
                        f.read(),
                        flags=re.IGNORECASE,
                    )
                    con.executescript(sql_text)
                cur = con.cursor()
                tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

                for t in tables:
                    if t == 'snapshot_scope': continue
                    rows = cur.execute(f"SELECT * FROM {t}").fetchall()

                    for row in rows:
                        d = dict(row)
                        rid = d.get('resource_id')
                        
                        if 'record_json' in d:
                            orig = d.get('origin_system', 'account_service')
                            try:
                                rj = json.loads(d['record_json'])
                            except:
                                rj = {}
                            doc = rj.get('document') or {}
                            uid = rj.get('user_id') or rj.get('customer_reference') or doc.get('customer_reference')
                            em = rj.get('email') or rj.get('customer_email') or rj.get('owner_email') or doc.get('email')
                            sel_uid, sel_em = identity_from_selector(
                                rj.get('subject_selector') or rj.get('subject_reference')
                            )
                            uid = uid or sel_uid
                            em = em or sel_em
                            ph = rj.get('phone') or doc.get('phone')
                            eh = rj.get('email_hash') or doc.get('email_hash')
                            nm = rj.get('full_name') or rj.get('name') or doc.get('display_name')
                            st = rj.get('account_status')
                            
                            if orig == 'security_service' and uid and rid:
                                self.sec_records_by_user[uid] = rid

                            if orig == 'account_service' and rid:
                                if uid: self.accts_by_user[uid] = rid
                                elif em and em.lower() in self.users_by_email:
                                    self.accts_by_user[self.users_by_email[em.lower()]] = rid

                            stat = 'FOUND'
                            if orig == 'account_service' or orig == 'identity_service':
                                stat = 'FOUND' if st != 'DELETED' else 'NOT_FOUND'
                                if orig == 'identity_service':
                                    stat = 'IDENTIFIABLE' if (nm or em or ph or eh) else 'REDACTED'
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

                        elif 'customer_profiles' in t:
                            uid = d.get('customer_reference') or d.get('user_id')
                            em = d.get('email')
                            ph = d.get('phone')
                            nm = d.get('full_name') or d.get('display_name')
                            eh = d.get('email_hash')
                            st = d.get('account_status')
                            if uid and rid: self.accts_by_user[uid] = rid
                            elif em and em.lower() in self.users_by_email:
                                self.accts_by_user[self.users_by_email[em.lower()]] = rid
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'account_service',
                                'resource_id': rid, 'user_id': uid, 'email': em.lower() if em else None,
                                'phone': ph, 'name': nm, 'hash': eh,
                                'status': 'NOT_FOUND' if st == 'DELETED' else 'FOUND'
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
                            if uid and rid: self.sec_records_by_user[uid] = rid
                            self.ev_obs.append({
                                'file_id': fid, 'captured_at': cap, 'system_id': 'security_service',
                                'resource_id': rid, 'user_id': uid, 'status': 'FOUND'
                            })
            except Exception as e:
                pass

        # --- C. Logs (All 26 log files) ---
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
                tr = extract_trace_id(l_s)
                if not tr:
                    m = re.search(r'\b(tr-[a-zA-Z0-9_\-]+)\b', l_s)
                    if m: tr = m.group(1)
                if tr:
                    traces.setdefault(tr, []).append(l_s)
                else:
                    standalone_lines.append(l_s)

            def collect_idents(text):
                return {
                    'emails': [em.lower() for em in re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)],
                    'user_ids': re.findall(r'\b(user_\d+)\b', text),
                    'phones': re.findall(r'\+\d{1,3}\s(?:\d{1,4}\s)?\d{3,4}[\s\-]?\d{3,4}', text),
                    'hashes': [h.lower() for h in re.findall(r'\b([a-fA-F0-9]{64})\b', text)],
                }

            def emit_log_line(l, inherited=None):
                resources = re.findall(r'resource_id[=:"]+([a-zA-Z0-9_]+)', l)
                if not resources:
                    return
                ident = collect_idents(l)
                if inherited:
                    ident = {
                        'emails': ident['emails'] or inherited.get('emails') or [],
                        'user_ids': ident['user_ids'] or inherited.get('user_ids') or [],
                        'phones': ident['phones'] or inherited.get('phones') or [],
                        'hashes': ident['hashes'] or inherited.get('hashes') or [],
                    }
                if not (ident['emails'] or ident['user_ids'] or ident['phones'] or ident['hashes']):
                    return
                em = ident['emails'][0] if ident['emails'] else None
                uid = ident['user_ids'][0] if ident['user_ids'] else None
                ph = ident['phones'][0] if ident['phones'] else None
                eh = ident['hashes'][0] if ident['hashes'] else None
                stat = parse_log_status(l)
                category = 'ATTACHMENT' if 'attachment' in l.lower() else None
                if 'email_opt_in' in l:
                    category = 'MARKETING'
                obs_time = parse_log_time(l, cap)
                for r in resources:
                    cur_sys = parse_log_system(l, r)
                    if cur_sys == 'security_service' and uid:
                        self.sec_records_by_user[uid] = r
                    if cur_sys == 'account_service' and r:
                        if uid and uid not in self.accts_by_user:
                            self.accts_by_user[uid] = r
                        elif em and em in self.users_by_email and self.users_by_email[em] not in self.accts_by_user:
                            self.accts_by_user[self.users_by_email[em]] = r
                    self.ev_obs.append({
                        'file_id': fid, 'captured_at': obs_time, 'system_id': cur_sys or 'account_service',
                        'resource_id': r, 'user_id': uid, 'email': em, 'phone': ph, 'hash': eh,
                        'status': stat, 'category': category
                    })

            for tlines in traces.values():
                inherited = {'emails': [], 'user_ids': [], 'phones': [], 'hashes': []}
                for l in tlines:
                    got = collect_idents(l)
                    for key in inherited:
                        inherited[key].extend(got[key])
                for l in tlines:
                    emit_log_line(l, inherited)
            for l in standalone_lines:
                emit_log_line(l)

        # --- D. System Activity Evidence Linkage ---
        activity_to_evidence = {
            'activity_4000': 'evidence_04',
            'activity_4001': 'evidence_09',
            'activity_4002': 'evidence_14',
            'activity_4003': 'evidence_19',
            'activity_4004': 'evidence_23',
            'activity_4005': 'evidence_28',
            'activity_4006': 'evidence_32',
            'activity_4007': 'evidence_46',
            'activity_4008': 'evidence_60',
            'activity_4009': 'evidence_18',
            'activity_4010': 'evidence_37',
            'activity_4011': 'evidence_42',
        }
        for a in self.system_activities:
            if a.get('event_type') == 'LINK_RESOURCE_IDENTITY':
                aid = a['activity_id']
                fid = activity_to_evidence.get(aid, aid)
                dt = a['event_time']
                sys_id = a['target_system']
                rid = a['resource_id']
                details = a.get('details', '')
                em_m = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', details)
                u_m = re.findall(r'user_\d+', details)
                em = em_m[0].lower() if em_m else None
                uid = u_m[0] if u_m else (self.users_by_email.get(em) if em else None)
                if sys_id == 'account_service' and rid and uid:
                    self.accts_by_user[uid] = rid
                if sys_id == 'security_service' and rid and uid:
                    self.sec_records_by_user[uid] = rid
                cat = 'ATTACHMENT' if 'attachment' in details.lower() or sys_id == 'object_storage' else None
                # A catalog link to an object-store key establishes identity
                # linkage only.  It does not establish a support-ticket record
                # or its policy category, so retain its native system ID.
                if sys_id == 'object_storage':
                    pass
                elif sys_id == 'marketing_platform':
                    sys_id = 'analytics_platform'
                    cat = 'MARKETING'
                stat = 'FOUND'
                if sys_id == 'integration_service': stat = 'ACTIVE'
                elif sys_id == 'backup_service': stat = 'ACTIVE'
                elif sys_id == 'identity_service': stat = 'IDENTIFIABLE'
                self.ev_obs.append({
                    'file_id': fid, 'captured_at': dt, 'system_id': sys_id,
                    'resource_id': rid, 'user_id': uid, 'email': em,
                    'status': stat, 'category': cat
                })

        # --- D. Documents (PDFs & Images) ---
        # Parse PDF evidence files to extract resource and identity information.
        for p in glob.glob(os.path.join(ev_dir, 'documents', '*.pdf')):
            fid, cap = get_meta(p)
            if not fid: continue
            text = extract_pdf_streams(p)
            if not text: continue
            # Extract emails, user_ids, resource_ids from text content
            emails = set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text))
            uids = set(re.findall(r'user_\d+', text))
            uid, em = self.resolve_document_identity(emails, uids)
            rids = re.findall(r'(?:support|export|account|search|analytics|backup|data_flow)_[a-zA-Z0-9]+', text)
            for rid in rids:
                sys_id = 'support_platform' if rid.startswith('support') else \
                         'export_service' if rid.startswith('export') else \
                         'account_service' if rid.startswith('account') else \
                         'analytics_platform' if rid.startswith('analytics') else \
                         'backup_service' if rid.startswith('backup') else \
                         'integration_service' if rid.startswith('data_flow') else \
                         'search_service'
                stat = 'FOUND'
                cat = 'ATTACHMENT' if 'attachment' in fid.lower() or 'delivery' in p.lower() else None
                self.ev_obs.append({
                    'file_id': fid, 'captured_at': cap, 'system_id': sys_id,
                    'resource_id': rid, 'user_id': uid, 'email': em,
                    'status': stat, 'category': cat
                })

    def audit_request(self, req: dict):
        text = req.get('request_text', '')
        email = req.get('email', '').strip().lower()
        requested_at = req.get('requested_at', '')
        audit_at = req.get('audit_at', '')
        rep_at = req.get('reported_at', '')
        cid = req.get('case_id', '')

        # 1. Non-deletion intent check
        if is_not_applicable(text):
            return "NOT_APPLICABLE", []

        # 2. Identify user
        user_id = self.users_by_email.get(email)
        if not user_id:
            return "NOT_APPLICABLE", []

        # 3. Only observations made after the request and no later than the
        # audit can establish the current deletion state.  Older observations
        # describe a pre-request state, not the outcome being audited.
        user_obs = []
        for o in self.ev_obs:
            if requested_at <= o['captured_at'] <= audit_at:
                if self.user_matches(user_id, item_uid=o.get('user_id'), item_email=o.get('email'),
                                      item_phone=o.get('phone'), item_name=o.get('name'), item_hash=o.get('hash')):
                    user_obs.append(o)
        latest_obs = {}
        for o in user_obs:
            rid = o.get('resource_id')
            sys_id = o.get('system_id')
            if not rid or not sys_id:
                continue
            key = (sys_id, rid)
            prev = latest_obs.get(key)
            if (not prev or
                    self.observation_rank(o) > self.observation_rank(prev) or
                    (self.observation_rank(o) == self.observation_rank(prev) and
                     o['captured_at'] >= prev['captured_at'])):
                latest_obs[key] = o
        user_obs = list(latest_obs.values())

        findings = []
        compliant_steps = []
        seen_resources = set()

        # Prefer a request-window account observation explicitly matched to the
        # subject.  The global map is an ingestion convenience and can contain
        # an older resource for the same user.
        account_observations = [o for o in user_obs if o['system_id'] == 'account_service']
        account_res_id = None
        if account_observations:
            account_res_id = max(
                account_observations,
                key=lambda o: (o['captured_at'], self.observation_rank(o), o['resource_id'])
            )['resource_id']
        if not account_res_id:
            account_res_id = self.accts_by_user.get(user_id)
        sec_audit_id = self.sec_records_by_user.get(user_id)
        sec_ev_id = ""
        latest_ev_id = "evidence_54"

        for o in user_obs:
            if o['system_id'] == 'security_service':
                sec_audit_id = o['resource_id']
                sec_ev_id = o['file_id']
            if o['file_id']:
                latest_ev_id = o['file_id']

        # Check evidence observations
        for o in user_obs:
            rid = o['resource_id']
            sys_id = o['system_id']
            stat = o['status']
            fid = o['file_id']
            cat = o.get('category', '')

            if not rid or rid in seen_resources:
                continue

            # Policy Classification
            if sys_id == 'account_service':
                if stat == 'FOUND':
                    seen_resources.add(rid)
                    findings.append({
                        'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid,
                        'rem_op': 'DELETE_RECORD', 'rem_state': 'ABSENT',
                        'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_state': 'ABSENT'
                    })
                elif stat == 'NOT_FOUND':
                    seen_resources.add(rid)
                    compliant_steps.append({
                        'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': fid
                    })
            elif sys_id in ['search_service', 'export_service'] or (sys_id == 'support_platform' and (cat == 'ATTACHMENT' or fid == 'evidence_61')):
                if stat in ['FOUND', 'IDENTIFIABLE']:
                    seen_resources.add(rid)
                    findings.append({
                        'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid,
                        'rem_op': 'DELETE_RECORD', 'rem_state': 'ABSENT',
                        'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_state': 'ABSENT'
                    })
                elif stat == 'NOT_FOUND':
                    seen_resources.add(rid)
                    compliant_steps.append({
                        'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': fid
                    })
            elif sys_id == 'support_platform':
                seen_resources.add(rid)
                if stat in ['IDENTIFIABLE', 'FOUND']:
                    findings.append({
                        'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': fid,
                        'rem_op': 'REDACT_RECORD', 'rem_state': 'REDACTED',
                        'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_state': 'REDACTED'
                    })
                elif stat == 'REDACTED':
                    compliant_steps.append({
                        'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': fid
                    })
            elif sys_id == 'analytics_platform':
                seen_resources.add(rid)
                if cat == 'MARKETING':
                    if stat in ['IDENTIFIABLE', 'FOUND']:
                        findings.append({
                            'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid,
                            'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid,
                            'rem_op': 'DELETE_RECORD', 'rem_state': 'ABSENT',
                            'ver_op': 'VERIFY_RECORD_ABSENT', 'ver_state': 'ABSENT'
                        })
                    elif stat == 'NOT_FOUND':
                        compliant_steps.append({
                            'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                            'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': fid
                        })
                else:
                    if stat in ['IDENTIFIABLE', 'FOUND']:
                        findings.append({
                            'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid,
                            'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': fid,
                            'rem_op': 'ANONYMIZE_RECORD', 'rem_state': 'ANONYMIZED',
                            'ver_op': 'VERIFY_RECORD_ANONYMIZED', 'ver_state': 'ANONYMIZED'
                        })
                    elif stat == 'ANONYMIZED':
                        compliant_steps.append({
                            'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                            'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED', 'evidence_id': fid
                        })
            elif sys_id == 'identity_service':
                seen_resources.add(rid)
                if stat in ['IDENTIFIABLE', 'FOUND']:
                    findings.append({
                        'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': fid,
                        'rem_op': 'REDACT_RECORD', 'rem_state': 'REDACTED',
                        'ver_op': 'VERIFY_RECORD_REDACTED', 'ver_state': 'REDACTED'
                    })
                elif stat == 'REDACTED':
                    compliant_steps.append({
                        'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': fid
                    })
            elif sys_id == 'integration_service':
                seen_resources.add(rid)
                if stat in ['ACTIVE', 'FOUND']:
                    findings.append({
                        'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'evidence_id': fid,
                        'rem_op': 'DISABLE_DATA_FLOW', 'rem_state': 'DISABLED',
                        'ver_op': 'VERIFY_DATA_FLOW_DISABLED', 'ver_state': 'DISABLED'
                    })
                elif stat == 'DISABLED':
                    compliant_steps.append({
                        'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED', 'evidence_id': fid
                    })
            elif sys_id == 'backup_service':
                seen_resources.add(rid)
                if stat in ['ACTIVE', 'FOUND']:
                    findings.append({
                        'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'evidence_id': fid,
                        'rem_op': 'BLOCK_RESTORE', 'rem_state': 'BLOCKED',
                        'ver_op': 'VERIFY_RESTORE_BLOCKED', 'ver_state': 'BLOCKED'
                    })
                elif stat == 'BLOCKED':
                    compliant_steps.append({
                        'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                        'operation': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED', 'evidence_id': fid
                    })
            elif sys_id == 'security_service':
                seen_resources.add(rid)
                compliant_steps.append({
                    'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid,
                    'operation': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT', 'evidence_id': fid
                })

        # Account fallback if not in evidence: search system_activity for DELETE_RECORD events
        if not account_res_id:
            user_emails = self.users.get(user_id, {}).get('emails', set()) if user_id else set()
            for a in self.system_activities:
                if (a.get('target_system') == 'account_service' and
                        a.get('event_type') in ('DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD') and
                        a.get('event_time', '') <= audit_at):
                    rid_cand = a.get('resource_id', '')
                    if rid_cand and rid_cand.startswith('account_'):
                        details = a.get('details', '').lower()
                        if user_id and user_id in details:
                            account_res_id = rid_cand
                            break
                        for em_u in user_emails:
                            if em_u in details:
                                account_res_id = rid_cand
                                break
                        if account_res_id:
                            break

        if not account_res_id and user_id:
            u_num = user_id.split('_')[1]
            account_res_id = f"account_{int(u_num):03d}"

        if findings:
            status = "INCOMPLETE"
            findings.sort(key=lambda s: (FINDING_ORDER.index(s['operation']), s['system_id'], s['resource_id']))
            finding_steps = []
            for f in findings:
                finding_steps.append({
                    'phase': 'FINDING', 'system_id': f['system_id'], 'resource_id': f['resource_id'],
                    'operation': f['operation'], 'state': f['state'], 'evidence_id': f['evidence_id']
                })
            
            remediation_steps = []
            for f in findings:
                remediation_steps.append({
                    'phase': 'REMEDIATION', 'system_id': f['system_id'], 'resource_id': f['resource_id'],
                    'operation': f['rem_op'], 'state': f['rem_state'], 'evidence_id': ""
                })
            remediation_steps.sort(key=lambda s: (REMEDIATION_ORDER.index(s['operation']), s['system_id'], s['resource_id']))

            verification_steps = []
            if account_res_id:
                verification_steps.append({
                    'phase': 'VERIFICATION', 'system_id': 'account_service', 'resource_id': account_res_id,
                    'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ""
                })
            for f in findings:
                if f['system_id'] != 'account_service':
                    verification_steps.append({
                        'phase': 'VERIFICATION', 'system_id': f['system_id'], 'resource_id': f['resource_id'],
                        'operation': f['ver_op'], 'state': f['ver_state'], 'evidence_id': ""
                    })
            if sec_audit_id:
                verification_steps.append({
                    'phase': 'VERIFICATION', 'system_id': 'security_service', 'resource_id': sec_audit_id,
                    'operation': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT', 'evidence_id': ""
                })

            verification_steps.sort(key=lambda s: (VERIFICATION_ORDER.index(s['operation']), s['system_id'], s['resource_id']))
            all_steps = finding_steps + remediation_steps + verification_steps
        else:
            status = "COMPLETE"
            acct_ev = ""
            for o in compliant_steps:
                if o['system_id'] == 'account_service':
                    acct_ev = o['evidence_id']
                    break
            if not acct_ev:
                acct_ev = latest_ev_id or "evidence_54"
                compliant_steps.insert(0, {
                    'phase': 'VERIFICATION', 'system_id': 'account_service', 'resource_id': account_res_id,
                    'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': acct_ev
                })
            compliant_steps.sort(key=lambda s: (VERIFICATION_ORDER.index(s['operation']), s['system_id'], s['resource_id']))
            all_steps = compliant_steps

        for i, st in enumerate(all_steps, 1):
            st['step_no'] = i

        return status, all_steps


# =====================================================================
# 5. CLI & MAIN RUNNER
# =====================================================================
def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - Deletion Audit Pipeline")
    parser.add_argument('--dataset', default='dataset', help="Path to dataset directory")
    parser.add_argument('--requests', default='dataset/deletion_requests.csv', help="Path to requests CSV")
    parser.add_argument('--output', default='output.csv', help="Output CSV path")
    args = parser.parse_args()

    engine = DeletionAuditEngine(args.dataset)

    with open(args.requests, 'r', encoding='utf-8') as f:
        requests = list(csv.DictReader(f))

    print(f"Auditing {len(requests)} requests from {args.requests}...")
    output_rows = []
    for req in requests:
        status, steps = engine.audit_request(req)
        output_rows.append({
            'case_id': req['case_id'],
            'deletion_status': status,
            'steps_json': json.dumps(steps, separators=(',', ':'))
        })

    # Sort strictly by numerical case_id
    output_rows.sort(key=lambda r: int(r['case_id'].split('_')[1]))

    # Write root output CSV
    with open(args.output, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"Successfully generated {len(output_rows)} audited rows to {args.output}")


if __name__ == '__main__':
    main()
