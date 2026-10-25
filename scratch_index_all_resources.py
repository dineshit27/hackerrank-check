import csv
import json
import os
import sqlite3
import glob
import re
import sys
sys.stdout.reconfigure(encoding='utf-8')

resource_to_info = {}

def add_res(rid, system_id=None, user_id=None, email=None, phone=None, name=None, category=None):
    if not rid:
        return
    if rid not in resource_to_info:
        resource_to_info[rid] = {
            'system_id': system_id,
            'user_ids': set(),
            'emails': set(),
            'phones': set(),
            'names': set(),
            'categories': set()
        }
    info = resource_to_info[rid]
    if system_id and not info['system_id']:
        info['system_id'] = system_id
    if user_id:
        info['user_ids'].add(user_id)
    if email:
        info['emails'].add(email.lower())
    if phone:
        info['phones'].add(phone)
    if name:
        info['names'].add(name)
    if category:
        info['categories'].add(category)

# 1. Scan all snapshot bundles
for p in glob.glob('dataset/evidence/records/customer_data_snapshot_bundle_*.json'):
    try:
        with open(p, 'r', encoding='utf-8') as f:
            d = json.load(f)
        for s in d.get('snapshots', []):
            sys_id = s.get('data_store')
            col = s.get('collection')
            for r in s.get('records', []):
                rid = r.get('resource_id')
                uid = r.get('customer_reference') or r.get('subject_reference') or r.get('user_id')
                em = r.get('email') or r.get('requester_email') or r.get('owner_email')
                ph = r.get('phone') or r.get('requester_phone')
                nm = r.get('full_name') or r.get('name') or r.get('requester_name')
                add_res(rid, system_id=sys_id, user_id=uid, email=em, phone=ph, name=nm, category=col)
    except Exception as e:
        pass

# 2. Scan all service_resource_export JSON files
for p in glob.glob('dataset/evidence/records/service_resource_export_*.json'):
    try:
        with open(p, 'r', encoding='utf-8') as f:
            d = json.load(f)
        sexp = d.get('service_exports', {})
        # account_service
        for r in sexp.get('account_service', {}).get('profile_lookups', []):
            rid = r.get('resource_id')
            prof = r.get('profile') or {}
            add_res(rid, system_id='account_service', user_id=prof.get('customer_reference'), email=prof.get('email'), phone=prof.get('phone'), name=prof.get('full_name'))
        # analytics_platform
        for r in sexp.get('analytics_platform', {}).get('profiles', []):
            rid = r.get('resource_id')
            add_res(rid, system_id='analytics_platform', user_id=r.get('customer_reference'), email=r.get('email'), phone=r.get('phone'))
        # backup_service
        for r in sexp.get('backup_service', {}).get('restore_entries', []):
            rid = r.get('resource_id')
            add_res(rid, system_id='backup_service', user_id=r.get('customer_reference'), email=r.get('customer_email'))
        # export_service
        for r in sexp.get('export_service', {}).get('exports', []):
            rid = r.get('resource_id')
            add_res(rid, system_id='export_service', user_id=r.get('customer_reference'), email=r.get('owner_email'))
        # integration_service
        for r in sexp.get('integration_service', {}).get('connectors', []):
            rid = r.get('resource_id')
            add_res(rid, system_id='integration_service', user_id=r.get('customer_reference'), email=r.get('customer_email'))
        # search_service
        for r in sexp.get('search_service', {}).get('index_queries', []):
            rid = r.get('resource_id')
            q = r.get('query')
            hits = r.get('hits', {}).get('documents', [])
            doc_em = hits[0].get('email') if hits else None
            doc_uid = hits[0].get('customer_reference') if hits else None
            add_res(rid, system_id='search_service', user_id=doc_uid, email=doc_em or q)
        # security_service
        for r in sexp.get('security_service', {}).get('audit_records', []):
            rid = r.get('resource_id')
            add_res(rid, system_id='security_service', user_id=r.get('subject_reference'))
        # support_platform
        for r in sexp.get('support_platform', {}).get('tickets', []):
            rid = r.get('resource_id')
            add_res(rid, system_id='support_platform', user_id=r.get('customer_reference'), email=r.get('requester_email'), phone=r.get('requester_phone'), name=r.get('requester_name'))
    except Exception as e:
        pass

# 3. Scan all readback logs (resource_lookup_trace_*.log)
for p in glob.glob('dataset/evidence/logs/resource_lookup_trace_*.log'):
    try:
        with open(p, 'r', encoding='utf-8') as f:
            for line in f:
                parts = dict(re.findall(r'(\w+)=([^\s]+)', line))
                rid = parts.get('resource_id')
                svc = parts.get('service')
                lk = parts.get('lookup_key')
                uid = parts.get('customer_reference') or parts.get('subject_reference')
                if lk and lk.startswith('user_'):
                    uid = uid or lk
                em = parts.get('email') or parts.get('customer_email') or parts.get('owner_email')
                if lk and '@' in lk:
                    em = em or lk
                if rid:
                    add_res(rid, system_id=svc, user_id=uid if uid != 'null' else None, email=em if em != 'null' else None)
    except Exception as e:
        pass

# 4. Scan customer_account_handover_20261001.txt
if os.path.exists('dataset/evidence/records/customer_account_handover_20261001.txt'):
    with open('dataset/evidence/records/customer_account_handover_20261001.txt', 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('- '):
                # - timestamp | service | resource_id | category | status | identifier
                parts = [p.strip() for p in line[2:].split('|')]
                if len(parts) >= 6:
                    ts, svc, rid, cat, stat, ident = parts[:6]
                    uid = ident if ident.startswith('user_') else None
                    em = ident if '@' in ident else None
                    add_res(rid, system_id=svc, user_id=uid, email=em, category=cat)

# 5. Scan all SQL files (including failover, primary search, inventory, replicas)
for p in glob.glob('dataset/evidence/databases/*.sql'):
    try:
        con = sqlite3.connect(':memory:')
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            con.executescript(f.read())
        cur = con.cursor()
        tbls = [t[0] for t in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for t in tbls:
            cols = [c[1] for c in cur.execute(f"PRAGMA table_info({t})").fetchall()]
            rows = cur.execute(f"SELECT * FROM {t}").fetchall()
            for row in rows:
                row_dict = dict(zip(cols, row))
                rid = row_dict.get('resource_id')
                sys_id = row_dict.get('system_id')
                uid = row_dict.get('user_id') or row_dict.get('customer_reference') or row_dict.get('subject_reference')
                em = row_dict.get('email') or row_dict.get('owner_email') or row_dict.get('requester_email')
                ph = row_dict.get('phone') or row_dict.get('requester_phone')
                nm = row_dict.get('full_name') or row_dict.get('display_name') or row_dict.get('name') or row_dict.get('requester_name')
                payload_str = row_dict.get('payload')
                if payload_str:
                    try:
                        pl = json.loads(payload_str)
                        uid = uid or pl.get('customer_reference') or pl.get('subject_reference') or pl.get('user_id')
                        em = em or pl.get('email') or pl.get('owner_email') or pl.get('requester_email') or pl.get('subject_selector')
                        doc = pl.get('document', {})
                        if isinstance(doc, dict):
                            em = em or doc.get('email')
                            uid = uid or doc.get('customer_reference')
                    except Exception:
                        pass
                if 'customer_profiles' in t:
                    sys_id = sys_id or 'account_service'
                elif 'search' in t:
                    sys_id = sys_id or 'search_service'
                if rid:
                    add_res(rid, system_id=sys_id, user_id=uid, email=em, phone=ph, name=nm, category=t)
    except Exception as e:
        pass

# 6. Scan service_events logs (e.g. evidence_01, evidence_06, etc.)
for p in glob.glob('dataset/evidence/logs/service_events_*.log'):
    try:
        with open(p, 'r', encoding='utf-8') as f:
            for line in f:
                parts = dict(re.findall(r'(\w+)=([^\s]+)', line))
                rid = parts.get('resource_id')
                svc = parts.get('service')
                mk = parts.get('match_key') or parts.get('lookup_key')
                em = parts.get('email') or parts.get('customer_email')
                if mk and '@' in mk:
                    em = em or mk.strip('"')
                uid = parts.get('customer_reference') or parts.get('subject_reference')
                if mk and mk.startswith('user_'):
                    uid = uid or mk.strip('"')
                if rid:
                    add_res(rid, system_id=svc, user_id=uid if uid != 'null' else None, email=em if em != 'null' else None)
    except Exception as e:
        pass

# 7. Scan system_activity.csv
with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        rid = r.get('resource_id')
        tgt = r.get('target_system')
        src = r.get('source_system')
        sys_id = tgt if tgt != 'deletion_worker' else src
        add_res(rid, system_id=sys_id)

print(f"Total mapped resources: {len(resource_to_info)}")
with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    sample_outs = list(csv.DictReader(f))

found_count = 0
total_sample_res = set()
for s in sample_outs:
    steps = json.loads(s['steps_json'])
    for st in steps:
        total_sample_res.add(st['resource_id'])

missing = []
for r in total_sample_res:
    if r in resource_to_info:
        found_count += 1
    else:
        missing.append(r)

print(f"Sample resources found: {found_count} / {len(total_sample_res)}")
if missing:
    print("Remaining missing:", missing)
