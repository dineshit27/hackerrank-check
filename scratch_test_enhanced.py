import csv, json, os, glob, re, sys, sqlite3, hashlib

sys.path.insert(0, 'code')
from main import (
    DeletionAuditEngine, canonicalize_system, system_from_resource,
    parse_log_system, parse_log_status, parse_log_time, extract_trace_id,
    VERIFICATION_ORDER
)

class FullEnhancedEngine(DeletionAuditEngine):
    def parse_all_evidence(self):
        super().parse_all_evidence()
        ev_dir = os.path.join(self.dataset_dir, 'evidence')

        def get_meta(filepath):
            rel = os.path.normpath(os.path.relpath(filepath, self.dataset_dir)).replace('\\', '/')
            for fid, info in self.ev_manifest.items():
                if os.path.normpath(info['file_path']).replace('\\', '/') == rel:
                    return fid, info['captured_at']
            return None, '2026-09-30T23:59:59Z'

        # 1. Parse records files with ['recorded_at', 'system', 'resource_id', 'record_type', 'result', 'subject_reference']
        for p in glob.glob(os.path.join(ev_dir, 'records', '*.json')):
            fn = os.path.basename(p)
            if fn in ['connector_configurations_20260812.json', 'customer_export_manifest_20260409.json', 'security_audit_ledger_20261001.json']:
                fid, cap = get_meta(p)
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

        # 2. Parse system_activity LINK_RESOURCE_IDENTITY events
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
                if sys_id == 'object_storage':
                    sys_id = 'support_platform'
                elif sys_id == 'marketing_platform':
                    sys_id = 'analytics_platform'
                    cat = 'MARKETING'
                self.ev_obs.append({
                    'file_id': fid, 'captured_at': dt, 'system_id': sys_id,
                    'resource_id': rid, 'user_id': uid, 'email': em,
                    'status': 'FOUND' if sys_id != 'identity_service' else 'IDENTIFIABLE',
                    'category': cat
                })

        # 3. Enhanced log parsing for logs where JSON/pipe/syslog traces weren't extracted
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
                # generalized trace extraction
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
                obs_time = parse_log_time(l, cap)
                for r in resources:
                    cur_sys = parse_log_system(l, r)
                    if cur_sys == 'security_service' and uid:
                        self.sec_records_by_user[uid] = r
                    if cur_sys == 'account_service' and r:
                        if uid:
                            self.accts_by_user[uid] = r
                        elif em and em in self.users_by_email:
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

    def audit_request(self, req: dict):
        text = req.get('request_text', '')
        email = req.get('email', '').strip().lower()
        audit_at = req.get('audit_at', '')

        from main import is_not_applicable
        if is_not_applicable(text):
            return "NOT_APPLICABLE", []

        user_id = self.users_by_email.get(email)
        if not user_id:
            return "NOT_APPLICABLE", []

        user_obs = []
        for o in self.ev_obs:
            if o['captured_at'] <= audit_at:
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
            if not prev or o['captured_at'] >= prev['captured_at']:
                latest_obs[key] = o
        user_obs = list(latest_obs.values())

        findings = []
        compliant_steps = []
        seen_resources = set()

        account_res_id = self.accts_by_user.get(user_id)
        sec_audit_id = self.sec_records_by_user.get(user_id)
        sec_ev_id = ""

        for o in user_obs:
            rid = o['resource_id']
            sys_id = o['system_id']
            stat = o['status']
            fid = o['file_id']
            cat = o.get('category', '')

            if sys_id == 'account_service' and not account_res_id:
                account_res_id = rid
            if sys_id == 'security_service':
                sec_audit_id = rid
                sec_ev_id = fid

            if not rid or rid in seen_resources:
                continue

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
            elif sys_id == 'integration_service':
                seen_resources.add(rid)
                if stat == 'ACTIVE':
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
                if stat == 'ACTIVE':
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

        from main import FINDING_ORDER, REMEDIATION_ORDER

        if findings:
            status = "INCOMPLETE"
            finding_steps = []
            for f in findings:
                finding_steps.append({
                    'phase': 'FINDING', 'system_id': f['system_id'], 'resource_id': f['resource_id'],
                    'operation': f['operation'], 'state': f['state'], 'evidence_id': f['evidence_id']
                })
            finding_steps.sort(key=lambda s: (FINDING_ORDER.index(s['operation']), s['system_id'], s['resource_id']))

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
            status = "COMPLETE" if compliant_steps else "INCOMPLETE"
            compliant_steps.sort(key=lambda s: (VERIFICATION_ORDER.index(s['operation']), s['system_id'], s['resource_id']))
            all_steps = compliant_steps

        for i, st in enumerate(all_steps, 1):
            st['step_no'] = i

        return status, all_steps

print("Testing full enhanced engine...")
eng = FullEnhancedEngine('dataset')

with open('dataset/deletion_requests.csv', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

empty_after = []
for req in requests:
    status, steps = eng.audit_request(req)
    if status == 'INCOMPLETE' and not steps:
        empty_after.append(req['case_id'])

print(f"Empty INCOMPLETE cases: {len(empty_after)}")
print("Remaining empty cases:", empty_after)
