import re, csv, hashlib

# Simulate the log parsing for evidence_94 specifically
users_by_email = {}
users = {}
with open('dataset/user_identities.csv', newline='', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        if uid not in users:
            users[uid] = {'emails': set(), 'names': set(), 'phones': set(), 'hashes': set()}
        if r.get('email'):
            em = r['email'].strip().lower()
            users[uid]['emails'].add(em)
            users_by_email[em] = uid
            users[uid]['hashes'].add(hashlib.sha256(em.encode()).hexdigest())
        if r.get('email_hash'):
            users[uid]['hashes'].add(r['email_hash'].strip().lower())

with open('dataset/user_audit_log.csv', newline='', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        uid = r['user_id']
        fn = r.get('field_name')
        if uid not in users:
            users[uid] = {'emails': set(), 'names': set(), 'phones': set(), 'hashes': set()}
        for v in [r.get('old_value'), r.get('new_value')]:
            if not v or v.lower() == 'null': continue
            if fn == 'email':
                em = v.strip().lower()
                users[uid]['emails'].add(em)
                users_by_email[em] = uid
                users[uid]['hashes'].add(hashlib.sha256(em.encode()).hexdigest())

path = 'dataset/evidence/logs/resource_lookup_trace_20260926_103856.log'
cap = '2026-09-26T10:38:56Z'
audit_at = '2026-09-26T11:00:00Z'

with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

# Replicate the trace grouping
traces = {}
standalone_lines = []
for line in lines:
    l_s = line.strip()
    if not l_s: continue
    tr_m = re.search(r'(?:trace_id|requestId|trace)=([a-zA-Z0-9_\-]+)', l_s)
    if tr_m:
        traces.setdefault(tr_m.group(1), []).append(l_s)
    else:
        standalone_lines.append(l_s)

print('Number of traces:', len(traces))
print('Standalone lines:', len(standalone_lines))

def collect_idents(text):
    return {
        'emails': [em.lower() for em in re.findall(r'[\b\s\'\"=]([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', text)],
        'user_ids': re.findall(r'[\b\s\'\"=](user_\d+)', text),
        'phones': re.findall(r'\+\d{1,3}\s(?:\d{1,4}\s)?\d{3,4}[\s\-]?\d{3,4}', text),
        'hashes': [h.lower() for h in re.findall(r'[\b\s\'\"=]([a-fA-F0-9]{64})', text)],
    }

def parse_log_status(line):
    m = re.search(r'\bresult["\s:=]+"?([A-Za-z_]+)"?', line)
    if m:
        result = m.group(1).upper()
        if result in ('NOT_FOUND', 'MISS'): return 'NOT_FOUND'
        if result in ('FOUND', 'HIT', 'PRESENT'): return 'FOUND'
    http = re.search(r'http_status["\s:=]+"?(\d+)"?', line)
    if http:
        if http.group(1) == '404': return 'NOT_FOUND'
        if http.group(1) == '200': return 'FOUND'
    rows = re.search(r'\brows["\s:=]+"?(\d+)"?', line)
    if rows:
        return 'NOT_FOUND' if rows.group(1) == '0' else 'FOUND'
    return 'FOUND'

# Target: case_03 user = l.fontaine46@yahoo.com
target_user_id = users_by_email.get('l.fontaine46@yahoo.com')
print('Target user for case_03:', target_user_id)
print('Emails:', users.get(target_user_id, {}).get('emails'))

# Simulate what the engine does for trace rb-085737-009
trace_id = 'rb-085737-009'
tlines = traces.get(trace_id, [])
print('\nTrace %s lines:' % trace_id)
for l in tlines:
    print('  %s' % l)

inherited = {'emails': [], 'user_ids': [], 'phones': [], 'hashes': []}
for l in tlines:
    got = collect_idents(l)
    for key in inherited:
        inherited[key].extend(got[key])

print('\nInherited identities:', inherited)

ev_obs = []

def emit_log_line(l, inherited_idents=None):
    resources = re.findall(r'resource_id=\\?"?([a-zA-Z0-9_]+)\\?"?', l)
    if not resources:
        return
    ident = collect_idents(l)
    if inherited_idents:
        ident = {
            'emails': ident['emails'] or inherited_idents.get('emails') or [],
            'user_ids': ident['user_ids'] or inherited_idents.get('user_ids') or [],
            'phones': ident['phones'] or inherited_idents.get('phones') or [],
            'hashes': ident['hashes'] or inherited_idents.get('hashes') or [],
        }
    if not (ident['emails'] or ident['user_ids'] or ident['phones'] or ident['hashes']):
        print('  SKIP: no idents in line: %s' % l[:100])
        return
    em = ident['emails'][0] if ident['emails'] else None
    uid = ident['user_ids'][0] if ident['user_ids'] else None
    stat = parse_log_status(l)
    obs_time_m = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)', l)
    obs_time = obs_time_m.group(1) if obs_time_m else cap
    
    # Check if this user matches our target
    user_em = em
    matched_uid = uid if uid else (users_by_email.get(user_em) if user_em else None)
    
    for r in resources:
        ev_obs.append({
            'file_id': 'evidence_94', 'captured_at': obs_time, 'system_id': 'account_service',
            'resource_id': r, 'user_id': uid, 'email': em, 'status': stat
        })
        print('  OBS: resource=%s uid=%s em=%s status=%s time=%s' % (r, uid, em, stat, obs_time))

for l in tlines:
    emit_log_line(l, inherited)

print('\nAll observations from trace %s:' % trace_id)
for o in ev_obs:
    print('  %s' % o)

# Now check what happens when we filter for user_03
print('\nFiltering for user:', target_user_id)
user_target = target_user_id
u_data = users.get(user_target, {})

def user_matches(obs):
    if obs.get('user_id') and obs.get('user_id') == user_target: return True
    if obs.get('email') and obs.get('email') in u_data.get('emails', set()): return True
    return False

user_obs = [o for o in ev_obs if o['captured_at'] <= audit_at and user_matches(o)]
print('Matching user obs:', user_obs)

# Latest per resource
latest = {}
for o in user_obs:
    key = (o['system_id'], o['resource_id'])
    if not latest.get(key) or o['captured_at'] >= latest[key]['captured_at']:
        latest[key] = o

print('Latest obs per resource:', list(latest.values()))
