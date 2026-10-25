"""
Trace how evidence_92 is parsed by the current engine.
Show what observations are generated for each user.
"""
import sys
sys.path.insert(0, 'code')

# Monkey-patch to trace what ev_obs get added for evidence_92
import csv, json, os, glob, sqlite3, hashlib, re, base64

# Load evidence manifest
ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

ev92 = ev_manifest['evidence_92']
fid = 'evidence_92'
cap = ev92['captured_at']

p = os.path.join('dataset', ev92['file_path'])
print("File:", p, "| Captured:", cap)

with open(p, encoding='utf-8') as f:
    d = json.load(f)

sexp = d.get('service_exports', {})

obs_generated = []

# Simulate current engine parsing for service_resource_export
for svc, records in sexp.items():
    if isinstance(records, list):
        for r in records:
            rid = r.get('resource_id')
            uid = r.get('customer_reference')
            em = r.get('owner_email') or r.get('customer_email')
            ph = r.get('owner_phone')
            obs_generated.append({'fid': fid, 'svc': svc, 'rid': rid, 'uid': uid, 'em': em})
    elif isinstance(records, dict):
        for subsection, subrecs in records.items():
            if isinstance(subrecs, list):
                for r in subrecs:
                    if isinstance(r, dict):
                        rid = r.get('resource_id')
                        # nested hits structure (search)
                        if 'hits' in r:
                            for doc in r.get('hits', {}).get('documents', []):
                                rid2 = doc.get('resource_id')
                                em2 = doc.get('email')
                                uid2 = doc.get('customer_reference')
                                obs_generated.append({'fid': fid, 'svc': svc+'.'+subsection+'.hit', 'rid': rid2, 'uid': uid2, 'em': em2})
                        else:
                            uid = r.get('customer_reference') or r.get('subject_reference')
                            em = r.get('email') or r.get('owner_email') or r.get('customer_email') or r.get('requester_email')
                            profile = r.get('profile')
                            if isinstance(profile, dict):
                                em = em or profile.get('email')
                                uid = uid or profile.get('customer_reference')
                            obs_generated.append({'fid': fid, 'svc': svc+'.'+subsection, 'rid': rid, 'uid': uid, 'em': em})

print(f"\nTotal observations from evidence_92: {len(obs_generated)}")
for o in obs_generated:
    print(f"  {o['svc']:40s} rid={o['rid']:20s} uid={str(o['uid']):15s} em={o['em']}")
