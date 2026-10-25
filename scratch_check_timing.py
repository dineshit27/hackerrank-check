import csv
import json
import datetime
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    sample_outs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

# For each sample, check the steps in sample_output
for cid, req in list(sample_reqs.items())[:10]:
    out = sample_outs.get(cid)
    steps = json.loads(out['steps_json']) if out else []
    step_res = [st['resource_id'] for st in steps]
    rep_at = req['reported_at']
    req_at = req['requested_at']
    print(f"\n{cid}: requested_at={req_at}, reported_at={rep_at}")
    print(f"  Expected resources: {step_res}")
    
    # Check activities within 48h before reported_at
    # parse time
    t_rep = datetime.datetime.fromisoformat(rep_at.replace('Z', '+00:00'))
    t_req = datetime.datetime.fromisoformat(req_at.replace('Z', '+00:00'))
    
    nearby_acts = []
    for a in activities:
        t_act = datetime.datetime.fromisoformat(a['event_time'].replace('Z', '+00:00'))
        if t_req <= t_act <= t_rep:
            if a['source_system'] == 'deletion_worker' or 'DELETE' in a['event_type'] or 'CHECK' in a['event_type'] or 'ANONYMIZE' in a['event_type'] or 'REDACT' in a['event_type']:
                nearby_acts.append(a)
    print(f"  Activities between requested_at and reported_at ({len(nearby_acts)}):")
    for a in nearby_acts[:10]:
        print(f"    {a['event_time']} | {a['event_type']} | {a['source_system']}->{a['target_system']} | res={a['resource_id']} | res={a['reported_result']}")
