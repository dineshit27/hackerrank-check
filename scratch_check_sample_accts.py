import csv
import json
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Load sample outputs and check where each account_XXXX came from
with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    samples = list(csv.DictReader(f))

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    sample_reqs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

# Check for each sample case: what was the account_id in sample_output?
for s in samples:
    cid = s['case_id']
    req = sample_reqs[cid]
    steps = json.loads(s['steps_json'])
    acct_steps = [st for st in steps if st['system_id'] == 'account_service']
    if acct_steps:
        acct_id = acct_steps[0]['resource_id']
        # Find all activities with this acct_id
        acts = [a for a in activities if a['resource_id'] == acct_id]
        print(f"{cid} ({req['email']}): acct_id={acct_id}, found in {len(acts)} acts. First act: {acts[0]['event_time'] if acts else 'NONE'}")
