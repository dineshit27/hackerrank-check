import csv, json, re

# Check what resource_ids appear in sample_output for accounts
sample = list(csv.DictReader(open('dataset/sample_output.csv')))
for s in sample[:10]:
    steps = json.loads(s['steps_json'])
    acct_steps = [st for st in steps if st.get('system_id') == 'account_service']
    if acct_steps:
        print(s['case_id'], s['deletion_status'], [st['resource_id'] for st in acct_steps])
