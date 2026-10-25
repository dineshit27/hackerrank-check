import csv
import datetime
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Load requests
with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

# Load activities
with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

# Parse activity times
parsed_acts = []
for a in activities:
    t = datetime.datetime.fromisoformat(a['event_time'].replace('Z', '+00:00'))
    parsed_acts.append((t, a))

# For each request, find activities within [requested_at, reported_at + 1 hour]
cases_with_acts = 0
for r in requests[:30]:
    t_req = datetime.datetime.fromisoformat(r['requested_at'].replace('Z', '+00:00'))
    t_rep = datetime.datetime.fromisoformat(r['reported_at'].replace('Z', '+00:00'))
    nearby = [a for (t, a) in parsed_acts if t_req <= t <= t_rep + datetime.timedelta(hours=2)]
    # filter by deletion_worker
    worker_acts = [a for a in nearby if a['source_system'] == 'deletion_worker']
    if worker_acts:
        cases_with_acts += 1
    print(f"{r['case_id']} ({r['email']}): {len(worker_acts)} deletion worker acts around reported_at ({r['reported_at']})")
    for wa in worker_acts[:5]:
        print(f"   {wa['event_time']} | {wa['target_system']} | {wa['resource_id']} | {wa['event_type']} | {wa['reported_result']}")
