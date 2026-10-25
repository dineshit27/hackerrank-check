import csv
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = list(csv.DictReader(f))

audit_times = sorted(list(set(r['audit_at'] for r in requests)))
print(f"Total unique audit_at values in deletion_requests: {len(audit_times)}")

ev_by_time = {}
for ef in ev_files:
    cap = ef['captured_at']
    if cap not in ev_by_time:
        ev_by_time[cap] = []
    ev_by_time[cap].append(ef)

for at in audit_times:
    # find evidence files captured at or immediately before at
    exact = ev_by_time.get(at, [])
    # also find any evidence within 2 hours before at
    before = [ef for ef in ev_files if ef['captured_at'] <= at]
    latest_before = max(ef['captured_at'] for ef in before) if before else None
    latest_efs = [ef['file_id'] + f"({ef['origin']})" for ef in ev_files if ef['captured_at'] == latest_before]
    print(f"audit_at: {at} -> exact: {[ef['file_id'] for ef in exact]}, latest <= audit_at ({latest_before}): {latest_efs}")
