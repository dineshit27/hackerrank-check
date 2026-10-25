import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence/logs/service_events_ap_south_20260915.log', encoding='utf-8') as f:
    lines = f.readlines()

traces = {}
for line in lines:
    tr = re.search(r'trace_id=([a-zA-Z0-9_\-]+)', line)
    if not tr:
        continue
    tid = tr.group(1)
    if tid not in traces:
        traces[tid] = {'emails': [], 'users': [], 'resources': [], 'lines': []}
    
    # check email or subject
    for m in re.finditer(r'(?:match_key|subject_key|lookup_key|scan_key|correlation_key|matched_value)="([^"]+)"', line):
        val = m.group(1)
        if '@' in val:
            traces[tid]['emails'].append(val)
    # check subject_ref
    for m in re.finditer(r'subject_ref="([^"]+)"', line):
        traces[tid]['users'].append(m.group(1))
    # check resource_id
    for m in re.finditer(r'resource_id=([a-zA-Z0-9_\-]+)', line):
        traces[tid]['resources'].append(m.group(1))
    traces[tid]['lines'].append(line.strip())

print('Total traces:', len(traces))
for tid, data in list(traces.items())[:15]:
    print(f'Trace {tid}: emails={data["emails"]}, users={data["users"]}, res={data["resources"]}')
