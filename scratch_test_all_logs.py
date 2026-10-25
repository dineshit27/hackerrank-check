import os
import re
import glob
import csv
import sys

sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    ev_files = {r['file_path']: r for r in csv.DictReader(f)}

log_files = glob.glob('dataset/evidence/logs/*.log')
print(f"Total log files: {len(log_files)}")

total_obs = 0
for lp in sorted(log_files):
    rel_p = os.path.normpath(os.path.relpath(lp, 'dataset')).replace('\\', '/')
    ev_info = ev_files.get(rel_p, {})
    fid = ev_info.get('file_id', os.path.basename(lp))
    cap_time = ev_info.get('captured_at', '2026-09-30T23:59:59Z')

    with open(lp, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    # Group by trace_id / requestId
    traces = {}
    standalone_lines = []
    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue
        tr_match = re.search(r'(?:trace_id|requestId|trace)=([a-zA-Z0-9_\-]+)', line_s)
        if tr_match:
            tid = tr_match.group(1)
            traces.setdefault(tid, []).append(line_s)
        else:
            standalone_lines.append(line_s)

    file_obs = 0
    # Process traces
    for tid, tlines in traces.items():
        # find user identifiers
        emails = set()
        user_ids = set()
        phones = set()
        resources = []
        systems = set()
        results = []

        for l in tlines:
            # find system/service
            sys_m = re.search(r'(?:service|function|system)=([a-zA-Z0-9_]+)', l) or re.search(r'\[([a-zA-Z0-9_]+_service|[a-zA-Z0-9_]+_platform)\]', l)
            if sys_m:
                systems.add(sys_m.group(1))

            # find emails
            for em in re.findall(r'[\b\s\'\"=]([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', l):
                emails.add(em)
            # find user_ids
            for u in re.findall(r'[\b\s\'\"=](user_\d+)', l):
                user_ids.add(u)
            # find resources
            for r in re.findall(r'(?:resource_id)=([a-zA-Z0-9_]+)', l) or re.findall(r'resource_id=\"([^\"]+)\"', l):
                if r not in resources:
                    resources.append(r)
            # check status clues
            if 'http_status=404' in l or 'http_status="404"' in l or 'rows=0' in l or 'rows="0"' in l or 'result=miss' in l or 'result="miss"' in l or 'result="NOT_FOUND"' in l:
                results.append('NOT_FOUND')
            elif 'http_status=200' in l or 'http_status="200"' in l or 'rows=1' in l or 'rows="1"' in l or 'result=hit' in l or 'result="hit"' in l or 'result="FOUND"' in l:
                results.append('FOUND')

        if resources and (emails or user_ids):
            file_obs += len(resources)
            # print sample
            # print(f"  [{fid}] trace {tid}: sys={systems}, res={resources}, emails={emails}, users={user_ids}, res_stat={results}")

    # Process standalone lines
    for l in standalone_lines:
        res_m = re.findall(r'resource_id=([a-zA-Z0-9_]+)', l) or re.findall(r'resource_id="([^"]+)"', l)
        em_m = re.findall(r'[\b\s\'"=]([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', l)
        u_m = re.findall(r'[\b\s\'"=](user_\d+)', l)
        if res_m and (em_m or u_m):
            file_obs += len(res_m)

    total_obs += file_obs
    print(f"{fid} ({os.path.basename(lp)}): {file_obs} correlated observations")

print(f"\nTotal correlated observations from all logs: {total_obs}")
