import csv, json

# Deep analysis of each sample case
sample = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
sample_reqs = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
req_map = {r['case_id']: r for r in sample_reqs}

print('Per-case detail:')
for s in sample:
    req = req_map.get(s['case_id'], {})
    steps = json.loads(s['steps_json'])
    systems = list(dict.fromkeys([st['system_id'] for st in steps]))
    ops = list(dict.fromkeys([st['operation'] for st in steps]))
    evids = [st['evidence_id'] for st in steps if st['evidence_id']]
    rids = list(dict.fromkeys([st['resource_id'] for st in steps]))
    line = '{} | {} | steps={} | sys={} | rids={} | evids={}'.format(
        s['case_id'], s['deletion_status'], len(steps), systems, rids, evids
    )
    print(line)
