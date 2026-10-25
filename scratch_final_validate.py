import csv, json, collections

rows = list(csv.DictReader(open('output.csv')))
status_counts = collections.Counter(r['deletion_status'] for r in rows)
print('Total rows:', len(rows))
print('Status distribution:', dict(status_counts))

errors = 0
for r in rows:
    try:
        steps = json.loads(r['steps_json'])
        if r['deletion_status'] == 'NOT_APPLICABLE' and steps != []:
            print('BAD NA:', r['case_id'], 'has non-empty steps')
            errors += 1
        for i, st in enumerate(steps):
            for field in ['step_no','phase','system_id','resource_id','operation','state','evidence_id']:
                if field not in st:
                    print('MISSING FIELD:', r['case_id'], 'step', i+1, field)
                    errors += 1
    except Exception as e:
        print('JSON ERROR:', r['case_id'], str(e))
        errors += 1
print('Total errors:', errors)

# Sample accuracy
sample = list(csv.DictReader(open('dataset/sample_output.csv')))
pred_map = {r['case_id']: r for r in rows}
status_match = 0
exact_match = 0
for s in sample:
    p = pred_map.get(s['case_id'])
    if not p:
        continue
    if p['deletion_status'] == s['deletion_status']:
        status_match += 1
    if p['steps_json'] == s['steps_json']:
        exact_match += 1

print('Sample status accuracy: {}/{}'.format(status_match, len(sample)))
print('Sample exact step match: {}/{}'.format(exact_match, len(sample)))
