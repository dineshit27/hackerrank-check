import csv, json, collections

sample = list(csv.DictReader(open('dataset/sample_output.csv')))
pred = list(csv.DictReader(open('sample_test_output.csv')))
pred_map = {r['case_id']: r for r in pred}

# Collect all resource_id mismatches
resource_mismatches = collections.Counter()
operation_mismatches = collections.Counter()
system_mismatches = collections.Counter()

for s in sample:
    p = pred_map.get(s['case_id'])
    if not p: continue
    s_steps = json.loads(s['steps_json'])
    p_steps = json.loads(p['steps_json'])

    for i in range(min(len(s_steps), len(p_steps))):
        ss = s_steps[i]
        ps = p_steps[i]
        if ss.get('resource_id') != ps.get('resource_id'):
            resource_mismatches[(ps.get('resource_id'), ss.get('resource_id'))] += 1
        if ss.get('operation') != ps.get('operation'):
            operation_mismatches[(ps.get('operation'), ss.get('operation'))] += 1
        if ss.get('system_id') != ps.get('system_id'):
            system_mismatches[(ps.get('system_id'), ss.get('system_id'))] += 1

print('Top resource_id mismatches (got -> expected):')
for (got, exp), cnt in resource_mismatches.most_common(15):
    print(f'  {got!r} -> {exp!r}: {cnt}x')

print()
print('Top operation mismatches:')
for (got, exp), cnt in operation_mismatches.most_common(10):
    print(f'  {got!r} -> {exp!r}: {cnt}x')

print()
print('Top system_id mismatches:')
for (got, exp), cnt in system_mismatches.most_common(10):
    print(f'  {got!r} -> {exp!r}: {cnt}x')
