import csv, json

with open('sample_test_output.csv', newline='', encoding='utf-8') as f:
    my = {r['case_id']: r for r in csv.DictReader(f)}
with open('dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    ref = {r['case_id']: r for r in csv.DictReader(f)}

status_match = 0
cases_w_steps = 0
step_mismatches = []

for cid in sorted(ref.keys()):
    r = ref[cid]
    m = my.get(cid, {})
    
    status_ok = m.get('deletion_status') == r.get('deletion_status')
    if status_ok:
        status_match += 1
    else:
        print('STATUS MISMATCH %s: mine=%s ref=%s' % (cid, m.get('deletion_status'), r.get('deletion_status')))
    
    ref_steps = json.loads(r.get('steps_json', '[]'))
    my_steps = json.loads(m.get('steps_json', '[]'))
    if my_steps:
        cases_w_steps += 1
    
    if ref_steps and not my_steps:
        step_mismatches.append('%s: ref has %d steps, mine has 0' % (cid, len(ref_steps)))
    elif len(ref_steps) != len(my_steps):
        step_mismatches.append('%s: ref has %d steps, mine has %d' % (cid, len(ref_steps), len(my_steps)))
    else:
        for i, (rs, ms) in enumerate(zip(ref_steps, my_steps)):
            diff = {}
            for k in set(list(rs.keys()) + list(ms.keys())):
                if rs.get(k) != ms.get(k):
                    diff[k] = (rs.get(k), ms.get(k))
            if diff:
                step_mismatches.append('%s step %d: %s' % (cid, i+1, diff))

print('Status match: %d/%d' % (status_match, len(ref)))
print('Cases with steps: %d/%d' % (cases_w_steps, len(ref)))
print('Step mismatches: %d' % len(step_mismatches))
for msg in step_mismatches[:40]:
    print('  ' + msg)
