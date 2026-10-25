import csv, json

sample = list(csv.DictReader(open('dataset/sample_output.csv')))
pred = list(csv.DictReader(open('sample_test_output.csv')))

pred_map = {r['case_id']: r for r in pred}
status_match = 0
exact_match = 0
mismatches = []

for s in sample:
    p = pred_map.get(s['case_id'])
    if not p:
        print('MISSING:', s['case_id'])
        continue
    sm = p['deletion_status'] == s['deletion_status']
    em = p['steps_json'] == s['steps_json']
    if sm:
        status_match += 1
    if em:
        exact_match += 1
    else:
        mismatches.append((s['case_id'], s['deletion_status'], p['deletion_status']))

print('Sample status accuracy: {}/{} ({:.1f}%)'.format(status_match, len(sample), 100*status_match/len(sample)))
print('Sample exact step match: {}/{} ({:.1f}%)'.format(exact_match, len(sample), 100*exact_match/len(sample)))
print()
print('Status mismatches:')
for cid, expected, got in mismatches:
    if expected != got:
        print(f'  {cid}: expected={expected}, got={got}')
