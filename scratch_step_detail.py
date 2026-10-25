import csv, json

# Study the reference output patterns to understand what's missing
with open('dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    ref = {r['case_id']: r for r in csv.DictReader(f)}

with open('sample_test_output.csv', newline='', encoding='utf-8') as f:
    my = {r['case_id']: r for r in csv.DictReader(f)}

# Cases with wrong step count - print full details
problem_cases = ['case_03', 'case_06', 'case_07', 'case_08', 'case_09', 'case_10',
                 'case_18', 'case_20', 'case_21', 'case_22', 'case_23', 'case_25',
                 'case_26', 'case_27', 'case_28', 'case_29', 'case_30', 'case_31', 'case_32']

for cid in problem_cases:
    r = ref[cid]
    m = my.get(cid, {})
    ref_steps = json.loads(r.get('steps_json', '[]'))
    my_steps = json.loads(m.get('steps_json', '[]'))
    print('=== %s (ref=%d, mine=%d) ===' % (cid, len(ref_steps), len(my_steps)))
    print('REF:')
    for s in ref_steps:
        print('  %s %s/%s/%s [%s]' % (s['step_no'], s['phase'], s['system_id'], s['resource_id'], s['evidence_id']))
    print('MINE:')
    for s in my_steps:
        print('  %s %s/%s/%s [%s]' % (s['step_no'], s['phase'], s['system_id'], s['resource_id'], s['evidence_id']))
    print()
