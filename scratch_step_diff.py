import csv, json

sample = list(csv.DictReader(open('dataset/sample_output.csv')))
pred = list(csv.DictReader(open('sample_test_output.csv')))
pred_map = {r['case_id']: r for r in pred}

step_field_matches = 0
step_field_total = 0
step_count_match = 0

for s in sample:
    p = pred_map.get(s['case_id'])
    if not p: continue
    s_steps = json.loads(s['steps_json'])
    p_steps = json.loads(p['steps_json'])

    if len(s_steps) == len(p_steps):
        step_count_match += 1

    for i, (ss, ps) in enumerate(zip(s_steps, p_steps)):
        for field in ['phase', 'system_id', 'resource_id', 'operation', 'state']:
            step_field_total += 1
            if ss.get(field) == ps.get(field):
                step_field_matches += 1

print(f'Step count match: {step_count_match}/{len(sample)}')
print(f'Step field match (excl evidence): {step_field_matches}/{step_field_total} ({100*step_field_matches/step_field_total:.1f}%)')

# Show first mismatch in detail
print()
for s in sample[:5]:
    p = pred_map.get(s['case_id'])
    if not p: continue
    s_steps = json.loads(s['steps_json'])
    p_steps = json.loads(p['steps_json'])
    if s_steps != p_steps:
        print(f'=== {s["case_id"]} ===')
        print('EXPECTED:', json.dumps(s_steps[:2], indent=2))
        print('GOT:', json.dumps(p_steps[:2], indent=2))
        break
