"""
Full audit: compare current pipeline output against sample_output.csv
Reports per-case mismatches in detail for root cause analysis.
"""
import csv, json, sys

PY = "C:\\Users\\dinesh\\AppData\\Local\\Programs\\Python\\Python310\\python.exe"

sample = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
pred = list(csv.DictReader(open('sample_test_output.csv', encoding='utf-8')))
pred_map = {r['case_id']: r for r in pred}

FIELDS = ['step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id']

status_match = 0
step_count_match = 0
full_step_match = 0
total_step_field_match = 0
total_step_fields = 0

mismatches = []

for s in sample:
    cid = s['case_id']
    p = pred_map.get(cid)
    if not p:
        mismatches.append((cid, 'MISSING', None, None))
        continue

    s_status = s['deletion_status']
    p_status = p['deletion_status']
    s_steps = json.loads(s['steps_json'])
    p_steps = json.loads(p['steps_json'])

    status_ok = (s_status == p_status)
    if status_ok:
        status_match += 1

    step_count_ok = (len(s_steps) == len(p_steps))
    if step_count_ok:
        step_count_match += 1

    # Compare step fields pairwise
    all_fields_ok = True
    field_diffs = []
    for i, (ss, ps) in enumerate(zip(s_steps, p_steps)):
        for f in FIELDS:
            total_step_fields += 1
            sv = ss.get(f)
            pv = ps.get(f)
            if sv == pv:
                total_step_field_match += 1
            else:
                all_fields_ok = False
                field_diffs.append((i+1, f, sv, pv))

    if all_fields_ok and step_count_ok:
        full_step_match += 1

    if not status_ok or not step_count_ok or field_diffs:
        mismatches.append((cid, s_status, p_status, s_steps, p_steps, field_diffs, step_count_ok))

print("=" * 70)
print("SUMMARY")
print("=" * 70)
print("Status accuracy:     {}/{} ({:.1f}%)".format(status_match, len(sample), 100*status_match/len(sample)))
print("Step count match:    {}/{} ({:.1f}%)".format(step_count_match, len(sample), 100*step_count_match/len(sample)))
print("Full step match:     {}/{} ({:.1f}%)".format(full_step_match, len(sample), 100*full_step_match/len(sample)))
print("Step field accuracy: {}/{} ({:.1f}%)".format(total_step_field_match, total_step_fields, 100*total_step_field_match/total_step_fields if total_step_fields else 0))
print()

print("=" * 70)
print("MISMATCHES")
print("=" * 70)
for m in mismatches:
    cid = m[0]
    if m[1] == 'MISSING':
        print(f"\n{cid}: MISSING from predictions")
        continue
    cid, s_status, p_status, s_steps, p_steps, field_diffs, step_count_ok = m
    print(f"\n{cid}: expected_status={s_status} got={p_status} expected_steps={len(s_steps)} got_steps={len(p_steps)}")
    if field_diffs:
        for (step_i, field, expected, got) in field_diffs[:5]:  # show first 5 diffs
            print(f"  step {step_i} field={field}: expected={expected!r} got={got!r}")
        if len(field_diffs) > 5:
            print(f"  ... and {len(field_diffs)-5} more field diffs")
    # Show expected steps for context
    print(f"  EXPECTED steps:")
    for ss in s_steps:
        print(f"    {ss}")
    print(f"  GOT steps:")
    for ps in p_steps:
        print(f"    {ps}")
