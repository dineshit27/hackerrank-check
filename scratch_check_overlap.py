import csv, json

sample = list(csv.DictReader(open('dataset/sample_output.csv')))
pred_rows = list(csv.DictReader(open('sample_test_output.csv'))) if __import__('os').path.exists('sample_test_output.csv') else []

sample_ids = [r['case_id'] for r in sample]
print('Sample IDs:', sample_ids[:5], '...', sample_ids[-3:])

pred_ids = [r['case_id'] for r in pred_rows]
print('Pred IDs from sample_test_output.csv:', pred_ids[:5] if pred_ids else 'FILE NOT FOUND')

output_rows = list(csv.DictReader(open('output.csv')))
output_ids = {r['case_id'] for r in output_rows}
overlap = [sid for sid in sample_ids if sid in output_ids]
print(f'Overlap between sample and output.csv: {len(overlap)}/{len(sample_ids)}')

if overlap:
    pred_map = {r['case_id']: r for r in output_rows}
    status_match = sum(1 for s in sample if pred_map.get(s['case_id'], {}).get('deletion_status') == s['deletion_status'])
    print(f'Status accuracy on overlapping: {status_match}/{len(overlap)}')
