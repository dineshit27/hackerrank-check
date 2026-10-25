"""Check expected steps for cases 21 and 25 from sample_output.csv"""
import csv, json

rows = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
for r in rows:
    if r['case_id'] in ['case_21', 'case_25', 'case_26', 'case_27', 'case_28']:
        steps = json.loads(r['steps_json'])
        print('=' * 60)
        print(r['case_id'], r['deletion_status'])
        for s in steps:
            print(' ', s)
