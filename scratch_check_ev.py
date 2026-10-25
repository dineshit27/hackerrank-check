import csv

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = {r['file_id']: r for r in csv.DictReader(f)}

sample_evs = ['evidence_54', 'evidence_56', 'evidence_57', 'evidence_58', 'evidence_59', 'evidence_94', 'evidence_93', 'evidence_01', 'evidence_03', 'evidence_92', 'evidence_51']
for eid in sample_evs:
    print(eid, ev_files.get(eid))
