import csv

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        if row['deletion_status'] == 'NOT_APPLICABLE':
            print("Found NOT_APPLICABLE:", row)
