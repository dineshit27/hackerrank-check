import csv

with open('dataset/user_identities.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if 'mori.ren' in r['email'] or 'akosua.gyasi' in r['email']:
            print(r)
