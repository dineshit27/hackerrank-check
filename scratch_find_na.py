import csv
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

# Let's inspect all unique patterns or classify request_text
deletion_indicators = [
    'delet', 'eras', 'remov', 'clos', 'suppress', 'eliminar', 'supprim', 
    '削除', 'lösch', 'exclus', 'cancella', 'borrar', 'apagar', 'verwijder',
    'slett', 'poist', 'odstran', 'töröl', 'usun', 'usuni', 'usuń',
    'izbris', 'smaz', 'törl', 'destroy', 'wipe', 'purge'
]

# Non-deletion indicators
access_indicators = ['access', 'copy', 'export', 'download', 'portability', 'what data', 'categories of data']
optout_indicators = ['unsubscribe', 'opt-out', 'opt out', 'newsletter', 'marketing emails']
rectify_indicators = ['correct', 'rectify', 'update my', 'change my']

na_cases = []
for r in requests:
    text = r['request_text'].lower()
    has_del = any(w in text for w in deletion_indicators)
    # Also check Korean/Japanese/etc. characters for delete
    # Japanese: 削除 (sakujo)
    # Korean: 삭제 (sakje)
    # Chinese: 删除 (shanchu)
    if '삭제' in r['request_text'] or '削除' in r['request_text'] or '删除' in r['request_text']:
        has_del = True
    if not has_del:
        na_cases.append(r)

print(f"Total non-deletion cases found: {len(na_cases)}")
for r in na_cases:
    print(f"{r['case_id']}: {r['request_text']}")
