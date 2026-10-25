import csv

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

print(f"Total requests: {len(requests)}")

# Check for non-deletion keywords in requests
non_deletion_keywords = [
    'access', 'export', 'download', 'copy', 'rectify', 'correct', 'update',
    'marketing', 'unsubscribe', 'opt-out', 'opt out', 'newsletter', 'promotional',
    'information', 'category', 'categories'
]

potential_na = []
for r in requests:
    text = r['request_text'].lower()
    # Check if text does NOT mention delete, erase, remove, close, suppression, eliminar, etc.
    delete_words = ['delete', 'erasure', 'erase', 'remove', 'close', 'suppression', 'eliminar', 'supprimer', '削除', 'lösch']
    has_delete = any(w in text for w in delete_words)
    if not has_delete:
        potential_na.append(r)

print(f"Requests without obvious delete words: {len(potential_na)}")
for r in potential_na[:15]:
    print(f"\n{r['case_id']}: {r['request_text']}")
