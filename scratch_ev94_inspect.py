"""
Inspect evidence_94 (log file) for analytics records and understand
why analytics_9406 isn't being associated with the user for case_03.
"""
import csv, json, os

ev_manifest = {}
with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        ev_manifest[r['file_id']] = r

info = ev_manifest['evidence_94']
print(f"evidence_94: path={info['file_path']} captured={info['captured_at']}")

p = os.path.join('dataset', info['file_path'])
with open(p, encoding='utf-8', errors='ignore') as f:
    content = f.read()

print(f"File size: {len(content)} chars")
print("\nFirst 50 lines:")
for i, line in enumerate(content.splitlines()[:50]):
    print(f"  {i+1}: {line}")

# Check if analytics_9406 appears in the file
print("\n=== Lines containing analytics or l.fontaine ===")
for line in content.splitlines():
    if 'analytics' in line.lower() or 'fontaine' in line.lower() or 'analytics_9406' in line:
        print(f"  {line}")
