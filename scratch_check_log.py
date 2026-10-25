with open('dataset/evidence/logs/resource_lookup_trace_20260926_103856.log', 'r', encoding='utf-8') as f:
    lines = [line.strip() for line in f if '2016' in line or '7566' in line or '9406' in line]
print(f"Matching lines in evidence_94 ({len(lines)}):")
for l in lines[:20]:
    print(l)
