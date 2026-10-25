with open('dataset/evidence/logs/resource_lookup_trace_20260926_103856.log', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines in evidence_94: {len(lines)}")
for l in lines:
    print(l.strip())
